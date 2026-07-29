//! Expression evaluation without a full transaction context.
//!
//! This module provides [`eval_expression`], which evaluates a SimplicityHL expression
//! against named runtime bindings. It is intended for wallet tooling that needs to
//! compute derived values (e.g. asset IDs from outpoint data) before constructing a
//! transaction.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;

use simplicity::jet::Elements;
use simplicity::CommitNode;

use crate::ast::ElementsJetHinter;
use crate::dummy_env;
use crate::jet::target_type;
use crate::str::WitnessName;
use crate::tracker::DefaultTracker;
use crate::value::Value;
use crate::witness::Arguments;
use crate::{TemplateProgram, WitnessValues};

/// Error type returned by [`eval_expression`].
#[derive(Debug, Clone)]
pub enum EvalError {
    /// The expression references one or more jets that require a live transaction
    /// context (introspection jets). These cannot be evaluated without an
    /// [`ElementsEnv`](simplicity::jet::elements::ElementsEnv).
    RequiresTransactionContext(Vec<String>),
    /// The expression failed to compile or execute.
    CompilationError(String),
    /// The expression executed but produced no value. This can occur when the
    /// expression contains no jet calls (e.g. a bare binding reference), since
    /// the result is captured via the jet trace sink rather than the bit machine
    /// output cell.
    NoResult,
}

impl std::fmt::Display for EvalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvalError::RequiresTransactionContext(jets) => write!(
                f,
                "expression references transaction introspection jets: {}",
                jets.join(", ")
            ),
            EvalError::CompilationError(e) => write!(f, "compilation error: {e}"),
            EvalError::NoResult => write!(f, "expression produced no result"),
        }
    }
}

impl std::error::Error for EvalError {}

/// Returns `true` if the given Elements jet reads from the transaction environment
/// (i.e., requires a real [`ElementsEnv`](simplicity::jet::elements::ElementsEnv)).
///
/// **Maintenance**: this is a positive allowlist, so a jet that is *not* listed
/// is treated as pure and will be executed against the dummy environment. That
/// is a fail-open default: a new upstream introspection jet would silently return
/// bogus data. The `introspection_allowlist_is_pinned_to_jet_set` test guards
/// against this by pinning the total jet count — when the `simplicity` crate
/// changes its jet set, that test fails so the new variants get audited and any
/// transaction-reading ones added below.
pub fn requires_transaction_context(jet: Elements) -> bool {
    use Elements::*;
    matches!(
        jet,
        // Signature hash modes (hash transaction fields)
        SigAllHash
            | TxHash
            | TapEnvHash
            | InputsHash
            | OutputsHash
            | IssuancesHash
            | InputUtxosHash
            | OutputAmountsHash
            | OutputScriptsHash
            | OutputNoncesHash
            | OutputRangeProofsHash
            | OutputSurjectionProofsHash
            | InputOutpointsHash
            | InputAnnexesHash
            | InputSequencesHash
            | InputScriptSigsHash
            | IssuanceAssetAmountsHash
            | IssuanceTokenAmountsHash
            | IssuanceRangeProofsHash
            | IssuanceBlindingEntropyHash
            | InputAmountsHash
            | InputScriptsHash
            | TapleafHash
            | TappathHash
            // Time lock checks that read from the transaction
            | CheckLockTime
            | BrokenDoNotUseCheckLockDistance
            | BrokenDoNotUseCheckLockDuration
            | CheckLockHeight
            | TxLockTime
            | BrokenDoNotUseTxLockDistance
            | BrokenDoNotUseTxLockDuration
            | TxLockHeight
            | TxIsFinal
            // Issuance introspection (reads current input's issuance)
            | Issuance
            | IssuanceAsset
            | IssuanceToken
            | IssuanceEntropy
            // Transaction-level fields
            | ScriptCMR
            | InternalKey
            | CurrentIndex
            | NumInputs
            | NumOutputs
            | LockTime
            | CurrentPegin
            | CurrentPrevOutpoint
            | CurrentAsset
            | CurrentAmount
            | CurrentScriptHash
            | CurrentSequence
            | CurrentAnnexHash
            | CurrentScriptSigHash
            | CurrentReissuanceBlinding
            | CurrentNewIssuanceContract
            | CurrentReissuanceEntropy
            | CurrentIssuanceTokenAmount
            | CurrentIssuanceAssetAmount
            | CurrentIssuanceAssetProof
            | CurrentIssuanceTokenProof
            | TapleafVersion
            | Version
            | GenesisBlockHash
            | LbtcAsset
            | TransactionId
            // Per-input and per-output field access
            | OutputAsset
            | OutputAmount
            | OutputNonce
            | OutputScriptHash
            | OutputIsFee
            | OutputSurjectionProof
            | OutputRangeProof
            | OutputHash
            | OutputNullDatum
            | InputPegin
            | InputPrevOutpoint
            | InputAsset
            | InputAmount
            | InputScriptHash
            | InputSequence
            | InputAnnexHash
            | InputScriptSigHash
            | InputHash
            | InputUtxoHash
            | ReissuanceBlinding
            | NewIssuanceContract
            | ReissuanceEntropy
            | IssuanceAssetAmount
            | IssuanceTokenAmount
            | IssuanceAssetProof
            | IssuanceTokenProof
            | IssuanceHash
            | TotalFee
            | Tappath
    )
}

/// Convert a binding key such as `"yes_issuance.outpoint_hash"` into a valid
/// uppercase SimplicityHL parameter name such as `"EB_YES_ISSUANCE_OUTPOINT_HASH"`.
fn sanitize_key(key: &str) -> String {
    let sanitized: String = key
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' })
        .collect();
    format!("EB_{}", sanitized.to_ascii_uppercase())
}

/// Strip `//` line comments and `/* */` block comments from `s`.
fn strip_comments(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '/' {
            match chars.peek() {
                Some('/') => {
                    chars.next();
                    for ch in chars.by_ref() {
                        if ch == '\n' {
                            result.push('\n');
                            break;
                        }
                    }
                }
                Some('*') => {
                    chars.next();
                    let mut prev = '\0';
                    for ch in chars.by_ref() {
                        if prev == '*' && ch == '/' {
                            break;
                        }
                        prev = ch;
                    }
                    result.push(' ');
                }
                _ => result.push(c),
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Whether `c` can appear inside an identifier (alphanumeric or `_`).
fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Collect the names of Elements introspection jets referenced by a compiled
/// node.
///
/// This walks the node's DAG — the robust, structural check — rather than
/// scanning source text, so jets reached through `let` bindings, tuples, or
/// comments are still caught. Both [`eval_expression`] and
/// [`CompiledFunction::execute`](crate::CompiledFunction::execute) use it to
/// reject work that needs a live transaction context before running it against
/// the dummy environment.
pub(crate) fn introspection_jets_in(commit: &Arc<CommitNode>) -> Vec<String> {
    use simplicity::dag::DagLike as _;
    use simplicity::node::Inner;

    let mut found: Vec<String> = Vec::new();
    for data in Arc::clone(commit).post_order_iter::<simplicity::dag::NoSharing>() {
        if let Inner::Jet(jet) = data.node.inner() {
            if let Some(el) = jet.as_ref().as_any().downcast_ref::<Elements>() {
                if requires_transaction_context(*el) {
                    let name = el.to_string();
                    if !found.contains(&name) {
                        found.push(name);
                    }
                }
            }
        }
    }
    found
}

/// Attempt to infer the SimplicityHL return type string by inspecting the
/// outermost expression. Only works when the expression is a direct jet call
/// (`jet::name(...)`).
fn infer_return_type(expr: &str) -> Option<String> {
    let trimmed = expr.trim();
    let rest = trimmed.strip_prefix("jet::")?;
    let end = rest
        .find(|c: char| !is_ident_char(c))
        .unwrap_or(rest.len());
    let name = &rest[..end];
    let jet = Elements::from_str(name).ok()?;
    Some(target_type(&jet).to_string())
}

/// Replace `key` with `replacement` in `s` only at identifier word boundaries.
///
/// A match is accepted only when the character immediately before it is not
/// alphanumeric or `_` (or it is the start of the string), and the character
/// immediately after it is not alphanumeric or `_` (or it is the end of the
/// string). This prevents short binding names (e.g. `"c"`) from corrupting
/// jet identifiers (e.g. `calculate_asset`).
fn replace_identifier(s: &str, key: &str, replacement: &str) -> String {
    let mut result = String::with_capacity(s.len() + replacement.len());
    let mut remaining = s;

    while !remaining.is_empty() {
        if remaining.starts_with(key) {
            let before_ok = result
                .chars()
                .last()
                .map_or(true, |c| !is_ident_char(c));
            let after_ok = remaining[key.len()..]
                .chars()
                .next()
                .map_or(true, |c| !is_ident_char(c));

            if before_ok && after_ok {
                result.push_str(replacement);
                remaining = &remaining[key.len()..];
                continue;
            }
        }

        let ch = remaining.chars().next().unwrap();
        result.push(ch);
        remaining = &remaining[ch.len_utf8()..];
    }

    result
}

/// Evaluate a SimplicityHL expression string against named runtime bindings.
///
/// `source` is a single SimplicityHL expression whose outermost term is a
/// direct jet call, such as:
/// ```text
/// jet::calculate_asset(jet::calculate_issuance_entropy((param::HASH, param::VOUT), param::CONTRACT))
/// ```
///
/// **The outermost expression must be a `jet::name(...)` call.** Expressions
/// whose result comes from a `let` binding, a tuple, or a bare variable are
/// not supported and will return [`EvalError::CompilationError`].
///
/// `bindings` maps free-variable names that appear in `source` to their runtime
/// values. The names may contain dots (e.g. `"yes_issuance.outpoint_hash"`); they
/// are automatically sanitised into valid SimplicityHL parameter names.
///
/// # Errors
///
/// * [`EvalError::RequiresTransactionContext`] — the expression references one or
///   more transaction introspection jets.
/// * [`EvalError::CompilationError`] — the expression is not valid SimplicityHL,
///   the outermost expression is not a direct jet call, or execution failed.
/// * [`EvalError::NoResult`] — the expression executed but fired no jets, so no
///   result was captured (e.g. the expression contains no jet calls).
pub fn eval_expression<S: std::hash::BuildHasher>(
    source: &str,
    bindings: &HashMap<String, Value, S>,
) -> Result<Value, EvalError> {
    // Strip comments so that comments embedded in `source` don't corrupt the
    // synthetic program we build below. The introspection-jet guard runs on the
    // compiled DAG further down, so jets hidden in comments are naturally ignored
    // by the compiler rather than by this textual pass.
    let source_stripped = strip_comments(source);
    let source = source_stripped.as_str();

    // Build sanitised parameter names. Sort keys by length (longest first) so
    // that longer keys are replaced before shorter keys that might be substrings.
    let mut sorted_keys: Vec<&str> = bindings.keys().map(String::as_str).collect();
    sorted_keys.sort_by_key(|k| std::cmp::Reverse(k.len()));

    // Reject collisions where two distinct keys sanitise to the same param name
    // (e.g. `"a.b"` and `"a-b"` both -> `EB_A_B`). Without this check one binding
    // would be silently dropped and the wrong value used for both occurrences.
    let mut sanitized: HashMap<&str, String> = HashMap::with_capacity(sorted_keys.len());
    let mut by_name: HashMap<String, &str> = HashMap::with_capacity(sorted_keys.len());
    for &key in &sorted_keys {
        let name = sanitize_key(key);
        if let Some(&other) = by_name.get(&name) {
            return Err(EvalError::CompilationError(format!(
                "binding keys `{other}` and `{key}` both map to the parameter name \
                 `{name}`; rename one to avoid the collision"
            )));
        }
        by_name.insert(name.clone(), key);
        sanitized.insert(key, name);
    }

    // Replace each free-variable occurrence in the source with `param::SANITIZED`.
    // Use word-boundary-aware replacement so a short key like "c" doesn't corrupt
    // jet names like `calculate_asset` that contain it as a substring.
    let mut expr = source.to_string();
    for &key in &sorted_keys {
        expr = replace_identifier(&expr, key, &format!("param::{}", sanitized[key]));
    }

    // Infer the return type of the outermost expression so we can annotate the
    // let binding in the synthetic program.
    let return_type = infer_return_type(&expr).ok_or_else(|| {
        EvalError::CompilationError(format!(
            "cannot infer return type for expression `{expr}`; \
             the outermost expression must be a direct jet call (e.g. `jet::calculate_asset(...)`)"
        ))
    })?;

    // Build a minimal SimplicityHL program that computes the expression.
    let program_src = format!(
        "fn main() {{\n    let _result: {return_type} = {expr};\n}}\n"
    );

    // Compile.
    let template =
        TemplateProgram::new(program_src.as_str(), Box::new(ElementsJetHinter::new()))
            .map_err(|e| EvalError::CompilationError(e.to_string()))?;

    // Supply binding values as compile-time parameters.
    let arg_map: HashMap<WitnessName, Value> = sorted_keys
        .iter()
        .map(|&k| {
            (
                WitnessName::from_str_unchecked(&sanitized[k]),
                bindings[k].clone(),
            )
        })
        .collect();
    let arguments = Arguments::from(arg_map);

    let compiled = template
        .instantiate(arguments, false)
        .map_err(EvalError::CompilationError)?;

    // Reject expressions that need a live transaction context, walking the
    // compiled DAG rather than the source text (matches CompiledFunction::execute).
    let introspection = introspection_jets_in(&compiled.commit());
    if !introspection.is_empty() {
        return Err(EvalError::RequiresTransactionContext(introspection));
    }

    let satisfied = compiled
        .satisfy(WitnessValues::default())
        .map_err(EvalError::CompilationError)?;

    // Execute the program using the dummy environment and capture the result of
    // the last jet call via the jet trace sink.
    let last_result: Rc<RefCell<Option<Value>>> = Rc::default();
    let result_clone = last_result.clone();

    let mut tracker = DefaultTracker::build(satisfied.debug_symbols(), Box::new(ElementsJetHinter::new()))
        .with_jet_trace_sink(move |_jet, _args, result| {
            if let Some(value) = result {
                *result_clone.borrow_mut() = Some(value);
            }
        });

    satisfied
        .redeem()
        .prune_with_tracker(&dummy_env::dummy(), &mut tracker)
        .map_err(|e| EvalError::CompilationError(format!("execution error: {e:?}")))?;

    let result = last_result.borrow().clone();
    result.ok_or(EvalError::NoResult)
}

#[cfg(test)]
mod tests {
    use crate::num::U256;
    use crate::value::ValueConstructible;

    use super::*;

    /// SHA-256 of the empty string — the standard "no contract hash" value used
    /// in Elements new-issuance entropy calculations.
    const SHA256_EMPTY: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn u256_from_hex(s: &str) -> Value {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Value::u256(U256::from_byte_array(arr))
    }

    fn make_u32(n: u32) -> Value {
        Value::u32(n)
    }

    fn make_u256(bytes: [u8; 32]) -> Value {
        Value::u256(U256::from_byte_array(bytes))
    }

    /// Number of Elements jets `requires_transaction_context` was audited against.
    /// Bump this only after reviewing added/removed jets and updating the
    /// allowlist. See the pin test below for why.
    const EXPECTED_ELEMENTS_JET_COUNT: usize = 471;

    #[test]
    fn introspection_allowlist_is_pinned_to_jet_set() {
        // `requires_transaction_context` is a fail-open allowlist. Pin the jet
        // set so a change upstream fails loudly instead of silently letting a new
        // introspection jet run against the dummy environment.
        assert_eq!(
            Elements::ALL.len(),
            EXPECTED_ELEMENTS_JET_COUNT,
            "Elements jet set changed; audit new jets, update \
             requires_transaction_context, then set EXPECTED_ELEMENTS_JET_COUNT"
        );
    }

    #[test]
    fn test_introspection_jet_rejected() {
        let bindings = HashMap::new();
        let result = eval_expression("jet::num_inputs()", &bindings);
        match result {
            Err(EvalError::RequiresTransactionContext(jets)) => {
                assert!(jets.contains(&"num_inputs".to_string()));
            }
            other => panic!("expected RequiresTransactionContext, got {other:?}"),
        }
    }

    #[test]
    fn test_introspection_jet_in_comment_not_rejected() {
        // A jet name that appears only in a comment must not trigger the guard.
        let txid = [5u8; 32];
        let mut bindings = HashMap::new();
        bindings.insert("h".to_string(), make_u256(txid));
        bindings.insert("v".to_string(), make_u32(0));
        bindings.insert("c".to_string(), u256_from_hex(SHA256_EMPTY));

        // Line comment containing an introspection jet name.
        let result = eval_expression(
            "jet::calculate_asset(jet::calculate_issuance_entropy((h, v), c)) // not jet::num_inputs",
            &bindings,
        );
        assert!(result.is_ok(), "introspection jet in comment should not be rejected: {result:?}");

        // Block comment containing an introspection jet name.
        let result2 = eval_expression(
            "jet::calculate_asset(jet::calculate_issuance_entropy((h, v), c)) /* jet::current_index */",
            &bindings,
        );
        assert!(result2.is_ok(), "introspection jet in block comment should not be rejected: {result2:?}");
    }

    #[test]
    fn test_sanitize_key_collision_rejected() {
        // `"a.b"` and `"a-b"` both sanitise to `EB_A_B`. This must be rejected,
        // not silently collapsed into one binding.
        let mut bindings = HashMap::new();
        bindings.insert("a.b".to_string(), make_u32(1));
        bindings.insert("a-b".to_string(), make_u32(2));
        match eval_expression("jet::calculate_asset(a.b)", &bindings) {
            Err(EvalError::CompilationError(msg)) => {
                assert!(
                    msg.contains("map to the parameter name"),
                    "expected a collision error, got: {msg}"
                );
            }
            other => panic!("expected CompilationError for key collision, got {other:?}"),
        }
    }

    #[test]
    fn test_introspection_jet_rejected_input_amount() {
        let mut bindings = HashMap::new();
        bindings.insert("idx".to_string(), make_u32(0));
        let result = eval_expression("jet::input_amount(idx)", &bindings);
        match result {
            Err(EvalError::RequiresTransactionContext(_)) => {}
            other => panic!("expected RequiresTransactionContext, got {other:?}"),
        }
    }

    #[test]
    fn test_calculate_issuance_entropy_and_asset() {
        // Issuance entropy = sha256(sha256d(txid || vout_le) || contract_hash)
        // For txid = [1u8; 32], vout = 0, contract_hash = sha256("") this must
        // match the reference implementation.
        let txid = [1u8; 32];
        let vout: u32 = 0;

        let mut bindings = HashMap::new();
        bindings.insert("outpoint_hash".to_string(), make_u256(txid));
        bindings.insert("vout".to_string(), make_u32(vout));
        bindings.insert("contract_hash".to_string(), u256_from_hex(SHA256_EMPTY));

        // Compute the entropy first.
        let entropy = eval_expression(
            "jet::calculate_issuance_entropy((outpoint_hash, vout), contract_hash)",
            &bindings,
        )
        .expect("entropy calculation should succeed");

        // Now compute the asset ID from the entropy.
        let mut entropy_bindings = HashMap::new();
        entropy_bindings.insert("entropy".to_string(), entropy.clone());

        let asset = eval_expression("jet::calculate_asset(entropy)", &entropy_bindings)
            .expect("asset calculation should succeed");

        // Verify the types are as expected.
        assert_eq!(entropy.ty().to_string(), "u256", "entropy type");
        // ExplicitAsset is a type alias for u256; the resolved Value type is u256.
        assert_eq!(asset.ty().to_string(), "u256", "asset type");
    }

    #[test]
    fn test_nested_jet_call() {
        // Chain both calculations in a single expression.
        let txid = [2u8; 32];
        let vout: u32 = 1;

        let mut bindings = HashMap::new();
        bindings.insert("outpoint_hash".to_string(), make_u256(txid));
        bindings.insert("vout".to_string(), make_u32(vout));
        bindings.insert("contract_hash".to_string(), u256_from_hex(SHA256_EMPTY));

        let asset = eval_expression(
            "jet::calculate_asset(jet::calculate_issuance_entropy((outpoint_hash, vout), contract_hash))",
            &bindings,
        )
        .expect("chained calculation should succeed");

        // Should produce the same result as the two-step version.
        let mut entropy_bindings = bindings.clone();
        let entropy = eval_expression(
            "jet::calculate_issuance_entropy((outpoint_hash, vout), contract_hash)",
            &entropy_bindings,
        )
        .unwrap();
        entropy_bindings.insert("entropy".to_string(), entropy);

        let asset_two_step =
            eval_expression("jet::calculate_asset(entropy)", &entropy_bindings).unwrap();

        assert_eq!(asset, asset_two_step, "single-expression and two-step results must match");
    }

    #[test]
    fn test_dotted_binding_names() {
        // Binding keys containing dots are sanitised automatically.
        let txid = [3u8; 32];
        let vout: u32 = 2;

        let mut bindings = HashMap::new();
        bindings.insert("issuance.outpoint_hash".to_string(), make_u256(txid));
        bindings.insert("issuance.vout".to_string(), make_u32(vout));
        bindings.insert(
            "issuance.contract_hash".to_string(),
            u256_from_hex(SHA256_EMPTY),
        );

        let result = eval_expression(
            "jet::calculate_asset(jet::calculate_issuance_entropy((issuance.outpoint_hash, issuance.vout), issuance.contract_hash))",
            &bindings,
        )
        .expect("dotted binding names should work");

        // Should equal result using plain names.
        let mut plain_bindings = HashMap::new();
        plain_bindings.insert("outpoint_hash".to_string(), make_u256(txid));
        plain_bindings.insert("vout".to_string(), make_u32(vout));
        plain_bindings.insert("contract_hash".to_string(), u256_from_hex(SHA256_EMPTY));

        let expected = eval_expression(
            "jet::calculate_asset(jet::calculate_issuance_entropy((outpoint_hash, vout), contract_hash))",
            &plain_bindings,
        )
        .unwrap();

        assert_eq!(result, expected);
    }

    #[test]
    fn test_explicit_token() {
        let txid = [4u8; 32];
        let vout: u32 = 0;

        let mut bindings = HashMap::new();
        bindings.insert("h".to_string(), make_u256(txid));
        bindings.insert("v".to_string(), make_u32(vout));
        bindings.insert("c".to_string(), u256_from_hex(SHA256_EMPTY));

        let token = eval_expression(
            "jet::calculate_explicit_token(jet::calculate_issuance_entropy((h, v), c))",
            &bindings,
        )
        .expect("explicit token calculation should succeed");

        let asset = eval_expression(
            "jet::calculate_asset(jet::calculate_issuance_entropy((h, v), c))",
            &bindings,
        )
        .expect("asset calculation should succeed");

        // Asset and token IDs are derived from the same entropy but must differ.
        assert_ne!(asset, token, "asset and token IDs must be distinct");
    }
}
