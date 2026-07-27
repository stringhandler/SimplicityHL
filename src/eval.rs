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

use simplicity::jet::Elements;

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
/// **Maintenance**: this is a positive allowlist. When the `simplicity` crate
/// adds new Elements jets, audit the new variants and add any that access
/// transaction state to the `matches!` below.
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

/// Scan `expr` for `jet::name(...)` patterns and return the name and parsed
/// jet for each occurrence. The caller must have already stripped comments
/// from `expr`; see [`eval_expression`] which does this before calling here.
fn scan_jets(expr: &str) -> Vec<(String, Elements)> {
    let mut jets = Vec::new();
    let mut remaining = expr;

    while let Some(pos) = remaining.find("jet::") {
        remaining = &remaining[pos + 5..];
        let end = remaining
            .find(|c: char| !c.is_alphanumeric() && c != '_')
            .unwrap_or(remaining.len());
        let name = &remaining[..end];
        if let Ok(jet) = Elements::from_str(name) {
            jets.push((name.to_string(), jet));
        }
        remaining = &remaining[end..];
    }

    jets
}

/// Attempt to infer the SimplicityHL return type string by inspecting the
/// outermost expression. Only works when the expression is a direct jet call
/// (`jet::name(...)`).
fn infer_return_type(expr: &str) -> Option<String> {
    let trimmed = expr.trim();
    let rest = trimmed.strip_prefix("jet::")?;
    let end = rest
        .find(|c: char| !c.is_alphanumeric() && c != '_')
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
                .map(|c| !c.is_alphanumeric() && c != '_')
                .unwrap_or(true);
            let after_ok = remaining[key.len()..]
                .chars()
                .next()
                .map(|c| !c.is_alphanumeric() && c != '_')
                .unwrap_or(true);

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
pub fn eval_expression(
    source: &str,
    bindings: &HashMap<String, Value>,
) -> Result<Value, EvalError> {
    // Strip comments before any further processing so that jet names inside
    // comments don't trigger false-positive rejections, and so that comments
    // embedded in `source` don't corrupt the synthetic program we build below.
    let source_stripped = strip_comments(source);
    let source = source_stripped.as_str();

    // Early-exit if any jet in the expression requires transaction context.
    let introspection_jets: Vec<String> = scan_jets(source)
        .into_iter()
        .filter(|(_, jet)| requires_transaction_context(*jet))
        .map(|(name, _)| name)
        .collect();

    if !introspection_jets.is_empty() {
        return Err(EvalError::RequiresTransactionContext(introspection_jets));
    }

    // Build sanitised parameter names. Sort keys by length (longest first) so
    // that longer keys are replaced before shorter keys that might be substrings.
    let mut sorted_keys: Vec<&str> = bindings.keys().map(String::as_str).collect();
    sorted_keys.sort_by(|a, b| b.len().cmp(&a.len()));

    let sanitized: HashMap<&str, String> = sorted_keys
        .iter()
        .map(|&k| (k, sanitize_key(k)))
        .collect();

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
