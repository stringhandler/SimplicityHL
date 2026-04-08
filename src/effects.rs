//! Effects analysis for compiled SimplicityHL programs.
//!
//! Wraps `simplicity::effects` with source-map integration and higher-level result types.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use simplicity::dag::{DagLike, MaxSharing};
use simplicity::effects::{
    annotate_commit, enumerate_code_paths, malleability_analysis, pruneable_nodes, BranchArm,
    TransactionField,
};
use simplicity::jet::Elements;
use simplicity::node::{Commit, Inner};
use simplicity::CommitNode;

use crate::source_map::{SourceMap, SourceSpan};

/// A pruneable subtree: target type is `Unit`, no side effects, not a bare `unit` literal.
pub struct PruneableNode {
    /// MaxSharing post-order index of the node.
    pub ms_index: usize,
    /// Resolved source location, if a source map is available.
    pub source_span: Option<SourceSpan>,
}

/// A code path that has no failure effect (accepts all inputs unconditionally).
pub struct WeakCodePath {
    /// 0-based index into all enumerated paths.
    pub path_index: usize,
    /// Branch choices that select this path: `(ms_index_of_case_node, arm)`.
    pub choices: Vec<(usize, BranchArm)>,
    /// Resolved source locations for each branch point, in choices order.
    pub branch_spans: Vec<SourceSpan>,
}

impl WeakCodePath {
    /// Human-readable description of the branch choices for this path.
    pub fn label(&self) -> String {
        if self.choices.is_empty() {
            "(no branches)".to_owned()
        } else {
            self.choices
                .iter()
                .map(|(sid, arm)| {
                    let arm_str = match arm {
                        BranchArm::Left => "left",
                        BranchArm::Right => "right",
                    };
                    format!("case #{sid} -> {arm_str}")
                })
                .collect::<Vec<_>>()
                .join(", ")
        }
    }
}

/// Results of all effects analyses for a compiled program.
pub struct EffectsAnalysis {
    /// `true` if the program has at least one path that can fail.
    pub has_failure_path: bool,
    /// Transaction fields not read by any code path (malleable).
    pub malleable_fields: Vec<TransactionField>,
    /// Top-level pruneable subtrees (deduplicated, compiler plumbing filtered out).
    pub pruneable_nodes: Vec<PruneableNode>,
    /// Total number of enumerated code paths (may be capped).
    pub total_code_paths: usize,
    /// `true` if path enumeration was capped before exploring all paths.
    pub code_paths_truncated: bool,
    /// Code paths that have no failure effect.
    pub weak_code_paths: Vec<WeakCodePath>,
}

/// Analyse the effects of a compiled Simplicity program.
///
/// Pass the optional source map to attach source locations to results.
pub fn analyse(
    commit: &Arc<CommitNode<Elements>>,
    source_map: Option<&SourceMap>,
) -> EffectsAnalysis {
    let summaries = annotate_commit(commit);

    let has_failure_path = summaries.last().map_or(true, |s| s.can_fail);

    let universe = TransactionField::all_elements();
    let mal = malleability_analysis(&summaries, &universe);
    let malleable_fields: Vec<TransactionField> = mal.uncovered.into_iter().collect();

    // Single MaxSharing walk: build ms_index→IHR map and filtering sets.
    let pruneable = pruneable_nodes(&summaries);
    let pruneable_set: HashSet<usize> = pruneable.iter().map(|p| p.node_index).collect();
    let mut subsumed: HashSet<usize> = HashSet::new();
    let mut bare_units: HashSet<usize> = HashSet::new();
    let mut drop_iden: HashSet<usize> = HashSet::new();
    let mut ms_to_ihr: HashMap<usize, String> = HashMap::new();

    for item in commit
        .clone()
        .post_order_iter::<MaxSharing<Commit<Elements>>>()
    {
        if pruneable_set.contains(&item.index) {
            if let Some(l) = item.left_index {
                subsumed.insert(l);
            }
            if let Some(r) = item.right_index {
                subsumed.insert(r);
            }
        }
        if matches!(item.node.inner(), Inner::Unit) {
            bare_units.insert(item.index);
        }
        // drop(iden) is compiler-generated sequencing plumbing — not user-actionable.
        if let Inner::Drop(child) = item.node.inner() {
            if matches!(child.inner(), Inner::Iden) {
                drop_iden.insert(item.index);
            }
        }
        if let Some(ihr) = item.node.sharing_id() {
            ms_to_ihr.insert(item.index, ihr.to_string());
        }
    }

    let lookup_span = |ms_index: usize| -> Option<SourceSpan> {
        ms_to_ihr
            .get(&ms_index)
            .and_then(|ihr| source_map?.lookup_by_ihr(ihr))
            .cloned()
    };

    let pruneable_nodes: Vec<PruneableNode> = pruneable
        .iter()
        .filter(|p| !subsumed.contains(&p.node_index))
        .filter(|p| !bare_units.contains(&p.node_index))
        .filter(|p| !drop_iden.contains(&p.node_index))
        .map(|p| PruneableNode {
            ms_index: p.node_index,
            source_span: lookup_span(p.node_index),
        })
        .collect();

    let (paths, truncated) = enumerate_code_paths(commit, 64);
    let total_code_paths = paths.len();
    let weak_code_paths: Vec<WeakCodePath> = paths
        .iter()
        .enumerate()
        .filter(|(_, p)| !p.can_fail)
        .map(|(i, path)| {
            let branch_spans: Vec<SourceSpan> = path
                .choices
                .iter()
                .filter_map(|(idx, _)| lookup_span(*idx))
                .collect();
            WeakCodePath {
                path_index: i,
                choices: path.choices.clone(),
                branch_spans,
            }
        })
        .collect();

    EffectsAnalysis {
        has_failure_path,
        malleable_fields,
        pruneable_nodes,
        total_code_paths,
        code_paths_truncated: truncated,
        weak_code_paths,
    }
}
