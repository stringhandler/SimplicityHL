use std::collections::HashMap;

use crate::error::Span;

/// Maps Simplicity encoding node indices to SimplicityHL source line numbers.
///
/// Each entry records which source expression (by line range) produced the root node
/// at a given position in the post-order (encoding-order) DAG enumeration.
#[derive(Clone, Debug)]
pub struct SourceMap {
    entries: Vec<SourceMapEntry>,
}

/// A mapping from a single Simplicity encoding index to source line numbers.
#[derive(Clone, Debug)]
pub struct SourceMapEntry {
    /// Position of the node in the post-order (encoding-order) enumeration of the Simplicity DAG.
    pub node_index: usize,
    /// First line of the SimplicityHL expression that produced this node (1-based).
    pub start_line: u32,
    /// Last line of the SimplicityHL expression that produced this node (1-based, inclusive).
    pub end_line: u32,
}

impl SourceMap {
    /// Build a source map from the encoding-index-to-span map and the source text.
    pub(crate) fn new(index_to_span: HashMap<usize, Span>, source: &str) -> Self {
        let mut entries: Vec<SourceMapEntry> = index_to_span
            .into_iter()
            .map(|(node_index, span)| {
                let (start_line, end_line) = span_to_lines(span, source);
                SourceMapEntry {
                    node_index,
                    start_line,
                    end_line,
                }
            })
            .collect();
        entries.sort_by_key(|e| e.node_index);
        SourceMap { entries }
    }

    /// Access the individual node entries, sorted by encoding index.
    pub fn entries(&self) -> &[SourceMapEntry] {
        &self.entries
    }

    /// Serialize to a `.map` JSON string.
    ///
    /// The format is inspired by Source Map v3 but adapted for Simplicity's DAG node model
    /// instead of line/column pairs in text output.  Two sections are produced:
    ///
    /// - `nodes`: one entry per annotated node — its encoding index and the source lines.
    /// - `groups`: one entry per unique source line range — the set of node indices it produced.
    pub fn to_map_json(&self, source_file: &str) -> String {
        // Aggregate groups: (start_line, end_line) -> sorted node_indices
        let mut groups: HashMap<(u32, u32), Vec<usize>> = HashMap::new();
        for entry in &self.entries {
            groups
                .entry((entry.start_line, entry.end_line))
                .or_default()
                .push(entry.node_index);
        }
        let mut groups_vec: Vec<((u32, u32), Vec<usize>)> = groups.into_iter().collect();
        groups_vec.sort_by_key(|((start, _), _)| *start);

        let mut out = format!(
            "{{\n  \"version\": 1,\n  \"sourceFile\": \"{source_file}\",\n  \"nodes\": [\n"
        );
        for (i, entry) in self.entries.iter().enumerate() {
            if i > 0 {
                out.push_str(",\n");
            }
            out.push_str(&format!(
                "    {{\"index\": {}, \"start_line\": {}, \"end_line\": {}}}",
                entry.node_index, entry.start_line, entry.end_line
            ));
        }
        out.push_str("\n  ],\n  \"groups\": [\n");
        for (i, ((start, end), mut indices)) in groups_vec.into_iter().enumerate() {
            if i > 0 {
                out.push_str(",\n");
            }
            indices.sort_unstable();
            let indices_str: String = indices
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!(
                "    {{\"start_line\": {start}, \"end_line\": {end}, \"node_indices\": [{indices_str}]}}"
            ));
        }
        out.push_str("\n  ]\n}");
        out
    }
}

/// Compute 1-based start and end line numbers for a byte-offset span.
fn span_to_lines(span: Span, source: &str) -> (u32, u32) {
    let start_line = 1 + source[..span.start.min(source.len())]
        .bytes()
        .filter(|&b| b == b'\n')
        .count() as u32;
    let end_line = 1 + source[..span.end.min(source.len())]
        .bytes()
        .filter(|&b| b == b'\n')
        .count() as u32;
    (start_line, end_line)
}
