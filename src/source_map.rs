use std::collections::HashMap;
use std::fmt::Write;

use crate::error::Span;

/// Metadata collected for a single Simplicity node during compilation.
pub(crate) struct NodeMeta {
    pub span: Span,
    pub node_type: String,
    pub parent_index: Option<usize>,
}

/// Maps Simplicity encoding node indices to SimplicityHL source locations.
///
/// Each entry records which source expression (by line:column range) produced the root node
/// at a given position in the post-order (encoding-order) DAG enumeration.
#[derive(Clone, Debug)]
pub struct SourceMap {
    entries: Vec<SourceMapEntry>,
}

/// A mapping from a single Simplicity encoding index to a source location.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceMapEntry {
    /// Position of the node in the post-order (encoding-order / InternalSharing) enumeration
    /// of the Simplicity DAG.
    pub node_index: usize,
    /// Position of the node in the MaxSharing post-order enumeration, used by the effects
    /// analysis. Multiple entries may share the same `max_sharing_index` when MaxSharing
    /// deduplicates nodes that InternalSharing keeps separate.
    /// `None` until [`SourceMap::populate_max_sharing_indices`] is called.
    pub max_sharing_index: Option<usize>,
    /// The Simplicity combinator type of this node (e.g. "comp", "pair", "jet(eq_16)").
    pub node_type: String,
    /// Encoding index of this node's parent in the DAG, if any.
    pub parent_index: Option<usize>,
    /// First line of the SimplicityHL expression that produced this node (1-based).
    pub start_line: u32,
    /// Column on `start_line` where the expression begins (1-based).
    pub start_col: u32,
    /// Last line of the SimplicityHL expression that produced this node (1-based, inclusive).
    pub end_line: u32,
    /// Column on `end_line` where the expression ends (1-based, exclusive).
    pub end_col: u32,
}

impl SourceMap {
    /// Build a source map from per-node metadata and the source text.
    pub(crate) fn new(node_metas: HashMap<usize, NodeMeta>, source: &str) -> Self {
        let mut entries: Vec<SourceMapEntry> = node_metas
            .into_iter()
            .map(|(node_index, meta)| {
                let (start_line, start_col, end_line, end_col) =
                    span_to_location(meta.span, source);
                SourceMapEntry {
                    node_index,
                    max_sharing_index: None,
                    node_type: meta.node_type,
                    parent_index: meta.parent_index,
                    start_line,
                    start_col,
                    end_line,
                    end_col,
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

    /// Populate the `max_sharing_index` field on each entry using a mapping
    /// from InternalSharing index to MaxSharing index.
    pub fn populate_max_sharing_indices(&mut self, is_to_ms: &HashMap<usize, usize>) {
        for entry in &mut self.entries {
            entry.max_sharing_index = is_to_ms.get(&entry.node_index).copied();
        }
    }

    /// Find the first entry whose `max_sharing_index` matches the given value.
    pub fn lookup_by_max_sharing_index(&self, ms_index: usize) -> Option<&SourceMapEntry> {
        self.entries
            .iter()
            .find(|e| e.max_sharing_index == Some(ms_index))
    }

    /// Parse a source map from a `.map` JSON string produced by [`Self::to_map_json`].
    pub fn from_map_json(json: &str) -> Result<(Self, String), String> {
        let source_file = extract_json_string(json, "\"sourceFile\"")
            .ok_or_else(|| "missing \"sourceFile\" in source map".to_string())?;

        let mut entries = Vec::new();
        let nodes_start = json
            .find("\"nodes\"")
            .ok_or_else(|| "missing \"nodes\" in source map".to_string())?;
        let nodes_section = &json[nodes_start..];
        let mut search_from = 0;
        while let Some(open) = nodes_section[search_from..].find('{') {
            let abs_open = search_from + open;
            if let Some(close) = nodes_section[abs_open..].find('}') {
                let obj = &nodes_section[abs_open..abs_open + close + 1];
                if let Some(entry) = parse_node_entry(obj) {
                    entries.push(entry);
                }
                search_from = abs_open + close + 1;
            } else {
                break;
            }
        }
        entries.sort_by_key(|e| e.node_index);
        Ok((SourceMap { entries }, source_file))
    }

    /// Produce an annotated version of the source text.
    ///
    /// Each source line is emitted verbatim. After lines that produced Simplicity nodes,
    /// a comment is appended listing the node indices and their types.
    pub fn annotate_source(&self, source: &str) -> String {
        // Build a map: line_number (1-based) -> sorted list of (node_index, node_type).
        let mut line_to_nodes: HashMap<u32, Vec<(usize, &str)>> = HashMap::new();
        for entry in &self.entries {
            for line in entry.start_line..=entry.end_line {
                line_to_nodes
                    .entry(line)
                    .or_default()
                    .push((entry.node_index, &entry.node_type));
            }
        }
        for nodes in line_to_nodes.values_mut() {
            nodes.sort_by_key(|(idx, _)| *idx);
            nodes.dedup_by_key(|(idx, _)| *idx);
        }

        let lines: Vec<&str> = source.lines().collect();
        let max_len = lines.iter().map(|l| l.len()).max().unwrap_or(0);
        let comment_col = max_len + 2;

        let mut out = String::new();
        for (i, line) in lines.iter().enumerate() {
            let line_num = (i + 1) as u32;
            if let Some(nodes) = line_to_nodes.get(&line_num) {
                let padding = comment_col.saturating_sub(line.len());
                let nodes_str: String = nodes
                    .iter()
                    .map(|(idx, ty)| format!("#{idx} {ty}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let _ = writeln!(out, "{line}{:padding$}// {nodes_str}", "");
            } else {
                let _ = writeln!(out, "{line}");
            }
        }
        out
    }

    /// Serialize to a `.map` JSON string.
    pub fn to_map_json(&self, source_file: &str) -> String {
        let mut out = format!(
            "{{\n  \"version\": 1,\n  \"sourceFile\": \"{source_file}\",\n  \"nodes\": [\n"
        );
        for (i, entry) in self.entries.iter().enumerate() {
            if i > 0 {
                out.push_str(",\n");
            }
            let parent_str = match entry.parent_index {
                Some(p) => format!("{p}"),
                None => "null".to_string(),
            };
            let ms_str = match entry.max_sharing_index {
                Some(ms) => format!("{ms}"),
                None => "null".to_string(),
            };
            out.push_str(&format!(
                "    {{\"index\": {}, \"max_sharing_index\": {}, \"type\": \"{}\", \"parent\": {}, \
                 \"start_line\": {}, \"start_col\": {}, \"end_line\": {}, \"end_col\": {}}}",
                entry.node_index,
                ms_str,
                entry.node_type,
                parent_str,
                entry.start_line,
                entry.start_col,
                entry.end_line,
                entry.end_col,
            ));
        }
        out.push_str("\n  ]\n}");
        out
    }
}

/// Extract a JSON string value for a given key.
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pos = json.find(key)?;
    let after = &json[pos..];
    let colon = after.find(':')?;
    let rest = after[colon + 1..].trim_start();
    if rest.starts_with('"') {
        let inner = &rest[1..];
        let end = inner.find('"')?;
        Some(inner[..end].to_string())
    } else {
        None
    }
}

/// Extract a u64 value for a given JSON key.
fn extract_u64(obj: &str, key: &str) -> Option<u64> {
    let pos = obj.find(key)?;
    let after_key = &obj[pos + key.len()..];
    let colon = after_key.find(':')?;
    let rest = after_key[colon + 1..].trim_start();
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    rest[..end].parse().ok()
}

/// Parse a single node entry JSON object.
fn parse_node_entry(obj: &str) -> Option<SourceMapEntry> {
    let node_type = extract_json_string(obj, "\"type\"").unwrap_or_default();
    let parent_index = extract_u64(obj, "\"parent\"").map(|v| v as usize);

    let max_sharing_index = extract_u64(obj, "\"max_sharing_index\"").map(|v| v as usize);

    Some(SourceMapEntry {
        node_index: extract_u64(obj, "\"index\"")? as usize,
        max_sharing_index,
        node_type,
        parent_index,
        start_line: extract_u64(obj, "\"start_line\"")? as u32,
        start_col: extract_u64(obj, "\"start_col\"")? as u32,
        end_line: extract_u64(obj, "\"end_line\"")? as u32,
        end_col: extract_u64(obj, "\"end_col\"")? as u32,
    })
}

/// Compute 1-based (line, col) for both start and end of a byte-offset span.
fn span_to_location(span: Span, source: &str) -> (u32, u32, u32, u32) {
    let start = span.start.min(source.len());
    let end = span.end.min(source.len());

    let start_line = 1 + source[..start].bytes().filter(|&b| b == b'\n').count() as u32;
    let start_col = 1 + source[..start]
        .rfind('\n')
        .map_or(start, |nl| start - nl - 1) as u32;

    let end_line = 1 + source[..end].bytes().filter(|&b| b == b'\n').count() as u32;
    let end_col = 1 + source[..end]
        .rfind('\n')
        .map_or(end, |nl| end - nl - 1) as u32;

    (start_line, start_col, end_line, end_col)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_meta(span: Span) -> NodeMeta {
        NodeMeta {
            span,
            node_type: "unit".to_string(),
            parent_index: None,
        }
    }

    fn make_meta_with(span: Span, node_type: &str, parent: Option<usize>) -> NodeMeta {
        NodeMeta {
            span,
            node_type: node_type.to_string(),
            parent_index: parent,
        }
    }

    #[test]
    fn span_to_location_single_line() {
        let source = "fn main() {\n    let x = 1;\n}\n";
        let span = Span { start: 16, end: 26 };
        let (sl, sc, el, ec) = span_to_location(span, source);
        assert_eq!((sl, sc), (2, 5));
        assert_eq!((el, ec), (2, 15));
    }

    #[test]
    fn span_to_location_multi_line() {
        let source = "line1\nline2\nline3\nline4\n";
        let span = Span { start: 6, end: 17 };
        let (sl, sc, el, ec) = span_to_location(span, source);
        assert_eq!((sl, sc), (2, 1));
        assert_eq!((el, ec), (3, 6));
    }

    #[test]
    fn span_to_location_first_line() {
        let source = "hello\nworld\n";
        let span = Span { start: 0, end: 4 };
        let (sl, sc, el, ec) = span_to_location(span, source);
        assert_eq!((sl, sc), (1, 1));
        assert_eq!((el, ec), (1, 5));
    }

    #[test]
    fn span_to_location_clamped_past_end() {
        let source = "ab\ncd\n";
        let span = Span { start: 0, end: 999 };
        let (sl, sc, el, _ec) = span_to_location(span, source);
        assert_eq!(sl, 1);
        assert_eq!(sc, 1);
        assert_eq!(el, 3);
    }

    #[test]
    fn source_map_new_sorts_by_index() {
        let source = "aaa\nbbb\nccc\n";
        let mut metas = HashMap::new();
        metas.insert(5, make_meta(Span { start: 4, end: 7 }));
        metas.insert(2, make_meta(Span { start: 0, end: 3 }));
        metas.insert(9, make_meta(Span { start: 8, end: 11 }));

        let sm = SourceMap::new(metas, source);
        let entries = sm.entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].node_index, 2);
        assert_eq!(entries[1].node_index, 5);
        assert_eq!(entries[2].node_index, 9);
    }

    #[test]
    fn source_map_entries_have_correct_locations() {
        let source = "fn main() {\n    let x = 1;\n    let y = 2;\n}\n";
        let mut metas = HashMap::new();
        metas.insert(0, make_meta(Span { start: 16, end: 26 }));
        metas.insert(1, make_meta(Span { start: 31, end: 41 }));

        let sm = SourceMap::new(metas, source);
        let entries = sm.entries();
        assert_eq!(entries[0].start_line, 2);
        assert_eq!(entries[0].start_col, 5);
        assert_eq!(entries[0].end_line, 2);
        assert_eq!(entries[0].end_col, 15);
        assert_eq!(entries[1].start_line, 3);
        assert_eq!(entries[1].start_col, 5);
    }

    #[test]
    fn source_map_empty() {
        let sm = SourceMap::new(HashMap::new(), "anything\n");
        assert!(sm.entries().is_empty());
    }

    #[test]
    fn to_map_json_contains_type_and_parent() {
        let source = "line1\nline2\n";
        let mut metas = HashMap::new();
        metas.insert(
            0,
            make_meta_with(Span { start: 0, end: 5 }, "iden", Some(1)),
        );
        metas.insert(
            1,
            make_meta_with(Span { start: 0, end: 5 }, "comp", None),
        );

        let sm = SourceMap::new(metas, source);
        let json = sm.to_map_json("test.simf");

        assert!(json.contains("\"type\": \"iden\""));
        assert!(json.contains("\"type\": \"comp\""));
        assert!(json.contains("\"parent\": 1"));
        assert!(json.contains("\"parent\": null"));
    }

    #[test]
    fn from_map_json_roundtrip() {
        let source = "aaa\nbbb\nccc\n";
        let mut metas = HashMap::new();
        metas.insert(
            0,
            make_meta_with(Span { start: 0, end: 3 }, "take", Some(3)),
        );
        metas.insert(
            3,
            make_meta_with(Span { start: 4, end: 7 }, "comp", None),
        );

        let original = SourceMap::new(metas, source);
        let json = original.to_map_json("hello.simf");
        let (parsed, source_file) = SourceMap::from_map_json(&json).unwrap();

        assert_eq!(source_file, "hello.simf");
        assert_eq!(parsed.entries().len(), original.entries().len());
        for (a, b) in parsed.entries().iter().zip(original.entries().iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn from_map_json_missing_source_file() {
        let json = r#"{"version": 1, "nodes": []}"#;
        assert!(SourceMap::from_map_json(json).is_err());
    }

    #[test]
    fn from_map_json_missing_nodes() {
        let json = r#"{"version": 1, "sourceFile": "x.simf"}"#;
        assert!(SourceMap::from_map_json(json).is_err());
    }

    #[test]
    fn annotate_source_shows_types() {
        let source = "fn main() {\n    let x = 1;\n    let y = 2;\n}\n";
        let mut metas = HashMap::new();
        metas.insert(
            0,
            make_meta_with(Span { start: 12, end: 26 }, "comp", None),
        );
        metas.insert(
            1,
            make_meta_with(Span { start: 27, end: 41 }, "pair", None),
        );

        let sm = SourceMap::new(metas, source);
        let annotated = sm.annotate_source(source);

        let lines: Vec<&str> = annotated.lines().collect();
        assert!(!lines[0].contains("//"));
        assert!(lines[1].contains("#0 comp"));
        assert!(lines[2].contains("#1 pair"));
        assert!(!lines[3].contains("//"));
    }

    #[test]
    fn annotate_source_multiple_nodes_same_line() {
        let source = "aaa\nbbb\n";
        let mut metas = HashMap::new();
        metas.insert(
            2,
            make_meta_with(Span { start: 0, end: 3 }, "take", None),
        );
        metas.insert(
            5,
            make_meta_with(Span { start: 0, end: 3 }, "drop", None),
        );

        let sm = SourceMap::new(metas, source);
        let annotated = sm.annotate_source(source);

        let lines: Vec<&str> = annotated.lines().collect();
        assert!(lines[0].contains("#2 take"));
        assert!(lines[0].contains("#5 drop"));
    }

    #[test]
    fn annotate_source_multiline_span() {
        let source = "line1\nline2\nline3\n";
        let mut metas = HashMap::new();
        metas.insert(
            0,
            make_meta_with(Span { start: 0, end: 11 }, "comp", None),
        );

        let sm = SourceMap::new(metas, source);
        let annotated = sm.annotate_source(source);

        let lines: Vec<&str> = annotated.lines().collect();
        assert!(lines[0].contains("#0 comp"));
        assert!(lines[1].contains("#0 comp"));
        assert!(!lines[2].contains("//"));
    }

    #[test]
    fn annotate_source_empty_map() {
        let source = "fn main() {}\n";
        let sm = SourceMap::new(HashMap::new(), source);
        let annotated = sm.annotate_source(source);
        assert_eq!(annotated, "fn main() {}\n");
    }
}
