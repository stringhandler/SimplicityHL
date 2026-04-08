use std::collections::HashMap;
use std::fmt::Write;

use crate::error::Span;

/// A resolved source span (1-based line/col) with the Simplicity combinator type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceSpan {
    pub start_line: u32,
    pub start_col: u32,
    pub end_line: u32,
    pub end_col: u32,
    pub node_type: String,
}

/// A raw (byte-offset) span paired with a node type, collected during compilation.
pub(crate) struct RawSpanMeta {
    pub span: Span,
    pub node_type: String,
}

/// Raw IHR-keyed span data collected during compilation, before line/col resolution.
///
/// Each element is `(ihr_hex, spans)` where spans are in IS encounter order.
pub(crate) struct IhrSpanData(pub Vec<(String, Vec<Option<RawSpanMeta>>)>);

/// One entry in the IHR-keyed source map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IhrEntry {
    /// The IHR as a hex string.
    pub ihr: String,
    /// Spans in IS post-order encounter order.
    /// `None` entries represent compiler-generated nodes without a source annotation.
    pub spans: Vec<Option<SourceSpan>>,
}

/// Maps IHR (Identity Hash Root) values to source locations.
///
/// Each IHR may appear multiple times in the InternalSharing post-order traversal.
/// The spans list records one entry per occurrence, in encounter order.
#[derive(Clone, Debug)]
pub struct SourceMap {
    entries: Vec<IhrEntry>,
    /// IHR hex → index into `entries`.
    lookup: HashMap<String, usize>,
}

impl SourceMap {
    /// Build a source map from IHR-keyed raw span data and the source text.
    ///
    /// Each element is `(ihr_hex, spans)` where spans are in IS encounter order.
    /// Byte-offset spans are converted to 1-based line/col using the source text.
    pub(crate) fn new(
        data: IhrSpanData,
        source: &str,
    ) -> Self {
        let data = data.0;
        let mut entries = Vec::with_capacity(data.len());
        let mut lookup = HashMap::with_capacity(data.len());

        for (ihr, raw_spans) in data {
            let idx = entries.len();
            let spans = raw_spans
                .into_iter()
                .map(|opt| {
                    opt.map(|meta| {
                        let (sl, sc, el, ec) = span_to_location(meta.span, source);
                        SourceSpan {
                            start_line: sl,
                            start_col: sc,
                            end_line: el,
                            end_col: ec,
                            node_type: meta.node_type,
                        }
                    })
                })
                .collect();
            lookup.insert(ihr.clone(), idx);
            entries.push(IhrEntry { ihr, spans });
        }

        SourceMap { entries, lookup }
    }

    /// Access all entries.
    pub fn entries(&self) -> &[IhrEntry] {
        &self.entries
    }

    /// Look up the first non-null span for the given IHR.
    pub fn lookup_by_ihr(&self, ihr: &str) -> Option<&SourceSpan> {
        let idx = *self.lookup.get(ihr)?;
        self.entries[idx]
            .spans
            .iter()
            .find_map(|opt| opt.as_ref())
    }

    /// Look up the span at a specific occurrence index for the given IHR.
    pub fn lookup_by_ihr_occurrence(
        &self,
        ihr: &str,
        occurrence: usize,
    ) -> Option<&SourceSpan> {
        let idx = *self.lookup.get(ihr)?;
        self.entries[idx]
            .spans
            .get(occurrence)
            .and_then(|opt| opt.as_ref())
    }

    /// Parse a source map from a `.map` JSON string produced by [`Self::to_map_json`].
    pub fn from_map_json(json: &str) -> Result<(Self, String), String> {
        let source_file = extract_json_string(json, "\"sourceFile\"")
            .ok_or_else(|| "missing \"sourceFile\" in source map".to_string())?;

        let mut entries = Vec::new();
        let mut lookup = HashMap::new();

        let nodes_start = json
            .find("\"nodes\"")
            .ok_or_else(|| "missing \"nodes\" in source map".to_string())?;
        let nodes_section = &json[nodes_start..];

        // Parse each {...} object at the top level of the nodes array.
        let mut pos = 0;
        while let Some(open) = nodes_section[pos..].find('{') {
            let abs_open = pos + open;
            // Find the matching closing brace (the IHR entry object).
            // We need to handle nested braces from span objects.
            let close = find_matching_brace(nodes_section, abs_open)
                .ok_or_else(|| "unmatched brace in source map".to_string())?;
            let obj = &nodes_section[abs_open..=close];

            if let Some(entry) = parse_ihr_entry(obj) {
                let idx = entries.len();
                lookup.insert(entry.ihr.clone(), idx);
                entries.push(entry);
            }
            pos = close + 1;
        }

        Ok((SourceMap { entries, lookup }, source_file))
    }

    /// Produce an annotated version of the source text.
    ///
    /// Each source line is emitted verbatim. After lines that produced Simplicity nodes,
    /// a comment is appended listing the abbreviated IHR and node type.
    pub fn annotate_source(&self, source: &str) -> String {
        // Build a map: line_number (1-based) -> list of (ihr_abbrev, node_type).
        let mut line_to_nodes: HashMap<u32, Vec<(String, &str)>> = HashMap::new();
        for entry in &self.entries {
            let ihr_abbrev = if entry.ihr.len() > 8 {
                format!("{}...", &entry.ihr[..8])
            } else {
                entry.ihr.clone()
            };
            for (i, opt_span) in entry.spans.iter().enumerate() {
                if let Some(span) = opt_span {
                    let label = format!("{}[{}]", ihr_abbrev, i);
                    for line in span.start_line..=span.end_line {
                        line_to_nodes
                            .entry(line)
                            .or_default()
                            .push((label.clone(), &span.node_type));
                    }
                }
            }
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
                    .map(|(label, ty)| format!("{label} {ty}"))
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
            "{{\n  \"version\": 2,\n  \"sourceFile\": \"{source_file}\",\n  \"nodes\": [\n"
        );
        for (i, entry) in self.entries.iter().enumerate() {
            if i > 0 {
                out.push_str(",\n");
            }
            out.push_str(&format!("    {{\"ihr\": \"{}\", \"spans\": [", entry.ihr));
            for (j, opt_span) in entry.spans.iter().enumerate() {
                if j > 0 {
                    out.push_str(", ");
                }
                match opt_span {
                    None => out.push_str("null"),
                    Some(span) => {
                        out.push_str(&format!(
                            "{{\"start_line\": {}, \"start_col\": {}, \"end_line\": {}, \"end_col\": {}, \"type\": \"{}\"}}",
                            span.start_line, span.start_col, span.end_line, span.end_col, span.node_type,
                        ));
                    }
                }
            }
            out.push_str("]}");
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

/// Find the index of the closing brace that matches the opening brace at `start`.
fn find_matching_brace(s: &str, start: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    if bytes.get(start).copied() != Some(b'{') {
        return None;
    }
    let mut depth = 0;
    for (i, &b) in bytes[start..].iter().enumerate() {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(start + i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Parse a single IHR entry JSON object.
fn parse_ihr_entry(obj: &str) -> Option<IhrEntry> {
    let ihr = extract_json_string(obj, "\"ihr\"")?;

    let spans_start = obj.find("\"spans\"")?;
    let after_spans = &obj[spans_start..];
    let bracket_start = after_spans.find('[')?;
    let bracket_abs = spans_start + bracket_start;
    // Find matching ]
    let bracket_end = find_matching_bracket(obj, bracket_abs)?;
    let spans_content = &obj[bracket_abs + 1..bracket_end];

    let mut spans = Vec::new();
    let mut pos = 0;
    while pos < spans_content.len() {
        let rest = spans_content[pos..].trim_start();
        if rest.is_empty() {
            break;
        }
        if rest.starts_with("null") {
            spans.push(None);
            pos = spans_content.len() - rest.len() + 4;
        } else if rest.starts_with('{') {
            let abs_open = spans_content.len() - rest.len();
            let close = find_matching_brace(spans_content, abs_open)?;
            let span_obj = &spans_content[abs_open..=close];
            spans.push(parse_source_span(span_obj));
            pos = close + 1;
        } else {
            // Skip commas and whitespace
            pos = spans_content.len() - rest.len() + 1;
        }
    }

    Some(IhrEntry { ihr, spans })
}

/// Find the matching ] for a [ at position `start`.
fn find_matching_bracket(s: &str, start: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    if bytes.get(start).copied() != Some(b'[') {
        return None;
    }
    let mut depth = 0;
    for (i, &b) in bytes[start..].iter().enumerate() {
        match b {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(start + i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Parse a span object like `{"start_line": 1, "start_col": 2, ...}`.
fn parse_source_span(obj: &str) -> Option<SourceSpan> {
    let node_type = extract_json_string(obj, "\"type\"").unwrap_or_default();
    Some(SourceSpan {
        start_line: extract_u64(obj, "\"start_line\"")? as u32,
        start_col: extract_u64(obj, "\"start_col\"")? as u32,
        end_line: extract_u64(obj, "\"end_line\"")? as u32,
        end_col: extract_u64(obj, "\"end_col\"")? as u32,
        node_type,
    })
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

/// Compute 1-based (line, col) for both start and end of a byte-offset span.
pub(crate) fn span_to_location(span: Span, source: &str) -> (u32, u32, u32, u32) {
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
    fn source_map_new_and_lookup() {
        let source = "aaa\nbbb\nccc\n";
        let data = vec![
            (
                "aabb".to_string(),
                vec![Some(RawSpanMeta {
                    span: Span { start: 0, end: 3 },
                    node_type: "comp".to_string(),
                })],
            ),
            (
                "ccdd".to_string(),
                vec![
                    None,
                    Some(RawSpanMeta {
                        span: Span { start: 4, end: 7 },
                        node_type: "pair".to_string(),
                    }),
                ],
            ),
        ];

        let sm = SourceMap::new(IhrSpanData(data), source);
        assert_eq!(sm.entries().len(), 2);

        let span = sm.lookup_by_ihr("aabb").unwrap();
        assert_eq!(span.start_line, 1);
        assert_eq!(span.node_type, "comp");

        // First span is null, should return the second.
        let span = sm.lookup_by_ihr("ccdd").unwrap();
        assert_eq!(span.start_line, 2);
        assert_eq!(span.node_type, "pair");

        // Occurrence lookup.
        assert!(sm.lookup_by_ihr_occurrence("ccdd", 0).is_none());
        assert!(sm.lookup_by_ihr_occurrence("ccdd", 1).is_some());
    }

    #[test]
    fn source_map_empty() {
        let sm = SourceMap::new(IhrSpanData(Vec::new()), "anything\n");
        assert!(sm.entries().is_empty());
    }

    #[test]
    fn json_roundtrip() {
        let source = "aaa\nbbb\nccc\n";
        let data = vec![
            (
                "aabb0011".to_string(),
                vec![Some(RawSpanMeta {
                    span: Span { start: 0, end: 3 },
                    node_type: "take".to_string(),
                })],
            ),
            (
                "ccdd2233".to_string(),
                vec![
                    None,
                    Some(RawSpanMeta {
                        span: Span { start: 4, end: 7 },
                        node_type: "comp".to_string(),
                    }),
                ],
            ),
        ];

        let original = SourceMap::new(IhrSpanData(data), source);
        let json = original.to_map_json("hello.simf");
        assert!(json.contains("\"version\": 2"));

        let (parsed, source_file) = SourceMap::from_map_json(&json).unwrap();
        assert_eq!(source_file, "hello.simf");
        assert_eq!(parsed.entries().len(), original.entries().len());
        for (a, b) in parsed.entries().iter().zip(original.entries().iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn from_map_json_missing_source_file() {
        let json = r#"{"version": 2, "nodes": []}"#;
        assert!(SourceMap::from_map_json(json).is_err());
    }

    #[test]
    fn from_map_json_missing_nodes() {
        let json = r#"{"version": 2, "sourceFile": "x.simf"}"#;
        assert!(SourceMap::from_map_json(json).is_err());
    }

    #[test]
    fn annotate_source_basic() {
        let source = "line1\nline2\nline3\n";
        let data = vec![(
            "abcdef01".to_string(),
            vec![Some(RawSpanMeta {
                span: Span { start: 0, end: 5 },
                node_type: "comp".to_string(),
            })],
        )];

        let sm = SourceMap::new(IhrSpanData(data), source);
        let annotated = sm.annotate_source(source);

        let lines: Vec<&str> = annotated.lines().collect();
        assert!(lines[0].contains("abcdef01[0] comp"));
        assert!(!lines[1].contains("//"));
    }
}
