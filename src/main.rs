use base64::display::Base64Display;
use base64::engine::general_purpose::STANDARD;
use clap::{Arg, ArgAction, Command};

use simplicity::effects::{
    annotate_commit, enumerate_code_paths, malleability_analysis, pruneable_nodes, BranchArm,
    TransactionField,
};
use simplicityhl::source_map::{SourceMap, SourceMapEntry};
use simplicityhl::{AbiMeta, CompiledProgram};
use std::{env, fmt};

#[cfg_attr(feature = "serde", derive(serde::Serialize))]
/// The compilation output.
struct Output {
    /// Simplicity program result, base64 encoded.
    program: String,
    /// Simplicity witness result, base64 encoded, if the .wit file was provided.
    witness: Option<String>,
    /// Simplicity program ABI metadata to the program which the user provides.
    abi_meta: Option<AbiMeta>,
    /// Commitment Merkle Root (CMR) of the program, hex encoded.
    cmr: String,
}

impl fmt::Display for Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Program:\n{}", self.program)?;
        writeln!(f, "CMR:\n{}", self.cmr)?;
        if let Some(witness) = &self.witness {
            writeln!(f, "Witness:\n{}", witness)?;
        }
        if let Some(witness) = &self.abi_meta {
            writeln!(f, "ABI meta:\n{:?}", witness)?;
        }
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let command = {
        Command::new(env!("CARGO_BIN_NAME"))
            .about(
                "\
                Compile the given SimplicityHL program and print the resulting Simplicity base64 string.\n\
                If a SimplicityHL witness is provided, then use it to satisfy the program (requires \
                feature 'serde' to be enabled).\
                ",
            )
            .arg(
                Arg::new("prog_file")
                    .required_unless_present("help")
                    .value_name("PROGRAM_FILE")
                    .action(ArgAction::Set)
                    .help("SimplicityHL program file to build"),
            )
            .subcommand_negates_reqs(true)
            .arg(
                Arg::new("wit_file")
                    .long("wit")
                    .short('w')
                    .value_name("WITNESS_FILE")
                    .action(ArgAction::Set)
                    .help("File containing the witness data"),
            )
            .arg(
                Arg::new("args_file")
                    .long("args")
                    .short('a')
                    .value_name("ARGUMENTS_FILE")
                    .action(ArgAction::Set)
                    .help("File containing the arguments data"),
            )
            .arg(
                Arg::new("debug")
                    .long("debug")
                    .action(ArgAction::SetTrue)
                    .help("Include debug symbols in the output"),
            )
            .arg(
                Arg::new("json")
                    .long("json")
                    .action(ArgAction::SetTrue)
                    .help("Output in JSON"),
            )
            .arg(
                Arg::new("abi")
                    .long("abi")
                    .action(ArgAction::SetTrue)
                    .help("Additional ABI .simf contract types"),
            )
            .arg(
                Arg::new("build_source_map")
                    .long("build-source-map")
                    .action(ArgAction::SetTrue)
                    .help(
                        "Write a <program>.map file mapping each Simplicity node index \
                         to the SimplicityHL source lines that generated it",
                    ),
            )
    };

    let command = command.subcommand(
        Command::new("annotate")
            .about("Annotate a SimplicityHL source file with node indices from a source map")
            .arg(
                Arg::new("map_file")
                    .required(true)
                    .value_name("MAP_FILE")
                    .action(ArgAction::Set)
                    .help("Source map (.map) file"),
            )
            .arg(
                Arg::new("source_file")
                    .long("source")
                    .short('s')
                    .value_name("SOURCE_FILE")
                    .action(ArgAction::Set)
                    .help("SimplicityHL source file (defaults to sourceFile from the map)"),
            ),
    );

    let matches = command.get_matches();

    if let Some(sub) = matches.subcommand_matches("annotate") {
        return run_annotate(sub);
    }

    let prog_file = match matches.get_one::<String>("prog_file") {
        Some(f) => f,
        None => {
            eprintln!("error: missing required argument <PROGRAM_FILE>");
            std::process::exit(1);
        }
    };
    let prog_path = std::path::Path::new(prog_file);
    let prog_text = std::fs::read_to_string(prog_path).map_err(|e| e.to_string())?;
    let include_debug_symbols = matches.get_flag("debug");
    let output_json = matches.get_flag("json");
    let abi_param = matches.get_flag("abi");
    let build_source_map = matches.get_flag("build_source_map");

    #[cfg(feature = "serde")]
    let args_opt: simplicityhl::Arguments = match matches.get_one::<String>("args_file") {
        None => simplicityhl::Arguments::default(),
        Some(args_file) => {
            let args_path = std::path::Path::new(&args_file);
            let args_text = std::fs::read_to_string(args_path).map_err(|e| e.to_string())?;
            serde_json::from_str::<simplicityhl::Arguments>(&args_text)?
        }
    };
    #[cfg(not(feature = "serde"))]
    let args_opt: simplicityhl::Arguments = if matches.contains_id("args_file") {
        return Err(
            "Program was compiled without the 'serde' feature and cannot process .args files."
                .into(),
        );
    } else {
        simplicityhl::Arguments::default()
    };

    let compiled = match CompiledProgram::new(prog_text.clone(), args_opt, include_debug_symbols, true) {
        Ok(program) => program,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    if build_source_map {
        if let Some(source_map) = compiled.source_map() {
            let map_path = prog_path.with_extension("map");
            let source_file = prog_path.file_name().unwrap_or_default().to_string_lossy();
            std::fs::write(&map_path, source_map.to_map_json(&source_file))
                .map_err(|e| e.to_string())?;
        }
    }

    // ── Effects analysis ────────────────────────────────────────────────────
    {
        let commit = compiled.commit();
        let summaries = annotate_commit(&commit);
        let source_map = compiled.source_map();
        let universe = TransactionField::all_elements();

        let warn = "\x1b[1;33mwarning\x1b[0m";
        let bold = "\x1b[1m";
        let reset = "\x1b[0m";

        // ── Root summary ────────────────────────────────────────────────
        let root_summary = summaries.last().expect("non-empty program");
        eprintln!("{bold}=== Root summary ==={reset}");
        eprintln!("  can_fail:  {}", if root_summary.can_fail { "yes" } else { "no" });
        if root_summary.reads.is_empty() {
            eprintln!("  reads:     (none)");
        } else {
            eprintln!("  reads:");
            for field in &root_summary.reads {
                eprintln!("    {}", field);
            }
        }

        if !root_summary.can_fail {
            eprintln!();
            eprintln!("{warn}: program has no failure path — it accepts all inputs unconditionally");
        }

        // ── Malleability ────────────────────────────────────────────────
        let mal = malleability_analysis(&summaries, &universe);
        eprintln!();
        eprintln!("{bold}=== Malleability (uncovered fields) ==={reset}");
        if mal.uncovered.is_empty() {
            eprintln!("  (none — all fields are covered)");
        } else {
            for field in &mal.uncovered {
                eprintln!("  {}", field);
            }
        }

        // ── Pruneable subtrees ──────────────────────────────────────────
        let pruneable = pruneable_nodes(&summaries);
        if !pruneable.is_empty() {
            use simplicity::dag::{DagLike, MaxSharing};
            use simplicity::node::Inner;

            let pruneable_set: std::collections::HashSet<usize> =
                pruneable.iter().map(|p| p.node_index).collect();
            let mut subsumed: std::collections::HashSet<usize> =
                std::collections::HashSet::new();
            let mut bare_units: std::collections::HashSet<usize> =
                std::collections::HashSet::new();
            for item in (&*commit)
                .post_order_iter::<MaxSharing<simplicity::node::Commit<simplicity::jet::Elements>>>()
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
            }
            let top_level: Vec<_> = pruneable
                .iter()
                .filter(|p| !subsumed.contains(&p.node_index))
                .filter(|p| !bare_units.contains(&p.node_index))
                .collect();
            if !top_level.is_empty() {
                eprintln!();
                eprintln!("{warn}: {} pruneable subtree(s) have return type Unit with no side effects", top_level.len());
                eprintln!("  and can each be replaced with a bare `unit` node:");
                for p in &top_level {
                    eprintln!("  node #{}", p.node_index);
                    if let Some(entry) = source_map.and_then(|sm| lookup_node(sm, p.node_index)) {
                        print_source_snippet(prog_file, &prog_text, entry);
                    }
                }
            }
        }

        // ── Code path analysis ──────────────────────────────────────────
        let (paths, truncated) = enumerate_code_paths(&commit, 64);
        let with_write = paths.iter().filter(|p| p.can_fail).count();
        let without_write = paths.len() - with_write;
        eprintln!();
        eprintln!("{bold}=== Code path analysis ==={reset}");
        eprintln!(
            "  {} path(s) total{}: {} with write effects, {} without",
            paths.len(),
            if truncated { " (truncated)" } else { "" },
            with_write,
            without_write,
        );
        for (i, path) in paths.iter().enumerate() {
            let choices: Vec<String> = path
                .choices
                .iter()
                .map(|(sid, arm)| {
                    let arm_str = match arm {
                        BranchArm::Left => "left",
                        BranchArm::Right => "right",
                    };
                    format!("case #{sid} -> {arm_str}")
                })
                .collect();
            let path_label = if choices.is_empty() {
                "(no branches)".to_owned()
            } else {
                choices.join(", ")
            };
            let reads = if path.reads.is_empty() {
                "no reads".to_owned()
            } else {
                format!("reads {} fields", path.reads.len())
            };
            let fail = if path.can_fail { "can fail" } else { "cannot fail" };
            let no_write = if !path.can_fail { " << NO WRITE EFFECT" } else { "" };
            let path_uncovered: Vec<_> = universe.difference(&path.reads).collect();
            eprintln!();
            eprintln!("  Path {}: {}", i + 1, path_label);
            eprintln!("    {}, {}{}", reads, fail, no_write);
            if path_uncovered.len() < universe.len() && !path_uncovered.is_empty() {
                eprintln!("    uncovered fields ({}):", path_uncovered.len());
                for field in &path_uncovered {
                    eprintln!("      {}", field);
                }
            } else if path_uncovered.is_empty() {
                eprintln!("    all fields covered");
            } else {
                eprintln!("    no fields covered (reads nothing)");
            }
            // Show source for branch choices on paths without write effects.
            if !path.can_fail {
                for (idx, _arm) in &path.choices {
                    if let Some(entry) = source_map.and_then(|sm| lookup_node(sm, *idx)) {
                        print_source_snippet(prog_file, &prog_text, entry);
                    }
                }
            }
        }
    }

    #[cfg(feature = "serde")]
    let witness_opt = matches
        .get_one::<String>("wit_file")
        .map(|wit_file| -> Result<simplicityhl::WitnessValues, String> {
            let wit_path = std::path::Path::new(wit_file);
            let wit_text = std::fs::read_to_string(wit_path).map_err(|e| e.to_string())?;
            let witness = serde_json::from_str::<simplicityhl::WitnessValues>(&wit_text).unwrap();
            Ok(witness)
        })
        .transpose()?;
    #[cfg(not(feature = "serde"))]
    let witness_opt = if matches.contains_id("wit_file") {
        return Err(
            "Program was compiled without the 'serde' feature and cannot process .wit files."
                .into(),
        );
    } else {
        None
    };

    let (program_bytes, witness_bytes) = match witness_opt {
        Some(witness) => {
            let satisfied = compiled.satisfy(witness)?;
            let (program_bytes, witness_bytes) = satisfied.redeem().to_vec_with_witness();
            (program_bytes, Some(witness_bytes))
        }
        None => {
            let program_bytes = compiled.commit().to_vec_without_witness();
            (program_bytes, None)
        }
    };

    let abi_opt = if abi_param {
        Some(compiled.generate_abi_meta()?)
    } else {
        None
    };

    let cmr_hex = compiled.commit().cmr().to_string();
    let output = Output {
        program: Base64Display::new(&program_bytes, &STANDARD).to_string(),
        witness: witness_bytes.map(|bytes| Base64Display::new(&bytes, &STANDARD).to_string()),
        abi_meta: abi_opt,
        cmr: cmr_hex,
    };

    if output_json {
        #[cfg(not(feature = "serde"))]
        return Err(
            "Program was compiled without the 'serde' feature and cannot output JSON.".into(),
        );
        #[cfg(feature = "serde")]
        println!("{}", serde_json::to_string(&output)?);
    } else {
        println!("{}", output);
    }

    Ok(())
}

fn run_annotate(matches: &clap::ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let map_file = matches.get_one::<String>("map_file").unwrap();
    let map_path = std::path::Path::new(map_file);
    let map_text = std::fs::read_to_string(map_path).map_err(|e| e.to_string())?;

    let (source_map, source_file_from_map) =
        SourceMap::from_map_json(&map_text).map_err(|e| e.to_string())?;

    let source_path = match matches.get_one::<String>("source_file") {
        Some(p) => std::path::PathBuf::from(p),
        None => map_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join(&source_file_from_map),
    };

    let source_text = std::fs::read_to_string(&source_path).map_err(|e| {
        format!(
            "cannot read source file '{}': {e}",
            source_path.display()
        )
    })?;

    print!("{}", source_map.annotate_source(&source_text));
    Ok(())
}

fn lookup_node(source_map: &SourceMap, node_index: usize) -> Option<&SourceMapEntry> {
    source_map
        .entries()
        .binary_search_by_key(&node_index, |e| e.node_index)
        .ok()
        .map(|i| &source_map.entries()[i])
}

fn print_source_snippet(file: &str, source: &str, entry: &SourceMapEntry) {
    let blue = "\x1b[1;34m";
    let reset = "\x1b[0m";
    let lines: Vec<&str> = source.lines().collect();

    eprintln!(
        " {blue}-->{reset} {}:{}:{}",
        file, entry.start_line, entry.start_col,
    );

    let gutter_width = format!("{}", entry.end_line).len();
    eprintln!(" {blue}{:>gutter_width$} |{reset}", "");

    for line_num in entry.start_line..=entry.end_line {
        if let Some(line) = lines.get((line_num - 1) as usize) {
            eprintln!(" {blue}{line_num:>gutter_width$} |{reset} {line}");
        }
    }

    // Underline the relevant span on the first line.
    let start_col = entry.start_col as usize;
    let end_col = if entry.start_line == entry.end_line {
        entry.end_col as usize
    } else if let Some(line) = lines.get((entry.start_line - 1) as usize) {
        line.len() + 1
    } else {
        start_col + 1
    };
    let underline_len = end_col.saturating_sub(start_col).max(1);
    eprintln!(
        " {blue}{:>gutter_width$} |{reset} {:>padding$}{blue}{}{reset}",
        "",
        "",
        "^".repeat(underline_len),
        padding = start_col - 1,
    );
    eprintln!();
}
