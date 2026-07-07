#![cfg_attr(fuzzing, no_main)]

//! Positive-oracle fuzzing for `use` import resolution.
//!
//! The other targets feed random/near-random syntax at the compiler and only fail on a
//! panic -- a *valid program wrongly rejected* is invisible to them (an `Err` just gets
//! dropped). This target instead builds programs that are **valid by construction**: a few
//! modules of `pub` items, a set of `use` imports that provably resolve, and type-correct
//! usages in `main`. Such a program MUST compile, so any compile error is a bug -- e.g.
//! `resolve_use` dropping a `ModuleScope` binding kind across a module boundary (the class
//! of BlockstreamResearch/SimplicityHL#336, where imported enums lost their variants).

#[cfg(any(fuzzing, test))]
mod generator {
    use arbitrary::Unstructured;

    /// The `ModuleScope` binding kinds that `resolve_use` must carry across a module
    /// boundary. Keep in lockstep with the kinds `resolve_use` handles; add one here when
    /// `ModuleScope` gains a field.
    #[derive(Clone, Copy)]
    enum Kind {
        Alias,
        Function,
        Enum,
    }

    struct Item {
        kind: Kind,
        module: usize,
        /// Globally-unique declared name, e.g. `Sym7`.
        decl: String,
    }

    impl Item {
        /// The `pub` declaration placed inside its module.
        fn declaration(&self) -> String {
            match self.kind {
                Kind::Alias => format!("pub type {} = u8;", self.decl),
                Kind::Function => format!("pub fn {}(x: u32) -> u32 {{ x }}", self.decl),
                Kind::Enum => format!("pub enum {} {{ A = 0, B = 1 }}", self.decl),
            }
        }

        /// One or more statements in `main` that use the item under the name `used` (its
        /// declared name, or the alias it was imported as). `id` keeps locals unique.
        ///
        /// Every form is `;`-terminated so usages can be concatenated: SimplicityHL, unlike
        /// Rust, requires a `match` in statement position to end with a semicolon.
        fn usage(&self, used: &str, id: usize) -> String {
            match self.kind {
                Kind::Alias => format!("let _a{id}: {used} = 0;"),
                Kind::Function => format!("let _f{id}: u32 = {used}(7);"),
                Kind::Enum => format!(
                    "let _e{id}: {used} = 0; match _e{id} {{ {used}::A => {{}}, {used}::B => {{}} }};"
                ),
            }
        }
    }

    /// Build a valid multi-module import program and return its source text.
    ///
    /// Every choice keeps the program valid: module and item names are globally unique (no
    /// redefinition), every item is `pub` (importable), each import references a real item,
    /// aliases are unique, and every usage type-checks. `int_in_range`/`arbitrary` yield
    /// small defaults once the data runs dry, so this effectively never fails.
    pub fn program(u: &mut Unstructured) -> arbitrary::Result<String> {
        let num_modules = u.int_in_range(1..=3usize)?;

        let mut items: Vec<Item> = Vec::new();
        for module in 0..num_modules {
            let num_items = u.int_in_range(1..=3usize)?;
            for _ in 0..num_items {
                let kind = match u.int_in_range(0..=2u8)? {
                    0 => Kind::Alias,
                    1 => Kind::Function,
                    _ => Kind::Enum,
                };
                let decl = format!("Sym{}", items.len());
                items.push(Item { kind, module, decl });
            }
        }

        // Modules with their `pub` items.
        let mut src = String::new();
        for module in 0..num_modules {
            src.push_str(&format!("mod m{module} {{\n"));
            for item in items.iter().filter(|it| it.module == module) {
                src.push_str("    ");
                src.push_str(&item.declaration());
                src.push('\n');
            }
            src.push_str("}\n");
        }

        // Import a subset into `main` (some aliased) and use each imported item.
        let mut uses = String::new();
        let mut body = String::new();
        let mut imported_any = false;
        for (id, item) in items.iter().enumerate() {
            if !u.arbitrary::<bool>()? {
                continue; // leave this item unimported
            }
            imported_any = true;

            if u.arbitrary::<bool>()? {
                let alias = format!("{}Imp", item.decl);
                uses.push_str(&format!(
                    "use crate::m{}::{} as {};\n",
                    item.module, item.decl, alias
                ));
                body.push_str("    ");
                body.push_str(&item.usage(&alias, id));
            } else {
                uses.push_str(&format!("use crate::m{}::{};\n", item.module, item.decl));
                body.push_str("    ");
                body.push_str(&item.usage(&item.decl, id));
            }
            body.push('\n');
        }

        // Always import at least one item so the resolve path is exercised every run.
        if !imported_any {
            let item = &items[0];
            uses.push_str(&format!("use crate::m{}::{};\n", item.module, item.decl));
            body.push_str("    ");
            body.push_str(&item.usage(&item.decl, 0));
            body.push('\n');
        }

        src.push_str(&uses);
        src.push_str("fn main() {\n");
        src.push_str(&body);
        src.push_str("}\n");

        Ok(src)
    }
}

#[cfg(any(fuzzing, test))]
fn do_test(data: &[u8]) -> libfuzzer_sys::Corpus {
    use libfuzzer_sys::Corpus;
    use simplicityhl::ast::ElementsJetHinter;
    use simplicityhl::{TemplateProgram, UnstableFeatures};

    let mut u = arbitrary::Unstructured::new(data);
    let src = match generator::program(&mut u) {
        Ok(src) => src,
        Err(..) => return Corpus::Reject,
    };

    // Positive oracle: the program is valid by construction, so it must compile. Imports
    // and enums are gated behind unstable features, so enable them all.
    match TemplateProgram::new_with_unstable(
        src.clone(),
        &UnstableFeatures::all(),
        Box::new(ElementsJetHinter::new()),
    ) {
        Ok(_) => Corpus::Keep,
        Err(e) => panic!("valid generated program failed to compile:\n{src}\n--- error ---\n{e}"),
    }
}

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = do_test(data);
});

#[cfg(not(fuzzing))]
fn main() {}

#[cfg(test)]
mod tests {
    /// Smoke test: a spread of deterministic seeds must every one produce a program that
    /// compiles. Doubles as a self-check that the generator only emits valid programs --
    /// `do_test` panics if any generated program is rejected by the compiler.
    #[test]
    fn generated_programs_compile() {
        for seed in 0u32..2000 {
            // Deterministic xorshift bytes (no RNG dependency).
            let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
            let mut buf = [0u8; 48];
            for b in buf.iter_mut() {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                *b = (x & 0xff) as u8;
            }
            let _ = super::do_test(&buf);
        }
    }
}
