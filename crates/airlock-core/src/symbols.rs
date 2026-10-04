//! F5 符号级冲突预测：tree-sitter AST 解析，提取函数/类/方法等符号。
//! 用于 claim 时预测语义冲突——两个 agent 改同一个函数比改同一目录的不同函数风险更高。

use std::path::Path;

/// 从源代码中提取符号（函数、类、方法等）。
/// 返回符号名称列表及其字节范围。
pub fn extract_symbols(path: &Path, source: &str) -> Vec<Symbol> {
    let Some(lang) = language_for_path(path) else {
        return Vec::new();
    };
    extract_symbols_with_lang(source, lang)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind,
    pub byte_range: (usize, usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    Function,
    Method,
    Class,
    Struct,
    Enum,
    Interface,
    Module,
    Constant,
    Other,
}

impl SymbolKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SymbolKind::Function => "function",
            SymbolKind::Method => "method",
            SymbolKind::Class => "class",
            SymbolKind::Struct => "struct",
            SymbolKind::Enum => "enum",
            SymbolKind::Interface => "interface",
            SymbolKind::Module => "module",
            SymbolKind::Constant => "constant",
            SymbolKind::Other => "other",
        }
    }
}

fn language_for_path(path: &Path) -> Option<tree_sitter::Language> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("rs") => Some(tree_sitter_rust::LANGUAGE.into()),
        Some("js") | Some("mjs") | Some("cjs") => Some(tree_sitter_javascript::LANGUAGE.into()),
        Some("ts") => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        Some("tsx") => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
        Some("py") => Some(tree_sitter_python::LANGUAGE.into()),
        Some("go") => Some(tree_sitter_go::LANGUAGE.into()),
        _ => None,
    }
}

fn extract_symbols_with_lang(source: &str, lang: tree_sitter::Language) -> Vec<Symbol> {
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    let mut symbols = Vec::new();
    collect_symbols(&tree.root_node(), source.as_bytes(), &mut symbols);
    symbols
}

fn collect_symbols(node: &tree_sitter::Node, source: &[u8], out: &mut Vec<Symbol>) {
    let kind = match node.kind() {
        // Rust/JS/TS
        "function_item" | "function_declaration" | "arrow_function" | "function" => {
            Some(SymbolKind::Function)
        }
        // Python
        "function_definition" => Some(SymbolKind::Function),
        "method_definition" | "method_declaration" => Some(SymbolKind::Method),
        // Rust/JS/TS/Python
        "struct_item" | "class_declaration" | "class_definition" => Some(SymbolKind::Class),
        "enum_item" => Some(SymbolKind::Enum),
        "interface_declaration" => Some(SymbolKind::Interface),
        "module" | "mod_item" => Some(SymbolKind::Module),
        "const_declaration" | "const_item" | "lexical_declaration" | "expression_statement" => {
            // For Python, constants are just assignments at module level
            // We'll be conservative and only count explicit const declarations
            None
        }
        _ => None,
    };

    if let Some(sym_kind) = kind {
        if let Some(name) = extract_name(node, source) {
            out.push(Symbol {
                name,
                kind: sym_kind,
                byte_range: (node.start_byte(), node.end_byte()),
            });
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_symbols(&child, source, out);
        }
    }
}

fn extract_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    for field_name in ["name", "name_field"] {
        if let Some(name_node) = node.child_by_field_name(field_name) {
            return Some(
                name_node
                    .utf8_text(source)
                    .unwrap_or("")
                    .trim()
                    .to_string(),
            );
        }
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "identifier" || child.kind() == "type_identifier" {
                return Some(
                    child.utf8_text(source).unwrap_or("").trim().to_string(),
                );
            }
        }
    }
    None
}

/// 判断两个符号范围是否重叠。
pub fn symbols_overlap(a: &Symbol, b: &Symbol) -> bool {
    a.byte_range.0 < b.byte_range.1 && b.byte_range.0 < a.byte_range.1
}

/// 找出两组符号中重叠的符号名称。
pub fn overlapping_symbols(a: &[Symbol], b: &[Symbol]) -> Vec<String> {
    let mut result = Vec::new();
    for sa in a {
        for sb in b {
            if symbols_overlap(sa, sb) && sa.name == sb.name {
                result.push(sa.name.clone());
            }
        }
    }
    result.sort();
    result.dedup();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_function_extraction() {
        let source = r#"
pub fn hello() {}
fn world() {}
struct Foo {}
"#;
        let syms = extract_symbols(Path::new("test.rs"), source);
        assert!(syms.iter().any(|s| s.name == "hello" && s.kind == SymbolKind::Function));
        assert!(syms.iter().any(|s| s.name == "world" && s.kind == SymbolKind::Function));
        assert!(syms.iter().any(|s| s.name == "Foo" && s.kind == SymbolKind::Class));
    }

    #[test]
    fn typescript_class_and_method() {
        let source = r#"
class Foo {
  bar() {}
}
function baz() {}
"#;
        let syms = extract_symbols(Path::new("test.ts"), source);
        assert!(syms.iter().any(|s| s.name == "Foo" && s.kind == SymbolKind::Class));
        assert!(syms.iter().any(|s| s.name == "bar" && s.kind == SymbolKind::Method));
        assert!(syms.iter().any(|s| s.name == "baz" && s.kind == SymbolKind::Function));
    }

    #[test]
    fn python_function_and_class() {
        let source = r#"
def hello():
    pass

class World:
    def method(self):
        pass
"#;
        let syms = extract_symbols(Path::new("test.py"), source);
        assert!(syms.iter().any(|s| s.name == "hello" && s.kind == SymbolKind::Function));
        assert!(syms.iter().any(|s| s.name == "World" && s.kind == SymbolKind::Class));
    }

    #[test]
    fn unknown_extension_returns_empty() {
        let syms = extract_symbols(Path::new("test.txt"), "hello");
        assert!(syms.is_empty());
    }

    #[test]
    fn overlap_detection() {
        let a = Symbol {
            name: "foo".into(),
            kind: SymbolKind::Function,
            byte_range: (0, 100),
        };
        let b = Symbol {
            name: "foo".into(),
            kind: SymbolKind::Function,
            byte_range: (50, 150),
        };
        assert!(symbols_overlap(&a, &b));
        assert_eq!(overlapping_symbols(&[a], &[b]), vec!["foo"]);
    }

    #[test]
    fn no_overlap() {
        let a = Symbol {
            name: "foo".into(),
            kind: SymbolKind::Function,
            byte_range: (0, 100),
        };
        let b = Symbol {
            name: "bar".into(),
            kind: SymbolKind::Function,
            byte_range: (200, 300),
        };
        assert!(!symbols_overlap(&a, &b));
    }
}
