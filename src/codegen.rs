use crate::ast::*;
use crate::dfa::BytecodeInstr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Rust,
    JavaScript,
    Python,
}

impl Target {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "rust" => Some(Target::Rust),
            "javascript" | "js" => Some(Target::JavaScript),
            "python" | "py" => Some(Target::Python),
            _ => None,
        }
    }
}

pub struct CodeGenerator {
    target: Target,
}

impl CodeGenerator {
    pub fn new(target: Target) -> Self {
        CodeGenerator { target }
    }

    pub fn generate(&self, regex: &str, optimized_regex: &str) -> String {
        match self.target {
            Target::Rust => self.generate_rust(regex, optimized_regex),
            Target::JavaScript => self.generate_javascript(regex, optimized_regex),
            Target::Python => self.generate_python(regex, optimized_regex),
        }
    }

    pub fn generate_from_ast(&self, expr: &Expr) -> String {
        let regex = self.ast_to_regex(expr);
        self.generate(&regex, &regex)
    }

    pub fn generate_from_bytecode(&self, bytecode: &[BytecodeInstr]) -> String {
        match self.target {
            Target::Rust => self.generate_rust_bytecode(bytecode),
            Target::JavaScript => self.generate_javascript_bytecode(bytecode),
            Target::Python => self.generate_python_bytecode(bytecode),
        }
    }

    fn ast_to_regex(&self, expr: &Expr) -> String {
        self.expr_to_string(expr, 0)
    }

    fn expr_to_string(&self, expr: &Expr, outer_prec: u8) -> String {
        let prec = expr.precedence();
        let needs_parens = prec < outer_prec;

        let inner = match expr {
            Expr::Empty => String::new(),
            Expr::Literal(c) => escape_literal(*c),
            Expr::Class(cls) => self.class_to_string(cls),
            Expr::Anchor(anchor) => self.anchor_to_string(anchor),
            Expr::Concat(items) => items
                .iter()
                .map(|e| self.expr_to_string(e, prec))
                .collect(),
            Expr::Alternation(branches) => branches
                .iter()
                .map(|e| self.expr_to_string(e, prec))
                .collect::<Vec<_>>()
                .join("|"),
            Expr::Repetition {
                expr,
                kind,
                greedy,
            } => {
                let inner = self.expr_to_string(expr, prec);
                let suffix = match kind {
                    RepetitionKind::ZeroOrMore => "*".to_string(),
                    RepetitionKind::OneOrMore => "+".to_string(),
                    RepetitionKind::ZeroOrOne => "?".to_string(),
                    RepetitionKind::Exactly(n) => format!("{{{}}}", n),
                    RepetitionKind::AtLeast(n) => format!("{{{},}}", n),
                    RepetitionKind::Range(min, max) => format!("{{{},{}}}", min, max),
                };
                let non_greedy = if !greedy { "?" } else { "" };
                format!("{}{}{}", inner, suffix, non_greedy)
            }
            Expr::Group { expr, kind } => {
                let inner = self.expr_to_string(expr, 0);
                match kind {
                    GroupKind::Capturing(_) => format!("({})", inner),
                    GroupKind::NonCapturing => format!("(?:{})", inner),
                    GroupKind::Lookahead(true) => format!("(?={})", inner),
                    GroupKind::Lookahead(false) => format!("(?!{})", inner),
                    GroupKind::Lookbehind(true) => format!("(?<={})", inner),
                    GroupKind::Lookbehind(false) => format!("(?<!{})", inner),
                    GroupKind::Atomic => format!("(?>{})", inner),
                }
            }
            Expr::Backreference(n) => format!("\\{}", n),
        };

        if needs_parens {
            format!("(?:{})", inner)
        } else {
            inner
        }
    }

    fn class_to_string(&self, cls: &CharClass) -> String {
        match cls {
            CharClass::Literal(c) => escape_literal(*c),
            CharClass::Range(start, end) => format!("[{}-{}]", start, end),
            CharClass::Any => ".".to_string(),
            CharClass::Digit => "\\d".to_string(),
            CharClass::Word => "\\w".to_string(),
            CharClass::Whitespace => "\\s".to_string(),
            CharClass::NegatedDigit => "\\D".to_string(),
            CharClass::NegatedWord => "\\W".to_string(),
            CharClass::NegatedWhitespace => "\\S".to_string(),
            CharClass::Class(items) => {
                let inner: String = items.iter().map(|i| self.class_item_to_string(i)).collect();
                format!("[{}]", inner)
            }
            CharClass::NegatedClass(items) => {
                let inner: String = items.iter().map(|i| self.class_item_to_string(i)).collect();
                format!("[^{}]", inner)
            }
        }
    }

    fn class_item_to_string(&self, item: &CharClassItem) -> String {
        match item {
            CharClassItem::Literal(c) => escape_class_char(*c),
            CharClassItem::Range(start, end) => format!("{}-{}", start, end),
            CharClassItem::Digit => "\\d".to_string(),
            CharClassItem::Word => "\\w".to_string(),
            CharClassItem::Whitespace => "\\s".to_string(),
            CharClassItem::NegatedDigit => "\\D".to_string(),
            CharClassItem::NegatedWord => "\\W".to_string(),
            CharClassItem::NegatedWhitespace => "\\S".to_string(),
        }
    }

    fn anchor_to_string(&self, anchor: &Anchor) -> String {
        match anchor {
            Anchor::StartOfLine => "^".to_string(),
            Anchor::EndOfLine => "$".to_string(),
            Anchor::StartOfString => "\\A".to_string(),
            Anchor::EndOfString => "\\z".to_string(),
            Anchor::WordBoundary => "\\b".to_string(),
            Anchor::NonWordBoundary => "\\B".to_string(),
        }
    }

    fn generate_rust(&self, regex: &str, optimized_regex: &str) -> String {
        let escaped_regex = escape_rust_string(optimized_regex);
        format!(
            r#"use regex::Regex;

fn main() {{
    let re = Regex::new(r"{}").unwrap();
    
    // Original regex: {}
    // Optimized regex: {}
    
    println!("Matching with regex: {{}}", re.as_str());
}}

pub fn is_match(text: &str) -> bool {{
    let re = Regex::new(r"{}").unwrap();
    re.is_match(text)
}}

pub fn find<'a>(text: &'a str) -> Option<&'a str> {{
    let re = Regex::new(r"{}").unwrap();
    re.find(text).map(|m| m.as_str())
}}

pub fn captures<'a>(text: &'a str) -> Option<regex::Captures<'a>> {{
    let re = Regex::new(r"{}").unwrap();
    re.captures(text)
}}
"#,
            escaped_regex, regex, optimized_regex, escaped_regex, escaped_regex, escaped_regex
        )
    }

    fn generate_javascript(&self, regex: &str, optimized_regex: &str) -> String {
        let escaped_regex = escape_js_regex(optimized_regex);
        let export_line = "export { regex, isMatch, find, findAll, replace };";
        format!(
            "/**\n * Original regex: {}\n * Optimized regex: {}\n */\n\nconst regex = /{}/;\n\nfunction isMatch(text) {{\n    return regex.test(text);\n}}\n\nfunction find(text) {{\n    return text.match(regex);\n}}\n\nfunction findAll(text) {{\n    return [...text.matchAll(new RegExp(regex.source, regex.flags + 'g'))];\n}}\n\nfunction replace(text, replacement) {{\n    return text.replace(regex, replacement);\n}}\n\n// Example usage:\n// console.log(isMatch('123-45'));\n// console.log(find('ID: 123-45'));\n\n{}\n",
            regex, optimized_regex, escaped_regex, export_line
        )
    }

    fn generate_python(&self, regex: &str, optimized_regex: &str) -> String {
        let escaped_regex = escape_python_string(optimized_regex);
        format!(
            r#"import re

"""
Original regex: {}
Optimized regex: {}
"""

_pattern = r"{}"
_regex = re.compile(_pattern)


def is_match(text: str) -> bool:
    """Check if the text matches the regex."""
    return _regex.fullmatch(text) is not None


def search(text: str):
    """Search for the pattern in text."""
    return _regex.search(text)


def find_all(text: str):
    """Find all matches in text."""
    return _regex.findall(text)


def find_iter(text: str):
    """Return an iterator over all matches."""
    return _regex.finditer(text)


def replace(text: str, replacement: str) -> str:
    """Replace matches in text."""
    return _regex.sub(replacement, text)


def split(text: str):
    """Split text by the pattern."""
    return _regex.split(text)


# Example usage:
# if __name__ == "__main__":
#     print(is_match("123-45"))
#     print(search("ID: 123-45"))
"#,
            regex, optimized_regex, escaped_regex
        )
    }

    fn generate_rust_bytecode(&self, bytecode: &[BytecodeInstr]) -> String {
        let mut code = String::from(
            "// DFA-based matcher generated from compiled regex\n\n",
        );
        code.push_str("#[allow(dead_code)]\n");
        code.push_str("pub fn is_match(input: &str) -> bool {\n");
        code.push_str("    let chars: Vec<char> = input.chars().collect();\n");
        code.push_str("    let mut pos = 0;\n");
        code.push_str("    let mut state = 0;\n\n");

        for (i, instr) in bytecode.iter().enumerate() {
            code.push_str(&format!("    // State {}\n", i));
            match instr {
                BytecodeInstr::Start => {
                    code.push_str("    // Start state\n");
                }
                BytecodeInstr::Accept => {
                    code.push_str("    return true;\n");
                }
                BytecodeInstr::Fail => {
                    code.push_str("    return false;\n");
                }
                BytecodeInstr::MatchChar(c, target) => {
                    code.push_str(&format!(
                        "    if pos < chars.len() && chars[pos] == '{}' {{\n",
                        escape_rust_char(*c)
                    ));
                    code.push_str("        pos += 1;\n");
                    code.push_str(&format!("        state = {};\n", target));
                    code.push_str("        continue;\n");
                    code.push_str("    }\n");
                }
                BytecodeInstr::MatchClass(cls, target) => {
                    let class_check = self.class_to_rust_check(cls);
                    code.push_str(&format!(
                        "    if pos < chars.len() && {} {{\n",
                        class_check
                    ));
                    code.push_str("        pos += 1;\n");
                    code.push_str(&format!("        state = {};\n", target));
                    code.push_str("        continue;\n");
                    code.push_str("    }\n");
                }
                BytecodeInstr::MatchAny(target) => {
                    code.push_str("    if pos < chars.len() {\n");
                    code.push_str("        pos += 1;\n");
                    code.push_str(&format!("        state = {};\n", target));
                    code.push_str("        continue;\n");
                    code.push_str("    }\n");
                }
                BytecodeInstr::Jump(target) => {
                    code.push_str(&format!("    state = {};\n", target));
                    code.push_str("    continue;\n");
                }
            }
        }

        code.push_str("}\n");
        code
    }

    fn class_to_rust_check(&self, cls: &CharClass) -> String {
        match cls {
            CharClass::Digit => "chars[pos].is_ascii_digit()".to_string(),
            CharClass::Word => "chars[pos].is_ascii_alphanumeric() || chars[pos] == '_'".to_string(),
            CharClass::Whitespace => "chars[pos].is_whitespace()".to_string(),
            CharClass::NegatedDigit => "!chars[pos].is_ascii_digit()".to_string(),
            CharClass::NegatedWord => "!(chars[pos].is_ascii_alphanumeric() || chars[pos] == '_')".to_string(),
            CharClass::NegatedWhitespace => "!chars[pos].is_whitespace()".to_string(),
            CharClass::Any => "true".to_string(),
            CharClass::Literal(c) => format!("chars[pos] == '{}'", escape_rust_char(*c)),
            CharClass::Range(start, end) => format!(
                "chars[pos] >= '{}' && chars[pos] <= '{}'",
                escape_rust_char(*start),
                escape_rust_char(*end)
            ),
            CharClass::Class(items) => {
                let checks: Vec<String> = items
                    .iter()
                    .map(|item| self.class_item_to_rust_check(item))
                    .collect();
                format!("({})", checks.join(" || "))
            }
            CharClass::NegatedClass(items) => {
                let checks: Vec<String> = items
                    .iter()
                    .map(|item| self.class_item_to_rust_check(item))
                    .collect();
                format!("!({})", checks.join(" || "))
            }
        }
    }

    fn class_item_to_rust_check(&self, item: &CharClassItem) -> String {
        match item {
            CharClassItem::Literal(c) => format!("chars[pos] == '{}'", escape_rust_char(*c)),
            CharClassItem::Range(start, end) => format!(
                "chars[pos] >= '{}' && chars[pos] <= '{}'",
                escape_rust_char(*start),
                escape_rust_char(*end)
            ),
            CharClassItem::Digit => "chars[pos].is_ascii_digit()".to_string(),
            CharClassItem::Word => "chars[pos].is_ascii_alphanumeric() || chars[pos] == '_'".to_string(),
            CharClassItem::Whitespace => "chars[pos].is_whitespace()".to_string(),
            CharClassItem::NegatedDigit => "!chars[pos].is_ascii_digit()".to_string(),
            CharClassItem::NegatedWord => "!(chars[pos].is_ascii_alphanumeric() || chars[pos] == '_')".to_string(),
            CharClassItem::NegatedWhitespace => "!chars[pos].is_whitespace()".to_string(),
        }
    }

    fn generate_javascript_bytecode(&self, _bytecode: &[BytecodeInstr]) -> String {
        "// JavaScript bytecode generator coming soon\n".to_string()
    }

    fn generate_python_bytecode(&self, _bytecode: &[BytecodeInstr]) -> String {
        "# Python bytecode generator coming soon\n".to_string()
    }
}

fn escape_literal(c: char) -> String {
    match c {
        '.' | '^' | '$' | '*' | '+' | '?' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '\\' => {
            format!("\\{}", c)
        }
        '\n' => "\\n".to_string(),
        '\r' => "\\r".to_string(),
        '\t' => "\\t".to_string(),
        _ => c.to_string(),
    }
}

fn escape_class_char(c: char) -> String {
    match c {
        ']' | '^' | '-' | '\\' => format!("\\{}", c),
        '\n' => "\\n".to_string(),
        '\r' => "\\r".to_string(),
        '\t' => "\\t".to_string(),
        _ => c.to_string(),
    }
}

fn escape_rust_string(s: &str) -> String {
    s.replace('"', "\\\"")
}

fn escape_rust_char(c: char) -> String {
    match c {
        '\'' => "\\'".to_string(),
        '\\' => "\\\\".to_string(),
        '\n' => "\\n".to_string(),
        '\r' => "\\r".to_string(),
        '\t' => "\\t".to_string(),
        _ => c.to_string(),
    }
}

fn escape_js_regex(s: &str) -> String {
    s.replace('/', "\\/")
}

fn escape_python_string(s: &str) -> String {
    s.replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;

    #[test]
    fn generate_rust_code() {
        let code_gen = CodeGenerator::new(Target::Rust);
        let code = code_gen.generate(r"^\d{3}-\d{2}$", r"^\d{3}-\d{2}$");
        assert!(code.contains("use regex::Regex"));
        assert!(code.contains("pub fn is_match"));
    }

    #[test]
    fn generate_javascript_code() {
        let code_gen = CodeGenerator::new(Target::JavaScript);
        let code = code_gen.generate(r"^\d{3}-\d{2}$", r"^\d{3}-\d{2}$");
        assert!(code.contains("const regex = /"));
        assert!(code.contains("function isMatch"));
    }

    #[test]
    fn generate_python_code() {
        let code_gen = CodeGenerator::new(Target::Python);
        let code = code_gen.generate(r"^\d{3}-\d{2}$", r"^\d{3}-\d{2}$");
        assert!(code.contains("import re"));
        assert!(code.contains("def is_match"));
    }

    #[test]
    fn generate_from_ast() {
        let ast = parse("abc").unwrap();
        let code_gen = CodeGenerator::new(Target::Rust);
        let code = code_gen.generate_from_ast(&ast);
        assert!(code.contains("abc"));
    }

    #[test]
    fn target_from_str() {
        assert_eq!(Target::from_str("rust"), Some(Target::Rust));
        assert_eq!(Target::from_str("javascript"), Some(Target::JavaScript));
        assert_eq!(Target::from_str("js"), Some(Target::JavaScript));
        assert_eq!(Target::from_str("python"), Some(Target::Python));
        assert_eq!(Target::from_str("py"), Some(Target::Python));
        assert_eq!(Target::from_str("unknown"), None);
    }

    #[test]
    fn generate_from_bytecode_rust() {
        use crate::dfa::build_nfa;
        let ast = parse("ab").unwrap();
        let nfa = build_nfa(&ast);
        let dfa = nfa.to_dfa();
        let bytecode = dfa.to_bytecode();
        let code_gen = CodeGenerator::new(Target::Rust);
        let code = code_gen.generate_from_bytecode(&bytecode);
        assert!(code.contains("pub fn is_match"));
    }

    #[test]
    fn handles_escaped_characters() {
        let code_gen = CodeGenerator::new(Target::Rust);
        let code = code_gen.generate("a\\.b", "a\\.b");
        assert!(code.contains("a\\.b"));
    }

    #[test]
    fn preserves_optimized_regex() {
        let code_gen = CodeGenerator::new(Target::JavaScript);
        let code = code_gen.generate("original", "optimized");
        assert!(code.contains("Original regex: original"));
        assert!(code.contains("Optimized regex: optimized"));
    }
}
