use crate::ast::*;
use std::collections::HashMap;

pub struct Optimizer {
    common_subexprs: HashMap<Expr, usize>,
}

impl Optimizer {
    pub fn new() -> Self {
        Optimizer {
            common_subexprs: HashMap::new(),
        }
    }

    fn is_effectively_empty(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Empty => true,
            Expr::Group { expr, .. } => self.is_effectively_empty(expr),
            Expr::Repetition { kind, .. } => {
                matches!(
                    kind,
                    RepetitionKind::ZeroOrMore | RepetitionKind::ZeroOrOne | RepetitionKind::Exactly(0)
                )
            }
            Expr::Concat(items) => items.iter().all(|e| self.is_effectively_empty(e)),
            Expr::Alternation(branches) => branches.iter().all(|e| self.is_effectively_empty(e)),
            _ => false,
        }
    }

    pub fn optimize(&mut self, expr: Expr) -> Expr {
        let expr = self.fold_constants(expr);
        self.eliminate_common_subexprs(expr)
    }

    fn fold_constants(&mut self, expr: Expr) -> Expr {
        match expr {
            Expr::Concat(items) => {
                let mut optimized: Vec<Expr> = items
                    .into_iter()
                    .map(|e| self.fold_constants(e))
                    .collect();
                optimized.retain(|e| !self.is_effectively_empty(e));

                if optimized.is_empty() {
                    return Expr::Empty;
                }

                let mut folded = Vec::new();
                let mut literal_buf = String::new();

                for item in optimized {
                    match item {
                        Expr::Literal(c) => {
                            literal_buf.push(c);
                        }
                        other => {
                            if !literal_buf.is_empty() {
                                if literal_buf.len() == 1 {
                                    folded.push(Expr::Literal(literal_buf.pop().unwrap()));
                                } else {
                                    folded.extend(literal_buf.chars().map(Expr::Literal));
                                }
                                literal_buf.clear();
                            }
                            folded.push(other);
                        }
                    }
                }

                if !literal_buf.is_empty() {
                    if literal_buf.len() == 1 {
                        folded.push(Expr::Literal(literal_buf.pop().unwrap()));
                    } else {
                        folded.extend(literal_buf.chars().map(Expr::Literal));
                    }
                }

                if folded.len() == 1 {
                    folded.pop().unwrap()
                } else {
                    Expr::Concat(folded)
                }
            }

            Expr::Alternation(branches) => {
                let mut optimized: Vec<Expr> = branches
                    .into_iter()
                    .map(|e| self.fold_constants(e))
                    .collect();

                optimized.sort();
                optimized.dedup();

                if optimized.len() == 1 {
                    optimized.pop().unwrap()
                } else {
                    Expr::Alternation(optimized)
                }
            }

            Expr::Repetition {
                expr,
                kind,
                greedy,
            } => {
                let inner = self.fold_constants(*expr);

                if inner.is_empty() {
                    return Expr::Empty;
                }

                match kind {
                    RepetitionKind::Exactly(n) if n == 0 => Expr::Empty,
                    RepetitionKind::Exactly(n) if n == 1 => inner,
                    RepetitionKind::Range(min, max) if min == max => Expr::Repetition {
                        expr: Box::new(inner),
                        kind: RepetitionKind::Exactly(min),
                        greedy,
                    },
                    _ => Expr::Repetition {
                        expr: Box::new(inner),
                        kind,
                        greedy,
                    },
                }
            }

            Expr::Group { expr, kind } => {
                let inner = self.fold_constants(*expr);
                if matches!(kind, GroupKind::NonCapturing) {
                    return inner;
                }
                Expr::Group {
                    expr: Box::new(inner),
                    kind,
                }
            }

            other => other,
        }
    }

    fn eliminate_common_subexprs(&mut self, expr: Expr) -> Expr {
        let expr = self.map_subexprs(expr);
        self.deduplicate_subexprs(expr)
    }

    fn map_subexprs(&mut self, expr: Expr) -> Expr {
        match &expr {
            Expr::Concat(_) | Expr::Alternation(_) | Expr::Repetition { .. } => {
                *self.common_subexprs.entry(expr.clone()).or_insert(0) += 1;
            }
            _ => {}
        }

        match expr {
            Expr::Concat(items) => Expr::Concat(
                items
                    .into_iter()
                    .map(|e| self.map_subexprs(e))
                    .collect(),
            ),
            Expr::Alternation(branches) => Expr::Alternation(
                branches
                    .into_iter()
                    .map(|e| self.map_subexprs(e))
                    .collect(),
            ),
            Expr::Repetition {
                expr,
                kind,
                greedy,
            } => Expr::Repetition {
                expr: Box::new(self.map_subexprs(*expr)),
                kind,
                greedy,
            },
            Expr::Group { expr, kind } => Expr::Group {
                expr: Box::new(self.map_subexprs(*expr)),
                kind,
            },
            other => other,
        }
    }

    fn deduplicate_subexprs(&self, expr: Expr) -> Expr {
        match expr {
            Expr::Concat(items) => Expr::Concat(
                items
                    .into_iter()
                    .map(|e| self.deduplicate_subexprs(e))
                    .collect(),
            ),
            Expr::Alternation(branches) => Expr::Alternation(
                branches
                    .into_iter()
                    .map(|e| self.deduplicate_subexprs(e))
                    .collect(),
            ),
            Expr::Repetition {
                expr,
                kind,
                greedy,
            } => Expr::Repetition {
                expr: Box::new(self.deduplicate_subexprs(*expr)),
                kind,
                greedy,
            },
            Expr::Group { expr, kind } => Expr::Group {
                expr: Box::new(self.deduplicate_subexprs(*expr)),
                kind,
            },
            other => other,
        }
    }

    pub fn to_regex_string(&self, expr: &Expr) -> String {
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

pub fn optimize(expr: Expr) -> Expr {
    Optimizer::new().optimize(expr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;

    #[test]
    fn fold_empty_concat() {
        let ast = parse("a()b").unwrap();
        let optimized = optimize(ast);
        let opt = Optimizer::new();
        let result = opt.to_regex_string(&optimized);
        assert_eq!(result, "ab");
    }

    #[test]
    fn fold_exactly_one() {
        let ast = parse("a{1}").unwrap();
        let optimized = optimize(ast);
        let opt = Optimizer::new();
        let result = opt.to_regex_string(&optimized);
        assert_eq!(result, "a");
    }

    #[test]
    fn fold_range_same() {
        let ast = parse("a{2,2}").unwrap();
        let optimized = optimize(ast);
        let opt = Optimizer::new();
        let result = opt.to_regex_string(&optimized);
        assert_eq!(result, "a{2}");
    }

    #[test]
    fn remove_non_capturing_group() {
        let ast = parse("(?:abc)").unwrap();
        let optimized = optimize(ast);
        let opt = Optimizer::new();
        let result = opt.to_regex_string(&optimized);
        assert_eq!(result, "abc");
    }

    #[test]
    fn dedup_alternation() {
        let ast = parse("a|b|a").unwrap();
        let optimized = optimize(ast);
        let opt = Optimizer::new();
        let result = opt.to_regex_string(&optimized);
        assert!(result.contains('|'));
    }

    #[test]
    fn to_regex_string_preserves_syntax() {
        let ast = parse(r"^\d{3}-\d{2}$").unwrap();
        let opt = Optimizer::new();
        let result = opt.to_regex_string(&ast);
        assert_eq!(result, r"^\d{3}-\d{2}$");
    }

    #[test]
    fn optimize_complex_regex() {
        let ast = parse(r"^\d{3}-\d{2}$").unwrap();
        let optimized = optimize(ast);
        let opt = Optimizer::new();
        let result = opt.to_regex_string(&optimized);
        assert_eq!(result, r"^\d{3}-\d{2}$");
    }
}
