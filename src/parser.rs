use crate::ast::*;

pub struct Parser {
    input: Vec<char>,
    pos: usize,
    group_counter: u32,
}

impl Parser {
    pub fn new(input: &str) -> Self {
        Parser {
            input: input.chars().collect(),
            pos: 0,
            group_counter: 0,
        }
    }

    pub fn parse(&mut self) -> Result<Expr, String> {
        let expr = self.parse_alternation()?;
        if self.pos < self.input.len() {
            return Err(format!(
                "Unexpected character '{}' at position {}",
                self.input[self.pos], self.pos
            ));
        }
        Ok(expr)
    }

    fn parse_alternation(&mut self) -> Result<Expr, String> {
        let mut branches = vec![self.parse_concat()?];
        while self.peek() == Some('|') {
            self.consume();
            branches.push(self.parse_concat()?);
        }
        if branches.len() == 1 {
            Ok(branches.pop().unwrap())
        } else {
            Ok(Expr::Alternation(branches))
        }
    }

    fn parse_concat(&mut self) -> Result<Expr, String> {
        let mut items = Vec::new();
        while let Some(c) = self.peek() {
            if c == '|' || c == ')' {
                break;
            }
            items.push(self.parse_repetition()?);
        }
        if items.is_empty() {
            Ok(Expr::Empty)
        } else if items.len() == 1 {
            Ok(items.pop().unwrap())
        } else {
            Ok(Expr::Concat(items))
        }
    }

    fn parse_repetition(&mut self) -> Result<Expr, String> {
        let expr = self.parse_atom()?;
        match self.peek() {
            Some('*') => {
                self.consume();
                let greedy = self.peek() != Some('?');
                if !greedy {
                    self.consume();
                }
                Ok(Expr::Repetition {
                    expr: Box::new(expr),
                    kind: RepetitionKind::ZeroOrMore,
                    greedy,
                })
            }
            Some('+') => {
                self.consume();
                let greedy = self.peek() != Some('?');
                if !greedy {
                    self.consume();
                }
                Ok(Expr::Repetition {
                    expr: Box::new(expr),
                    kind: RepetitionKind::OneOrMore,
                    greedy,
                })
            }
            Some('?') => {
                self.consume();
                let greedy = self.peek() != Some('?');
                if !greedy {
                    self.consume();
                }
                Ok(Expr::Repetition {
                    expr: Box::new(expr),
                    kind: RepetitionKind::ZeroOrOne,
                    greedy,
                })
            }
            Some('{') => {
                self.consume();
                let kind = self.parse_repetition_range()?;
                self.expect('}')?;
                let greedy = self.peek() != Some('?');
                if !greedy {
                    self.consume();
                }
                Ok(Expr::Repetition {
                    expr: Box::new(expr),
                    kind,
                    greedy,
                })
            }
            _ => Ok(expr),
        }
    }

    fn parse_repetition_range(&mut self) -> Result<RepetitionKind, String> {
        let min = self.parse_number()?;
        match self.peek() {
            Some(',') => {
                self.consume();
                if self.peek() == Some('}') {
                    Ok(RepetitionKind::AtLeast(min))
                } else {
                    let max = self.parse_number()?;
                    Ok(RepetitionKind::Range(min, max))
                }
            }
            Some('}') => Ok(RepetitionKind::Exactly(min)),
            _ => Err("Expected ',' or '}' in repetition".to_string()),
        }
    }

    fn parse_number(&mut self) -> Result<u32, String> {
        let mut num = String::new();
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                num.push(c);
                self.consume();
            } else {
                break;
            }
        }
        if num.is_empty() {
            Err("Expected number".to_string())
        } else {
            Ok(num.parse().unwrap())
        }
    }

    fn parse_atom(&mut self) -> Result<Expr, String> {
        match self.peek() {
            Some('(') => self.parse_group(),
            Some('[') => self.parse_class(),
            Some('\\') => self.parse_escape(),
            Some('^') => {
                self.consume();
                Ok(Expr::Anchor(Anchor::StartOfLine))
            }
            Some('$') => {
                self.consume();
                Ok(Expr::Anchor(Anchor::EndOfLine))
            }
            Some('.') => {
                self.consume();
                Ok(Expr::Class(CharClass::Any))
            }
            Some(c) if !is_meta_char(c) => {
                self.consume();
                Ok(Expr::Literal(c))
            }
            Some(c) => Err(format!("Unexpected character '{}' at position {}", c, self.pos)),
            None => Err("Unexpected end of input".to_string()),
        }
    }

    fn parse_group(&mut self) -> Result<Expr, String> {
        self.expect('(')?;
        let kind = if self.peek() == Some('?') {
            self.consume();
            match self.peek() {
                Some(':') => {
                    self.consume();
                    GroupKind::NonCapturing
                }
                Some('=') => {
                    self.consume();
                    GroupKind::Lookahead(true)
                }
                Some('!') => {
                    self.consume();
                    GroupKind::Lookahead(false)
                }
                Some('<') => {
                    self.consume();
                    match self.peek() {
                        Some('=') => {
                            self.consume();
                            GroupKind::Lookbehind(true)
                        }
                        Some('!') => {
                            self.consume();
                            GroupKind::Lookbehind(false)
                        }
                        _ => return Err("Invalid group syntax".to_string()),
                    }
                }
                Some('>') => {
                    self.consume();
                    GroupKind::Atomic
                }
                _ => return Err("Invalid group syntax".to_string()),
            }
        } else {
            self.group_counter += 1;
            GroupKind::Capturing(self.group_counter)
        };
        let expr = self.parse_alternation()?;
        self.expect(')')?;
        Ok(Expr::Group {
            expr: Box::new(expr),
            kind,
        })
    }

    fn parse_class(&mut self) -> Result<Expr, String> {
        self.expect('[')?;
        let negated = self.peek() == Some('^');
        if negated {
            self.consume();
        }
        let mut items = Vec::new();
        while let Some(c) = self.peek() {
            if c == ']' && !items.is_empty() {
                break;
            }
            items.push(self.parse_class_item()?);
        }
        self.expect(']')?;
        if negated {
            Ok(Expr::Class(CharClass::NegatedClass(items)))
        } else {
            Ok(Expr::Class(CharClass::Class(items)))
        }
    }

    fn parse_class_item(&mut self) -> Result<CharClassItem, String> {
        match self.peek() {
            Some('\\') => {
                self.consume();
                match self.peek() {
                    Some('d') => {
                        self.consume();
                        Ok(CharClassItem::Digit)
                    }
                    Some('D') => {
                        self.consume();
                        Ok(CharClassItem::NegatedDigit)
                    }
                    Some('w') => {
                        self.consume();
                        Ok(CharClassItem::Word)
                    }
                    Some('W') => {
                        self.consume();
                        Ok(CharClassItem::NegatedWord)
                    }
                    Some('s') => {
                        self.consume();
                        Ok(CharClassItem::Whitespace)
                    }
                    Some('S') => {
                        self.consume();
                        Ok(CharClassItem::NegatedWhitespace)
                    }
                    Some(c) => {
                        self.consume();
                        Ok(CharClassItem::Literal(c))
                    }
                    None => Err("Unexpected end of input in character class".to_string()),
                }
            }
            Some(c) => {
                self.consume();
                if self.peek() == Some('-') {
                    self.consume();
                    if let Some(end) = self.peek() {
                        if end != ']' {
                            self.consume();
                            return Ok(CharClassItem::Range(c, end));
                        }
                    }
                    return Ok(CharClassItem::Literal(c));
                }
                Ok(CharClassItem::Literal(c))
            }
            None => Err("Unexpected end of input in character class".to_string()),
        }
    }

    fn parse_escape(&mut self) -> Result<Expr, String> {
        self.expect('\\')?;
        match self.peek() {
            Some('d') => {
                self.consume();
                Ok(Expr::Class(CharClass::Digit))
            }
            Some('D') => {
                self.consume();
                Ok(Expr::Class(CharClass::NegatedDigit))
            }
            Some('w') => {
                self.consume();
                Ok(Expr::Class(CharClass::Word))
            }
            Some('W') => {
                self.consume();
                Ok(Expr::Class(CharClass::NegatedWord))
            }
            Some('s') => {
                self.consume();
                Ok(Expr::Class(CharClass::Whitespace))
            }
            Some('S') => {
                self.consume();
                Ok(Expr::Class(CharClass::NegatedWhitespace))
            }
            Some('b') => {
                self.consume();
                Ok(Expr::Anchor(Anchor::WordBoundary))
            }
            Some('B') => {
                self.consume();
                Ok(Expr::Anchor(Anchor::NonWordBoundary))
            }
            Some('A') => {
                self.consume();
                Ok(Expr::Anchor(Anchor::StartOfString))
            }
            Some('z') => {
                self.consume();
                Ok(Expr::Anchor(Anchor::EndOfString))
            }
            Some('Z') => {
                self.consume();
                Ok(Expr::Anchor(Anchor::EndOfString))
            }
            Some(c) if c.is_ascii_digit() => {
                let mut num = String::new();
                while let Some(d) = self.peek() {
                    if d.is_ascii_digit() {
                        num.push(d);
                        self.consume();
                    } else {
                        break;
                    }
                }
                Ok(Expr::Backreference(num.parse().unwrap()))
            }
            Some(c) => {
                self.consume();
                Ok(Expr::Literal(c))
            }
            None => Err("Unexpected end of input after backslash".to_string()),
        }
    }

    fn peek(&self) -> Option<char> {
        self.input.get(self.pos).copied()
    }

    fn consume(&mut self) {
        self.pos += 1;
    }

    fn expect(&mut self, c: char) -> Result<(), String> {
        if self.peek() == Some(c) {
            self.consume();
            Ok(())
        } else {
            Err(format!(
                "Expected '{}' at position {}, found '{}'",
                c,
                self.pos,
                self.peek().unwrap_or('\0')
            ))
        }
    }
}

fn is_meta_char(c: char) -> bool {
    matches!(
        c,
        '.' | '^' | '$' | '*' | '+' | '?' | '(' | ')' | '|' | '[' | '{' | '\\'
    )
}

pub fn parse(input: &str) -> Result<Expr, String> {
    Parser::new(input).parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_literal() {
        let result = parse("abc").unwrap();
        assert!(matches!(result, Expr::Concat(_)));
    }

    #[test]
    fn parse_alternation() {
        let result = parse("a|b").unwrap();
        assert!(matches!(result, Expr::Alternation(_)));
    }

    #[test]
    fn parse_repetition() {
        let result = parse("a*").unwrap();
        assert!(matches!(
            result,
            Expr::Repetition {
                kind: RepetitionKind::ZeroOrMore,
                ..
            }
        ));
    }

    #[test]
    fn parse_character_class() {
        let result = parse("[a-z]").unwrap();
        assert!(matches!(result, Expr::Class(CharClass::Class(_))));
    }

    #[test]
    fn parse_digit_class() {
        let result = parse(r"\d").unwrap();
        assert!(matches!(result, Expr::Class(CharClass::Digit)));
    }

    #[test]
    fn parse_group() {
        let result = parse("(abc)").unwrap();
        assert!(matches!(
            result,
            Expr::Group {
                kind: GroupKind::Capturing(1),
                ..
            }
        ));
    }

    #[test]
    fn parse_anchors() {
        let result = parse("^abc$").unwrap();
        assert!(matches!(result, Expr::Concat(_)));
    }

    #[test]
    fn parse_complex_regex() {
        let result = parse(r"^\d{3}-\d{2}$").unwrap();
        assert!(result.precedence() > 0);
    }

    #[test]
    fn parse_error() {
        let result = parse("[a-z");
        assert!(result.is_err());
    }
}
