#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Expr {
    Empty,
    Literal(char),
    Class(CharClass),
    Anchor(Anchor),
    Concat(Vec<Expr>),
    Alternation(Vec<Expr>),
    Repetition {
        expr: Box<Expr>,
        kind: RepetitionKind,
        greedy: bool,
    },
    Group {
        expr: Box<Expr>,
        kind: GroupKind,
    },
    Backreference(u32),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CharClass {
    Literal(char),
    Range(char, char),
    Any,
    Digit,
    Word,
    Whitespace,
    NegatedDigit,
    NegatedWord,
    NegatedWhitespace,
    Class(Vec<CharClassItem>),
    NegatedClass(Vec<CharClassItem>),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CharClassItem {
    Literal(char),
    Range(char, char),
    Digit,
    Word,
    Whitespace,
    NegatedDigit,
    NegatedWord,
    NegatedWhitespace,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Anchor {
    StartOfLine,
    EndOfLine,
    StartOfString,
    EndOfString,
    WordBoundary,
    NonWordBoundary,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RepetitionKind {
    ZeroOrMore,
    OneOrMore,
    ZeroOrOne,
    Exactly(u32),
    AtLeast(u32),
    Range(u32, u32),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GroupKind {
    Capturing(u32),
    NonCapturing,
    Lookahead(bool),
    Lookbehind(bool),
    Atomic,
}

impl Expr {
    pub fn precedence(&self) -> u8 {
        match self {
            Expr::Alternation(_) => 1,
            Expr::Concat(_) => 2,
            Expr::Repetition { .. } => 3,
            _ => 4,
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, Expr::Empty)
    }
}
