use crate::ast::*;
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Safe,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct ReDoSRisk {
    pub level: RiskLevel,
    pub description: String,
    pub suggestion: String,
    pub location: String,
}

#[derive(Debug, Clone)]
pub struct AnalysisResult {
    pub risks: Vec<ReDoSRisk>,
    pub overall_level: RiskLevel,
    pub summary: String,
}

pub struct ReDoSAnalyzer;

impl ReDoSAnalyzer {
    pub fn new() -> Self {
        ReDoSAnalyzer
    }

    pub fn analyze(&self, expr: &Expr) -> AnalysisResult {
        let mut risks = Vec::new();
        let mut visited = HashSet::new();

        self.analyze_expr(expr, &mut risks, &mut visited, "root");

        let overall_level = risks
            .iter()
            .map(|r| r.level.clone())
            .max()
            .unwrap_or(RiskLevel::Safe);

        let summary = match overall_level {
            RiskLevel::Safe => "No significant ReDoS risks detected.".to_string(),
            RiskLevel::Low => "Low risk - Minor performance concerns.".to_string(),
            RiskLevel::Medium => "Medium risk - May cause slowdowns on certain inputs.".to_string(),
            RiskLevel::High => "High risk - Likely to cause ReDoS on malicious inputs.".to_string(),
            RiskLevel::Critical => "Critical risk - Almost guaranteed ReDoS on crafted inputs.".to_string(),
        };

        AnalysisResult {
            risks,
            overall_level,
            summary,
        }
    }

    fn analyze_expr(
        &self,
        expr: &Expr,
        risks: &mut Vec<ReDoSRisk>,
        visited: &mut HashSet<*const Expr>,
        location: &str,
    ) {
        if visited.contains(&(expr as *const Expr)) {
            return;
        }
        visited.insert(expr as *const Expr);

        match expr {
            Expr::Repetition { expr: inner, kind, greedy } => {
                self.check_nested_quantifiers(inner, kind, greedy, risks, location);
                self.check_adjacent_overlap(expr, risks, location);
                self.check_greedy_backtracking(inner, kind, greedy, risks, location);

                let new_location = format!("{}.*", location);
                self.analyze_expr(inner, risks, visited, &new_location);
            }

            Expr::Group { expr: inner, kind } => {
                self.check_group_quantifier_combination(inner, kind, risks, location);

                let new_location = format!("{}.()", location);
                self.analyze_expr(inner, risks, visited, &new_location);
            }

            Expr::Concat(items) => {
                self.check_concat_overlapping_quantifiers(items, risks, location);

                for (i, item) in items.iter().enumerate() {
                    let new_location = format!("{}.{}", location, i);
                    self.analyze_expr(item, risks, visited, &new_location);
                }
            }

            Expr::Alternation(branches) => {
                self.check_alternation_overlap(branches, risks, location);

                for (i, branch) in branches.iter().enumerate() {
                    let new_location = format!("{}.|{}", location, i);
                    self.analyze_expr(branch, risks, visited, &new_location);
                }
            }

            Expr::Class(cls) => {
                self.check_overly_broad_class(cls, risks, location);
            }

            _ => {}
        }
    }

    fn check_nested_quantifiers(
        &self,
        inner: &Expr,
        outer_kind: &RepetitionKind,
        _outer_greedy: &bool,
        risks: &mut Vec<ReDoSRisk>,
        location: &str,
    ) {
        if self.contains_quantifier(inner) {
            let inner_has_many = self.contains_multiple_quantifiers(inner);
            let level = if inner_has_many {
                RiskLevel::Critical
            } else {
                RiskLevel::High
            };

            let description = format!(
                "Nested quantifiers detected: outer {:?} contains inner quantifier",
                outer_kind
            );

            let suggestion = match outer_kind {
                RepetitionKind::ZeroOrMore => 
                    "Consider using a more specific pattern or making the inner quantifier possessive. Example: (a*)* -> (a)* or use atomic groups if supported.".to_string(),
                RepetitionKind::OneOrMore =>
                    "Nested + quantifiers cause exponential backtracking. Simplify the pattern or use non-backtracking constructs.".to_string(),
                _ =>
                    "Flatten the nested quantifiers where possible. Example: (a{2})* -> a*".to_string(),
            };

            risks.push(ReDoSRisk {
                level,
                description,
                suggestion,
                location: location.to_string(),
            });
        }
    }

    fn check_adjacent_overlap(
        &self,
        _expr: &Expr,
        _risks: &mut Vec<ReDoSRisk>,
        _location: &str,
    ) {
    }

    fn check_greedy_backtracking(
        &self,
        inner: &Expr,
        _outer_kind: &RepetitionKind,
        greedy: &bool,
        risks: &mut Vec<ReDoSRisk>,
        location: &str,
    ) {
        if *greedy && self.can_match_empty(inner) {
            risks.push(ReDoSRisk {
                level: RiskLevel::Medium,
                description: "Greedy quantifier on subexpression that can match empty string".to_string(),
                suggestion: "Consider using a non-greedy quantifier (add ?) or ensure the subexpression matches at least one character.".to_string(),
                location: location.to_string(),
            });
        }
    }

    fn check_group_quantifier_combination(
        &self,
        inner: &Expr,
        group_kind: &GroupKind,
        risks: &mut Vec<ReDoSRisk>,
        location: &str,
    ) {
        if matches!(group_kind, GroupKind::Capturing(_) | GroupKind::NonCapturing) {
            if self.contains_alternation(inner) && self.contains_quantifier(inner) {
                risks.push(ReDoSRisk {
                    level: RiskLevel::High,
                    description: "Group contains both alternation and quantifiers - high backtracking potential".to_string(),
                    suggestion: "Consider restructuring to avoid alternation inside quantified groups, or use atomic groups/ possessive quantifiers if supported.".to_string(),
                    location: location.to_string(),
                });
            }
        }
    }

    fn check_concat_overlapping_quantifiers(
        &self,
        items: &[Expr],
        risks: &mut Vec<ReDoSRisk>,
        location: &str,
    ) {
        for i in 0..items.len().saturating_sub(1) {
            if let (Some(a), Some(b)) = (items.get(i), items.get(i + 1)) {
                if self.is_quantifier(a) && self.is_quantifier(b) {
                    let has_overlap = self.character_sets_overlap(a, b);
                    let level = if has_overlap {
                        RiskLevel::High
                    } else {
                        RiskLevel::Medium
                    };
                    let desc = if has_overlap {
                        "Adjacent quantifiers with overlapping character sets detected".to_string()
                    } else {
                        "Adjacent quantifiers detected - may cause backtracking issues".to_string()
                    };
                    risks.push(ReDoSRisk {
                        level,
                        description: desc,
                        suggestion: "Combine adjacent quantifiers where possible. Example: a*a* -> a* or a+a* -> a+".to_string(),
                        location: format!("{}.concat[{}..{}]", location, i, i + 1),
                    });
                }
            }
        }
    }

    fn check_alternation_overlap(
        &self,
        branches: &[Expr],
        risks: &mut Vec<ReDoSRisk>,
        location: &str,
    ) {
        if branches.len() < 2 {
            return;
        }

        let has_quantified_branch = branches.iter().any(|b| self.contains_quantifier(b));

        if has_quantified_branch {
            for i in 0..branches.len() {
                for j in i + 1..branches.len() {
                    if self.can_match_same_string(&branches[i], &branches[j]) {
                        risks.push(ReDoSRisk {
                            level: RiskLevel::Medium,
                            description: format!(
                                "Alternation branches {} and {} may match the same string, combined with quantifiers can cause backtracking",
                                i, j
                            ),
                            suggestion: "Reorder alternation branches from most specific to most general, or remove redundant branches.".to_string(),
                            location: format!("{}.alt[{}|{}]", location, i, j),
                        });
                    }
                }
            }
        }
    }

    fn check_overly_broad_class(
        &self,
        cls: &CharClass,
        risks: &mut Vec<ReDoSRisk>,
        location: &str,
    ) {
        match cls {
            CharClass::Any => {
                risks.push(ReDoSRisk {
                    level: RiskLevel::Low,
                    description: "Use of '.' (any character) - may match more than intended".to_string(),
                    suggestion: "Consider using a more specific character class if possible. Example: [^\\n] instead of . when matching lines.".to_string(),
                    location: location.to_string(),
                });
            }
            CharClass::NegatedClass(items) if items.is_empty() => {
                risks.push(ReDoSRisk {
                    level: RiskLevel::Low,
                    description: "Empty negated character class matches any character".to_string(),
                    suggestion: "Use a more specific character class to limit what can be matched.".to_string(),
                    location: location.to_string(),
                });
            }
            CharClass::Class(items) | CharClass::NegatedClass(items) => {
                let has_wide_range = items.iter().any(|item| match item {
                    CharClassItem::Range(start, end) => {
                        (*end as u32).saturating_sub(*start as u32) > 20
                    }
                    _ => false,
                });

                if has_wide_range {
                    risks.push(ReDoSRisk {
                        level: RiskLevel::Low,
                        description: "Character class contains a wide range of characters".to_string(),
                        suggestion: "Narrow the character range if possible to reduce matching possibilities.".to_string(),
                        location: location.to_string(),
                    });
                }
            }
            _ => {}
        }
    }

    fn contains_quantifier(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Repetition { .. } => true,
            Expr::Concat(items) => items.iter().any(|e| self.contains_quantifier(e)),
            Expr::Alternation(branches) => branches.iter().any(|e| self.contains_quantifier(e)),
            Expr::Group { expr: inner, .. } => self.contains_quantifier(inner),
            _ => false,
        }
    }

    fn contains_multiple_quantifiers(&self, expr: &Expr) -> bool {
        self.count_quantifiers(expr) >= 2
    }

    fn count_quantifiers(&self, expr: &Expr) -> usize {
        match expr {
            Expr::Repetition { expr: inner, .. } => 1 + self.count_quantifiers(inner),
            Expr::Concat(items) => items.iter().map(|e| self.count_quantifiers(e)).sum(),
            Expr::Alternation(branches) => branches.iter().map(|e| self.count_quantifiers(e)).sum(),
            Expr::Group { expr: inner, .. } => self.count_quantifiers(inner),
            _ => 0,
        }
    }

    fn contains_alternation(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Alternation(_) => true,
            Expr::Concat(items) => items.iter().any(|e| self.contains_alternation(e)),
            Expr::Repetition { expr: inner, .. } => self.contains_alternation(inner),
            Expr::Group { expr: inner, .. } => self.contains_alternation(inner),
            _ => false,
        }
    }

    fn is_quantifier(&self, expr: &Expr) -> bool {
        matches!(expr, Expr::Repetition { .. })
    }

    fn can_match_empty(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Empty => true,
            Expr::Literal(_) => false,
            Expr::Class(_) => false,
            Expr::Anchor(_) => true,
            Expr::Concat(items) => items.iter().all(|e| self.can_match_empty(e)),
            Expr::Alternation(branches) => branches.iter().any(|e| self.can_match_empty(e)),
            Expr::Repetition { kind, .. } => matches!(
                kind,
                RepetitionKind::ZeroOrMore
                    | RepetitionKind::ZeroOrOne
                    | RepetitionKind::Exactly(0)
                    | RepetitionKind::Range(0, _)
            ),
            Expr::Group { expr: inner, .. } => self.can_match_empty(inner),
            Expr::Backreference(_) => false,
        }
    }

    fn character_sets_overlap(&self, a: &Expr, b: &Expr) -> bool {
        let chars_a = self.get_character_set(a);
        let chars_b = self.get_character_set(b);

        if chars_a.is_empty() || chars_b.is_empty() {
            return true;
        }

        chars_a.intersection(&chars_b).next().is_some()
    }

    fn get_character_set(&self, expr: &Expr) -> HashSet<char> {
        let mut set = HashSet::new();
        self.collect_character_set(expr, &mut set);
        set
    }

    fn collect_character_set(&self, expr: &Expr, set: &mut HashSet<char>) {
        match expr {
            Expr::Literal(c) => {
                set.insert(*c);
            }
            Expr::Class(cls) => match cls {
                CharClass::Literal(c) => {
                    set.insert(*c);
                }
                CharClass::Range(start, end) => {
                    for c in *start as u32..=*end as u32 {
                        if let Some(ch) = char::from_u32(c) {
                            set.insert(ch);
                        }
                    }
                }
                CharClass::Any => {}
                CharClass::Digit => {
                    for c in '0'..='9' {
                        set.insert(c);
                    }
                }
                CharClass::Word => {
                    for c in '0'..='9' {
                        set.insert(c);
                    }
                    for c in 'a'..='z' {
                        set.insert(c);
                    }
                    for c in 'A'..='Z' {
                        set.insert(c);
                    }
                    set.insert('_');
                }
                CharClass::Whitespace => {
                    set.insert(' ');
                    set.insert('\t');
                    set.insert('\n');
                    set.insert('\r');
                }
                _ => {}
            },
            Expr::Concat(items) => {
                for item in items {
                    self.collect_character_set(item, set);
                }
            }
            Expr::Alternation(branches) => {
                for branch in branches {
                    self.collect_character_set(branch, set);
                }
            }
            Expr::Repetition { expr: inner, .. } => {
                self.collect_character_set(inner, set);
            }
            Expr::Group { expr: inner, .. } => {
                self.collect_character_set(inner, set);
            }
            _ => {}
        }
    }

    fn can_match_same_string(&self, a: &Expr, b: &Expr) -> bool {
        let chars_a = self.get_character_set(a);
        let chars_b = self.get_character_set(b);

        if chars_a.is_empty() || chars_b.is_empty() {
            return true;
        }

        chars_a.intersection(&chars_b).next().is_some()
    }

    pub fn format_report(&self, result: &AnalysisResult, regex: &str) -> String {
        let mut report = String::new();

        report.push_str(&format!("ReDoS Analysis Report for: {}\n", regex));
        report.push_str(&format!("Overall Risk Level: {:?}\n", result.overall_level));
        report.push_str(&format!("Summary: {}\n\n", result.summary));

        if result.risks.is_empty() {
            report.push_str("No ReDoS risks detected.\n");
        } else {
            report.push_str(&format!("Found {} potential risk(s):\n\n", result.risks.len()));

            for (i, risk) in result.risks.iter().enumerate() {
                report.push_str(&format!("Risk #{} - {:?}\n", i + 1, risk.level));
                report.push_str(&format!("  Location: {}\n", risk.location));
                report.push_str(&format!("  Issue: {}\n", risk.description));
                report.push_str(&format!("  Suggestion: {}\n\n", risk.suggestion));
            }
        }

        report
    }
}

pub fn analyze_redo(expr: &Expr) -> AnalysisResult {
    ReDoSAnalyzer::new().analyze(expr)
}

impl Default for ReDoSAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;

    #[test]
    fn detect_nested_quantifiers() {
        let ast = parse("(a*)*").unwrap();
        let analyzer = ReDoSAnalyzer::new();
        let result = analyzer.analyze(&ast);
        assert!(result.overall_level >= RiskLevel::High);
        assert!(result.risks.iter().any(|r| r.description.contains("Nested quantifiers")));
    }

    #[test]
    fn detect_deeply_nested_quantifiers() {
        let ast = parse("((a+)*)+").unwrap();
        let analyzer = ReDoSAnalyzer::new();
        let result = analyzer.analyze(&ast);
        assert_eq!(result.overall_level, RiskLevel::Critical);
    }

    #[test]
    fn detect_adjacent_overlapping_quantifiers() {
        let ast = parse("a*b*").unwrap();
        let analyzer = ReDoSAnalyzer::new();
        let result = analyzer.analyze(&ast);
        assert!(result.risks.iter().any(|r| r.description.contains("Adjacent quantifiers")));
    }

    #[test]
    fn detect_adjacent_quantifiers_with_overlap() {
        let ast = parse("[ab]*[ac]*").unwrap();
        let analyzer = ReDoSAnalyzer::new();
        let result = analyzer.analyze(&ast);
        assert!(result.risks.iter().any(|r| r.description.contains("overlapping character sets")));
    }

    #[test]
    fn detect_any_character() {
        let ast = parse(".*").unwrap();
        let analyzer = ReDoSAnalyzer::new();
        let result = analyzer.analyze(&ast);
        assert!(result.risks.iter().any(|r| r.description.contains("any character")));
    }

    #[test]
    fn safe_regex() {
        let ast = parse(r"^\d{3}-\d{2}$").unwrap();
        let analyzer = ReDoSAnalyzer::new();
        let result = analyzer.analyze(&ast);
        assert_eq!(result.overall_level, RiskLevel::Safe);
    }

    #[test]
    fn detect_alternation_with_quantifiers() {
        let ast = parse("(a|b*)*").unwrap();
        let analyzer = ReDoSAnalyzer::new();
        let result = analyzer.analyze(&ast);
        assert!(result.overall_level >= RiskLevel::High);
    }

    #[test]
    fn detect_greedy_empty_match() {
        let ast = parse("(a?)*").unwrap();
        let analyzer = ReDoSAnalyzer::new();
        let result = analyzer.analyze(&ast);
        assert!(result.risks.iter().any(|r| r.description.contains("empty string")));
    }

    #[test]
    fn non_greedy_no_warning() {
        let ast = parse("(a?)+?").unwrap();
        let analyzer = ReDoSAnalyzer::new();
        let result = analyzer.analyze(&ast);
        assert!(!result.risks.iter().any(|r| r.description.contains("empty string") && r.level == RiskLevel::Medium));
    }

    #[test]
    fn detect_class_with_wide_range() {
        let ast = parse("[a-z]{0,100}").unwrap();
        let analyzer = ReDoSAnalyzer::new();
        let result = analyzer.analyze(&ast);
        assert!(result.risks.iter().any(|r| r.description.contains("wide range")));
    }

    #[test]
    fn format_report_includes_level() {
        let ast = parse("(a*)*").unwrap();
        let analyzer = ReDoSAnalyzer::new();
        let result = analyzer.analyze(&ast);
        let report = analyzer.format_report(&result, "(a*)*");
        assert!(report.contains("Critical") || report.contains("High"));
        assert!(report.contains("Nested quantifiers"));
        assert!(report.contains("Suggestion"));
    }

    #[test]
    fn multiple_risks_detected() {
        let ast = parse("(a*|b*)*.*").unwrap();
        let analyzer = ReDoSAnalyzer::new();
        let result = analyzer.analyze(&ast);
        assert!(result.risks.len() >= 2);
    }

    #[test]
    fn count_quantifiers_nested() {
        let ast = parse("((a*)*)*").unwrap();
        let analyzer = ReDoSAnalyzer::new();
        assert_eq!(analyzer.count_quantifiers(&ast), 3);
    }

    #[test]
    fn count_quantifiers_concat() {
        let ast = parse("a+b*c?").unwrap();
        let analyzer = ReDoSAnalyzer::new();
        assert_eq!(analyzer.count_quantifiers(&ast), 3);
    }

    #[test]
    fn can_match_empty() {
        let ast = parse("a*").unwrap();
        let analyzer = ReDoSAnalyzer::new();
        assert!(analyzer.can_match_empty(&ast));
    }

    #[test]
    fn cannot_match_empty() {
        let ast = parse("a+").unwrap();
        let analyzer = ReDoSAnalyzer::new();
        assert!(!analyzer.can_match_empty(&ast));
    }
}
