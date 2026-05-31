use crate::ast::*;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StateId(pub usize);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NFA {
    pub start: StateId,
    pub accept: StateId,
    pub states: BTreeMap<StateId, Vec<Transition>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    Epsilon(StateId),
    Char(char, StateId),
    Class(CharClass, StateId),
    Any(StateId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DFA {
    pub start: StateId,
    pub accept: BTreeSet<StateId>,
    pub states: BTreeMap<StateId, BTreeMap<InputSymbol, StateId>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum InputSymbol {
    Char(char),
    Class(CharClass),
    Any,
}

pub struct NfaBuilder {
    next_state: usize,
    transitions: BTreeMap<StateId, Vec<Transition>>,
}

impl NfaBuilder {
    pub fn new() -> Self {
        NfaBuilder {
            next_state: 0,
            transitions: BTreeMap::new(),
        }
    }

    fn new_state(&mut self) -> StateId {
        let id = StateId(self.next_state);
        self.next_state += 1;
        self.transitions.insert(id, Vec::new());
        id
    }

    pub fn build(&mut self, expr: &Expr) -> NFA {
        let (start, accept) = self.build_expr(expr);
        NFA {
            start,
            accept,
            states: self.transitions.clone(),
        }
    }

    fn build_expr(&mut self, expr: &Expr) -> (StateId, StateId) {
        match expr {
            Expr::Empty => {
                let s = self.new_state();
                (s, s)
            }
            Expr::Literal(c) => {
                let start = self.new_state();
                let accept = self.new_state();
                self.add_transition(start, Transition::Char(*c, accept));
                (start, accept)
            }
            Expr::Class(cls) => {
                let start = self.new_state();
                let accept = self.new_state();
                self.add_transition(start, Transition::Class(cls.clone(), accept));
                (start, accept)
            }
            Expr::Anchor(_) => {
                let s = self.new_state();
                (s, s)
            }
            Expr::Concat(items) => {
                let mut prev_accept = None;
                let mut first_start = None;
                let mut last_accept = None;

                for item in items {
                    let (s, a) = self.build_expr(item);
                    if let Some(prev) = prev_accept {
                        self.add_transition(prev, Transition::Epsilon(s));
                    }
                    if first_start.is_none() {
                        first_start = Some(s);
                    }
                    prev_accept = Some(a);
                    last_accept = Some(a);
                }

                match (first_start, last_accept) {
                    (Some(s), Some(a)) => (s, a),
                    _ => {
                        let s = self.new_state();
                        (s, s)
                    }
                }
            }
            Expr::Alternation(branches) => {
                let start = self.new_state();
                let accept = self.new_state();

                for branch in branches {
                    let (s, a) = self.build_expr(branch);
                    self.add_transition(start, Transition::Epsilon(s));
                    self.add_transition(a, Transition::Epsilon(accept));
                }

                (start, accept)
            }
            Expr::Repetition {
                expr,
                kind,
                greedy: _,
            } => self.build_repetition(expr, kind),
            Expr::Group { expr, .. } => self.build_expr(expr),
            Expr::Backreference(_) => {
                let s = self.new_state();
                (s, s)
            }
        }
    }

    fn build_repetition(
        &mut self,
        expr: &Expr,
        kind: &RepetitionKind,
    ) -> (StateId, StateId) {
        match kind {
            RepetitionKind::ZeroOrMore => {
                if self.is_zero_or_more(expr) {
                    return self.build_expr(expr);
                }
                let start = self.new_state();
                let accept = self.new_state();
                let (s, a) = self.build_expr(expr);

                self.add_transition(start, Transition::Epsilon(s));
                self.add_transition(start, Transition::Epsilon(accept));
                self.add_transition(a, Transition::Epsilon(s));
                self.add_transition(a, Transition::Epsilon(accept));

                (start, accept)
            }
            RepetitionKind::OneOrMore => {
                let start = self.new_state();
                let accept = self.new_state();
                let (s, a) = self.build_expr(expr);

                self.add_transition(start, Transition::Epsilon(s));
                self.add_transition(a, Transition::Epsilon(s));
                self.add_transition(a, Transition::Epsilon(accept));

                (start, accept)
            }
            RepetitionKind::ZeroOrOne => {
                let start = self.new_state();
                let accept = self.new_state();
                let (s, a) = self.build_expr(expr);

                self.add_transition(start, Transition::Epsilon(s));
                self.add_transition(start, Transition::Epsilon(accept));
                self.add_transition(a, Transition::Epsilon(accept));

                (start, accept)
            }
            RepetitionKind::Exactly(n) => {
                let mut prev_accept = None;
                let mut first_start = None;

                for _ in 0..*n {
                    let (s, a) = self.build_expr(expr);
                    if let Some(prev) = prev_accept {
                        self.add_transition(prev, Transition::Epsilon(s));
                    }
                    if first_start.is_none() {
                        first_start = Some(s);
                    }
                    prev_accept = Some(a);
                }

                match (first_start, prev_accept) {
                    (Some(s), Some(a)) => (s, a),
                    _ => {
                        let s = self.new_state();
                        (s, s)
                    }
                }
            }
            RepetitionKind::AtLeast(n) => {
                let (s, a) = self.build_repetition(expr, &RepetitionKind::Exactly(*n));
                let (s2, a2) = self.build_repetition(expr, &RepetitionKind::ZeroOrMore);

                self.add_transition(a, Transition::Epsilon(s2));

                (s, a2)
            }
            RepetitionKind::Range(min, max) => {
                let (s, a) = self.build_repetition(expr, &RepetitionKind::Exactly(*min));
                let mut prev_accept = a;
                let mut last_accept = a;

                for _ in *min..*max {
                    let (s2, a2) = self.build_repetition(expr, &RepetitionKind::ZeroOrOne);
                    self.add_transition(prev_accept, Transition::Epsilon(s2));
                    prev_accept = a2;
                    last_accept = a2;
                }

                (s, last_accept)
            }
        }
    }

    fn add_transition(&mut self, from: StateId, trans: Transition) {
        self.next_state = self.next_state.max(from.0 + 1);
        let to = match &trans {
            Transition::Epsilon(to)
            | Transition::Char(_, to)
            | Transition::Class(_, to)
            | Transition::Any(to) => *to,
        };
        self.next_state = self.next_state.max(to.0 + 1);
        let existing = self.transitions.entry(from).or_insert_with(Vec::new);
        if !existing.contains(&trans) {
            existing.push(trans);
        }
    }

    fn is_zero_or_more(&self, expr: &Expr) -> bool {
        matches!(
            expr,
            Expr::Repetition {
                kind: RepetitionKind::ZeroOrMore,
                ..
            }
        )
    }
}

const MAX_DFA_STATES: usize = 1000;
const MAX_CLOSURE_SIZE: usize = 10000;

impl NFA {
    pub fn epsilon_closure(&self, states: &BTreeSet<StateId>) -> BTreeSet<StateId> {
        let mut closure = states.clone();
        let mut stack: Vec<StateId> = states.iter().copied().collect();

        while let Some(state) = stack.pop() {
            if closure.len() > MAX_CLOSURE_SIZE {
                break;
            }
            if let Some(transitions) = self.states.get(&state) {
                for trans in transitions {
                    if let Transition::Epsilon(next) = trans {
                        if closure.insert(*next) {
                            stack.push(*next);
                        }
                    }
                }
            }
        }

        closure
    }

    pub fn to_dfa(&self) -> DFA {
        let mut dfa_states: BTreeMap<BTreeSet<StateId>, StateId> = BTreeMap::new();
        let mut dfa_transitions: BTreeMap<StateId, BTreeMap<InputSymbol, StateId>> = BTreeMap::new();
        let mut accept_states = BTreeSet::new();
        let mut next_id = 0;

        let start_closure = self.epsilon_closure(&BTreeSet::from([self.start]));
        let start_id = StateId(next_id);
        next_id += 1;
        dfa_states.insert(start_closure.clone(), start_id);

        if start_closure.contains(&self.accept) {
            accept_states.insert(start_id);
        }

        let mut worklist = VecDeque::new();
        worklist.push_back(start_closure);

        while let Some(state_set) = worklist.pop_front() {
            if dfa_states.len() >= MAX_DFA_STATES {
                break;
            }

            let state_id = dfa_states[&state_set];

            let symbol_map = self.get_symbol_transitions(&state_set);

            let mut transitions = BTreeMap::new();
            for (symbol, targets) in symbol_map {
                let target_closure = self.epsilon_closure(&targets);
                let is_accept = target_closure.contains(&self.accept);

                let target_id = if let Some(&id) = dfa_states.get(&target_closure) {
                    id
                } else {
                    if dfa_states.len() >= MAX_DFA_STATES {
                        continue;
                    }
                    let id = StateId(next_id);
                    next_id += 1;
                    dfa_states.insert(target_closure.clone(), id);
                    worklist.push_back(target_closure);

                    if is_accept {
                        accept_states.insert(id);
                    }
                    id
                };

                transitions.insert(symbol, target_id);
            }

            dfa_transitions.insert(state_id, transitions);
        }

        DFA {
            start: start_id,
            accept: accept_states,
            states: dfa_transitions,
        }
    }

    fn get_symbol_transitions(
        &self,
        state_set: &BTreeSet<StateId>,
    ) -> BTreeMap<InputSymbol, BTreeSet<StateId>> {
        let mut result: BTreeMap<InputSymbol, BTreeSet<StateId>> = BTreeMap::new();

        for state in state_set {
            if let Some(transitions) = self.states.get(state) {
                for trans in transitions {
                    match trans {
                        Transition::Char(c, to) => {
                            result
                                .entry(InputSymbol::Char(*c))
                                .or_insert_with(BTreeSet::new)
                                .insert(*to);
                        }
                        Transition::Class(cls, to) => {
                            result
                                .entry(InputSymbol::Class(cls.clone()))
                                .or_insert_with(BTreeSet::new)
                                .insert(*to);
                        }
                        Transition::Any(to) => {
                            result
                                .entry(InputSymbol::Any)
                                .or_insert_with(BTreeSet::new)
                                .insert(*to);
                        }
                        Transition::Epsilon(_) => {}
                    }
                }
            }
        }

        result
    }
}

impl DFA {
    pub fn minimize(&self) -> DFA {
        let mut partition: BTreeSet<BTreeSet<StateId>> = BTreeSet::new();
        let non_accept: BTreeSet<StateId> = self
            .states
            .keys()
            .filter(|s| !self.accept.contains(s))
            .copied()
            .collect();
        let accept: BTreeSet<StateId> = self.accept.iter().copied().collect();

        if !non_accept.is_empty() {
            partition.insert(non_accept);
        }
        if !accept.is_empty() {
            partition.insert(accept);
        }

        let mut changed = true;
        while changed {
            changed = false;
            let mut new_partition = BTreeSet::new();

            for group in &partition {
                let mut subgroups: BTreeMap<BTreeMap<InputSymbol, BTreeSet<StateId>>, BTreeSet<StateId>> =
                    BTreeMap::new();

                for state in group {
                    let signature = self.get_state_signature(state, &partition);
                    subgroups
                        .entry(signature)
                        .or_insert_with(BTreeSet::new)
                        .insert(*state);
                }

                for (_, subgroup) in subgroups {
                    new_partition.insert(subgroup);
                }
            }

            if new_partition != partition {
                partition = new_partition;
                changed = true;
            }
        }

        let mut state_map: HashMap<StateId, StateId> = HashMap::new();
        let mut new_states: BTreeMap<StateId, BTreeMap<InputSymbol, StateId>> = BTreeMap::new();
        let mut new_accept = BTreeSet::new();
        let mut next_id = 0;

        let mut group_map: HashMap<BTreeSet<StateId>, StateId> = HashMap::new();
        for group in &partition {
            let id = StateId(next_id);
            next_id += 1;
            group_map.insert(group.clone(), id);

            for state in group {
                state_map.insert(*state, id);
            }

            if group.iter().any(|s| self.accept.contains(s)) {
                new_accept.insert(id);
            }
        }

        let new_start = state_map[&self.start];

        for group in &partition {
            let group_id = group_map[group];
            let representative = group.iter().next().unwrap();

            if let Some(transitions) = self.states.get(representative) {
                let mut new_transitions = BTreeMap::new();
                for (symbol, target) in transitions {
                    new_transitions.insert(symbol.clone(), state_map[target]);
                }
                new_states.insert(group_id, new_transitions);
            } else {
                new_states.insert(group_id, BTreeMap::new());
            }
        }

        DFA {
            start: new_start,
            accept: new_accept,
            states: new_states,
        }
    }

    fn get_state_signature(
        &self,
        state: &StateId,
        partition: &BTreeSet<BTreeSet<StateId>>,
    ) -> BTreeMap<InputSymbol, BTreeSet<StateId>> {
        let mut signature = BTreeMap::new();

        if let Some(transitions) = self.states.get(state) {
            for (symbol, target) in transitions {
                let target_group = partition
                    .iter()
                    .find(|g| g.contains(target))
                    .unwrap()
                    .clone();
                signature.insert(symbol.clone(), target_group);
            }
        }

        signature
    }

    pub fn to_dot(&self) -> String {
        let mut dot = String::from("digraph DFA {\n");
        dot.push_str("  rankdir=LR;\n");
        dot.push_str("  node [shape=circle];\n");

        dot.push_str("  start [shape=plaintext, label=\"\"];\n");
        dot.push_str(&format!("  start -> s{};\n", self.start.0));

        for (state, _) in &self.states {
            if self.accept.contains(state) {
                dot.push_str(&format!("  s{} [shape=doublecircle];\n", state.0));
            }
        }

        for (from, transitions) in &self.states {
            for (symbol, to) in transitions {
                let label = self.symbol_to_label(symbol);
                dot.push_str(&format!(
                    "  s{} -> s{} [label=\"{}\"];\n",
                    from.0, to.0, label
                ));
            }
        }

        dot.push_str("}\n");
        dot
    }

    fn symbol_to_label(&self, symbol: &InputSymbol) -> String {
        match symbol {
            InputSymbol::Char(c) => match c {
                '\n' => "\\n".to_string(),
                '\r' => "\\r".to_string(),
                '\t' => "\\t".to_string(),
                '"' => "\\\"".to_string(),
                '\\' => "\\\\".to_string(),
                _ => c.to_string(),
            },
            InputSymbol::Class(cls) => match cls {
                CharClass::Digit => "\\d".to_string(),
                CharClass::Word => "\\w".to_string(),
                CharClass::Whitespace => "\\s".to_string(),
                CharClass::NegatedDigit => "\\D".to_string(),
                CharClass::NegatedWord => "\\W".to_string(),
                CharClass::NegatedWhitespace => "\\S".to_string(),
                CharClass::Any => ".".to_string(),
                CharClass::Range(start, end) => format!("[{}-{}]", start, end),
                CharClass::Literal(c) => c.to_string(),
                CharClass::Class(_) => "[...]".to_string(),
                CharClass::NegatedClass(_) => "[^...]".to_string(),
            },
            InputSymbol::Any => ".".to_string(),
        }
    }

    pub fn to_bytecode(&self) -> Vec<BytecodeInstr> {
        let mut bytecode = Vec::new();
        let mut state_map = HashMap::new();
        let mut pc = 0;

        for (state_id, _) in &self.states {
            state_map.insert(state_id, pc);
            pc += 1;
        }

        bytecode.push(BytecodeInstr::Start);

        let state_order: Vec<_> = self.states.keys().copied().collect();
        for state_id in state_order {
            let _state_pc = state_map[&state_id];

            if self.accept.contains(&state_id) {
                bytecode.push(BytecodeInstr::Accept);
            }

            if let Some(transitions) = self.states.get(&state_id) {
                for (symbol, target) in transitions {
                    let target_pc = state_map[target];
                    match symbol {
                        InputSymbol::Char(c) => {
                            bytecode.push(BytecodeInstr::MatchChar(*c, target_pc));
                        }
                        InputSymbol::Class(cls) => {
                            bytecode.push(BytecodeInstr::MatchClass(cls.clone(), target_pc));
                        }
                        InputSymbol::Any => {
                            bytecode.push(BytecodeInstr::MatchAny(target_pc));
                        }
                    }
                }
            }

            bytecode.push(BytecodeInstr::Fail);
        }

        bytecode
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BytecodeInstr {
    Start,
    Accept,
    Fail,
    MatchChar(char, usize),
    MatchClass(CharClass, usize),
    MatchAny(usize),
    Jump(usize),
}

pub fn build_nfa(expr: &Expr) -> NFA {
    NfaBuilder::new().build(expr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;

    #[test]
    fn build_simple_nfa() {
        let ast = parse("ab").unwrap();
        let nfa = build_nfa(&ast);
        assert!(nfa.states.len() > 0);
    }

    #[test]
    fn nfa_to_dfa() {
        let ast = parse("ab").unwrap();
        let nfa = build_nfa(&ast);
        let dfa = nfa.to_dfa();
        assert!(dfa.states.len() > 0);
    }

    #[test]
    fn dfa_minimize() {
        let ast = parse("a|b").unwrap();
        let nfa = build_nfa(&ast);
        let dfa = nfa.to_dfa();
        let minimized = dfa.minimize();
        assert!(minimized.states.len() <= dfa.states.len());
    }

    #[test]
    fn dfa_to_dot() {
        let ast = parse("ab").unwrap();
        let nfa = build_nfa(&ast);
        let dfa = nfa.to_dfa();
        let dot = dfa.to_dot();
        assert!(dot.contains("digraph"));
        assert!(dot.contains("->"));
    }

    #[test]
    fn dfa_to_bytecode() {
        let ast = parse("ab").unwrap();
        let nfa = build_nfa(&ast);
        let dfa = nfa.to_dfa();
        let bytecode = dfa.to_bytecode();
        assert!(!bytecode.is_empty());
    }

    #[test]
    fn epsilon_closure() {
        let ast = parse("a*b").unwrap();
        let nfa = build_nfa(&ast);
        let closure = nfa.epsilon_closure(&BTreeSet::from([nfa.start]));
        assert!(!closure.is_empty());
    }

    #[test]
    fn complex_regex_dfa() {
        let ast = parse(r"^\d{3}-\d{2}$").unwrap();
        let nfa = build_nfa(&ast);
        let dfa = nfa.to_dfa();
        let minimized = dfa.minimize();
        assert!(minimized.states.len() > 0);
        assert!(!minimized.accept.is_empty());
    }

    #[test]
    fn alternation_dfa() {
        let ast = parse("(abc|def)").unwrap();
        let nfa = build_nfa(&ast);
        let dfa = nfa.to_dfa();
        assert!(dfa.states.len() > 0);
    }

    #[test]
    fn repetition_dfa() {
        let ast = parse("a+b*c?").unwrap();
        let nfa = build_nfa(&ast);
        let dfa = nfa.to_dfa();
        assert!(dfa.states.len() > 0);
    }

    #[test]
    fn nested_quantifier_dfa() {
        let ast = parse("(a*)*").unwrap();
        let nfa = build_nfa(&ast);
        let dfa = nfa.to_dfa();
        assert!(dfa.states.len() > 0);
        assert!(dfa.states.len() <= 10);
    }

    #[test]
    fn complex_nested_quantifier_dfa() {
        let ast = parse("(a+b*|c?d+)*").unwrap();
        let nfa = build_nfa(&ast);
        let dfa = nfa.to_dfa();
        let minimized = dfa.minimize();
        assert!(minimized.states.len() > 0);
        assert!(minimized.states.len() <= 20);
    }

    #[test]
    fn deeply_nested_quantifier() {
        let ast = parse("((a*)*)*").unwrap();
        let nfa = build_nfa(&ast);
        let dfa = nfa.to_dfa();
        assert!(dfa.states.len() > 0);
        assert!(dfa.states.len() <= 10);
    }
}
