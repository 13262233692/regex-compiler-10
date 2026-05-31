mod analyzer;
mod ast;
mod codegen;
mod dfa;
mod optimizer;
mod parser;

use analyzer::{analyze_redo, ReDoSAnalyzer};
use clap::{Parser, ValueEnum};
use codegen::{CodeGenerator, Target};
use optimizer::Optimizer;
use parser::parse;

#[derive(Parser, Debug)]
#[command(name = "regexc", about = "Regex Compiler - Compile regex to efficient DFA/bytecode", version)]
struct Cli {
    /// Target language for code generation
    #[arg(short, long, value_enum, default_value_t = TargetArg::Rust)]
    target: TargetArg,

    /// Output format: regex, ast, dfa, dot, bytecode, code
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Code)]
    format: OutputFormat,

    /// Show optimization information
    #[arg(short, long)]
    verbose: bool,

    /// Disable optimizations
    #[arg(long)]
    no_optimize: bool,

    /// Minimize DFA
    #[arg(long, default_value_t = true)]
    minimize: bool,

    /// Perform ReDoS vulnerability analysis
    #[arg(long)]
    analyze: bool,

    /// The regular expression to compile
    regex: String,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
enum TargetArg {
    Rust,
    JavaScript,
    Js,
    Python,
    Py,
}

impl From<TargetArg> for Target {
    fn from(arg: TargetArg) -> Self {
        match arg {
            TargetArg::Rust => Target::Rust,
            TargetArg::JavaScript | TargetArg::Js => Target::JavaScript,
            TargetArg::Python | TargetArg::Py => Target::Python,
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
enum OutputFormat {
    /// Output optimized regex string
    Regex,
    /// Output AST structure
    Ast,
    /// Output DFA statistics
    Dfa,
    /// Output DOT graph representation
    Dot,
    /// Output bytecode instructions
    Bytecode,
    /// Generate target language code
    Code,
    /// Perform ReDoS vulnerability analysis
    Analyze,
    /// Output all formats
    All,
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();

    if cli.verbose {
        eprintln!("Compiling regex: {}", cli.regex);
    }

    let ast = parse(&cli.regex).map_err(|e| format!("Parse error: {}", e))?;

    if cli.verbose {
        eprintln!("Parsed successfully");
    }

    let analysis_result = if cli.analyze || matches!(cli.format, OutputFormat::Analyze | OutputFormat::All) {
        Some(analyze_redo(&ast))
    } else {
        None
    };

    if cli.analyze {
        if let Some(ref result) = analysis_result {
            let analyzer = ReDoSAnalyzer::new();
            println!("{}", analyzer.format_report(result, &cli.regex));
        }
    }

    let (optimized_ast, optimized_regex) = if cli.no_optimize {
        let opt = Optimizer::new();
        let regex_str = opt.to_regex_string(&ast);
        (ast, regex_str)
    } else {
        let mut opt = Optimizer::new();
        let optimized = opt.optimize(ast);
        let regex_str = opt.to_regex_string(&optimized);

        if cli.verbose && regex_str != cli.regex {
            eprintln!("Optimized: {} -> {}", cli.regex, regex_str);
        }

        (optimized, regex_str)
    };

    match cli.format {
        OutputFormat::Regex => {
            println!("{}", optimized_regex);
        }
        OutputFormat::Ast => {
            println!("{:#?}", optimized_ast);
        }
        OutputFormat::Dfa => {
            let nfa = dfa::build_nfa(&optimized_ast);
            let dfa = nfa.to_dfa();
            let dfa = if cli.minimize { dfa.minimize() } else { dfa };

            println!("DFA Statistics:");
            println!("  States: {}", dfa.states.len());
            println!("  Accept states: {}", dfa.accept.len());
            println!("  Transitions: {}", dfa.states.values().map(|t| t.len()).sum::<usize>());
            println!("  Start state: s{}", dfa.start.0);
        }
        OutputFormat::Dot => {
            let nfa = dfa::build_nfa(&optimized_ast);
            let dfa = nfa.to_dfa();
            let dfa = if cli.minimize { dfa.minimize() } else { dfa };
            println!("{}", dfa.to_dot());
        }
        OutputFormat::Bytecode => {
            let nfa = dfa::build_nfa(&optimized_ast);
            let dfa = nfa.to_dfa();
            let dfa = if cli.minimize { dfa.minimize() } else { dfa };
            let bytecode = dfa.to_bytecode();

            println!("Bytecode Instructions:");
            for (i, instr) in bytecode.iter().enumerate() {
                println!("  {:>3}: {:?}", i, instr);
            }
        }
        OutputFormat::Code => {
            let target: Target = cli.target.into();
            let code_gen = CodeGenerator::new(target);
            let code = code_gen.generate(&cli.regex, &optimized_regex);
            println!("{}", code);
        }
        OutputFormat::Analyze => {
            if let Some(ref result) = analysis_result {
                let analyzer = ReDoSAnalyzer::new();
                println!("{}", analyzer.format_report(result, &cli.regex));
            }
        }
        OutputFormat::All => {
            println!("=== Original Regex ===");
            println!("{}", cli.regex);
            println!();

            println!("=== Optimized Regex ===");
            println!("{}", optimized_regex);
            println!();

            println!("=== AST ===");
            println!("{:#?}", optimized_ast);
            println!();

            let nfa = dfa::build_nfa(&optimized_ast);
            let dfa = nfa.to_dfa();
            let dfa = if cli.minimize { dfa.minimize() } else { dfa };

            println!("=== DFA Statistics ===");
            println!("States: {}", dfa.states.len());
            println!("Accept states: {}", dfa.accept.len());
            println!("Transitions: {}", dfa.states.values().map(|t| t.len()).sum::<usize>());
            println!();

            println!("=== DOT Graph ===");
            println!("{}", dfa.to_dot());
            println!();

            println!("=== Bytecode ===");
            let bytecode = dfa.to_bytecode();
            for (i, instr) in bytecode.iter().enumerate() {
                println!("  {:>3}: {:?}", i, instr);
            }
            println!();

            println!("=== ReDoS Analysis ===");
            if let Some(ref result) = analysis_result {
                let analyzer = ReDoSAnalyzer::new();
                println!("{}", analyzer.format_report(result, &cli.regex));
            }
            println!();

            println!("=== Generated Code (Rust) ===");
            let code_gen = CodeGenerator::new(Target::Rust);
            println!("{}", code_gen.generate(&cli.regex, &optimized_regex));
            println!();

            println!("=== Generated Code (JavaScript) ===");
            let code_gen = CodeGenerator::new(Target::JavaScript);
            println!("{}", code_gen.generate(&cli.regex, &optimized_regex));
            println!();

            println!("=== Generated Code (Python) ===");
            let code_gen = CodeGenerator::new(Target::Python);
            println!("{}", code_gen.generate(&cli.regex, &optimized_regex));
        }
    }

    Ok(())
}
