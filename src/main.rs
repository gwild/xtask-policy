mod analyze;
mod config;

use clap::{Parser, Subcommand};
use std::fs;

#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "Policy enforcement agent for architectural invariants")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check for policy violations (default)
    Check,
    /// Analyze repo and generate cleanup plan
    Analyze {
        /// Output file for cleanup plan (default: cleanup-plan.md)
        #[arg(short, long, default_value = "cleanup-plan.md")]
        output: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Check => {
            run_check();
        }
        Commands::Analyze { output } => {
            run_analyze(&output);
        }
    }
}

fn run_check() {
    // Load configuration
    let config = match config::PolicyConfig::load() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Failed to load policy config: {e}");
            eprintln!("Using default hardcoded configuration");
            std::process::exit(1);
        }
    };

    let mut failures = vec![];

    // 1) Locks
    let lock_patterns: Vec<&str> = config
        .patterns
        .lock_patterns
        .iter()
        .map(|s| s.as_str())
        .collect();
    failures.extend(run_rg_policy(
        "Locks outside allowlist",
        &lock_patterns,
        &config
            .allowlists
            .lock_allowed
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>(),
        config.options.require_ripgrep,
    ));

    // 2) Spawning
    let spawn_patterns: Vec<&str> = config
        .patterns
        .spawn_patterns
        .iter()
        .map(|s| s.as_str())
        .collect();
    failures.extend(run_rg_policy(
        "Spawning outside allowlist",
        &spawn_patterns,
        &config
            .allowlists
            .spawn_allowed
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>(),
        config.options.require_ripgrep,
    ));

    // 3) SSOT name leakage
    for ssot_type in &config.patterns.ssot_types {
        let pattern = format!(r"\b{}\b", ssot_type);
        let ssot_allowed: Vec<&str> = config
            .allowlists
            .ssot_allowed
            .iter()
            .map(|s| s.as_str())
            .collect();
        failures.extend(run_rg_policy(
            &format!("{ssot_type} referenced outside owner module"),
            &[&pattern],
            &ssot_allowed,
            config.options.require_ripgrep,
        ));
    }

    if failures.is_empty() {
        println!("policy: OK");
        return;
    }

    eprintln!("policy: FAILED");
    for f in failures {
        eprintln!("  - {f}");
    }
    std::process::exit(2);
}

fn run_analyze(output_file: &str) {
    // Load configuration
    let config = match config::PolicyConfig::load() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Failed to load policy config: {e}");
            std::process::exit(1);
        }
    };

    println!("Analyzing repository...");

    let plan = match analyze::analyze_repo(&config) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Analysis failed: {e}");
            std::process::exit(1);
        }
    };

    let plan_markdown = analyze::format_plan(&plan);

    // Write to file
    match fs::write(output_file, &plan_markdown) {
        Ok(_) => {
            println!("✅ Cleanup plan written to: {}", output_file);
            println!("\nSummary:");
            println!("  Total violations: {}", plan.summary.total_violations);
            println!("  Files affected: {}", plan.summary.files_affected);
            if plan.summary.total_violations > 0 {
                println!("\n⚠️  Review {} for detailed recommendations", output_file);
            }
        }
        Err(e) => {
            eprintln!("Failed to write cleanup plan: {e}");
            std::process::exit(1);
        }
    }
}

fn run_rg_policy(
    rule_name: &str,
    patterns: &[&str],
    allow_prefixes: &[&str],
    require_ripgrep: bool,
) -> Vec<String> {
    let mut out = vec![];

    for pat in patterns {
        // ripgrep: list matching files with line numbers
        let rg = std::process::Command::new("rg")
            .args([
                "-n",
                "--hidden",
                "--glob",
                "!target/**",
                "--glob",
                "!**/*.lock",
                "--glob",
                "!**/Cargo.lock",
                "--glob",
                "!**/*.md",
                pat,
                ".",
            ])
            .output();

        let Ok(rg) = rg else {
            let msg = format!("{rule_name}: could not execute ripgrep (rg). Install rg.");
            if require_ripgrep {
                out.push(msg);
            } else {
                eprintln!("Warning: {msg}");
            }
            continue;
        };

        if !rg.status.success() && rg.stdout.is_empty() {
            continue; // no matches
        }

        let stdout = String::from_utf8_lossy(&rg.stdout);
        for line in stdout.lines() {
            // line format: path:line:match...
            let path = line.split(':').next().unwrap_or("");
            if is_allowed(path, allow_prefixes) {
                continue;
            }
            out.push(format!("{rule_name}: {pat} -> {line}"));
        }
    }

    out
}

fn is_allowed(path: &str, allow_prefixes: &[&str]) -> bool {
    let p = std::path::Path::new(path);
    let s = p.to_string_lossy();
    allow_prefixes.iter().any(|prefix| s.contains(prefix))
}
