mod analyze;
mod config;

use clap::{Parser, Subcommand};
use std::fs;
use std::path::Path;

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
    let ctx = match config::repo_context() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    let config = match config::PolicyConfig::load_from_path(&ctx.policy_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("{e}");
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
        &config.options.rg_exclude_globs,
        &ctx.scan_root,
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
        &config.options.rg_exclude_globs,
        &ctx.scan_root,
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
            &config.options.rg_exclude_globs,
            &ctx.scan_root,
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
    let ctx = match config::repo_context() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    let config = match config::PolicyConfig::load_from_path(&ctx.policy_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    println!("Analyzing repository...");

    let plan = match analyze::analyze_repo(&config, &ctx.scan_root) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Analysis failed: {e}");
            std::process::exit(1);
        }
    };

    let plan_markdown = analyze::format_plan(&plan);

    let output_path = {
        let p = Path::new(output_file);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            ctx.scan_root.join(p)
        }
    };

    // Write to file (relative paths are anchored at scan_root, not at the current dir)
    match fs::write(&output_path, &plan_markdown) {
        Ok(_) => {
            println!("✅ Cleanup plan written to: {}", output_path.display());
            println!("\nSummary:");
            println!("  Total violations: {}", plan.summary.total_violations);
            println!("  Files affected: {}", plan.summary.files_affected);
            if plan.summary.total_violations > 0 {
                println!(
                    "\n⚠️  Review {} for detailed recommendations",
                    output_path.display()
                );
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
    rg_exclude_globs: &[String],
    scan_root: &Path,
) -> Vec<String> {
    let mut out = vec![];

    for pat in patterns {
        // ripgrep: list matching files with line numbers
        let mut args: Vec<String> = vec![
            "-n".to_string(),
            "--hidden".to_string(),
            "--glob".to_string(),
            "!**/target/**".to_string(),
            "--glob".to_string(),
            "!**/*.lock".to_string(),
            "--glob".to_string(),
            "!**/Cargo.lock".to_string(),
            "--glob".to_string(),
            "!**/*.md".to_string(),
        ];

        for glob in rg_exclude_globs {
            args.push("--glob".to_string());
            args.push(format!("!{glob}"));
        }

        args.push(pat.to_string());
        args.push(".".to_string());

        let rg = std::process::Command::new("rg")
            .args(&args)
            .current_dir(scan_root)
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
