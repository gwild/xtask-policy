mod analyze;
mod config;

use clap::{Parser, Subcommand};
use std::collections::HashMap;
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

    // 4) Fail-fast violations (classified if configured)
    if !config.patterns.fallback_classes.is_empty() {
        for class in &config.patterns.fallback_classes {
            let pats: Vec<&str> = class.patterns.iter().map(|s| s.as_str()).collect();
            let allow: Vec<&str> = if !class.allowed.is_empty() {
                class.allowed.iter().map(|s| s.as_str()).collect()
            } else {
                config
                    .allowlists
                    .fallbacks_allowed
                    .iter()
                    .map(|s| s.as_str())
                    .collect()
            };
            failures.extend(run_rg_policy(
                &format!("Fail-fast violations ({}) outside allowlist", class.name),
                &pats,
                &allow,
                config.options.require_ripgrep,
                &config.options.rg_exclude_globs,
                &ctx.scan_root,
            ));
        }
    } else {
        let fallback_patterns: Vec<&str> = config
            .patterns
            .fallback_patterns
            .iter()
            .map(|s| s.as_str())
            .collect();
        failures.extend(run_rg_policy(
            "Fail-fast violations outside allowlist",
            &fallback_patterns,
            &config
                .allowlists
                .fallbacks_allowed
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>(),
            config.options.require_ripgrep,
            &config.options.rg_exclude_globs,
            &ctx.scan_root,
        ));
    }

    // 5) Required config presence (no silent defaults)
    failures.extend(check_required_config(&config, &ctx.scan_root));

    // 6) Sensitive literals (IPs, secrets, absolute paths)
    if !config.patterns.sensitive_classes.is_empty() {
        for class in &config.patterns.sensitive_classes {
            let pats: Vec<&str> = class.patterns.iter().map(|s| s.as_str()).collect();
            let allow: Vec<&str> = if !class.allowed.is_empty() {
                class.allowed.iter().map(|s| s.as_str()).collect()
            } else {
                config
                    .allowlists
                    .sensitive_allowed
                    .iter()
                    .map(|s| s.as_str())
                    .collect()
            };
            failures.extend(run_rg_policy(
                &format!("Sensitive literals ({}) outside allowlist", class.name),
                &pats,
                &allow,
                config.options.require_ripgrep,
                &config.options.rg_exclude_globs,
                &ctx.scan_root,
            ));
        }
    }

    // 7) Hardcoded numeric preview limits (magic numbers)
    if !config.patterns.hardcode_classes.is_empty() {
        for class in &config.patterns.hardcode_classes {
            let pats: Vec<&str> = class.patterns.iter().map(|s| s.as_str()).collect();
            let allow: Vec<&str> = if !class.allowed.is_empty() {
                class.allowed.iter().map(|s| s.as_str()).collect()
            } else {
                config
                    .allowlists
                    .hardcode_allowed
                    .iter()
                    .map(|s| s.as_str())
                    .collect()
            };
            failures.extend(run_rg_policy(
                &format!("Hardcoded preview limits ({}) outside allowlist", class.name),
                &pats,
                &allow,
                config.options.require_ripgrep,
                &config.options.rg_exclude_globs,
                &ctx.scan_root,
            ));
        }
    }

    // 8) Style: channel labels should use standard colored RichText scheme
    if !config.patterns.style_classes.is_empty() {
        for class in &config.patterns.style_classes {
            let pats: Vec<&str> = class.patterns.iter().map(|s| s.as_str()).collect();
            let allow: Vec<&str> = if !class.allowed.is_empty() {
                class.allowed.iter().map(|s| s.as_str()).collect()
            } else {
                config
                    .allowlists
                    .style_allowed
                    .iter()
                    .map(|s| s.as_str())
                    .collect()
            };
            failures.extend(run_rg_policy(
                &format!("Style violations ({}) outside allowlist", class.name),
                &pats,
                &allow,
                config.options.require_ripgrep,
                &config.options.rg_exclude_globs,
                &ctx.scan_root,
            ));
        }
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

fn check_required_config(config: &config::PolicyConfig, scan_root: &Path) -> Vec<String> {
    let mut out = vec![];

    // ---- env (.env + process env) ----
    let dotenv_path = scan_root.join(".env");
    let dotenv_map = match fs::read_to_string(&dotenv_path) {
        Ok(s) => parse_dotenv(&s),
        Err(_) => HashMap::new(),
    };

    let process_env: HashMap<String, String> = std::env::vars().collect();

    for group in &config.required.env_any_of {
        let mut satisfied = false;
        for key in &group.any_of {
            if let Some(v) = process_env.get(key) {
                if !v.trim().is_empty() {
                    satisfied = true;
                    break;
                }
            }
            if let Some(v) = dotenv_map.get(key) {
                if !v.trim().is_empty() {
                    satisfied = true;
                    break;
                }
            }
        }
        if !satisfied {
            out.push(format!(
                "Required config missing: at least one of env vars {:?} must be set (in process env or .env)",
                group.any_of
            ));
        }
    }

    // ---- yaml ----
    for req in &config.required.yaml_non_null {
        let path = scan_root.join(&req.file);
        let Ok(content) = fs::read_to_string(&path) else {
            out.push(format!(
                "Required config missing: YAML file '{}' not found at {}",
                req.file,
                path.display()
            ));
            continue;
        };
        let yaml: serde_yaml::Value = match serde_yaml::from_str(&content) {
            Ok(v) => v,
            Err(e) => {
                out.push(format!(
                    "Required config invalid: YAML file '{}' failed to parse: {e}",
                    req.file
                ));
                continue;
            }
        };

        match yaml_path_non_null(&yaml, &req.path, req.all) {
            Ok(true) => {}
            Ok(false) => out.push(format!(
                "Required config missing: YAML '{}' path '{}' is missing or null{}",
                req.file,
                req.path,
                if req.all { " (expected non-null for all matches)" } else { "" }
            )),
            Err(e) => out.push(format!(
                "Required config invalid: YAML '{}' path '{}': {e}",
                req.file, req.path
            )),
        }
    }

    out
}

fn parse_dotenv(s: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for raw in s.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim().to_string();
        if key.is_empty() {
            continue;
        }
        let mut val = v.trim().to_string();
        // strip simple surrounding quotes
        if (val.starts_with('"') && val.ends_with('"')) || (val.starts_with('\'') && val.ends_with('\'')) {
            if val.len() >= 2 {
                val = val[1..val.len() - 1].to_string();
            }
        }
        out.insert(key, val);
    }
    out
}

fn yaml_path_non_null(root: &serde_yaml::Value, path: &str, all: bool) -> Result<bool, String> {
    let segments: Vec<&str> = path.split('.').filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        return Err("empty path".to_string());
    }

    let mut nodes: Vec<&serde_yaml::Value> = vec![root];
    for seg in segments {
        let mut next = vec![];
        for n in nodes {
            match seg {
                "*" => match n {
                    serde_yaml::Value::Mapping(m) => {
                        for (_, v) in m {
                            next.push(v);
                        }
                    }
                    serde_yaml::Value::Sequence(seq) => {
                        for v in seq {
                            next.push(v);
                        }
                    }
                    _ => {}
                },
                key => match n {
                    serde_yaml::Value::Mapping(m) => {
                        let k = serde_yaml::Value::String(key.to_string());
                        if let Some(v) = m.get(&k) {
                            next.push(v);
                        }
                    }
                    _ => {}
                },
            }
        }
        nodes = next;
        if nodes.is_empty() {
            return Ok(false);
        }
    }

    if all {
        Ok(nodes.iter().all(|v| !matches!(v, serde_yaml::Value::Null)))
    } else {
        Ok(nodes.iter().any(|v| !matches!(v, serde_yaml::Value::Null)))
    }
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
            let Some(path) = line.split(':').next() else {
                continue;
            };
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
