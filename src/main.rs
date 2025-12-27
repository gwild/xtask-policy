mod analyze;
mod config;

use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use postgres::{Client, NoTls};
use sha2::{Digest, Sha256};

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
        /// Postgres URL used to log analysis runs (if omitted, uses XTASK_ANALYSIS_DB_URL)
        #[arg(long)]
        db_url: Option<String>,
        /// Skip DB logging for this run (explicit opt-out)
        #[arg(long)]
        no_db: bool,
    },
    /// Update legacy manifest (explicit permission step for editing legacy/)
    UpdateLegacyManifest,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Check => {
            run_check();
        }
        Commands::Analyze { output, db_url, no_db } => {
            run_analyze(&output, db_url.as_deref(), no_db);
        }
        Commands::UpdateLegacyManifest => {
            run_update_legacy_manifest();
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

    // 9) Forbidden patterns (mechanical bans: e.g., matplotlib, polling defaults, timeout loops)
    if !config.patterns.forbidden_classes.is_empty() {
        // By default, scan forbidden patterns ONLY in code paths:
        // - Python: **/*.py
        // - Static JS: static/**/*.js
        // - Embedded JS in templates: templates/**/*.html
        //
        // And explicitly exclude docs/ + issue_reports/ so documentation can contain
        // "bad examples" without tripping CI. Repo owners can add additional excludes via
        // `options.rg_exclude_globs`.
        let mut forbidden_rg_excludes = config.options.rg_exclude_globs.clone();
        forbidden_rg_excludes.push("docs/**".to_string());
        forbidden_rg_excludes.push("issue_reports/**".to_string());

        let forbidden_rg_includes: [&str; 3] = ["**/*.py", "static/**/*.js", "templates/**/*.html"];

        for class in &config.patterns.forbidden_classes {
            let pats: Vec<&str> = class.patterns.iter().map(|s| s.as_str()).collect();
            let allow: Vec<&str> = if !class.allowed.is_empty() {
                class.allowed.iter().map(|s| s.as_str()).collect()
            } else {
                config
                    .allowlists
                    .forbidden_allowed
                    .iter()
                    .map(|s| s.as_str())
                    .collect()
            };
            failures.extend(run_rg_policy_scoped(
                &format!("Forbidden patterns ({}) outside allowlist", class.name),
                &pats,
                &allow,
                config.options.require_ripgrep,
                &forbidden_rg_excludes,
                &forbidden_rg_includes,
                &ctx.scan_root,
            ));
        }
    }

    // 9) Markdown files must live under docs/
    failures.extend(check_markdown_locations(&config, &ctx.scan_root));

    // 10) WebSocket send-after-close guard (Python)
    failures.extend(check_websocket_send_guard(&config, &ctx.scan_root));

    // 11) SSOT guard: circle_center must never be overwritten during regeneration
    failures.extend(check_circle_center_regeneration_ssot(&ctx.scan_root));

    // 11) Legacy directory is write-protected by manifest (explicit user permission step)
    failures.extend(check_legacy_manifest(&config, &ctx.scan_root));

    // 12) Prescriptive adjustment-process invariants (stringdriver control loop)
    failures.extend(check_adjustment_process_policy(&ctx.scan_root));

    // 13) NO CACHE: GUI/SSOT values must not be cached before loop iterations (must be re-read inside loops).
    failures.extend(check_no_gui_value_cache_before_loops(&ctx.scan_root));

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

fn check_adjustment_process_policy(scan_root: &Path) -> Vec<String> {
    let mut failures = vec![];

    let ops_path = scan_root.join("src/operations.rs");
    let content = match std::fs::read_to_string(&ops_path) {
        Ok(s) => s,
        Err(e) => {
            failures.push(format!(
                "Adjustment policy: failed to read {}: {e}",
                ops_path.display()
            ));
            return failures;
        }
    };

    // Helper for extracting a function-ish block by start token and next token.
    fn slice_block<'a>(hay: &'a str, start_pat: &str, next_pat: &str) -> Option<&'a str> {
        let start = hay.find(start_pat)?;
        let rest = &hay[start..];
        let search_start = start_pat.len().min(rest.len());
        let end = match rest[search_start..].find(next_pat) {
            Some(i) => i + search_start,
            None => rest.len(),
        };
        Some(&rest[..end])
    }

    // A) There must be exactly one audio sample per iteration: update_from_slot() only in run_adjustment_iteration.
    let update_calls = content.matches("update_from_slot();").count();
    if update_calls != 1 {
        failures.push(format!(
            "Adjustment policy: expected exactly 1 call to update_from_slot(); found {update_calls} (must only occur inside run_adjustment_iteration)"
        ));
    }

    // B) run_adjustment_iteration must call bump_check before update_from_slot.
    let Some(iter_block) = slice_block(
        &content,
        "fn run_adjustment_iteration",
        "pub fn right_left_move",
    ) else {
        failures.push("Adjustment policy: missing fn run_adjustment_iteration in src/operations.rs".to_string());
        return failures;
    };
    let bump_pos = iter_block.find("bump_check(");
    let update_pos = iter_block.find("update_from_slot();");
    if bump_pos.is_none() || update_pos.is_none() {
        failures.push(
            "Adjustment policy: run_adjustment_iteration must contain bump_check(...) and update_from_slot();"
                .to_string(),
        );
    } else if bump_pos.unwrap() > update_pos.unwrap() {
        failures.push(
            "Adjustment policy: run_adjustment_iteration must call bump_check(...) before update_from_slot();"
                .to_string(),
        );
    }

    // C) z_adjust_with_skip_and_previous must not bump_check or resample internally.
    if let Some(zadj_block) = slice_block(
        &content,
        "pub fn z_adjust_with_skip_and_previous",
        "fn run_adjustment_iteration",
    ) {
        if zadj_block.contains("bump_check(") {
            failures.push("Adjustment policy: z_adjust_with_skip_and_previous must not call bump_check(...) internally".to_string());
        }
        if zadj_block.contains("update_from_slot(") {
            failures.push("Adjustment policy: z_adjust_with_skip_and_previous must not call update_from_slot(...) internally".to_string());
        }
    } else {
        failures.push("Adjustment policy: missing pub fn z_adjust_with_skip_and_previous in src/operations.rs".to_string());
    }

    // D) Movement algorithms must use run_adjustment_iteration (enforces order + single-sample).
    for (name, start_pat) in [
        ("right_left_move", "pub fn right_left_move"),
        ("left_right_move", "pub fn left_right_move"),
        ("z_seeker", "pub fn z_seeker"),
    ] {
        let Some(block) = slice_block(&content, start_pat, "\npub fn ") else {
            failures.push(format!("Adjustment policy: missing {name} in src/operations.rs"));
            continue;
        };
        if !block.contains("run_adjustment_iteration(") {
            failures.push(format!(
                "Adjustment policy: {name} must call run_adjustment_iteration(...) (do not sample audio directly in move loops)"
            ));
        }
    }

    // E) SSOT/JIT: no getter layer in movement algorithms + no cached step sizes.
    // We require each move to compute `(*self.x_step.lock().unwrap()).abs()` immediately before calling rel_move_x.
    for (name, start_pat) in [
        ("right_left_move", "pub fn right_left_move"),
        ("left_right_move", "pub fn left_right_move"),
        ("z_seeker", "pub fn z_seeker"),
    ] {
        let Some(block) = slice_block(&content, start_pat, "\npub fn ") else {
            continue;
        };

        if block.contains("self.get_") {
            failures.push(format!(
                "Adjustment policy: {name} must not use self.get_*() (no getter layer; read SSOT fields directly JIT)"
            ));
        }

        // Additionally, every rel_move_x(...) within these algorithms must have a nearby JIT read of x_step.
        // This is a coarse but effective “no cache” check: if a rel_move_x happens without a nearby
        // x_step.lock().unwrap(), it likely used a cached step size.
        let mut search_from = 0usize;
        while let Some(rel_pos) = block[search_from..].find("rel_move_x(") {
            let rel_abs = search_from + rel_pos;
            let window_start = rel_abs.saturating_sub(800);
            let window = &block[window_start..rel_abs];
            if !window.contains("x_step.lock") {
                failures.push(format!(
                    "Adjustment policy: {name} calls rel_move_x(...) without a nearby self.x_step.lock().unwrap() JIT read (no cached step sizes allowed)"
                ));
                break;
            }
            search_from = rel_abs + "rel_move_x(".len();
        }
    }

    failures
}

fn check_no_gui_value_cache_before_loops(scan_root: &Path) -> Vec<String> {
    let mut failures = vec![];

    fn walk_rs_files(root: &Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(root) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk_rs_files(&path, out);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }

    // Scan only runtime code (not target/, not docs).
    let mut files: Vec<std::path::PathBuf> = vec![];
    walk_rs_files(&scan_root.join("src"), &mut files);

    // Detect the “GUI/SSOT cache” bug class:
    // - Read a GUI-tunable value into a local before a loop starts
    // - Then use that local inside the loop while the GUI can update the SSOT mid-run.
    //
    // Policy: In any function containing a loop, any `let <ident> = <ssot_read>` before the
    // first loop keyword is a violation IF `<ident>` is used after the loop begins.
    //
    // We support both patterns:
    // - getter layer (legacy): self.get_*(), ops_guard.get_*()
    // - direct SSOT reads (preferred): *self.<field>.lock().unwrap()
    let gui_fields = [
        "bump_check_enable",
        "z_up_step",
        "z_down_step",
        "tune_rest",
        "x_rest",
        "z_rest",
        "lap_rest",
        "adjustment_level",
        "retry_threshold",
        "delta_threshold",
        "z_variance_threshold",
        "x_start",
        "x_finish",
        "x_step",
        "z_min",
        "z_max",
        "max_bump_check_iterations",
    ];
    let loop_markers = ["loop {", "while ", "for "];

    fn contains_ident(hay: &str, ident: &str) -> bool {
        let bytes = hay.as_bytes();
        let ident_b = ident.as_bytes();
        if ident_b.is_empty() {
            return false;
        }
        let mut i = 0usize;
        while i + ident_b.len() <= bytes.len() {
            if &bytes[i..i + ident_b.len()] == ident_b {
                let prev_ok = i == 0
                    || !matches!(bytes[i - 1] as char, 'A'..='Z' | 'a'..='z' | '0'..='9' | '_');
                let next_i = i + ident_b.len();
                let next_ok = next_i == bytes.len()
                    || !matches!(bytes[next_i] as char, 'A'..='Z' | 'a'..='z' | '0'..='9' | '_');
                if prev_ok && next_ok {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn let_bound_ident(line: &str) -> Option<String> {
        let t = line.trim_start();
        if !t.starts_with("let ") {
            return None;
        }
        let t = &t["let ".len()..];
        let t = t.trim_start();
        let t = if t.starts_with("mut ") { &t["mut ".len()..] } else { t };
        let mut ident = String::new();
        for c in t.chars() {
            if c.is_ascii_alphanumeric() || c == '_' {
                ident.push(c);
            } else {
                break;
            }
        }
        if ident.is_empty() { None } else { Some(ident) }
    }

    fn is_gui_read_line(line: &str, gui_fields: &[&str]) -> bool {
        let gui_getters = [
            "get_bump_check_enable",
            "get_z_up_step",
            "get_z_down_step",
            "get_tune_rest",
            "get_x_rest",
            "get_z_rest",
            "get_lap_rest",
            "get_adjustment_level",
            "get_retry_threshold",
            "get_delta_threshold",
            "get_z_variance_threshold",
            "get_x_start",
            "get_x_finish",
            "get_x_step",
            "get_z_min",
            "get_z_max",
            "get_max_bump_check_iterations",
        ];
        if gui_getters.iter().any(|g| line.contains(g)) {
            return true;
        }
        // Direct field lock reads in Operations impl
        for f in gui_fields {
            if line.contains(&format!("self.{f}.lock")) || line.contains(&format!("ops_guard.{f}.lock")) {
                return true;
            }
        }
        false
    }

    for file in files {
        let Ok(content) = std::fs::read_to_string(&file) else {
            continue;
        };
        let rel_path = file
            .strip_prefix(scan_root)
            .unwrap_or(&file)
            .display()
            .to_string();

        // Find function boundaries by line starts (simple but effective for this repo).
        let lines: Vec<&str> = content.lines().collect();
        let mut fn_starts: Vec<usize> = vec![];
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim_start();
            if t.starts_with("fn ") || t.starts_with("pub fn ") {
                fn_starts.push(i);
            }
        }
        fn_starts.push(lines.len());

        for w in fn_starts.windows(2) {
            let start = w[0];
            let end = w[1];
            if start >= end || end > lines.len() {
                continue;
            }

            // Find the first loop keyword inside this function block.
            let mut first_loop: Option<usize> = None;
            for i in start..end {
                let t = lines[i].trim_start();
                if loop_markers.iter().any(|m| t.starts_with(m)) {
                    first_loop = Some(i);
                    break;
                }
            }
            let Some(loop_line) = first_loop else {
                continue; // no loop => no iteration caching issue
            };

            let rest = lines[loop_line..end].join("\n");

            // Flag any GUI/SSOT value cached before the first loop line AND used after loop start.
            for i in start..loop_line {
                let line = lines[i];
                if !line.contains("let ") || !line.contains(" = ") {
                    continue;
                }
                if !is_gui_read_line(line, &gui_fields) {
                    continue;
                }
                let Some(ident) = let_bound_ident(line) else {
                    continue;
                };
                if contains_ident(&rest, &ident) {
                    failures.push(format!(
                        "SSOT cache (gui) across loop: {rel_path}:{}: {line}",
                        i + 1
                    ));
                }
            }
        }
    }

    failures
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct LegacyManifest {
    algorithm: String,
    root: String,
    files: BTreeMap<String, String>,
}

fn run_update_legacy_manifest() {
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

    if !config.legacy.enabled {
        eprintln!("FATAL: legacy policy is not enabled in policy.toml ([legacy].enabled = true)");
        std::process::exit(1);
    }
    let Some(root) = &config.legacy.protected_root else {
        eprintln!("FATAL: legacy policy enabled but legacy.protected_root is not set");
        std::process::exit(1);
    };
    let Some(manifest_file) = &config.legacy.manifest_file else {
        eprintln!("FATAL: legacy policy enabled but legacy.manifest_file is not set");
        std::process::exit(1);
    };

    let root_dir = ctx.scan_root.join(root);
    if !root_dir.is_dir() {
        eprintln!("FATAL: legacy.protected_root does not exist or is not a directory: {}", root_dir.display());
        std::process::exit(1);
    }

    let files = build_legacy_file_hashes(&ctx.scan_root, root);
    let manifest = LegacyManifest {
        algorithm: "sha256".to_string(),
        root: root.to_string(),
        files,
    };

    let out_path = ctx.scan_root.join(manifest_file);
    let json = match serde_json::to_string_pretty(&manifest) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("FATAL: failed to serialize legacy manifest: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = fs::write(&out_path, format!("{json}\n")) {
        eprintln!("FATAL: failed to write legacy manifest {}: {e}", out_path.display());
        std::process::exit(1);
    }

    println!("legacy manifest updated: {}", out_path.display());
}

fn build_legacy_file_hashes(scan_root: &Path, protected_root: &str) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let mut stack = vec![scan_root.join(protected_root)];

    while let Some(dir) = stack.pop() {
        if let Some(name) = dir.file_name().and_then(|s| s.to_str()) {
            if name == "__pycache__" {
                continue;
            }
        }
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if !path.is_file() {
                continue;
            }
            let rel = match path.strip_prefix(scan_root) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let rel_s = rel.to_string_lossy().replace('\\', "/");
            if rel_s == protected_root.trim_end_matches('/') {
                continue;
            }

            let bytes = match fs::read(&path) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let digest = hasher.finalize();
            out.insert(rel_s, hex::encode(digest));
        }
    }

    out
}

fn check_legacy_manifest(config: &config::PolicyConfig, scan_root: &Path) -> Vec<String> {
    if !config.legacy.enabled {
        return vec![];
    }
    let Some(root) = &config.legacy.protected_root else {
        return vec!["Legacy policy enabled but legacy.protected_root is not set".to_string()];
    };
    let Some(manifest_file) = &config.legacy.manifest_file else {
        return vec!["Legacy policy enabled but legacy.manifest_file is not set".to_string()];
    };

    let manifest_path = scan_root.join(manifest_file);
    if !manifest_path.is_file() {
        return vec![format!(
            "Legacy policy: manifest file missing: {} (run: cargo run --manifest-path xtask-policy/Cargo.toml -- update-legacy-manifest)",
            manifest_path.display()
        )];
    }

    let raw = match fs::read_to_string(&manifest_path) {
        Ok(s) => s,
        Err(e) => {
            return vec![format!(
                "Legacy policy: failed to read manifest {}: {e}",
                manifest_path.display()
            )]
        }
    };
    let manifest: LegacyManifest = match serde_json::from_str(&raw) {
        Ok(m) => m,
        Err(e) => {
            return vec![format!(
                "Legacy policy: failed to parse manifest {}: {e}",
                manifest_path.display()
            )]
        }
    };

    if manifest.algorithm.to_lowercase() != "sha256" {
        return vec![format!(
            "Legacy policy: unsupported manifest algorithm '{}'; expected 'sha256'",
            manifest.algorithm
        )];
    }
    if manifest.root != *root {
        return vec![format!(
            "Legacy policy: manifest root '{}' does not match policy legacy.protected_root '{}'",
            manifest.root, root
        )];
    }

    let actual = build_legacy_file_hashes(scan_root, root);
    let expected = manifest.files;

    let actual_keys: BTreeSet<String> = actual.keys().cloned().collect();
    let expected_keys: BTreeSet<String> = expected.keys().cloned().collect();

    let mut failures = vec![];

    for missing in actual_keys.difference(&expected_keys) {
        failures.push(format!(
            "Legacy policy: legacy file added without permission (missing from manifest): {}",
            missing
        ));
    }
    for removed in expected_keys.difference(&actual_keys) {
        failures.push(format!(
            "Legacy policy: legacy file removed without permission (present in manifest but missing on disk): {}",
            removed
        ));
    }
    for (path, actual_hash) in &actual {
        if let Some(expected_hash) = expected.get(path) {
            if expected_hash != actual_hash {
                failures.push(format!(
                    "Legacy policy: legacy file modified without permission: {} (expected sha256={}, actual sha256={})",
                    path, expected_hash, actual_hash
                ));
            }
        }
    }

    failures
}

fn check_websocket_send_guard(config: &config::PolicyConfig, scan_root: &Path) -> Vec<String> {
    if !config.websocket.enabled {
        return vec![];
    }

    let mut failures = vec![];
    let mut stack = vec![scan_root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        if let Some(name) = dir.file_name().and_then(|s| s.to_str()) {
            if name == ".git"
                || name == ".venv"
                || name == "__pycache__"
                || name == "xtask-policy"
                || name == "docs"
                || name == "issue_reports"
                || name == "legacy"
            {
                continue;
            }
        }

        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if !path.is_file() {
                continue;
            }
            if path.extension().and_then(|s| s.to_str()) != Some("py") {
                continue;
            }

            let rel = match path.strip_prefix(scan_root) {
                Ok(p) => p,
                Err(_) => path.as_path(),
            };
            let rel_s = rel.to_string_lossy().replace('\\', "/");

            if config
                .websocket
                .allowed_prefixes
                .iter()
                .any(|p| rel_s.starts_with(p))
            {
                continue;
            }

            let content = match std::fs::read_to_string(&path) {
                Ok(s) => s,
                Err(_) => continue,
            };

            // Narrow heuristic:
            // - If a file has a long-running `while True:` loop sending via websocket.send_json(...)
            // - And it does not reference WebSocketDisconnect at all
            // then flag it as a likely "send after close" risk.
            let has_send = content.contains("websocket.send_json(");
            if !has_send {
                continue;
            }
            let has_while_true = content.contains("while True:") || content.contains("while True :");
            if !has_while_true {
                continue;
            }
            let has_disconnect_handling = content.contains("WebSocketDisconnect");
            if has_disconnect_handling {
                continue;
            }

            let send_line = content
                .lines()
                .enumerate()
                .find_map(|(i, line)| if line.contains("websocket.send_json(") { Some(i + 1) } else { None });
            let while_line = content
                .lines()
                .enumerate()
                .find_map(|(i, line)| if line.contains("while True") { Some(i + 1) } else { None });

            failures.push(format!(
                "WebSocket send loop must handle WebSocketDisconnect (send_json in while True): {} (while_line={:?}, send_line={:?})",
                rel_s, while_line, send_line
            ));
        }
    }

    failures
}

fn check_circle_center_regeneration_ssot(scan_root: &Path) -> Vec<String> {
    // Repo-specific SSOT invariant:
    // - app_state['circle_center'] is the stable alignment reference for circle execution.
    // - execution_state['initial_pose'] may be updated to the 0° start pose during execution.
    // - Therefore regenerate_circle_paths_if_needed() must NEVER assign to circle_center,
    //   or it will silently move the center and make subsequent executes fail the start gate.
    //
    // This is intentionally a targeted parser (not a regex policy) because forbidden_classes
    // are line-based ripgrep scans and cannot scope matches to a single function.
    let mut failures = vec![];

    let path = scan_root.join("server.py");
    let content = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return failures,
    };

    let mut in_regen = false;
    let mut regen_start_line: Option<usize> = None;

    for (i, raw_line) in content.lines().enumerate() {
        let line_no = i + 1;
        let line = raw_line.trim_end();

        if !in_regen && line.contains("async def regenerate_circle_paths_if_needed") {
            in_regen = true;
            regen_start_line = Some(line_no);
            continue;
        }

        if !in_regen {
            continue;
        }

        // Exit on the next top-level def/async def (column 0).
        if (line.starts_with("def ") || line.starts_with("async def "))
            && line_no != regen_start_line.unwrap_or(line_no)
        {
            in_regen = false;
        }

        if !in_regen {
            continue;
        }

        // Flag any assignment to circle_center inside this function.
        // Ignore reads like app_state.get('circle_center') and only block writes.
        let assigns_single = line.contains("app_state['circle_center']")
            && line.contains('=')
            && !line.contains(".get(");
        let assigns_double = line.contains("app_state[\"circle_center\"]")
            && line.contains('=')
            && !line.contains(".get(");
        if assigns_single || assigns_double {
            failures.push(format!(
                "SSOT policy: regenerate_circle_paths_if_needed must not assign app_state['circle_center']: server.py:{}",
                line_no
            ));
        }
    }

    failures
}

fn check_markdown_locations(config: &config::PolicyConfig, scan_root: &Path) -> Vec<String> {
    if !config.markdown.enabled {
        return vec![];
    }

    let Some(required_root) = &config.markdown.required_root else {
        return vec!["Markdown policy enabled but markdown.required_root is not set".to_string()];
    };

    let mut failures = vec![];
    let mut stack = vec![scan_root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        // Skip VCS/venv noise to keep the scan fast and deterministic.
        if let Some(name) = dir.file_name().and_then(|s| s.to_str()) {
            if name == ".git" || name == ".venv" || name == "__pycache__" {
                continue;
            }
        }

        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                failures.push(format!(
                    "Markdown policy: failed to read directory {}: {e}",
                    dir.display()
                ));
                continue;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    failures.push(format!("Markdown policy: read_dir entry error: {e}"));
                    continue;
                }
            };

            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }

            if !path.is_file() {
                continue;
            }

            let is_md = path
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("md"));
            if !is_md {
                continue;
            }

            let rel = match path.strip_prefix(scan_root) {
                Ok(p) => p,
                Err(_) => path.as_path(),
            };

            // Normalize to forward slashes for prefix matching.
            let rel_s = rel.to_string_lossy().replace('\\', "/");

            // Explicit file allowlist (exact relative path).
            if config
                .markdown
                .allowed_files
                .iter()
                .any(|f| f.as_str() == rel_s.as_str())
            {
                continue;
            }

            if rel_s.starts_with(required_root) {
                continue;
            }

            let mut allowed = false;
            for prefix in &config.markdown.allowed_prefixes {
                if rel_s.starts_with(prefix) {
                    allowed = true;
                    break;
                }
            }
            if allowed {
                continue;
            }

            failures.push(format!(
                "Markdown files must be under '{}': {}",
                required_root, rel_s
            ));
        }
    }

    failures
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

fn run_analyze(output_file: &str, db_url_arg: Option<&str>, no_db: bool) {
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
            println!("\nKey metrics:");
            println!("  Total violations: {}", plan.summary.total_violations);
            println!("  Files affected: {}", plan.summary.files_affected);
            if plan.summary.total_violations > 0 {
                println!(
                    "\n⚠️  Review {} for detailed recommendations",
                    output_path.display()
                );
            }
            println!("  Strategic outputs: included in the report (see \"Strategic Outputs\" section)");

            if no_db {
                return;
            }

            let resolved_db_url = match db_url_arg {
                Some(v) => v.to_string(),
                None => {
                    match std::env::var("XTASK_ANALYSIS_DB_URL") {
                        Ok(v) => {
                            if v.trim().is_empty() {
                                eprintln!("FATAL: XTASK_ANALYSIS_DB_URL is empty (required to log analyze runs). Use --no-db to skip logging explicitly.");
                                std::process::exit(1);
                            }
                            v
                        }
                        Err(_) => {
                            eprintln!("FATAL: XTASK_ANALYSIS_DB_URL not configured and --db-url not provided (required to log analyze runs). Use --no-db to skip logging explicitly.");
                            std::process::exit(1);
                        }
                    }
                }
            };

            if let Err(e) = log_analyze_to_db(
                &resolved_db_url,
                &ctx,
                output_file,
                &output_path,
                &plan,
                &plan_markdown,
            ) {
                eprintln!("FATAL: failed to log analyze run to DB: {e}");
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Failed to write cleanup plan: {e}");
            std::process::exit(1);
        }
    }
}

fn sha256_hex_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn sha256_hex_str(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}

fn log_analyze_to_db(
    db_url: &str,
    ctx: &config::RepoContext,
    output_arg: &str,
    output_path: &Path,
    plan: &analyze::CleanupPlan,
    plan_markdown: &str,
) -> Result<(), String> {
    let policy_sha256 = sha256_hex_file(&ctx.policy_path)?;
    let report_sha256 = sha256_hex_str(plan_markdown);

    let scan_root_str = ctx.scan_root.to_string_lossy().to_string();
    let policy_path_str = ctx.policy_path.to_string_lossy().to_string();
    let output_path_str = output_path.to_string_lossy().to_string();

    let hotspots = analyze::top_hotspots(plan, 5);
    let by_file = analyze::file_breakdown(plan);
    let mut hotspot_cols: Vec<Option<String>> = vec![];
    for h in &hotspots {
        hotspot_cols.push(Some(format!(
            "{}|total:{}|fail_fast:{}|blocking_locks:{}",
            h.file, h.total, h.fail_fast, h.blocking_locks
        )));
    }
    while hotspot_cols.len() < 5 {
        hotspot_cols.push(None);
    }

    let payload = serde_json::json!({
        "scan_root": scan_root_str,
        "policy_path": policy_path_str,
        "policy_sha256": policy_sha256,
        "output_arg": output_arg,
        "output_path": output_path_str,
        "output_sha256": report_sha256,
        "summary": {
            "total_violations": plan.summary.total_violations,
            "lock_violations": plan.summary.lock_violations,
            "spawn_violations": plan.summary.spawn_violations,
            "ssot_violations": plan.summary.ssot_violations,
            "ssot_leakage_violations": plan.summary.ssot_leakage_violations,
            "ssot_cache_violations": plan.summary.ssot_cache_violations,
            "ssot_cache_gui_violations": plan.summary.ssot_cache_gui_violations,
            "ssot_cache_non_gui_violations": plan.summary.ssot_cache_non_gui_violations,
            "fallback_violations": plan.summary.fallback_violations,
            "required_config_violations": plan.summary.required_config_violations,
            "sensitive_violations": plan.summary.sensitive_violations,
            "hardcode_violations": plan.summary.hardcode_violations,
            "style_violations": plan.summary.style_violations,
            "blocking_lock_violations": plan.summary.blocking_lock_violations,
            "files_affected": plan.summary.files_affected
        },
        "top_hotspots": hotspots,
        "by_file": by_file
    });

    let host = match std::env::var("HOSTNAME") {
        Ok(v) => v,
        Err(_) => "unknown".to_string(),
    };
    let xtask_version = env!("CARGO_PKG_VERSION").to_string();

    let mut client = Client::connect(db_url, NoTls).map_err(|e| format!("connect failed: {e}"))?;

    client
        .execute(
            r#"
INSERT INTO analysis (
  host,
  xtask_version,
  scan_root,
  policy_path,
  policy_sha256,
  output_arg,
  output_path,
  output_sha256,
  total_violations,
  lock_violations,
  spawn_violations,
  ssot_violations,
  fallback_violations,
  required_config_violations,
  sensitive_violations,
  hardcode_violations,
  style_violations,
  blocking_lock_violations,
  files_affected,
  hotspot_1,
  hotspot_2,
  hotspot_3,
  hotspot_4,
  hotspot_5,
  report_md,
  payload_json
)
VALUES (
  $1,$2,$3,$4,$5,$6,$7,$8,
  $9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,
  $20,$21,$22,$23,$24,
  $25,$26
)
"#,
            &[
                &host,
                &xtask_version,
                &scan_root_str,
                &policy_path_str,
                &policy_sha256,
                &output_arg,
                &output_path_str,
                &report_sha256,
                &(plan.summary.total_violations as i64),
                &(plan.summary.lock_violations as i64),
                &(plan.summary.spawn_violations as i64),
                &(plan.summary.ssot_violations as i64),
                &(plan.summary.fallback_violations as i64),
                &(plan.summary.required_config_violations as i64),
                &(plan.summary.sensitive_violations as i64),
                &(plan.summary.hardcode_violations as i64),
                &(plan.summary.style_violations as i64),
                &(plan.summary.blocking_lock_violations as i64),
                &(plan.summary.files_affected as i64),
                &hotspot_cols[0],
                &hotspot_cols[1],
                &hotspot_cols[2],
                &hotspot_cols[3],
                &hotspot_cols[4],
                &plan_markdown,
                &payload,
            ],
        )
        .map_err(|e| format!("insert failed: {e}"))?;

    println!("✅ Logged analyze run to DB table analysis");
    Ok(())
}

fn run_rg_policy_scoped(
    rule_name: &str,
    patterns: &[&str],
    allow_prefixes: &[&str],
    require_ripgrep: bool,
    rg_exclude_globs: &[String],
    rg_include_globs: &[&str],
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

        // Restrict scanning to code paths only (avoid docs/ and other non-runtime text).
        for g in rg_include_globs {
            args.push("--glob".to_string());
            args.push((*g).to_string());
        }

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
