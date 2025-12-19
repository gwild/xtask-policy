mod analyze;
mod config;

use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

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
        Commands::Analyze { output } => {
            run_analyze(&output);
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

    // 9) Forbidden patterns (mechanical bans: e.g., matplotlib, polling fallbacks, timeout loops)
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

    // 11) Legacy directory is write-protected by manifest (explicit user permission step)
    failures.extend(check_legacy_manifest(&config, &ctx.scan_root));

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
