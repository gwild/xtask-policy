use std::{collections::HashMap, path::Path, process::Command};

use crate::config::PolicyConfig;
use serde::Serialize;

struct ClassifyContext {
    env: HashMap<String, String>,
    presets_yaml: Option<serde_yaml::Value>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // Used in format_plan
pub struct Violation {
    pub rule: String,
    pub file: String,
    pub line: String,
    pub pattern: String,
    pub violation_type: ViolationType,
    pub category: Option<String>,
}

#[derive(Debug, Clone)]
pub enum ViolationType {
    Lock,
    Spawn,
    Ssot(String), // state type name
    FailFast(String),
    RequiredConfig,
    Sensitive(String),
    Style(String),
    BlockingLock(String),   // blocking lock in dangerous path (e.g., GUI thread)
    HardcodedSleep(String), // hardcoded thread::sleep in dangerous path - use config rest periods
    HardcodedLiteral(String), // hardcoded numeric literal - use config values
    NoCache,                // GUI/SSOT value cached before a loop iteration begins
}

#[derive(Debug)]
pub struct CleanupPlan {
    pub violations: Vec<Violation>,
    pub summary: PlanSummary,
    pub recommendations: Vec<Recommendation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HotspotEntry {
    pub file: String,
    pub total: usize,
    // Per-file breakdown for all key metrics, so plotting GUIs can share the same legend
    // between time-series and per-file stacked bars.
    pub lock_violations: usize,
    pub spawn_violations: usize,
    pub ssot_violations: usize,
    pub ssot_leakage_violations: usize,
    pub ssot_cache_violations: usize,
    pub fallback_violations: usize,
    pub required_config_violations: usize,
    pub sensitive_violations: usize,
    pub hardcoded_path_violations: usize,
    pub hardcoded_literal_violations: usize,
    pub hardcoded_sleep_violations: usize,
    pub style_violations: usize,
    pub blocking_lock_violations: usize,
    pub no_cache_violations: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileCountEntry {
    pub file: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubtypeBreakdownEntry {
    /// Broad class of violation (e.g., hardcoded_literal, sensitive, fail_fast).
    pub category: String,
    /// Subtype label (e.g., duration_millis_literal, abs_path_unix, unwrap_or).
    pub subtype: String,
    /// High-level kind (number/path/ip/secret/timing/etc.).
    pub kind: String,
    /// Count of violations of this subtype in this analysis run.
    pub count: usize,
    /// Top files where this subtype occurs.
    pub top_files: Vec<FileCountEntry>,
}

fn violation_kind(vt: &ViolationType) -> &'static str {
    match vt {
        ViolationType::HardcodedLiteral(_) => "number",
        ViolationType::HardcodedSleep(_) => "timing",
        ViolationType::Sensitive(name) => {
            if name.starts_with("abs_path_") {
                "path"
            } else if name == "ip_v4" {
                "ip"
            } else if name == "secret_literal" {
                "secret"
            } else {
                "sensitive"
            }
        }
        ViolationType::RequiredConfig => "config",
        ViolationType::Lock | ViolationType::Spawn | ViolationType::BlockingLock(_) => "concurrency",
        ViolationType::Ssot(_) | ViolationType::NoCache => "state",
        ViolationType::Style(_) => "style",
        ViolationType::FailFast(_) => "fail_fast",
    }
}

fn violation_category_and_subtype(vt: &ViolationType) -> (String, String) {
    match vt {
        ViolationType::Lock => ("lock".to_string(), "lock".to_string()),
        ViolationType::Spawn => ("spawn".to_string(), "spawn".to_string()),
        ViolationType::Ssot(name) => ("ssot".to_string(), name.clone()),
        ViolationType::FailFast(name) => ("fail_fast".to_string(), name.clone()),
        ViolationType::RequiredConfig => ("required_config".to_string(), "required_config".to_string()),
        ViolationType::Sensitive(name) => ("sensitive".to_string(), name.clone()),
        ViolationType::Style(name) => ("style".to_string(), name.clone()),
        ViolationType::BlockingLock(name) => ("blocking_lock".to_string(), name.clone()),
        ViolationType::HardcodedSleep(name) => ("hardcoded_sleep".to_string(), name.clone()),
        ViolationType::HardcodedLiteral(name) => ("hardcoded_literal".to_string(), name.clone()),
        ViolationType::NoCache => ("no_cache".to_string(), "no_cache".to_string()),
    }
}

pub fn violation_subtype_breakdown(plan: &CleanupPlan, top_files: usize) -> Vec<SubtypeBreakdownEntry> {
    let mut counts: HashMap<(String, String), usize> = HashMap::new();
    let mut by_subtype_file: HashMap<(String, String), HashMap<String, usize>> = HashMap::new();
    let mut meta: HashMap<(String, String), (String, String)> = HashMap::new(); // -> (kind, category)

    for v in &plan.violations {
        let (category, subtype) = violation_category_and_subtype(&v.violation_type);
        let key = (category.clone(), subtype.clone());
        *counts.entry(key.clone()).or_insert(0) += 1;
        meta.entry(key.clone())
            .or_insert_with(|| (violation_kind(&v.violation_type).to_string(), category));

        let per_file = by_subtype_file.entry(key).or_insert_with(HashMap::new);
        *per_file.entry(v.file.clone()).or_insert(0) += 1;
    }

    let mut entries: Vec<SubtypeBreakdownEntry> = Vec::new();
    for ((category, subtype), count) in counts {
        let (kind, _cat) = meta
            .get(&(category.clone(), subtype.clone()))
            .cloned()
            .unwrap_or_else(|| ("unknown".to_string(), category.clone()));
        let mut files: Vec<FileCountEntry> = by_subtype_file
            .get(&(category.clone(), subtype.clone()))
            .map(|m| {
                let mut v: Vec<FileCountEntry> = m
                    .iter()
                    .map(|(file, c)| FileCountEntry { file: file.clone(), count: *c })
                    .collect();
                v.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.file.cmp(&b.file)));
                v
            })
            .unwrap_or_else(Vec::new);
        if top_files > 0 && files.len() > top_files {
            files.truncate(top_files);
        }

        entries.push(SubtypeBreakdownEntry {
            category,
            subtype,
            kind,
            count,
            top_files: files,
        });
    }

    entries.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.category.cmp(&b.category)).then_with(|| a.subtype.cmp(&b.subtype)));
    entries
}

pub fn file_breakdown(plan: &CleanupPlan) -> Vec<HotspotEntry> {
    file_breakdown_internal(plan, None)
}

pub fn top_hotspots(plan: &CleanupPlan, n: usize) -> Vec<HotspotEntry> {
    file_breakdown_internal(plan, Some(n))
}

fn file_breakdown_internal(plan: &CleanupPlan, limit: Option<usize>) -> Vec<HotspotEntry> {
    if plan.violations.is_empty() {
        return vec![];
    }
    if let Some(n) = limit {
        if n == 0 {
            return vec![];
        }
    }

    let mut by_file_total: HashMap<&str, usize> = HashMap::new();
    let mut by_file_lock: HashMap<&str, usize> = HashMap::new();
    let mut by_file_spawn: HashMap<&str, usize> = HashMap::new();
    let mut by_file_ssot: HashMap<&str, usize> = HashMap::new();
    let mut by_file_ssot_leakage: HashMap<&str, usize> = HashMap::new();
    let mut by_file_ssot_cache: HashMap<&str, usize> = HashMap::new();
    let mut by_file_fallback: HashMap<&str, usize> = HashMap::new();
    let mut by_file_required_config: HashMap<&str, usize> = HashMap::new();
    let mut by_file_sensitive: HashMap<&str, usize> = HashMap::new();
    let mut by_file_hardcoded_path: HashMap<&str, usize> = HashMap::new();
    let mut by_file_hardcoded_literal: HashMap<&str, usize> = HashMap::new();
    let mut by_file_hardcoded_sleep: HashMap<&str, usize> = HashMap::new();
    let mut by_file_style: HashMap<&str, usize> = HashMap::new();
    let mut by_file_blocking_lock: HashMap<&str, usize> = HashMap::new();
    let mut by_file_no_cache: HashMap<&str, usize> = HashMap::new();

    for v in &plan.violations {
        *by_file_total.entry(v.file.as_str()).or_insert(0) += 1;
        match &v.violation_type {
            ViolationType::Lock => {
                *by_file_lock.entry(v.file.as_str()).or_insert(0) += 1;
            }
            ViolationType::Spawn => {
                *by_file_spawn.entry(v.file.as_str()).or_insert(0) += 1;
            }
            ViolationType::Ssot(_) => {
                *by_file_ssot.entry(v.file.as_str()).or_insert(0) += 1;
                *by_file_ssot_leakage.entry(v.file.as_str()).or_insert(0) += 1;
            }
            ViolationType::NoCache => {
                *by_file_ssot.entry(v.file.as_str()).or_insert(0) += 1;
                *by_file_ssot_cache.entry(v.file.as_str()).or_insert(0) += 1;
                *by_file_no_cache.entry(v.file.as_str()).or_insert(0) += 1;
            }
            ViolationType::FailFast(_) => {
                *by_file_fallback.entry(v.file.as_str()).or_insert(0) += 1;
            }
            ViolationType::RequiredConfig => {
                *by_file_required_config.entry(v.file.as_str()).or_insert(0) += 1;
            }
            ViolationType::Sensitive(name) => {
                *by_file_sensitive.entry(v.file.as_str()).or_insert(0) += 1;
                if name.starts_with("abs_path_") {
                    *by_file_hardcoded_path.entry(v.file.as_str()).or_insert(0) += 1;
                }
            }
            ViolationType::HardcodedLiteral(_) => {
                *by_file_hardcoded_literal.entry(v.file.as_str()).or_insert(0) += 1;
            }
            ViolationType::HardcodedSleep(_) => {
                *by_file_blocking_lock.entry(v.file.as_str()).or_insert(0) += 1;
                *by_file_hardcoded_sleep.entry(v.file.as_str()).or_insert(0) += 1;
            }
            ViolationType::Style(_) => {
                *by_file_style.entry(v.file.as_str()).or_insert(0) += 1;
            }
            ViolationType::BlockingLock(_) => {
                *by_file_blocking_lock.entry(v.file.as_str()).or_insert(0) += 1;
            }
        }
    }

    let mut files_sorted: Vec<(&str, usize)> = by_file_total
        .iter()
        .map(|(k, v)| (*k, *v))
        .collect();
    files_sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));

    let mut out: Vec<HotspotEntry> = vec![];
    let iter: Box<dyn Iterator<Item = (&str, usize)>> = match limit {
        Some(n) => Box::new(files_sorted.into_iter().take(n)),
        None => Box::new(files_sorted.into_iter()),
    };
    for (file, total) in iter {
        let lock_violations = by_file_lock.get(file).copied().unwrap_or(0);
        let spawn_violations = by_file_spawn.get(file).copied().unwrap_or(0);
        let ssot_violations = by_file_ssot.get(file).copied().unwrap_or(0);
        let ssot_leakage_violations = by_file_ssot_leakage.get(file).copied().unwrap_or(0);
        let ssot_cache_violations = by_file_ssot_cache.get(file).copied().unwrap_or(0);
        let fallback_violations = by_file_fallback.get(file).copied().unwrap_or(0);
        let required_config_violations = by_file_required_config.get(file).copied().unwrap_or(0);
        let sensitive_violations = by_file_sensitive.get(file).copied().unwrap_or(0);
        let hardcoded_path_violations = by_file_hardcoded_path.get(file).copied().unwrap_or(0);
        let hardcoded_literal_violations = by_file_hardcoded_literal.get(file).copied().unwrap_or(0);
        let hardcoded_sleep_violations = by_file_hardcoded_sleep.get(file).copied().unwrap_or(0);
        let style_violations = by_file_style.get(file).copied().unwrap_or(0);
        let blocking_lock_violations = by_file_blocking_lock.get(file).copied().unwrap_or(0);
        let no_cache_violations = by_file_no_cache.get(file).copied().unwrap_or(0);
        out.push(HotspotEntry {
            file: file.to_string(),
            total,
            lock_violations,
            spawn_violations,
            ssot_violations,
            ssot_leakage_violations,
            ssot_cache_violations,
            fallback_violations,
            required_config_violations,
            sensitive_violations,
            hardcoded_path_violations,
            hardcoded_literal_violations,
            hardcoded_sleep_violations,
            style_violations,
            blocking_lock_violations,
            no_cache_violations,
        });
    }
    out
}

#[derive(Debug)]
pub struct PlanSummary {
    pub total_violations: usize,
    pub lock_violations: usize,
    pub spawn_violations: usize,
    // SSOT violations include:
    // - leakage: SSOT owner types referenced outside allowlist (ViolationType::Ssot)
    // - caching: GUI/SSOT values cached before loops (ViolationType::NoCache)
    pub ssot_violations: usize,
    pub ssot_leakage_violations: usize,
    pub ssot_cache_violations: usize,
    pub ssot_cache_gui_violations: usize,
    pub ssot_cache_non_gui_violations: usize,
    pub fallback_violations: usize,
    pub required_config_violations: usize,
    pub sensitive_violations: usize,
    pub hardcoded_path_violations: usize,
    pub hardcoded_literal_violations: usize,
    pub hardcoded_sleep_violations: usize,
    pub style_violations: usize,
    pub blocking_lock_violations: usize,
    pub no_cache_violations: usize,
    pub files_affected: usize,
}

#[derive(Debug, Clone)]
pub struct Recommendation {
    pub priority: Priority,
    pub action: String,
    pub reason: String,
    pub files: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)] // Medium may be used in future
pub enum Priority {
    High,   // Blocks deployment
    Medium, // Should fix soon
    Low,    // Nice to have
}

pub fn analyze_repo(config: &PolicyConfig, scan_root: &Path) -> Result<CleanupPlan, String> {
    let mut violations = Vec::new();
    let classify_ctx = build_classify_context(scan_root);

    // Scan for locks
    for pattern in &config.patterns.lock_patterns {
        let found = scan_pattern(
            pattern,
            &config.allowlists.lock_allowed,
            &config.options.rg_exclude_globs,
            scan_root,
        )?;
        for (file, line) in found {
            violations.push(Violation {
                rule: "Locks outside allowlist".to_string(),
                file: file.clone(),
                line,
                pattern: pattern.clone(),
                violation_type: ViolationType::Lock,
                category: None,
            });
        }
    }

    // Scan for spawning
    for pattern in &config.patterns.spawn_patterns {
        let found = scan_pattern(
            pattern,
            &config.allowlists.spawn_allowed,
            &config.options.rg_exclude_globs,
            scan_root,
        )?;
        for (file, line) in found {
            violations.push(Violation {
                rule: "Spawning outside allowlist".to_string(),
                file: file.clone(),
                line,
                pattern: pattern.clone(),
                violation_type: ViolationType::Spawn,
                category: None,
            });
        }
    }

    // Scan for SSOT violations
    for ssot_type in &config.patterns.ssot_types {
        let pattern = format!(r"\b{}\b", ssot_type);
        let found = scan_pattern(
            &pattern,
            &config.allowlists.ssot_allowed,
            &config.options.rg_exclude_globs,
            scan_root,
        )?;
        for (file, line) in found {
            violations.push(Violation {
                rule: format!("{} referenced outside owner module", ssot_type),
                file: file.clone(),
                line,
                pattern: pattern.clone(),
                violation_type: ViolationType::Ssot(ssot_type.clone()),
                category: None,
            });
        }
    }

    // Scan for fail-fast violations (classified if configured)
    if !config.patterns.fallback_classes.is_empty() {
        for class in &config.patterns.fallback_classes {
            let allow = if !class.allowed.is_empty() {
                &class.allowed
            } else {
                &config.allowlists.fallbacks_allowed
            };
            for pattern in &class.patterns {
                let found = scan_pattern(pattern, allow, &config.options.rg_exclude_globs, scan_root)?;
                for (file, line) in found {
                    let category = classify_fail_fast_violation(&classify_ctx, scan_root, &file, &line);
                    violations.push(Violation {
                        rule: format!("Fail-fast violations ({}) outside allowlist", class.name),
                        file: file.clone(),
                        line,
                        pattern: pattern.clone(),
                        violation_type: ViolationType::FailFast(class.name.clone()),
                        category: Some(category.to_string()),
                    });
                }
            }
        }
    } else {
        for pattern in &config.patterns.fallback_patterns {
            let found = scan_pattern(
                pattern,
                &config.allowlists.fallbacks_allowed,
                &config.options.rg_exclude_globs,
                scan_root,
            )?;
            for (file, line) in found {
                let category = classify_fail_fast_violation(&classify_ctx, scan_root, &file, &line);
                violations.push(Violation {
                    rule: "Fail-fast violations outside allowlist".to_string(),
                    file: file.clone(),
                    line,
                    pattern: pattern.clone(),
                    violation_type: ViolationType::FailFast("uncategorized".to_string()),
                    category: Some(category.to_string()),
                });
            }
        }
    }

    // Check required config (env/yaml) presence
    for v in required_config_violations(config, scan_root) {
        violations.push(v);
    }

    // Scan for sensitive literals (IPs, secrets, absolute paths)
    for class in &config.patterns.sensitive_classes {
        let allow = if !class.allowed.is_empty() {
            &class.allowed
        } else {
            &config.allowlists.sensitive_allowed
        };
        for pattern in &class.patterns {
            let found = scan_pattern(pattern, allow, &config.options.rg_exclude_globs, scan_root)?;
            for (file, line) in found {
                violations.push(Violation {
                    rule: format!("Sensitive literals ({}) outside allowlist", class.name),
                    file: file.clone(),
                    line,
                    pattern: pattern.clone(),
                    violation_type: ViolationType::Sensitive(class.name.clone()),
                    category: None,
                });
            }
        }
    }

    // Scan for hardcoded numeric preview limits (magic numbers)
    for class in &config.patterns.hardcode_classes {
        let allow = if !class.allowed.is_empty() {
            &class.allowed
        } else {
            &config.allowlists.hardcode_allowed
        };
        for pattern in &class.patterns {
            let found = scan_pattern(pattern, allow, &config.options.rg_exclude_globs, scan_root)?;
            for (file, line) in found {
                violations.push(Violation {
                    rule: format!("Hardcoded preview limits ({}) outside allowlist", class.name),
                    file: file.clone(),
                    line,
                    pattern: pattern.clone(),
                    violation_type: ViolationType::HardcodedLiteral(class.name.clone()),
                    category: None,
                });
            }
        }
    }

    // Scan for style violations (e.g., plain channel labels)
    for class in &config.patterns.style_classes {
        let allow = if !class.allowed.is_empty() {
            &class.allowed
        } else {
            &config.allowlists.style_allowed
        };
        for pattern in &class.patterns {
            let found = scan_pattern(pattern, allow, &config.options.rg_exclude_globs, scan_root)?;
            for (file, line) in found {
                violations.push(Violation {
                    rule: format!("Style violations ({}) outside allowlist", class.name),
                    file: file.clone(),
                    line,
                    pattern: pattern.clone(),
                    violation_type: ViolationType::Style(class.name.clone()),
                    category: None,
                });
            }
        }
    }

    // Scan for blocking lock patterns in dangerous paths (e.g., GUI code)
    // These are .lock() calls that could block the main thread and freeze the UI
    for class in &config.patterns.blocking_lock_classes {
        let allow = if !class.allowed.is_empty() {
            &class.allowed
        } else {
            &config.allowlists.blocking_lock_allowed
        };
        for pattern in &class.patterns {
            let found = scan_pattern(pattern, allow, &config.options.rg_exclude_globs, scan_root)?;
            for (file, line) in found {
                // Only flag if the file is in a dangerous path (e.g., gui/)
                let is_dangerous = class.dangerous_paths.is_empty() 
                    || class.dangerous_paths.iter().any(|p| file.contains(p));
                if is_dangerous {
                    // Additional context check: is this in a spawned thread or main thread?
                    let category = classify_blocking_lock(&classify_ctx, scan_root, &file, &line);
                    // Policy: we only treat blocking locks as violations when they can block UI paths.
                    // A blocking lock inside a spawned worker thread is not a GUI-freeze risk by itself
                    // (and is often required for executor serialization).
                    if category == "spawned_thread" || category == "logger_thread" {
                        continue;
                    }
                    violations.push(Violation {
                        rule: format!("Blocking lock ({}) in GUI/main thread path", class.name),
                        file: file.clone(),
                        line,
                        pattern: pattern.clone(),
                        violation_type: ViolationType::BlockingLock(class.name.clone()),
                        category: Some(category.to_string()),
                    });
                }
            }
        }
    }

    // Scan for hardcoded sleep patterns in dangerous paths (e.g., GUI/IPC code)
    // These are thread::sleep() calls with hardcoded durations that violate event-driven architecture
    for class in &config.patterns.hardcoded_sleep_classes {
        let allow = if !class.allowed.is_empty() {
            &class.allowed
        } else {
            &Vec::new() // No global allowlist for sleeps
        };
        for pattern in &class.patterns {
            let found = scan_pattern(pattern, allow, &config.options.rg_exclude_globs, scan_root)?;
            for (file, line) in found {
                // Only flag if the file is in a dangerous path (e.g., gui/)
                let is_dangerous = class.dangerous_paths.is_empty() 
                    || class.dangerous_paths.iter().any(|p| file.contains(p));
                if is_dangerous {
                    violations.push(Violation {
                        rule: format!("Hardcoded sleep ({}) - use configured rest periods", class.name),
                        file: file.clone(),
                        line,
                        pattern: pattern.clone(),
                        violation_type: ViolationType::HardcodedSleep(class.name.clone()),
                        category: None,
                    });
                }
            }
        }
    }

    // Scan for hardcoded literal patterns (magic numbers that should come from config)
    for class in &config.patterns.hardcoded_literal_classes {
        let allow = if !class.allowed.is_empty() {
            &class.allowed
        } else {
            &Vec::new()
        };
        for pattern in &class.patterns {
            let found = scan_pattern(pattern, allow, &config.options.rg_exclude_globs, scan_root)?;
            for (file, line) in found {
                violations.push(Violation {
                    rule: format!("Hardcoded literal ({}) - use config values", class.name),
                    file: file.clone(),
                    line,
                    pattern: pattern.clone(),
                    violation_type: ViolationType::HardcodedLiteral(class.name.clone()),
                    category: None,
                });
            }
        }
    }

    // Scan for "NO CACHE before loop" (GUI-tunable SSOT values cached before iteration begins)
    // NOTE: This is not a regex class; it's a code-level policy check (same bug class as cached x_step).
    violations.extend(no_cache_before_loop_violations(scan_root, &config.allowlists.ssot_cache_allowed));

    // Generate summary
    let lock_violations = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::Lock))
        .count();
    let spawn_violations = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::Spawn))
        .count();
    let ssot_leakage_violations = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::Ssot(_)))
        .count();
    let fail_fast_violations = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::FailFast(_)))
        .count();
    let required_config_violations = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::RequiredConfig))
        .count();
    let sensitive_violations = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::Sensitive(_)))
        .count();
    let hardcoded_path_violations = violations
        .iter()
        .filter(|v| matches!(&v.violation_type, ViolationType::Sensitive(name) if name.starts_with("abs_path_")))
        .count();
    let hardcoded_literal_violations = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::HardcodedLiteral(_)))
        .count();
    let style_violations = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::Style(_)))
        .count();
    let blocking_lock_violations = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::BlockingLock(_)))
        .count();
    let hardcoded_sleep_violations = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::HardcodedSleep(_)))
        .count();
    let ssot_cache_violations = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::NoCache))
        .count();
    let ssot_cache_gui_violations = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::NoCache))
        .filter(|v| v.category.as_deref() == Some("gui"))
        .count();
    let ssot_cache_non_gui_violations = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::NoCache))
        .filter(|v| v.category.as_deref() == Some("non_gui"))
        .count();

    let ssot_violations = ssot_leakage_violations + ssot_cache_violations;

    let mut files_affected = std::collections::HashSet::new();
    for v in &violations {
        files_affected.insert(v.file.clone());
    }

    let summary = PlanSummary {
        total_violations: violations.len(),
        lock_violations,
        spawn_violations,
        ssot_violations,
        ssot_leakage_violations,
        ssot_cache_violations,
        ssot_cache_gui_violations,
        ssot_cache_non_gui_violations,
        fallback_violations: fail_fast_violations,
        required_config_violations,
        sensitive_violations,
        hardcoded_path_violations,
        hardcoded_literal_violations,
        hardcoded_sleep_violations,
        style_violations,
        blocking_lock_violations,
        no_cache_violations: ssot_cache_violations,
        files_affected: files_affected.len(),
    };

    // Generate recommendations
    let recommendations = generate_recommendations(&violations, config);

    Ok(CleanupPlan {
        violations,
        summary,
        recommendations,
    })
}

fn scan_pattern(
    pattern: &str,
    allowlist: &[String],
    rg_exclude_globs: &[String],
    scan_root: &Path,
) -> Result<Vec<(String, String)>, String> {
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

    args.push(pattern.to_string());
    args.push(".".to_string());

    let rg = Command::new("rg")
        .args(&args)
        .current_dir(scan_root)
        .output();

    let Ok(rg) = rg else {
        // ripgrep not available - return empty (will be handled by main check)
        return Ok(vec![]);
    };

    if !rg.status.success() && rg.stdout.is_empty() {
        return Ok(vec![]);
    }

    let stdout = String::from_utf8_lossy(&rg.stdout);
    let mut results = Vec::new();

    for line in stdout.lines() {
        // line format: path:line:match...
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() < 2 {
            continue;
        }
        let file = parts[0];
        let line_num = parts[1];

        if !is_allowed(file, allowlist) {
            results.push((file.to_string(), line_num.to_string()));
        }
    }

    Ok(results)
}

fn no_cache_before_loop_violations(scan_root: &Path, ssot_cache_allowed: &[String]) -> Vec<Violation> {
    // This is the same bug class as cached x_step: GUI-tunable values read once into locals,
    // then used inside a loop while the GUI can update them mid-run.
    //
    // Policy: in any function containing a loop, any `let <ident> = <ssot_read>` before the first
    // loop keyword is a violation IF `<ident>` is used after the loop begins.
    //
    // Files matching ssot_cache_allowed are skipped (intentional immediate-mode GUI reads).

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

    let mut files: Vec<std::path::PathBuf> = vec![];
    walk_rs_files(&scan_root.join("src"), &mut files);

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

    fn is_gui_read_line(line: &str, gui_fields: &[&str]) -> Option<String> {
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
            return Some("gui".to_string());
        }
        for f in gui_fields {
            if line.contains(&format!("self.{f}.lock")) || line.contains(&format!("ops_guard.{f}.lock")) {
                return Some("gui".to_string());
            }
        }
        None
    }

    let mut out: Vec<Violation> = vec![];
    for file in files {
        let Ok(content) = std::fs::read_to_string(&file) else {
            continue;
        };
        let rel_path = file
            .strip_prefix(scan_root)
            .unwrap_or(&file)
            .display()
            .to_string();

        // Skip files in the ssot_cache_allowed list (intentional immediate-mode GUI reads)
        if ssot_cache_allowed.iter().any(|allowed| rel_path.contains(allowed)) {
            continue;
        }

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

            let mut first_loop: Option<usize> = None;
            for i in start..end {
                let t = lines[i].trim_start();
                if loop_markers.iter().any(|m| t.starts_with(m)) {
                    first_loop = Some(i);
                    break;
                }
            }
            let Some(loop_line) = first_loop else {
                continue;
            };

            let rest = lines[loop_line..end].join("\n");
            for i in start..loop_line {
                let line = lines[i];
                if !line.contains("let ") || !line.contains(" = ") {
                    continue;
                }
                let Some(category) = is_gui_read_line(line, &gui_fields) else {
                    continue;
                };
                let Some(ident) = let_bound_ident(line) else {
                    continue;
                };
                if contains_ident(&rest, &ident) {
                    out.push(Violation {
                        rule: "NO CACHE before loop".to_string(),
                        file: rel_path.clone(),
                        line: format!("{}: {line}", i + 1),
                        pattern: "let <ident> = <ssot_read> before first loop, used after loop begins".to_string(),
                        violation_type: ViolationType::NoCache,
                        category: Some(category),
                    });
                }
            }
        }
    }

    out
}

fn is_allowed(path: &str, allow_prefixes: &[String]) -> bool {
    let p = Path::new(path);
    let s = p.to_string_lossy();
    allow_prefixes.iter().any(|prefix| s.contains(prefix))
}

fn generate_recommendations(
    violations: &[Violation],
    config: &PolicyConfig,
) -> Vec<Recommendation> {
    let mut recommendations = Vec::new();

    // Group violations by file
    let mut by_file: HashMap<String, Vec<&Violation>> = HashMap::new();
    for v in violations {
        by_file.entry(v.file.clone()).or_default().push(v);
    }

    // Analyze lock violations
    let lock_files: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::Lock))
        .map(|v| v.file.clone())
        .collect();

    if !lock_files.is_empty() {
        let unique_files: Vec<String> = lock_files
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        recommendations.push(Recommendation {
            priority: Priority::High,
            action: "Move locks to allowed paths or add paths to allowlist in policy.toml"
                .to_string(),
            reason: format!(
                "Found {} lock violations in {} file(s). Locks should only be in: {}",
                violations
                    .iter()
                    .filter(|v| matches!(v.violation_type, ViolationType::Lock))
                    .count(),
                unique_files.len(),
                config.allowlists.lock_allowed.join(", ")
            ),
            files: unique_files,
        });
    }

    // Analyze spawn violations
    let spawn_files: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::Spawn))
        .map(|v| v.file.clone())
        .collect();

    if !spawn_files.is_empty() {
        let unique_files: Vec<String> = spawn_files
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        recommendations.push(Recommendation {
            priority: Priority::High,
            action: "Move thread/task spawning to allowed paths or add paths to allowlist"
                .to_string(),
            reason: format!(
                "Found {} spawn violations in {} file(s). Spawning should only be in: {}",
                violations
                    .iter()
                    .filter(|v| matches!(v.violation_type, ViolationType::Spawn))
                    .count(),
                unique_files.len(),
                config.allowlists.spawn_allowed.join(", ")
            ),
            files: unique_files,
        });
    }

    // Analyze SSOT violations
    let mut ssot_by_type: HashMap<String, Vec<String>> = HashMap::new();
    for v in violations {
        if let ViolationType::Ssot(ref state_type) = v.violation_type {
            ssot_by_type
                .entry(state_type.clone())
                .or_default()
                .push(v.file.clone());
        }
    }

    for (state_type, files) in ssot_by_type {
        let unique_files: Vec<String> = files
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        recommendations.push(Recommendation {
            priority: Priority::High,
            action: format!(
                "Remove direct references to {} or add files to allowlist",
                state_type
            ),
            reason: format!(
                "Found {} references to {} outside owner module. Allowed paths: {}",
                unique_files.len(),
                state_type,
                config.allowlists.ssot_allowed.join(", ")
            ),
            files: unique_files,
        });
    }

    // Analyze fail-fast violations
    let fail_fast_files: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::FailFast(_)))
        .map(|v| v.file.clone())
        .collect();
    if !fail_fast_files.is_empty() {
        let unique_files: Vec<String> = fail_fast_files
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        recommendations.push(Recommendation {
            priority: Priority::High,
            action: "Remove unwrap_or/or_else/get_or_insert patterns or add narrow allowlist entries".to_string(),
            reason: format!(
                "Found {} fail-fast violations in {} file(s). Prefer fail-fast; use allowlists only for explicit exceptions.",
                violations
                    .iter()
                    .filter(|v| matches!(v.violation_type, ViolationType::FailFast(_)))
                    .count(),
                unique_files.len(),
            ),
            files: unique_files,
        });
    }

    // Analyze required-config violations
    let required_files: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::RequiredConfig))
        .map(|v| v.file.clone())
        .collect();
    if !required_files.is_empty() {
        let unique_files: Vec<String> = required_files
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        recommendations.push(Recommendation {
            priority: Priority::High,
            action: "Fill required values in .env / YAML files (no silent defaults)"
                .to_string(),
            reason: format!(
                "Found {} required-config violations. Add missing values to configuration files rather than relying on defaults.",
                violations
                    .iter()
                    .filter(|v| matches!(v.violation_type, ViolationType::RequiredConfig))
                    .count(),
            ),
            files: unique_files,
        });
    }

    // Analyze hardcode violations
    let hardcode_files: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::HardcodedLiteral(_)))
        .map(|v| v.file.clone())
        .collect();
    if !hardcode_files.is_empty() {
        let unique_files: Vec<String> = hardcode_files
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        recommendations.push(Recommendation {
            priority: Priority::High,
            action: "Remove hardcoded numeric preview limits (magic numbers) or add narrow allowlist entries"
                .to_string(),
            reason: format!(
                "Found {} hardcode violations in {} file(s). Prefer config/state-driven values rather than silent UI constraints.",
                violations
                    .iter()
                    .filter(|v| matches!(v.violation_type, ViolationType::HardcodedLiteral(_)))
                    .count(),
                unique_files.len(),
            ),
            files: unique_files,
        });
    }

    // Analyze style violations
    let style_files: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::Style(_)))
        .map(|v| v.file.clone())
        .collect();
    if !style_files.is_empty() {
        let unique_files: Vec<String> = style_files
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        recommendations.push(Recommendation {
            priority: Priority::High,
            action: "Fix channel label style violations (use standard colored RichText scheme) or add narrow allowlist entries"
                .to_string(),
            reason: format!(
                "Found {} style violations in {} file(s). Keep channel labels consistent and colored.",
                violations
                    .iter()
                    .filter(|v| matches!(v.violation_type, ViolationType::Style(_)))
                    .count(),
                unique_files.len(),
            ),
            files: unique_files,
        });
    }

    // Analyze blocking lock violations
    let blocking_files: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::BlockingLock(_)))
        .map(|v| v.file.clone())
        .collect();
    if !blocking_files.is_empty() {
        let unique_files: Vec<String> = blocking_files
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        recommendations.push(Recommendation {
            priority: Priority::High,
            action: "Replace blocking .lock() with .try_lock() in GUI/main thread paths, or move to spawned thread"
                .to_string(),
            reason: format!(
                "Found {} blocking lock calls in {} file(s). Blocking locks in GUI code can freeze the UI for extended periods. Use try_lock() for non-blocking acquisition or ensure the lock is only acquired in background threads.",
                violations
                    .iter()
                    .filter(|v| matches!(v.violation_type, ViolationType::BlockingLock(_)))
                    .count(),
                unique_files.len(),
            ),
            files: unique_files,
        });
    }

    // Add general recommendation about allowlist adjustment
    if !violations.is_empty() {
        recommendations.push(Recommendation {
            priority: Priority::Low,
            action: "Consider adjusting allowlists in policy.toml if violations are intentional"
                .to_string(),
            reason: "Some violations might be acceptable. Review and update policy.toml allowlists if needed.".to_string(),
            files: vec![],
        });
    }

    recommendations.sort_by_key(|r| r.priority.clone());
    recommendations
}

pub fn format_plan(plan: &CleanupPlan) -> String {
    let mut output = String::new();

    fn classify_kind(vt: &ViolationType) -> &'static str {
        match vt {
            ViolationType::HardcodedLiteral(_) => "number",
            ViolationType::HardcodedSleep(_) => "timing",
            ViolationType::Sensitive(name) => {
                if name.starts_with("abs_path_") {
                    "path"
                } else if name == "ip_v4" {
                    "ip"
                } else if name == "secret_literal" {
                    "secret"
                } else {
                    "sensitive"
                }
            }
            ViolationType::RequiredConfig => "config",
            ViolationType::Lock | ViolationType::Spawn | ViolationType::BlockingLock(_) => "concurrency",
            ViolationType::Ssot(_) | ViolationType::NoCache => "state",
            ViolationType::Style(_) => "style",
            ViolationType::FailFast(_) => "fail-fast",
        }
    }

    output.push_str("# Cleanup Plan\n\n");
    output.push_str("## Key Metrics\n\n");
    output.push_str(&format!(
        "- **Total Violations**: {}\n",
        plan.summary.total_violations
    ));
    output.push_str(&format!(
        "- **Lock Violations**: {}\n",
        plan.summary.lock_violations
    ));
    output.push_str(&format!(
        "- **Spawn Violations**: {}\n",
        plan.summary.spawn_violations
    ));
    output.push_str(&format!(
        "- **SSOT Violations**: {}\n",
        plan.summary.ssot_violations
    ));
    output.push_str(&format!(
        "  - **SSOT leakage**: {}\n",
        plan.summary.ssot_leakage_violations
    ));
    output.push_str(&format!(
        "  - **SSOT cache**: {} (gui: {}, non-gui: {})\n",
        plan.summary.ssot_cache_violations,
        plan.summary.ssot_cache_gui_violations,
        plan.summary.ssot_cache_non_gui_violations
    ));
    output.push_str(&format!(
        "- **Fallback Violations**: {}\n",
        plan.summary.fallback_violations
    ));
    output.push_str(&format!(
        "- **Required Config Violations**: {}\n",
        plan.summary.required_config_violations
    ));
    output.push_str(&format!(
        "- **Sensitive Literal Violations**: {}\n",
        plan.summary.sensitive_violations
    ));
    output.push_str(&format!(
        "  - **Hardcoded Path Violations**: {}\n",
        plan.summary.hardcoded_path_violations
    ));
    output.push_str(&format!(
        "  - **Hardcoded Literals**: {}\n",
        plan.summary.hardcoded_literal_violations
    ));
    output.push_str(&format!(
        "  - **Hardcoded Sleeps**: {}\n",
        plan.summary.hardcoded_sleep_violations
    ));
    output.push_str(&format!(
        "- **Style Violations**: {}\n",
        plan.summary.style_violations
    ));
    output.push_str(&format!(
        "- **Blocking Lock Violations**: {}\n",
        plan.summary.blocking_lock_violations
    ));
    output.push_str(&format!(
        "- **Files Affected**: {}\n\n",
        plan.summary.files_affected
    ));

    // Subtype breakdowns (helps distinguish number vs path vs other literal classes)
    let mut sensitive_by_subtype: HashMap<String, usize> = HashMap::new();
    let mut hardcoded_literal_by_subtype: HashMap<String, usize> = HashMap::new();
    let mut hardcode_by_subtype: HashMap<String, usize> = HashMap::new();
    for v in &plan.violations {
        match &v.violation_type {
            ViolationType::Sensitive(name) => {
                *sensitive_by_subtype.entry(name.clone()).or_insert(0) += 1;
            }
            ViolationType::HardcodedLiteral(name) => {
                *hardcoded_literal_by_subtype.entry(name.clone()).or_insert(0) += 1;
            }
            _ => {}
        }
    }
    if !sensitive_by_subtype.is_empty()
        || !hardcoded_literal_by_subtype.is_empty()
        || !hardcode_by_subtype.is_empty()
    {
        output.push_str("## Literal/Hardcode Classification\n\n");
        if !sensitive_by_subtype.is_empty() {
            output.push_str("### Sensitive literal subtypes\n\n");
            let mut pairs: Vec<(String, usize)> = sensitive_by_subtype.into_iter().collect();
            pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            for (name, count) in pairs {
                output.push_str(&format!("- **{}** (kind: {}): {}\n", name, classify_kind(&ViolationType::Sensitive(name.clone())), count));
            }
            output.push('\n');
        }
        if !hardcode_by_subtype.is_empty() {
            output.push_str("### Hardcode subtypes\n\n");
            let mut pairs: Vec<(String, usize)> = hardcode_by_subtype.into_iter().collect();
            pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            for (name, count) in pairs {
                output.push_str(&format!("- **{}** (kind: number): {}\n", name, count));
            }
            output.push('\n');
        }
        if !hardcoded_literal_by_subtype.is_empty() {
            output.push_str("### Hardcoded literal subtypes\n\n");
            let mut pairs: Vec<(String, usize)> = hardcoded_literal_by_subtype.into_iter().collect();
            pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            for (name, count) in pairs {
                output.push_str(&format!("- **{}** (kind: number): {}\n", name, count));
            }
            output.push('\n');
        }
    }

    // Executive Summary with tables
    output.push_str("## 📊 Executive View\n\n");
    output.push_str("### Overall Health\n\n");
    output.push_str("| Metric | Count | Status |\n");
    output.push_str("|--------|-------|--------|\n");
    let status = if plan.summary.total_violations == 0 {
        "🟢"
    } else if plan.summary.total_violations < 50 {
        "🟡"
    } else {
        "⚠️"
    };
    output.push_str(&format!(
        "| **Total Violations** | {} | {} |\n",
        plan.summary.total_violations, status
    ));
    output.push_str(&format!(
        "| Files Affected | {} | |\n\n",
        plan.summary.files_affected
    ));

    output.push_str("### Violation Breakdown\n\n");
    output.push_str("| Category | Count | Severity |\n");
    output.push_str("|----------|-------|----------|\n");
    if plan.summary.fallback_violations > 0 {
        output.push_str(&format!(
            "| **Fallbacks** (`unwrap_or` etc.) | {} | 🔴 High |\n",
            plan.summary.fallback_violations
        ));
    }
    if plan.summary.blocking_lock_violations > 0 {
        output.push_str(&format!(
            "| **Blocking Locks** (`.lock()` in GUI) | {} | 🟡 Medium |\n",
            plan.summary.blocking_lock_violations
        ));
    }
    if plan.summary.ssot_cache_violations > 0 {
        output.push_str(&format!(
            "| **SSOT cache** (GUI values cached before loops) | {} | 🔴 High |\n",
            plan.summary.ssot_cache_violations
        ));
    }
    let clean_count = plan.summary.lock_violations
        + plan.summary.spawn_violations
        + plan.summary.ssot_violations
        + plan.summary.required_config_violations
        + plan.summary.sensitive_violations
        + plan.summary.hardcoded_path_violations
        + plan.summary.hardcoded_literal_violations
        + plan.summary.hardcoded_sleep_violations
        + plan.summary.style_violations;
    if clean_count == 0
        && (plan.summary.fallback_violations > 0
            || plan.summary.blocking_lock_violations > 0
            || plan.summary.ssot_cache_violations > 0)
    {
        output.push_str("| Lock/Spawn/SSOT/Config | 0 | 🟢 Clean |\n");
    }
    output.push('\n');

    // Hotspots by file
    let mut file_fallbacks: HashMap<String, usize> = HashMap::new();
    let mut file_blocking: HashMap<String, usize> = HashMap::new();
    for v in &plan.violations {
        match &v.violation_type {
            ViolationType::FailFast(_) => {
                *file_fallbacks.entry(v.file.clone()).or_insert(0) += 1;
            }
            ViolationType::BlockingLock(_) => {
                *file_blocking.entry(v.file.clone()).or_insert(0) += 1;
            }
            _ => {}
        }
    }
    if !file_fallbacks.is_empty() || !file_blocking.is_empty() {
        output.push_str("### Hotspots (by file)\n\n");
        output.push_str("| File | Fallbacks | Blocking Locks |\n");
        output.push_str("|------|-----------|----------------|\n");
        let mut all_files: Vec<String> = file_fallbacks.keys().chain(file_blocking.keys()).cloned().collect();
        all_files.sort();
        all_files.dedup();
        all_files.sort_by(|a, b| {
            let a_total = file_fallbacks.get(a).copied().unwrap_or(0) + file_blocking.get(a).copied().unwrap_or(0);
            let b_total = file_fallbacks.get(b).copied().unwrap_or(0) + file_blocking.get(b).copied().unwrap_or(0);
            b_total.cmp(&a_total)
        });
        for f in all_files {
            let fb = file_fallbacks.get(&f).copied().unwrap_or(0);
            let bl = file_blocking.get(&f).copied().unwrap_or(0);
            // Extract just filename for cleaner display
            let short = f.rsplit('/').next().unwrap_or(&f);
            output.push_str(&format!("| `{}` | {} | {} |\n", short, fb, bl));
        }
        output.push('\n');
    }

    // Prompt-applied output (always included)
    output.push_str(&format_prompt_applied(plan));

    // FOCUS Assessment
    output.push_str("## 🎯 FOCUS Assessment\n\n");
    output.push_str("*Feedback Optimized Closed-loop Unified System*\n\n");
    output.push_str("| Metric | Status | Notes |\n");
    output.push_str("|--------|--------|-------|\n");
    
    // F - Feedback: OK if no required config violations
    let feedback_status = if plan.summary.required_config_violations == 0 { "OK" } else { "DEGRADED" };
    let feedback_note = if plan.summary.required_config_violations == 0 {
        "Audio peaks flowing via shared memory"
    } else {
        "Missing required configuration"
    };
    output.push_str(&format!("| **F**eedback | {} | {} |\n", feedback_status, feedback_note));
    
    // O - Optimization: Based on fail-fast violations
    let opt_status = if plan.summary.fallback_violations == 0 {
        "OK"
    } else if plan.summary.fallback_violations < 20 {
        "TUNING"
    } else {
        "UNSTABLE"
    };
    let opt_note = if plan.summary.fallback_violations == 0 {
        "Fail-fast patterns enforced"
    } else {
        &format!("{} fail-fast patterns need enforcement", plan.summary.fallback_violations)
    };
    output.push_str(&format!("| **O**ptimization | {} | {} |\n", opt_status, opt_note));
    
    // C - Closed-loop: Based on blocking locks that could break the loop
    let main_thread_dangerous = plan.violations.iter()
        .filter(|v| matches!(&v.violation_type, ViolationType::BlockingLock(_)))
        .filter(|v| v.category.as_deref() == Some("main_thread_dangerous"))
        .count();
    let closed_status = if main_thread_dangerous == 0 { "OK" } else { "PARTIAL" };
    let closed_note = if main_thread_dangerous == 0 {
        "End-to-end signal path clear"
    } else {
        &format!("{} main-thread locks could block loop", main_thread_dangerous)
    };
    output.push_str(&format!("| **C**losed-loop | {} | {} |\n", closed_status, closed_note));
    
    // U - Unified: Based on SSOT violations
    let unified_status = if plan.summary.ssot_violations == 0 { "OK" } else { "FRAGMENTED" };
    let unified_note = if plan.summary.ssot_violations == 0 {
        "State management coherent"
    } else {
        &format!("{} SSOT violations", plan.summary.ssot_violations)
    };
    output.push_str(&format!("| **U**nified | {} | {} |\n", unified_status, unified_note));
    
    // S - System: Overall health
    let system_status = if plan.summary.total_violations == 0 {
        "OK"
    } else if plan.summary.total_violations < 50 {
        "DEGRADED"
    } else {
        "DOWN"
    };
    let system_note = if plan.summary.total_violations == 0 {
        "All policy checks pass"
    } else {
        &format!("{} policy violations", plan.summary.total_violations)
    };
    output.push_str(&format!("| **S**ystem | {} | {} |\n\n", system_status, system_note));

    // Priority Actions
    if !plan.violations.is_empty() {
        output.push_str("### Priority Actions\n\n");
        if main_thread_dangerous > 0 {
            output.push_str(&format!(
                "1. **🔴 Fix {} `main_thread_dangerous` locks** — these can freeze GUI\n",
                main_thread_dangerous
            ));
        }
        let unwrap_or_count = plan.violations.iter()
            .filter(|v| matches!(&v.violation_type, ViolationType::FailFast(n) if n == "unwrap_or"))
            .count();
        if unwrap_or_count > 0 {
            output.push_str(&format!(
                "2. **🔴 Convert {} `unwrap_or` to fail-fast** — or add to allowlist if intentional\n",
                unwrap_or_count
            ));
        }
        let poll_risky = plan.violations.iter()
            .filter(|v| matches!(&v.violation_type, ViolationType::BlockingLock(_)))
            .filter(|v| v.category.as_deref() == Some("poll_method_risky"))
            .count();
        if poll_risky > 0 {
            output.push_str(&format!(
                "3. **🟡 Review {} `poll_method_risky` locks** — may need try_lock()\n",
                poll_risky
            ));
        }
        output.push('\n');
    }

    if plan.violations.is_empty() {
        output.push_str("✅ **No violations found!** Your repo is clean.\n");
        return output;
    }

    // Breakdown of fail-fast violations by class
    let mut by_class: HashMap<String, usize> = HashMap::new();
    for v in &plan.violations {
        if let ViolationType::FailFast(name) = &v.violation_type {
            *by_class.entry(name.clone()).or_insert(0) += 1;
        }
    }
    if !by_class.is_empty() {
        output.push_str("## Fallback Breakdown\n\n");
        let mut pairs: Vec<(String, usize)> = by_class.into_iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        for (name, count) in pairs {
            output.push_str(&format!("- **{}**: {}\n", name, count));
        }
        output.push('\n');
    }

    // Breakdown of fail-fast violations by category (config vs runtime vs examples)
    let mut by_category: HashMap<String, usize> = HashMap::new();
    for v in &plan.violations {
        if matches!(v.violation_type, ViolationType::FailFast(_)) {
            let key = match &v.category {
                Some(s) => s.clone(),
                None => "unknown".to_string(),
            };
            *by_category.entry(key).or_insert(0) += 1;
        }
    }
    if !by_category.is_empty() {
        output.push_str("## Fallback Category Breakdown\n\n");
        let mut pairs: Vec<(String, usize)> = by_category.into_iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        for (name, count) in pairs {
            output.push_str(&format!("- **{}**: {}\n", name, count));
        }
        output.push('\n');
    }

    // Breakdown of sensitive literal violations by class
    let mut sens_by_class: HashMap<String, usize> = HashMap::new();
    for v in &plan.violations {
        if let ViolationType::Sensitive(name) = &v.violation_type {
            *sens_by_class.entry(name.clone()).or_insert(0) += 1;
        }
    }
    if !sens_by_class.is_empty() {
        output.push_str("## Sensitive Literal Breakdown\n\n");
        let mut pairs: Vec<(String, usize)> = sens_by_class.into_iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        for (name, count) in pairs {
            output.push_str(&format!("- **{}**: {}\n", name, count));
        }
        output.push('\n');
    }

    // Breakdown of hardcode violations by class
    let mut hard_by_class: HashMap<String, usize> = HashMap::new();
    for v in &plan.violations {
        if let ViolationType::HardcodedLiteral(name) = &v.violation_type {
            *hard_by_class.entry(name.clone()).or_insert(0) += 1;
        }
    }
    if !hard_by_class.is_empty() {
        output.push_str("## Hardcode Breakdown\n\n");
        let mut pairs: Vec<(String, usize)> = hard_by_class.into_iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        for (name, count) in pairs {
            output.push_str(&format!("- **{}**: {}\n", name, count));
        }
        output.push('\n');
    }

    // Breakdown of style violations by class
    let mut style_by_class: HashMap<String, usize> = HashMap::new();
    for v in &plan.violations {
        if let ViolationType::Style(name) = &v.violation_type {
            *style_by_class.entry(name.clone()).or_insert(0) += 1;
        }
    }
    if !style_by_class.is_empty() {
        output.push_str("## Style Breakdown\n\n");
        let mut pairs: Vec<(String, usize)> = style_by_class.into_iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        for (name, count) in pairs {
            output.push_str(&format!("- **{}**: {}\n", name, count));
        }
        output.push('\n');
    }

    // Breakdown of blocking lock violations by class
    let mut blocking_by_class: HashMap<String, usize> = HashMap::new();
    for v in &plan.violations {
        if let ViolationType::BlockingLock(name) = &v.violation_type {
            *blocking_by_class.entry(name.clone()).or_insert(0) += 1;
        }
    }
    if !blocking_by_class.is_empty() {
        output.push_str("## Blocking Lock Breakdown\n\n");
        let mut pairs: Vec<(String, usize)> = blocking_by_class.into_iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        for (name, count) in pairs {
            output.push_str(&format!("- **{}**: {}\n", name, count));
        }
        output.push('\n');
    }

    // Breakdown of blocking lock violations by category (main_thread vs spawned_thread)
    let mut blocking_by_category: HashMap<String, usize> = HashMap::new();
    for v in &plan.violations {
        if matches!(v.violation_type, ViolationType::BlockingLock(_)) {
            let key = match &v.category {
                Some(s) => s.clone(),
                None => "unknown".to_string(),
            };
            *blocking_by_category.entry(key).or_insert(0) += 1;
        }
    }
    if !blocking_by_category.is_empty() {
        output.push_str("## Blocking Lock Category Breakdown\n\n");
        let mut pairs: Vec<(String, usize)> = blocking_by_category.into_iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        for (name, count) in pairs {
            output.push_str(&format!("- **{}**: {}\n", name, count));
        }
        output.push('\n');
    }

    output.push_str("## Recommendations\n\n");

    for (idx, rec) in plan.recommendations.iter().enumerate() {
        let priority_emoji = match rec.priority {
            Priority::High => "🔴",
            Priority::Medium => "🟡",
            Priority::Low => "🟢",
        };

        output.push_str(&format!(
            "### {} {}. {}\n\n",
            priority_emoji,
            idx + 1,
            rec.action
        ));
        output.push_str(&format!("**Reason**: {}\n\n", rec.reason));

        if !rec.files.is_empty() {
            output.push_str("**Affected Files**:\n");
            for file in &rec.files {
                output.push_str(&format!("- `{}`\n", file));
            }
            output.push('\n');
        }
    }

    output.push_str("## Detailed Violations\n\n");
    output.push_str("| File | Line | Kind | Type | Category | Pattern |\n");
    output.push_str("|------|------|------|------|----------|----------|\n");

    for v in &plan.violations {
        let violation_type = match &v.violation_type {
            ViolationType::Lock => "Lock",
            ViolationType::Spawn => "Spawn",
            ViolationType::Ssot(name) => name,
            ViolationType::FailFast(name) => name,
            ViolationType::RequiredConfig => "RequiredConfig",
            ViolationType::Sensitive(name) => name,
            ViolationType::Style(name) => name,
            ViolationType::BlockingLock(name) => name,
            ViolationType::HardcodedSleep(name) => name,
            ViolationType::HardcodedLiteral(name) => name,
            ViolationType::NoCache => "NoCache",
        };
        let category = match &v.category {
            Some(s) => s.as_str(),
            None => "",
        };
        let kind = classify_kind(&v.violation_type);

        output.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | `{}` |\n",
            v.file, v.line, kind, violation_type, category, v.pattern
        ));
    }

    output.push_str("\n## Next Steps\n\n");
    output.push_str("1. Review violations above\n");
    output.push_str("2. Fix violations by:\n");
    output.push_str("   - Moving code to allowed paths\n");
    output.push_str("   - Or updating `xtask/policy.toml` allowlists\n");
    output.push_str("3. Re-run: `cargo run -p xtask`\n");
    output.push_str("4. Commit fixes\n");

    output
}

fn format_prompt_applied(plan: &CleanupPlan) -> String {
    let mut out = String::new();

    // File-level counts (for concentration + targeting)
    let mut by_file_total: HashMap<String, usize> = HashMap::new();
    let mut by_file_fail_fast: HashMap<String, usize> = HashMap::new();
    let mut by_file_blocking: HashMap<String, usize> = HashMap::new();
    for v in &plan.violations {
        *by_file_total.entry(v.file.clone()).or_insert(0) += 1;
        match &v.violation_type {
            ViolationType::FailFast(_) => {
                *by_file_fail_fast.entry(v.file.clone()).or_insert(0) += 1;
            }
            ViolationType::BlockingLock(_) => {
                *by_file_blocking.entry(v.file.clone()).or_insert(0) += 1;
            }
            _ => {}
        }
    }

    let mut files_sorted: Vec<(String, usize)> = by_file_total.into_iter().collect();
    files_sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let main_thread_dangerous = plan
        .violations
        .iter()
        .filter(|v| matches!(&v.violation_type, ViolationType::BlockingLock(_)))
        .filter(|v| v.category.as_deref() == Some("main_thread_dangerous"))
        .count();

    let poll_method_risky = plan
        .violations
        .iter()
        .filter(|v| matches!(&v.violation_type, ViolationType::BlockingLock(_)))
        .filter(|v| v.category.as_deref() == Some("poll_method_risky"))
        .count();

    let has_try_lock = plan
        .violations
        .iter()
        .filter(|v| matches!(&v.violation_type, ViolationType::BlockingLock(_)))
        .filter(|v| v.category.as_deref() == Some("has_try_lock"))
        .count();

    let unwrap_or_count = plan
        .violations
        .iter()
        .filter(|v| matches!(&v.violation_type, ViolationType::FailFast(n) if n == "unwrap_or"))
        .count();

    let files_affected = plan.summary.files_affected;

    let top_file = files_sorted.first().map(|(f, _)| f.as_str());
    let top_file_short = top_file
        .and_then(|f| f.rsplit('/').next())
        .unwrap_or("");

    out.push_str("## Strategic Outputs (Prompt-Applied)\n\n");

    // 1) Strategic insights
    out.push_str("### 1) Strategic Insights (5) — and the decision each informs\n\n");
    if plan.violations.is_empty() {
        out.push_str("- **Insight 1: The repo is currently clean under policy.**\n");
        out.push_str("  **Decision it informs**: Preserve the gate—treat new violations as regressions.\n\n");
        out.push_str("- **Insight 2: Most future risk will come from “small convenience changes”.**\n");
        out.push_str("  **Decision it informs**: Require explicit intent for any non-fail-fast or blocking behavior.\n\n");
        out.push_str("- **Insight 3: The highest leverage is prevention, not cleanup.**\n");
        out.push_str("  **Decision it informs**: Keep `xtask` checks in the tightest loop (pre-merge / pre-run).\n\n");
        out.push_str("- **Insight 4: Tooling clarity is the bottleneck once the repo is clean.**\n");
        out.push_str("  **Decision it informs**: Keep outputs prescriptive (owners + metrics), not descriptive.\n\n");
        out.push_str("- **Insight 5: Exceptions should remain rare and documented.**\n");
        out.push_str("  **Decision it informs**: If an allowlist entry is added, require justification in `policy.toml` review.\n\n");
    } else {
        out.push_str(&format!(
            "- **Insight 1: The violation mix is concentrated ({} file(s), {} total).**\n",
            files_affected, plan.summary.total_violations
        ));
        out.push_str("  **Decision it informs**: Fix hotspots first; avoid broad repo-wide churn.\n\n");

        out.push_str(&format!(
            "- **Insight 2: Fail-fast policy dominates the risk surface ({} fail-fast violations).**\n",
            plan.summary.fallback_violations
        ));
        out.push_str("  **Decision it informs**: Treat missing-required-value behavior as a contract decision: convert vs explicit allowlist.\n\n");

        out.push_str(&format!(
            "- **Insight 3: UI stability is the second-order risk ({} blocking locks; {} main-thread dangerous).**\n",
            plan.summary.blocking_lock_violations, main_thread_dangerous
        ));
        out.push_str("  **Decision it informs**: Prioritize removing main-thread blocking first to prevent freezes.\n\n");

        if !top_file_short.is_empty() {
            out.push_str(&format!(
                "- **Insight 4: One file likely anchors the quickest wins (`{}` is the largest hotspot).**\n",
                top_file_short
            ));
            out.push_str("  **Decision it informs**: Start with the biggest hotspot to reduce totals fastest.\n\n");
        } else {
            out.push_str("- **Insight 4: Hotspots are identifiable by file-level totals.**\n");
            out.push_str("  **Decision it informs**: Start with the top-ranked file in the hotspot table.\n\n");
        }

        out.push_str("- **Insight 5: Not every violation should be “fixed” the same way.**\n");
        out.push_str("  **Decision it informs**: For each pattern, decide: enforce (fail-fast / non-blocking) vs narrow allowlist with justification.\n\n");
    }

    // 2) Action plan
    out.push_str("### 2) 5-step execution plan (owners, quick wins, measurable results)\n\n");
    if plan.violations.is_empty() {
        out.push_str("1. **Keep the gate tight** (Owner: Repo owner)\n");
        out.push_str("   - Quick win: Run `cargo run -p xtask -- check` before changes land.\n");
        out.push_str("   - Metric: total violations stays at 0.\n\n");
        out.push_str("2. **Prevent main-thread blocking regressions** (Owner: GUI maintainer)\n");
        out.push_str("   - Quick win: Prefer non-blocking patterns in UI paths.\n");
        out.push_str("   - Metric: main-thread blocking locks stays at 0.\n\n");
        out.push_str("3. **Keep fail-fast strict** (Owner: Rust core maintainer)\n");
        out.push_str("   - Quick win: refuse silent defaults for required inputs.\n");
        out.push_str("   - Metric: fail-fast violations stays at 0.\n\n");
        out.push_str("4. **Keep allowlists narrow** (Owner: Repo owner)\n");
        out.push_str("   - Quick win: treat allowlists as explicit exceptions only.\n");
        out.push_str("   - Metric: allowlist entries grow slowly and deliberately.\n\n");
        out.push_str("5. **Re-run analyze after meaningful edits** (Owner: Repo owner)\n");
        out.push_str("   - Quick win: keep `cleanup-plan.md` current.\n");
        out.push_str("   - Metric: any regression shows up immediately.\n\n");
    } else {
        out.push_str("1. **Classify each fail-fast instance (required vs runtime-data)** (Owner: Rust core maintainer)\n");
        out.push_str("   - Quick win: tag each hotspot instance as “convert” vs “explicit allowlist”.\n");
        out.push_str("   - Metric: classification completed for all fail-fast violations.\n\n");

        out.push_str(&format!(
            "2. **Remove main-thread dangerous blocking** (Owner: GUI maintainer)\n   - Quick win: fix the {} `main_thread_dangerous` locks first.\n   - Metric: main-thread dangerous locks: {} → 0.\n\n",
            main_thread_dangerous, main_thread_dangerous
        ));

        out.push_str(&format!(
            "3. **Convert `unwrap_or` where it masks required values** (Owner: Rust core maintainer)\n   - Quick win: convert the {} `unwrap_or` sites that should be fatal.\n   - Metric: `unwrap_or` violations: {} → 0 (or explicit allowlist).\n\n",
            unwrap_or_count, unwrap_or_count
        ));

        out.push_str(&format!(
            "4. **Handle remaining lock-risk categories** (Owner: GUI maintainer)\n   - Quick win: address {} `poll_method_risky` + {} `has_try_lock` flagged contexts.\n   - Metric: blocking locks: {} → 0 (or minimized to justified contexts).\n\n",
            poll_method_risky, has_try_lock, plan.summary.blocking_lock_violations
        ));

        out.push_str("5. **Re-run analyze until clean (or intentionally allowlisted)** (Owner: Repo owner)\n");
        out.push_str(&format!(
            "   - Quick win: iterate file-by-file starting from the top hotspot.\n   - Metric: total violations: {} → 0.\n\n",
            plan.summary.total_violations
        ));
    }

    // 3) Hidden assumptions
    out.push_str("### 3) Hidden assumptions / blind spots — and what changes if they’re wrong\n\n");
    out.push_str("- **Assumption: “runtime_data” defaults are benign.** If wrong: treat more sites as required and make them fatal.\n");
    out.push_str("- **Assumption: Non-blocking lock patterns are acceptable in UI code paths.** If wrong: move work off-thread or restructure ownership.\n");
    out.push_str("- **Assumption: Hotspot counts correlate with impact.** If wrong: prioritize by call-path criticality, not counts.\n\n");

    // 4) Compare opposing views
    out.push_str("### 4) Competing perspectives — where each fits\n\n");
    out.push_str("- **Perspective A: Strict policy enforcement everywhere.** Best when missing values indicate broken invariants and must fail loudly.\n");
    out.push_str("- **Perspective B: Narrow, explicit allowlists for intentional exceptions.** Best when missing data is expected and does not affect correctness.\n\n");

    // 5) Contrarian takeaways
    out.push_str("### 5) Contrarian takeaways (credible one-liners)\n\n");
    if plan.violations.is_empty() {
        out.push_str("- **The hard part isn’t cleanup; it’s keeping the repo clean under pressure.**\n");
        out.push_str("- **Allowlist growth is a leading indicator of policy decay.**\n");
        out.push_str("- **Tool outputs should drive decisions, not narrate problems.**\n\n");
    } else {
        out.push_str("- **Your fastest stability gains are likely in UI lock hygiene, not core logic rewrites.**\n");
        out.push_str("- **One “convenience” default can silently invalidate an entire run’s correctness assumptions.**\n");
        out.push_str("- **Fixing the biggest hotspot file first usually beats “fix one violation type everywhere”.**\n\n");
    }

    // 6) Leverage points
    out.push_str("### 6) Leverage points (small actions, outsized results)\n\n");
    if plan.violations.is_empty() {
        out.push_str("- **Leverage 1: Keep `xtask` in the tight loop.** It prevents regressions from landing.\n");
        out.push_str("- **Leverage 2: Keep UI paths non-blocking by default.** It avoids user-visible freezes.\n");
        out.push_str("- **Leverage 3: Keep allowlists explicit and rare.** It preserves policy meaning.\n\n");
    } else {
        out.push_str(&format!(
            "- **Leverage 1: Eliminate the {} main-thread dangerous locks.** It directly reduces UI freeze risk.\n",
            main_thread_dangerous
        ));
        out.push_str("- **Leverage 2: Standardize fatal error paths for required values.** It prevents silent contract drift.\n");
        out.push_str("- **Leverage 3: Use `policy.toml` sparingly but explicitly.** It prevents churn and keeps exceptions reviewable.\n\n");
    }

    // 7) Target list (practical)
    out.push_str("### 7) Where to start (top hotspots)\n\n");
    if plan.violations.is_empty() {
        out.push_str("- No hotspots (0 violations).\n\n");
        return out;
    }
    for (idx, (file, total)) in files_sorted.iter().take(5).enumerate() {
        let fb = by_file_fail_fast.get(file).copied().unwrap_or(0);
        let bl = by_file_blocking.get(file).copied().unwrap_or(0);
        let short = file.rsplit('/').next().unwrap_or(file);
        out.push_str(&format!(
            "{}. `{}` — total: {}, fail-fast: {}, blocking locks: {}\n",
            idx + 1,
            short,
            total,
            fb,
            bl
        ));
    }
    out.push('\n');

    out
}

fn required_config_violations(config: &PolicyConfig, scan_root: &Path) -> Vec<Violation> {
    let mut out = vec![];

    // env: we don't print actual values; only check existence/non-empty.
    let dotenv_path = scan_root.join(".env");
    let dotenv_map = match std::fs::read_to_string(&dotenv_path) {
        Ok(s) => parse_dotenv(&s),
        Err(_) => std::collections::HashMap::new(),
    };
    let process_env: std::collections::HashMap<String, String> = std::env::vars().collect();

    for group in &config.required.env_any_of {
        let mut satisfied = false;
        for key in &group.any_of {
            if process_env.get(key).is_some_and(|v| !v.trim().is_empty()) {
                satisfied = true;
                break;
            }
            if dotenv_map.get(key).is_some_and(|v| !v.trim().is_empty()) {
                satisfied = true;
                break;
            }
        }
        if !satisfied {
            out.push(Violation {
                rule: "Required config present".to_string(),
                file: "./.env".to_string(),
                line: "N/A".to_string(),
                pattern: format!("any_of={:?}", group.any_of),
                violation_type: ViolationType::RequiredConfig,
                category: None,
            });
        }
    }

    for req in &config.required.yaml_non_null {
        let path = scan_root.join(&req.file);
        let Ok(content) = std::fs::read_to_string(&path) else {
            out.push(Violation {
                rule: "Required config present".to_string(),
                file: format!("./{}", req.file),
                line: "N/A".to_string(),
                pattern: format!("missing file (path={})", req.path),
                violation_type: ViolationType::RequiredConfig,
                category: None,
            });
            continue;
        };
        let yaml: serde_yaml::Value = match serde_yaml::from_str(&content) {
            Ok(v) => v,
            Err(e) => {
                out.push(Violation {
                    rule: "Required config present".to_string(),
                    file: format!("./{}", req.file),
                    line: "N/A".to_string(),
                    pattern: format!("invalid yaml: {e}"),
                    violation_type: ViolationType::RequiredConfig,
                    category: None,
                });
                continue;
            }
        };

        let ok = match yaml_path_non_null(&yaml, &req.path, req.all) {
            Ok(v) => v,
            Err(e) => {
                out.push(Violation {
                    rule: "Required config present".to_string(),
                    file: format!("./{}", req.file),
                    line: "N/A".to_string(),
                    pattern: format!("invalid path {}: {e}", req.path),
                    violation_type: ViolationType::RequiredConfig,
                    category: None,
                });
                continue;
            }
        };
        if !ok {
            out.push(Violation {
                rule: "Required config present".to_string(),
                file: format!("./{}", req.file),
                line: "N/A".to_string(),
                pattern: format!("non_null path {}", req.path),
                violation_type: ViolationType::RequiredConfig,
                category: None,
            });
        }
    }

    out
}

fn classify_fail_fast_violation(
    ctx: &ClassifyContext,
    scan_root: &Path,
    file: &str,
    line_num: &str,
) -> &'static str {
    let file_lc = file.to_ascii_lowercase();
    if file_lc.starts_with("./examples/") || file_lc.starts_with("examples/") {
        return "examples";
    }
    if let Ok(n) = line_num.parse::<usize>() {
        if let Some(s) = read_context(scan_root, file, n) {
            let s = s.trim();
            if file_lc.ends_with("config_loader.rs") && (s.contains("PG_") || s.contains("DB_")) {
                let has_host = env_has_any(ctx, &["PG_HOST", "DB_HOST"]);
                let has_port = env_has_any(ctx, &["PG_PORT", "DB_PORT"]);
                let has_user = env_has_any(ctx, &["PG_USER", "DB_USER"]);
                let has_password = env_has_any(ctx, &["PG_PASSWORD", "DB_PASSWORD"]);
                let has_db = env_has_any(ctx, &["PG_DATABASE", "DB_NAME"]);
                if has_host && has_port && has_user && has_password && has_db {
                    return "env_present";
                }
                return "env_missing";
            }

            if s.contains("get_adjustment_level")
                || s.contains("get_retry_threshold")
                || s.contains("get_delta_threshold")
                || s.contains("get_z_variance_threshold")
            {
                if presets_has_default_key(ctx, s) {
                    return "preset_present";
                }
                return "preset_missing";
            }

            if s.contains("try_read") || s.contains("try_lock") {
                return "runtime_lock";
            }
            if s.contains(".lock()") && s.contains("unwrap_or_else") {
                // often poison handling / recovery path
                return "runtime_lock";
            }
            if s.contains(".get(") || s.contains("positions.get(") || s.contains("enabled_states.get(") {
                return "runtime_data";
            }
            if s.contains("read_control_file") {
                return "runtime_data";
            }
        }
    }
    "unknown"
}

fn read_line(scan_root: &Path, file: &str, one_based: usize) -> Option<String> {
    if one_based == 0 {
        return None;
    }
    let rel = match file.strip_prefix("./") {
        Some(s) => s,
        None => file,
    };
    let path = scan_root.join(rel);
    let Ok(content) = std::fs::read_to_string(path) else {
        return None;
    };
    content.lines().nth(one_based - 1).map(|s| s.to_string())
}

fn read_context(scan_root: &Path, file: &str, one_based: usize) -> Option<String> {
    if one_based == 0 {
        return None;
    }
    let cur = read_line(scan_root, file, one_based)?;
    let prev1 = if one_based > 1 {
        read_line(scan_root, file, one_based - 1)
    } else {
        None
    };
    let prev2 = if one_based > 2 {
        read_line(scan_root, file, one_based - 2)
    } else {
        None
    };

    let mut out = String::new();
    if let Some(p2) = prev2 {
        out.push_str(&p2);
        out.push('\n');
    }
    if let Some(p1) = prev1 {
        out.push_str(&p1);
        out.push('\n');
    }
    out.push_str(&cur);
    Some(out)
}

fn build_classify_context(scan_root: &Path) -> ClassifyContext {
    let mut env: HashMap<String, String> = std::env::vars().collect();

    let dotenv_path = scan_root.join(".env");
    if let Ok(s) = std::fs::read_to_string(&dotenv_path) {
        let dotenv_map = parse_dotenv(&s);
        for (k, v) in dotenv_map {
            env.entry(k).or_insert(v);
        }
    }

    let presets_yaml = {
        let path = scan_root.join("presets.yaml");
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_yaml::from_str::<serde_yaml::Value>(&s).ok())
    };

    ClassifyContext { env, presets_yaml }
}

fn env_has_any(ctx: &ClassifyContext, keys: &[&str]) -> bool {
    keys.iter()
        .any(|k| ctx.env.get(*k).is_some_and(|v| !v.trim().is_empty()))
}

fn yaml_default_has_non_null(root: &serde_yaml::Value, key: &str) -> bool {
    let serde_yaml::Value::Mapping(m) = root else {
        return false;
    };
    let def = m.get(&serde_yaml::Value::String("default".to_string()));
    let Some(serde_yaml::Value::Mapping(def)) = def else {
        return false;
    };
    let v = def.get(&serde_yaml::Value::String(key.to_string()));
    matches!(v, Some(v) if !matches!(v, serde_yaml::Value::Null))
}

fn presets_has_default_key(ctx: &ClassifyContext, line: &str) -> bool {
    let Some(root) = &ctx.presets_yaml else {
        return false;
    };
    let key = if line.contains("get_adjustment_level") {
        "adjustment_level"
    } else if line.contains("get_retry_threshold") {
        "retry_threshold"
    } else if line.contains("get_delta_threshold") {
        "delta_threshold"
    } else if line.contains("get_z_variance_threshold") {
        "z_variance_threshold"
    } else {
        return false;
    };
    yaml_default_has_non_null(root, key)
}

fn parse_dotenv(s: &str) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
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
        if (val.starts_with('"') && val.ends_with('"')) || (val.starts_with('\'') && val.ends_with('\'')) {
            if val.len() >= 2 {
                val = val[1..val.len() - 1].to_string();
            }
        }
        out.insert(key, val);
    }
    out
}

/// Classify a blocking lock violation based on context
/// Returns one of:
/// - "main_thread_dangerous" - blocking lock in GUI update path (can freeze UI)
/// - "poll_method_risky" - blocking lock in poll method (runs on GUI thread, can freeze)
/// - "spawned_thread" - blocking lock in spawned thread (expected, OK)  
/// - "constructor" - blocking lock in new()/init function (usually OK)
/// - "helper_method" - blocking lock in helper method (risk depends on caller)
/// - "logger_thread" - blocking lock in logging thread (OK, runs in background)
/// - "unknown" - cannot determine context
fn classify_blocking_lock(
    _ctx: &ClassifyContext,
    scan_root: &Path,
    file: &str,
    line_num: &str,
) -> &'static str {
    if let Ok(n) = line_num.parse::<usize>() {
        // Read more context (function signature, surrounding code)
        // Use larger window (150 lines) to catch enclosing function and thread::spawn
        // This covers most function bodies even in large files
        if let Some(context) = read_extended_context(scan_root, file, n, 150) {
            let context_lower = context.to_ascii_lowercase();
            
            // Check if this is inside a spawned thread (OK)
            // Look for thread::spawn closure pattern
            if context_lower.contains("thread::spawn(move ||")
                || context_lower.contains("thread::spawn(||")
                || context_lower.contains("spawn_thread(move ||")
                || context_lower.contains("scheduler::spawn_thread")
            {
                return "spawned_thread";
            }
            
            // Check for logger thread pattern (OK - runs in background at 1Hz)
            if context_lower.contains("log_interval")
                || (context_lower.contains("logger") && context_lower.contains("thread::spawn"))
            {
                return "logger_thread";
            }
            
            // Check if this is in a constructor (usually OK - runs once at startup)
            if context_lower.contains("pub fn new(")
                || context_lower.contains("fn new(")
                || context_lower.contains("fn init(")
                || context_lower.contains("fn create(")
            {
                return "constructor";
            }
            
            // Check if there's a try_lock nearby that suggests intentional non-blocking
            if context_lower.contains("try_lock") {
                return "has_try_lock";
            }
            
            // Check for poll/update methods that run on GUI thread (RISKY)
            if context_lower.contains("fn poll_")
                || context_lower.contains("poll_operation")
                || context_lower.contains("fn try_recv")
            {
                return "poll_method_risky";
            }
            
            // Check for helper methods (risk depends on who calls them)
            if context_lower.contains("fn append_message")
                || context_lower.contains("fn log_")
                || context_lower.contains("fn sync_")
            {
                return "helper_method";
            }
            
            // Check for GUI update patterns (DANGEROUS)
            if context_lower.contains("fn update(")
                || context_lower.contains("fn show(")
                || context_lower.contains("fn ui(")
                || context_lower.contains("impl egui")
                || context_lower.contains("impl eframe")
                || context_lower.contains("ui.horizontal")
                || context_lower.contains("ui.vertical")
            {
                return "main_thread_dangerous";
            }
            
            // Check for event handler patterns (DANGEROUS)
            if context_lower.contains(".clicked()")
                || context_lower.contains("button")
                || context_lower.contains("fn on_")
            {
                return "event_handler_dangerous";
            }
            
            // Check if inside a closure passed to thread (OK)
            // Look for "move ||" pattern before the lock
            if context_lower.contains("move ||") {
                // Count braces to see if we're inside a closure
                let before_line = &context[..context.len().min(n * 80)]; // approximate
                if before_line.matches("move ||").count() > before_line.matches("});").count() {
                    return "spawned_thread";
                }
            }
        }
    }
    "unknown"
}

/// Read extended context around a line (before and after)
fn read_extended_context(scan_root: &Path, file: &str, one_based: usize, window: usize) -> Option<String> {
    if one_based == 0 {
        return None;
    }
    let rel = match file.strip_prefix("./") {
        Some(s) => s,
        None => file,
    };
    let path = scan_root.join(rel);
    let Ok(content) = std::fs::read_to_string(path) else {
        return None;
    };
    let lines: Vec<&str> = content.lines().collect();
    let start = one_based.saturating_sub(window).max(1);
    let end = (one_based + window).min(lines.len());
    
    let mut result = String::new();
    for i in start..=end {
        if i > 0 && i <= lines.len() {
            if let Some(line) = lines.get(i - 1) {
                result.push_str(line);
                result.push('\n');
            }
        }
    }
    Some(result)
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
