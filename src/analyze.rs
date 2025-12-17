use std::{collections::HashMap, path::Path, process::Command};

use crate::config::PolicyConfig;

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
    Hardcode(String),
    Style(String),
}

#[derive(Debug)]
pub struct CleanupPlan {
    pub violations: Vec<Violation>,
    pub summary: PlanSummary,
    pub recommendations: Vec<Recommendation>,
}

#[derive(Debug)]
pub struct PlanSummary {
    pub total_violations: usize,
    pub lock_violations: usize,
    pub spawn_violations: usize,
    pub ssot_violations: usize,
    pub fallback_violations: usize,
    pub required_config_violations: usize,
    pub sensitive_violations: usize,
    pub hardcode_violations: usize,
    pub style_violations: usize,
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
                    violation_type: ViolationType::Hardcode(class.name.clone()),
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

    // Generate summary
    let lock_violations = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::Lock))
        .count();
    let spawn_violations = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::Spawn))
        .count();
    let ssot_violations = violations
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
    let hardcode_violations = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::Hardcode(_)))
        .count();
    let style_violations = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::Style(_)))
        .count();

    let mut files_affected = std::collections::HashSet::new();
    for v in &violations {
        files_affected.insert(v.file.clone());
    }

    let summary = PlanSummary {
        total_violations: violations.len(),
        lock_violations,
        spawn_violations,
        ssot_violations,
        fallback_violations: fail_fast_violations,
        required_config_violations,
        sensitive_violations,
        hardcode_violations,
        style_violations,
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
        .filter(|v| matches!(v.violation_type, ViolationType::Hardcode(_)))
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
                    .filter(|v| matches!(v.violation_type, ViolationType::Hardcode(_)))
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

    output.push_str("# Cleanup Plan\n\n");
    output.push_str("## Summary\n\n");
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
        "- **Hardcode Violations**: {}\n",
        plan.summary.hardcode_violations
    ));
    output.push_str(&format!(
        "- **Style Violations**: {}\n",
        plan.summary.style_violations
    ));
    output.push_str(&format!(
        "- **Files Affected**: {}\n\n",
        plan.summary.files_affected
    ));

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
        if let ViolationType::Hardcode(name) = &v.violation_type {
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
    output.push_str("| File | Line | Type | Category | Pattern |\n");
    output.push_str("|------|------|------|----------|----------|\n");

    for v in &plan.violations {
        let violation_type = match &v.violation_type {
            ViolationType::Lock => "Lock",
            ViolationType::Spawn => "Spawn",
            ViolationType::Ssot(name) => name,
            ViolationType::FailFast(name) => name,
            ViolationType::RequiredConfig => "RequiredConfig",
            ViolationType::Sensitive(name) => name,
            ViolationType::Hardcode(name) => name,
            ViolationType::Style(name) => name,
        };
        let category = match &v.category {
            Some(s) => s.as_str(),
            None => "",
        };

        output.push_str(&format!(
            "| `{}` | {} | {} | {} | `{}` |\n",
            v.file, v.line, violation_type, category, v.pattern
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
