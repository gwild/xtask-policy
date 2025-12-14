use std::{collections::HashMap, path::Path, process::Command};

use crate::config::PolicyConfig;

#[derive(Debug, Clone)]
#[allow(dead_code)] // Used in format_plan
pub struct Violation {
    pub rule: String,
    pub file: String,
    pub line: String,
    pub pattern: String,
    pub violation_type: ViolationType,
}

#[derive(Debug, Clone)]
pub enum ViolationType {
    Lock,
    Spawn,
    Ssot(String), // state type name
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

pub fn analyze_repo(config: &PolicyConfig) -> Result<CleanupPlan, String> {
    let mut violations = Vec::new();

    // Scan for locks
    for pattern in &config.patterns.lock_patterns {
        let found = scan_pattern(pattern, &config.allowlists.lock_allowed)?;
        for (file, line) in found {
            violations.push(Violation {
                rule: "Locks outside allowlist".to_string(),
                file: file.clone(),
                line,
                pattern: pattern.clone(),
                violation_type: ViolationType::Lock,
            });
        }
    }

    // Scan for spawning
    for pattern in &config.patterns.spawn_patterns {
        let found = scan_pattern(pattern, &config.allowlists.spawn_allowed)?;
        for (file, line) in found {
            violations.push(Violation {
                rule: "Spawning outside allowlist".to_string(),
                file: file.clone(),
                line,
                pattern: pattern.clone(),
                violation_type: ViolationType::Spawn,
            });
        }
    }

    // Scan for SSOT violations
    for ssot_type in &config.patterns.ssot_types {
        let pattern = format!(r"\b{}\b", ssot_type);
        let found = scan_pattern(&pattern, &config.allowlists.ssot_allowed)?;
        for (file, line) in found {
            violations.push(Violation {
                rule: format!("{} referenced outside owner module", ssot_type),
                file: file.clone(),
                line,
                pattern: pattern.clone(),
                violation_type: ViolationType::Ssot(ssot_type.clone()),
            });
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

    let mut files_affected = std::collections::HashSet::new();
    for v in &violations {
        files_affected.insert(v.file.clone());
    }

    let summary = PlanSummary {
        total_violations: violations.len(),
        lock_violations,
        spawn_violations,
        ssot_violations,
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

fn scan_pattern(pattern: &str, allowlist: &[String]) -> Result<Vec<(String, String)>, String> {
    let rg = Command::new("rg")
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
            pattern,
            ".",
        ])
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
        "- **Files Affected**: {}\n\n",
        plan.summary.files_affected
    ));

    if plan.violations.is_empty() {
        output.push_str("✅ **No violations found!** Your repo is clean.\n");
        return output;
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
    output.push_str("| File | Line | Type | Pattern |\n");
    output.push_str("|------|------|------|----------|\n");

    for v in &plan.violations {
        let violation_type = match &v.violation_type {
            ViolationType::Lock => "Lock",
            ViolationType::Spawn => "Spawn",
            ViolationType::Ssot(name) => name,
        };

        output.push_str(&format!(
            "| `{}` | {} | {} | `{}` |\n",
            v.file, v.line, violation_type, v.pattern
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
