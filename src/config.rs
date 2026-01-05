use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone)]
pub struct RepoContext {
    /// Root directory that should be scanned (usually the parent repo root).
    pub scan_root: PathBuf,
    /// Path to the policy.toml that configures scanning.
    pub policy_path: PathBuf,
}

/// Determine where to scan and where to load policy from.
///
/// Supported layouts (checked in order):
/// 1. **Parent repo layout**: `<repo_root>/policy.toml` (policy in parent, xtask is submodule)
/// 2. **Submodule layout**: `<repo_root>/xtask/policy.toml` (legacy/standalone testing)
///
/// Fail-fast: if neither layout can be located, return a fatal error.
pub fn repo_context() -> Result<RepoContext, String> {
    let start = std::env::current_dir()
        .map_err(|e| format!("FATAL: failed to read current working directory: {e}"))?;

    // 1) Prefer parent repo layout: find nearest ancestor containing `policy.toml` at root level
    //    This is the recommended layout where policy.toml lives in the parent repo, not the submodule.
    let mut cur: Option<&Path> = Some(&start);
    while let Some(dir) = cur {
        let candidate = dir.join("policy.toml");
        if candidate.is_file() {
            return Ok(RepoContext {
                scan_root: dir.to_path_buf(),
                policy_path: candidate,
            });
        }
        cur = dir.parent();
    }

    // 2) Alternate: submodule layout (xtask/policy.toml) for standalone testing
    let mut cur: Option<&Path> = Some(&start);
    while let Some(dir) = cur {
        let candidate = dir.join("xtask").join("policy.toml");
        if candidate.is_file() {
            return Ok(RepoContext {
                scan_root: dir.to_path_buf(),
                policy_path: candidate,
            });
        }
        cur = dir.parent();
    }

    Err("FATAL: could not locate policy.toml (expected <repo>/policy.toml or <repo>/xtask/policy.toml). Run xtask from the repo root (or ensure the policy file exists).".to_string())
}

#[derive(Debug, serde::Deserialize)]
pub struct PolicyConfig {
    pub allowlists: Allowlists,
    pub patterns: Patterns,
    #[serde(default)]
    pub required: RequiredConfig,
    pub options: Options,
    #[serde(default)]
    pub markdown: MarkdownPolicy,
    #[serde(default)]
    pub websocket: WebsocketPolicy,
    #[serde(default)]
    pub legacy: LegacyPolicy,
}

#[derive(Debug, serde::Deserialize, Default)]
pub struct MarkdownPolicy {
    #[serde(default)]
    pub enabled: bool,
    pub required_root: Option<String>,
    #[serde(default)]
    pub allowed_prefixes: Vec<String>,
    #[serde(default)]
    pub allowed_files: Vec<String>,
}

#[derive(Debug, serde::Deserialize, Default)]
pub struct WebsocketPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_prefixes: Vec<String>,
}

#[derive(Debug, serde::Deserialize, Default)]
pub struct LegacyPolicy {
    #[serde(default)]
    pub enabled: bool,
    pub protected_root: Option<String>,
    pub manifest_file: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct Allowlists {
    pub lock_allowed: Vec<String>,
    pub spawn_allowed: Vec<String>,
    pub ssot_allowed: Vec<String>,
    pub fallbacks_allowed: Vec<String>,
    pub sensitive_allowed: Vec<String>,
    #[serde(default)]
    pub hardcode_allowed: Vec<String>,
    #[serde(default)]
    pub style_allowed: Vec<String>,
    #[serde(default)]
    pub forbidden_allowed: Vec<String>,
    #[serde(default)]
    pub blocking_lock_allowed: Vec<String>,
    #[serde(default)]
    pub ssot_cache_allowed: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct FallbackClass {
    pub name: String,
    pub patterns: Vec<String>,
    #[serde(default)]
    pub allowed: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ForbiddenClass {
    pub name: String,
    pub patterns: Vec<String>,
    #[serde(default)]
    pub allowed: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct SensitiveClass {
    pub name: String,
    pub patterns: Vec<String>,
    #[serde(default)]
    pub allowed: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct HardcodeClass {
    pub name: String,
    pub patterns: Vec<String>,
    #[serde(default)]
    pub allowed: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct StyleClass {
    pub name: String,
    pub patterns: Vec<String>,
    #[serde(default)]
    pub allowed: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct BlockingLockClass {
    pub name: String,
    pub patterns: Vec<String>,
    #[serde(default)]
    pub allowed: Vec<String>,
    /// Paths where blocking locks are considered dangerous (e.g., GUI code)
    #[serde(default)]
    pub dangerous_paths: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct HardcodedSleepClass {
    pub name: String,
    pub patterns: Vec<String>,
    #[serde(default)]
    pub allowed: Vec<String>,
    /// Paths where hardcoded sleeps are considered dangerous (e.g., GUI code)
    #[serde(default)]
    pub dangerous_paths: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct HardcodedLiteralClass {
    pub name: String,
    pub patterns: Vec<String>,
    #[serde(default)]
    pub allowed: Vec<String>,
    /// Antipatterns: if ANY of these are found in the same file, the violation is suppressed
    #[serde(default)]
    pub antipatterns: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct HardcodedPathClass {
    pub name: String,
    pub patterns: Vec<String>,
    #[serde(default)]
    pub allowed: Vec<String>,
    #[serde(default)]
    pub antipatterns: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct BuildScriptClass {
    pub name: String,
    pub patterns: Vec<String>,
    #[serde(default)]
    pub allowed: Vec<String>,
    #[serde(default)]
    pub antipatterns: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct Patterns {
    pub lock_patterns: Vec<String>,
    pub spawn_patterns: Vec<String>,
    pub ssot_types: Vec<String>,
    pub fallback_patterns: Vec<String>,
    #[serde(default)]
    pub fallback_classes: Vec<FallbackClass>,
    #[serde(default)]
    pub forbidden_classes: Vec<ForbiddenClass>,
    #[serde(default)]
    pub sensitive_classes: Vec<SensitiveClass>,
    #[serde(default)]
    pub hardcode_classes: Vec<HardcodeClass>,
    #[serde(default)]
    pub style_classes: Vec<StyleClass>,
    #[serde(default)]
    pub blocking_lock_classes: Vec<BlockingLockClass>,
    #[serde(default)]
    pub hardcoded_sleep_classes: Vec<HardcodedSleepClass>,
    #[serde(default)]
    pub hardcoded_literal_classes: Vec<HardcodedLiteralClass>,
    #[serde(default)]
    pub hardcoded_path_classes: Vec<HardcodedPathClass>,
    #[serde(default)]
    pub build_script_classes: Vec<BuildScriptClass>,
}

#[derive(Debug, serde::Deserialize)]
pub struct Options {
    #[serde(default = "default_require_ripgrep")]
    pub require_ripgrep: bool,

    /// Additional ripgrep glob excludes (passed as `--glob !<pattern>`).
    /// Examples: `audmon/**`, `**/target/**`
    #[serde(default)]
    pub rg_exclude_globs: Vec<String>,
}

#[derive(Debug, serde::Deserialize, Default)]
pub struct RequiredConfig {
    #[serde(default)]
    pub env_any_of: Vec<RequiredEnvAnyOf>,
    #[serde(default)]
    pub yaml_non_null: Vec<RequiredYamlNonNull>,
}

#[derive(Debug, serde::Deserialize)]
pub struct RequiredEnvAnyOf {
    pub any_of: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct RequiredYamlNonNull {
    pub file: String,
    pub path: String,
    #[serde(default)]
    pub all: bool,
}

fn default_require_ripgrep() -> bool {
    false
}

impl PolicyConfig {
    pub fn load() -> Result<Self, String> {
        let ctx = repo_context()?;
        Self::load_from_path(&ctx.policy_path)
    }

    pub fn load_from_path(policy_path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(policy_path).map_err(|e| {
            format!(
                "FATAL: failed to read policy file {}: {e}",
                policy_path.display()
            )
        })?;
        toml::from_str(&content).map_err(|e| {
            format!(
                "FATAL: failed to parse policy file {}: {e}",
                policy_path.display()
            )
        })
    }
}
