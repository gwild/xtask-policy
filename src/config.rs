use std::fs;

#[derive(Debug, serde::Deserialize)]
pub struct PolicyConfig {
    pub allowlists: Allowlists,
    pub patterns: Patterns,
    pub options: Options,
}

#[derive(Debug, serde::Deserialize)]
pub struct Allowlists {
    pub lock_allowed: Vec<String>,
    pub spawn_allowed: Vec<String>,
    pub ssot_allowed: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct Patterns {
    pub lock_patterns: Vec<String>,
    pub spawn_patterns: Vec<String>,
    pub ssot_types: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct Options {
    #[serde(default = "default_require_ripgrep")]
    pub require_ripgrep: bool,
}

fn default_require_ripgrep() -> bool {
    false
}

impl PolicyConfig {
    pub fn load() -> Result<Self, String> {
        let config_path = "xtask/policy.toml";
        let content = fs::read_to_string(config_path)
            .map_err(|e| format!("Failed to read {config_path}: {e}"))?;
        toml::from_str(&content).map_err(|e| format!("Failed to parse {config_path}: {e}"))
    }
}
