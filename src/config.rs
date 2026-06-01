use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Persistent configuration loaded from/saved to a TOML file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub threads: u16,
    pub timeout_ms: u64,
    pub delay_ms: u64,
    pub randomize: bool,
    pub enable_service_detection: bool,
    pub syn_scan: bool,
    pub deep_inspection: bool,
    pub udp_scan: bool,
    pub severity_threshold: String,
    pub output_json: bool,
    pub port_range: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            threads: 4,
            timeout_ms: 1000,
            delay_ms: 0,
            randomize: false,
            enable_service_detection: true,
            syn_scan: false,
            deep_inspection: false,
            udp_scan: false,
            severity_threshold: "LOW".to_string(),
            output_json: false,
            port_range: None,
        }
    }
}

impl Config {
    /// Path to the config file (platform-specific config dir)
    pub fn path() -> PathBuf {
        if let Some(base) = dirs::config_dir() {
            base.join("akroatis").join("config.toml")
        } else {
            PathBuf::from("akroatis_config.toml")
        }
    }

    /// Load config from disk, or create default if not present
    pub fn load() -> Self {
        let path = Self::path();
        if path.exists() {
            match fs::read_to_string(&path) {
                Ok(content) => match toml::from_str(&content) {
                    Ok(cfg) => return cfg,
                    Err(e) => tracing::warn!("Failed to parse config: {}", e),
                },
                Err(e) => tracing::warn!("Failed to read config: {}", e),
            }
        }
        let cfg = Config::default();
        let _ = cfg.save();
        cfg
    }

    /// Save config to disk
    pub fn save(&self) -> Result<(), String> {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let content = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(&path, content).map_err(|e| e.to_string())?;
        Ok(())
    }
}
