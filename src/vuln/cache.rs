use std::collections::HashMap;
use std::fs;
use chrono::{Utc, Duration};
use serde::{Serialize, Deserialize};
use crate::vuln::nvd::Vulnerability;

const CACHE_FILE: &str = "akroatis_cve_cache.json";
const CACHE_EXPIRY_DAYS: i64 = 7;

#[derive(Serialize, Deserialize, Clone)]
struct CacheEntry {
    timestamp: i64,
    vulnerabilities: Vec<Vulnerability>,
}

#[derive(Serialize, Deserialize, Default)]
struct CveCache {
    entries: HashMap<String, CacheEntry>,
}

fn get_cache_key(product: &str, version: &str) -> String {
    format!("{}:{}", product.to_lowercase(), version.to_lowercase())
}

fn load_cache() -> CveCache {
    if let Ok(content) = fs::read_to_string(CACHE_FILE) {
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        CveCache::default()
    }
}

fn save_cache(cache: &CveCache) -> Result<(), String> {
    let content = serde_json::to_string_pretty(cache).map_err(|e| e.to_string())?;
    fs::write(CACHE_FILE, content).map_err(|e| e.to_string())?;
    Ok(())
}

/// Retrieve vulnerabilities from cache if they exist and are not expired
pub fn get_cached_vulns(product: &str, version: &str) -> Option<Vec<Vulnerability>> {
    let cache = load_cache();
    let key = get_cache_key(product, version);

    if let Some(entry) = cache.entries.get(&key) {
        let now = Utc::now().timestamp();
        let expiry = Duration::days(CACHE_EXPIRY_DAYS).num_seconds();
        
        if now - entry.timestamp < expiry {
            return Some(entry.vulnerabilities.clone());
        }
    }
    None
}

/// Update the cache with fresh results
pub fn update_cache(product: &str, version: &str, vulnerabilities: Vec<Vulnerability>) -> Result<(), String> {
    let mut cache = load_cache();
    let key = get_cache_key(product, version);
    
    cache.entries.insert(key, CacheEntry {
        timestamp: Utc::now().timestamp(),
        vulnerabilities,
    });
    
    save_cache(&cache)
}