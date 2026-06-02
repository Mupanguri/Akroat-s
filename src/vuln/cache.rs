use crate::vuln::db::VulnDb;
use crate::vuln::error::VulnError;
use crate::vuln::nvd::Vulnerability;

use std::sync::Mutex;
static GLOBAL_DB: Mutex<Option<VulnDb>> = Mutex::new(None);

/// Initialize the global cache with a VulnDb
pub fn init_cache(db: VulnDb) {
    if let Ok(mut g) = GLOBAL_DB.lock() {
        *g = Some(db);
    }
}

/// Retrieve vulnerabilities from SQLite cache
pub fn get_cached_vulns(product: &str, version: &str) -> Option<Vec<Vulnerability>> {
    let key = format!("{}:{}", product.to_lowercase(), version.to_lowercase());
    let db = GLOBAL_DB.lock().ok()?;
    let db = db.as_ref()?;
    let cached = db.cache_get(&key)?;
    serde_json::from_str(&cached).ok()
}

/// Update the SQLite cache with fresh results
pub fn update_cache(product: &str, version: &str, vulnerabilities: Vec<Vulnerability>) -> Result<(), VulnError> {
    let key = format!("{}:{}", product.to_lowercase(), version.to_lowercase());
    let db = GLOBAL_DB.lock().map_err(|e| VulnError::DbExecute(e.to_string()))?;
    if let Some(ref db) = *db {
        let json = serde_json::to_string(&vulnerabilities)?;
        db.cache_set(&key, &json)?;
    }
    Ok(())
}
