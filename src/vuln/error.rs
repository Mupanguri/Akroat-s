use std::fmt;

/// Errors that can occur in the vulnerability subsystem
#[derive(Debug, Clone)]
pub enum VulnError {
    DbOpen(String),
    DbExecute(String),
    DbQuery(String),
    Import(String),
    CacheExpired,
    CacheFull,
    Serde(String),
    NotFound(String),
    ApiRateLimited(String),
    Network(String),
}

impl fmt::Display for VulnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VulnError::DbOpen(msg) => write!(f, "Failed to open database: {}", msg),
            VulnError::DbExecute(msg) => write!(f, "Database execute error: {}", msg),
            VulnError::DbQuery(msg) => write!(f, "Database query error: {}", msg),
            VulnError::Import(msg) => write!(f, "Import error: {}", msg),
            VulnError::CacheExpired => write!(f, "Cache entry expired"),
            VulnError::CacheFull => write!(f, "Cache is full"),
            VulnError::Serde(msg) => write!(f, "Serialization error: {}", msg),
            VulnError::NotFound(msg) => write!(f, "Not found: {}", msg),
            VulnError::ApiRateLimited(msg) => write!(f, "API rate limited: {}", msg),
            VulnError::Network(msg) => write!(f, "Network error: {}", msg),
        }
    }
}

impl std::error::Error for VulnError {}

impl From<rusqlite::Error> for VulnError {
    fn from(e: rusqlite::Error) -> Self {
        VulnError::DbExecute(e.to_string())
    }
}

impl From<serde_json::Error> for VulnError {
    fn from(e: serde_json::Error) -> Self {
        VulnError::Serde(e.to_string())
    }
}

impl From<std::sync::PoisonError<std::sync::MutexGuard<'_, rusqlite::Connection>>> for VulnError {
    fn from(e: std::sync::PoisonError<std::sync::MutexGuard<'_, rusqlite::Connection>>) -> Self {
        VulnError::DbExecute(e.to_string())
    }
}
