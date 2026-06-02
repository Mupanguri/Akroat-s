use rusqlite::{Connection, params, OpenFlags};
use std::path::PathBuf;
use std::sync::Mutex;

use crate::config::Config;
use crate::vuln::engine::{ExploitRecord, VulnRecord};
use crate::vuln::error::VulnError;

/// Path to the exploit database
pub fn db_path() -> PathBuf {
    let mut p = Config::path();
    p.set_file_name("exploit.db");
    p
}

/// Thread-safe wrapper around SQLite connection
pub struct VulnDb {
    pub(crate) conn: Mutex<Connection>,
}

impl VulnDb {
    /// Open or create the database
    pub fn open(path: &PathBuf) -> Result<Self, VulnError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| VulnError::DbOpen(e.to_string()))?;
        }

        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| VulnError::DbOpen(e.to_string()))?;

        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .map_err(|e| VulnError::DbOpen(e.to_string()))?;

        let db = Self { conn: Mutex::new(conn) };
        db.initialize()?;
        Ok(db)
    }

    fn initialize(&self) -> Result<(), VulnError> {
        let conn = self.conn.lock().map_err(|e| VulnError::DbExecute(e.to_string()))?;
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS exploits (
                edb_id INTEGER PRIMARY KEY,
                title TEXT NOT NULL,
                platform TEXT NOT NULL DEFAULT '',
                exploit_type TEXT NOT NULL DEFAULT '',
                verified INTEGER NOT NULL DEFAULT 0,
                url TEXT NOT NULL DEFAULT '',
                author TEXT,
                date TEXT,
                cve_ids TEXT NOT NULL DEFAULT '[]'
            );

            CREATE VIRTUAL TABLE IF NOT EXISTS exploits_fts USING fts5(
                title, edb_id UNINDEXED
            );

            CREATE TABLE IF NOT EXISTS cve_cache (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL,
                timestamp INTEGER NOT NULL,
                access_count INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_cve_cache_ts ON cve_cache(timestamp);

            CREATE TABLE IF NOT EXISTS cve_index (
                cve_id TEXT PRIMARY KEY,
                product TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                severity TEXT NOT NULL DEFAULT 'NONE',
                cvss_score REAL,
                cvss_vector TEXT,
                affected_cpe TEXT NOT NULL DEFAULT '[]',
                fixed_cpe TEXT NOT NULL DEFAULT '[]',
                refs TEXT NOT NULL DEFAULT '[]',
                published_date TEXT,
                last_modified TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_cve_product ON cve_index(product);

            CREATE TABLE IF NOT EXISTS cpe_mappings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cpe TEXT NOT NULL,
                cve_id TEXT NOT NULL,
                version_start TEXT,
                version_end TEXT,
                version_type TEXT NOT NULL DEFAULT '='
            );

            CREATE INDEX IF NOT EXISTS idx_cpe ON cpe_mappings(cpe);
            CREATE INDEX IF NOT EXISTS idx_cpe_cve ON cpe_mappings(cve_id);
            ",
        )
        .map_err(|e| VulnError::DbExecute(e.to_string()))?;
        Ok(())
    }

    /// Import a single exploit record from files.csv
    pub fn import_exploit(&self, record: &ExploitRecord) -> Result<(), VulnError> {
        let conn = self.conn.lock().map_err(|e| VulnError::DbExecute(e.to_string()))?;
        let cve_ids_json = serde_json::to_string(&record.cve_ids)?;

        conn.execute(
            "INSERT OR REPLACE INTO exploits (edb_id, title, platform, exploit_type, verified, url, author, date, cve_ids)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                record.edb_id,
                record.title,
                record.platform,
                record.exploit_type,
                record.verified as i32,
                record.url,
                record.author,
                record.date,
                cve_ids_json,
            ],
        )?;

        conn.execute(
            "INSERT OR REPLACE INTO exploits_fts (edb_id, title) VALUES (?1, ?2)",
            params![record.edb_id, record.title],
        )?;

        Ok(())
    }

    /// Import a CVE/vulnerability record
    pub fn import_cve(&self, record: &VulnRecord) -> Result<(), VulnError> {
        let conn = self.conn.lock().map_err(|e| VulnError::DbExecute(e.to_string()))?;

        let product = record
            .affected_cpe
            .first()
            .and_then(|cpe| cpe.split(':').nth(4))
            .unwrap_or("unknown");

        let affected_cpe_json = serde_json::to_string(&record.affected_cpe)?;
        let fixed_cpe_json = serde_json::to_string(&record.fixed_cpe)?;
        let refs_json = serde_json::to_string(&record.references)?;

        conn.execute(
            "INSERT OR REPLACE INTO cve_index (cve_id, product, description, severity, cvss_score, cvss_vector, affected_cpe, fixed_cpe, refs, published_date, last_modified)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                record.id,
                product,
                record.description,
                format!("{:?}", record.severity),
                record.cvss_score,
                record.cvss_vector,
                affected_cpe_json,
                fixed_cpe_json,
                refs_json,
                record.published_date,
                record.last_modified,
            ],
        )?;

        Ok(())
    }

    /// Query NVD cache for a key
    pub fn cache_get(&self, key: &str) -> Option<String> {
        let conn = self.conn.lock().ok()?;
        let now = chrono::Utc::now().timestamp();
        let expiry = 7 * 24 * 3600;

        let result: Result<(Vec<u8>, i64, i32), _> = conn.query_row(
            "SELECT value, timestamp, access_count FROM cve_cache WHERE key = ?1",
            params![key],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i32>(2)?,
                ))
            },
        );

        match result {
            Ok((value, ts, _count)) => {
                if now - ts < expiry {
                    let _ = conn.execute(
                        "UPDATE cve_cache SET access_count = access_count + 1 WHERE key = ?1",
                        params![key],
                    );
                    String::from_utf8(value).ok()
                } else {
                    let _ = conn.execute("DELETE FROM cve_cache WHERE key = ?1", params![key]);
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Store in NVD cache
    pub fn cache_set(&self, key: &str, value: &str) -> Result<(), VulnError> {
        let conn = self.conn.lock().map_err(|e| VulnError::DbExecute(e.to_string()))?;
        let now = chrono::Utc::now().timestamp();

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM cve_cache", [], |row| row.get(0))
            .unwrap_or(0);

        if count >= 1000 {
            conn.execute(
                "DELETE FROM cve_cache WHERE rowid IN (
                    SELECT rowid FROM cve_cache ORDER BY access_count ASC, timestamp ASC LIMIT 100
                )",
                [],
            )?;
        }

        conn.execute(
            "INSERT OR REPLACE INTO cve_cache (key, value, timestamp, access_count) VALUES (?1, ?2, ?3, 0)",
            params![key, value.as_bytes(), now],
        )?;

        Ok(())
    }

    /// Search exploits using FTS5
    pub fn search_exploits(&self, query: &str, limit: usize) -> Result<Vec<ExploitRecord>, VulnError> {
        let conn = self.conn.lock().map_err(|e| VulnError::DbExecute(e.to_string()))?;

        let fts_query: String = query
            .split_whitespace()
            .map(|w| format!("\"{}\"", w.replace('"', "")))
            .collect::<Vec<_>>()
            .join(" OR ");

        let mut stmt = conn
            .prepare(
                "SELECT e.edb_id, e.title, e.platform, e.exploit_type, e.verified, e.url, e.author, e.date, e.cve_ids
                 FROM exploits_fts f
                 JOIN exploits e ON f.edb_id = e.edb_id
                 WHERE exploits_fts MATCH ?1
                 ORDER BY rank
                 LIMIT ?2",
            )
            .map_err(VulnError::from)?;

        let results = stmt
            .query_map(params![fts_query, limit as i64], |row| {
                let cve_ids_json: String = row.get(8)?;
                let cve_ids: Vec<String> =
                    serde_json::from_str(&cve_ids_json).unwrap_or_default();

                Ok(ExploitRecord {
                    edb_id: row.get(0)?,
                    title: row.get(1)?,
                    platform: row.get(2)?,
                    exploit_type: row.get(3)?,
                    verified: row.get::<_, i32>(4)? != 0,
                    url: row.get(5)?,
                    author: row.get(6)?,
                    date: row.get(7)?,
                    cve_ids,
                })
            })
            .map_err(VulnError::from)?
            .filter_map(|r| r.ok())
            .collect();

        Ok(results)
    }

    /// Get exploit count
    pub fn exploit_count(&self) -> Result<i64, VulnError> {
        let conn = self.conn.lock().map_err(|e| VulnError::DbExecute(e.to_string()))?;
        conn.query_row("SELECT COUNT(*) FROM exploits", [], |row| row.get(0))
            .map_err(|e| VulnError::DbQuery(e.to_string()))
    }

    /// Get CVE count
    pub fn cve_count(&self) -> Result<i64, VulnError> {
        let conn = self.conn.lock().map_err(|e| VulnError::DbExecute(e.to_string()))?;
        conn.query_row("SELECT COUNT(*) FROM cve_index", [], |row| row.get(0))
            .map_err(|e| VulnError::DbQuery(e.to_string()))
    }

    /// Search exploits by CVE ID (looks in the cve_ids JSON array)
    pub fn search_by_cve(&self, cve_id: &str) -> Result<Vec<ExploitRecord>, VulnError> {
        let conn = self.conn.lock().map_err(|e| VulnError::DbExecute(e.to_string()))?;
        let pattern = format!("%{}%", cve_id);
        let mut stmt = conn
            .prepare(
                "SELECT edb_id, title, platform, exploit_type, verified, url, author, date, cve_ids
                 FROM exploits WHERE cve_ids LIKE ?1",
            )
            .map_err(VulnError::from)?;

        let results = stmt
            .query_map(params![pattern], |row| {
                let cve_ids_json: String = row.get(8)?;
                let cve_ids: Vec<String> =
                    serde_json::from_str(&cve_ids_json).unwrap_or_default();
                Ok(ExploitRecord {
                    edb_id: row.get(0)?,
                    title: row.get(1)?,
                    platform: row.get(2)?,
                    exploit_type: row.get(3)?,
                    verified: row.get::<_, i32>(4)? != 0,
                    url: row.get(5)?,
                    author: row.get(6)?,
                    date: row.get(7)?,
                    cve_ids,
                })
            })
            .map_err(VulnError::from)?
            .filter_map(|r| r.ok())
            .collect();

        Ok(results)
    }
}
