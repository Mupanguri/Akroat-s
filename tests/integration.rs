use port_sniffer::vuln::engine::*;
use port_sniffer::vuln::db::VulnDb;
use std::path::PathBuf;

use std::sync::atomic::{AtomicU32, Ordering};

static DB_COUNTER: AtomicU32 = AtomicU32::new(0);

fn temp_db_path() -> PathBuf {
    let mut p = std::env::temp_dir();
    let n = DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    p.push(format!("akroatis_test_{}_{}.db", std::process::id(), n));
    let _ = std::fs::remove_file(&p);
    p
}

#[test]
fn test_version_parse_and_order() {
    let v1 = Version::parse("2.4.38");
    let v2 = Version::parse("2.4.39");
    let v3 = Version::parse("2.4");
    assert!(v1 < v2);
    assert!(v1 > v3);
}

#[test]
fn test_version_non_numeric_segments() {
    let v = Version::parse("1.0.0-beta");
    assert!(v > Version::parse("0.9.0"));
    assert!(v < Version::parse("1.0.1"));
}

#[test]
fn test_version_empty_parse() {
    let v = Version::parse("");
    assert_eq!(v, Version(vec![0]));
}

#[test]
fn test_severity_ordering() {
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);
    assert!(Severity::Low > Severity::None);
}

#[test]
fn test_severity_parse() {
    assert_eq!(Severity::parse("CRITICAL"), Severity::Critical);
    assert_eq!(Severity::parse("High"), Severity::High);
    assert_eq!(Severity::parse("medium"), Severity::Medium);
    assert_eq!(Severity::parse("LOW"), Severity::Low);
    assert_eq!(Severity::parse("unknown"), Severity::None);
}

#[test]
fn test_cpe_index_insert_and_lookup() {
    let mut idx = CpeIndex::new();
    idx.insert("apache", "http_server", "CVE-2021-41773");
    idx.insert("apache", "http_server", "CVE-2021-42013");

    let results = idx.lookup("apache", "http_server").expect("No results");
    assert_eq!(results.len(), 2);
    assert!(results.contains(&"CVE-2021-41773".to_string()));
}

#[test]
fn test_cpe_index_empty_lookup() {
    let idx = CpeIndex::new();
    assert!(idx.lookup("nonexistent", "product").is_none());
}

#[test]
fn test_cve_exploit_index_insert_and_lookup() {
    let mut idx = CveExploitIndex::new();
    idx.insert("CVE-2021-41773", 51193);
    idx.insert("CVE-2021-41773", 51194);

    let results = idx.lookup("CVE-2021-41773").expect("No results");
    assert_eq!(results.len(), 2);
    assert!(results.contains(&51193));
}

#[test]
fn test_cve_exploit_index_empty() {
    let idx = CveExploitIndex::new();
    assert!(idx.lookup("CVE-0000-00000").is_none());
}

#[test]
fn test_exploit_record_access() {
    let exploit = ExploitRecord {
        edb_id: 51193,
        title: "Test".to_string(),
        platform: "linux".to_string(),
        exploit_type: "remote".to_string(),
        verified: true,
        url: "https://example.com".to_string(),
        author: Some("tester".to_string()),
        date: Some("2021-01-01".to_string()),
        cve_ids: vec!["CVE-2021-41773".to_string()],
    };
    assert_eq!(exploit.edb_id, 51193);
    assert!(exploit.verified);
    assert_eq!(exploit.cve_ids.len(), 1);
}

#[test]
fn test_engine_match_service_exact_version() {
    let mut engine = VulnEngine::new();
    engine.insert_vuln(VulnRecord {
        id: "CVE-2021-41773".to_string(),
        description: "Apache HTTP Server path traversal".to_string(),
        severity: Severity::High,
        cvss_score: Some(7.5),
        cvss_vector: None,
        affected_cpe: vec!["cpe:2.3:a:apache:http_server:2.4.38:*:*:*:*:*:*:*".to_string()],
        fixed_cpe: vec!["cpe:2.3:a:apache:http_server:2.4.39:*:*:*:*:*:*:*".to_string()],
        references: vec![],
        published_date: None,
        last_modified: None,
        exploits: vec![],
    });
    engine.finalize();

    // Affected version should match
    let results = engine.match_service("apache", "2.4.38", &Severity::None);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, "CVE-2021-41773");

    // Fixed version should NOT match
    let results = engine.match_service("apache", "2.4.39", &Severity::None);
    assert!(!results.iter().any(|r| r.id == "CVE-2021-41773"));

    // Unrelated product should NOT match
    let results = engine.match_service("nginx", "2.4.38", &Severity::None);
    assert!(!results.iter().any(|r| r.id == "CVE-2021-41773"));
}

#[test]
fn test_engine_match_service_min_severity_filter() {
    let mut engine = VulnEngine::new();
    engine.insert_vuln(VulnRecord {
        id: "CVE-2021-00001".to_string(),
        description: "Low severity test".to_string(),
        severity: Severity::Low,
        cvss_score: None,
        cvss_vector: None,
        affected_cpe: vec!["cpe:2.3:a:test:product:1.0:*:*:*:*:*:*:*".to_string()],
        fixed_cpe: vec![],
        references: vec![],
        published_date: None,
        last_modified: None,
        exploits: vec![],
    });
    engine.finalize();

    // With No filter, should match
    let results = engine.match_service("test", "1.0", &Severity::None);
    assert!(results.iter().any(|r| r.id == "CVE-2021-00001"));

    // With High filter, should NOT match Low severity
    let results = engine.match_service("test", "1.0", &Severity::High);
    assert!(!results.iter().any(|r| r.id == "CVE-2021-00001"));
}

#[test]
fn test_engine_match_service_multiple_cves() {
    let mut engine = VulnEngine::new();
    // Two CVEs affecting the same product
    engine.insert_vuln(VulnRecord {
        id: "CVE-2021-00001".to_string(),
        description: "Bug one".to_string(),
        severity: Severity::High,
        cvss_score: None,
        cvss_vector: None,
        affected_cpe: vec!["cpe:2.3:a:example:app:1.0:*:*:*:*:*:*:*".to_string()],
        fixed_cpe: vec![],
        references: vec![],
        published_date: None,
        last_modified: None,
        exploits: vec![],
    });
    engine.insert_vuln(VulnRecord {
        id: "CVE-2021-00002".to_string(),
        description: "Bug two".to_string(),
        severity: Severity::Critical,
        cvss_score: None,
        cvss_vector: None,
        affected_cpe: vec!["cpe:2.3:a:example:app:1.0:*:*:*:*:*:*:*".to_string()],
        fixed_cpe: vec![],
        references: vec![],
        published_date: None,
        last_modified: None,
        exploits: vec![],
    });
    engine.finalize();

    let results = engine.match_service("example", "1.0", &Severity::None);
    assert_eq!(results.len(), 2);
    // Should be sorted by severity descending
    assert_eq!(results[0].severity, Severity::Critical);
    assert_eq!(results[1].severity, Severity::High);
}

#[test]
fn test_engine_search_bm25() {
    let mut engine = VulnEngine::new();
    engine.insert_vuln(VulnRecord {
        id: "CVE-2021-41773".to_string(),
        description: "Apache HTTP Server path traversal vulnerability".to_string(),
        severity: Severity::High,
        cvss_score: None,
        cvss_vector: None,
        affected_cpe: vec![],
        fixed_cpe: vec![],
        references: vec![],
        published_date: None,
        last_modified: None,
        exploits: vec![],
    });
    engine.finalize();

    let filters = SearchFilters::default();
    let results = engine.search("apache traversal", &filters);
    assert!(!results.is_empty());
    assert_eq!(
        results[0].vuln.as_ref().map(|v| v.id.as_str()),
        Some("CVE-2021-41773")
    );
}

#[test]
fn test_engine_search_no_match() {
    let engine = VulnEngine::new();
    let filters = SearchFilters::default();
    let results = engine.search("nonexistent", &filters);
    assert!(results.is_empty());
}

#[test]
fn test_engine_exploit_by_id() {
    let mut engine = VulnEngine::new();
    engine.insert_exploit(ExploitRecord {
        edb_id: 51193,
        title: "Test Exploit".to_string(),
        platform: "linux".to_string(),
        exploit_type: "remote".to_string(),
        verified: true,
        url: "https://example.com".to_string(),
        author: None,
        date: None,
        cve_ids: vec!["CVE-2021-41773".to_string()],
    });

    let found = engine.exploit_by_id(51193);
    assert!(found.is_some());
    assert_eq!(found.unwrap().edb_id, 51193);

    assert!(engine.exploit_by_id(99999).is_none());
}

#[test]
fn test_engine_exploits_by_cve() {
    let mut engine = VulnEngine::new();
    engine.insert_exploit(ExploitRecord {
        edb_id: 51193,
        title: "Exploit for CVE".to_string(),
        platform: "linux".to_string(),
        exploit_type: "remote".to_string(),
        verified: true,
        url: "https://example.com".to_string(),
        author: None,
        date: None,
        cve_ids: vec!["CVE-2021-41773".to_string()],
    });

    let exploits = engine.exploits_by_cve("CVE-2021-41773");
    assert_eq!(exploits.len(), 1);
    assert_eq!(exploits[0].edb_id, 51193);
}

#[test]
fn test_engine_full_pipeline() {
    // Simulate the full pipeline: DB import → engine init → match
    
    // Step 1: Create a VulnRecord that mirrors an NVD entry
    let vuln = VulnRecord {
        id: "CVE-2021-41773".to_string(),
        description: "A path traversal vulnerability in Apache HTTP Server".to_string(),
        severity: Severity::High,
        cvss_score: Some(7.5),
        cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".to_string()),
        affected_cpe: vec![
            "cpe:2.3:a:apache:http_server:2.4.38:*:*:*:*:*:*:*".to_string(),
        ],
        fixed_cpe: vec![
            "cpe:2.3:a:apache:http_server:2.4.39:*:*:*:*:*:*:*".to_string(),
        ],
        references: vec![],
        published_date: Some("2021-10-05".to_string()),
        last_modified: None,
        exploits: vec![
            ExploitRecord {
                edb_id: 51193,
                title: "Apache 2.4.38 Path Traversal".to_string(),
                platform: "linux".to_string(),
                exploit_type: "remote".to_string(),
                verified: true,
                url: "https://www.exploit-db.com/exploits/51193".to_string(),
                author: Some("test".to_string()),
                date: Some("2021-10-05".to_string()),
                cve_ids: vec!["CVE-2021-41773".to_string()],
            },
        ],
    };

    // Step 2: Initialize engine with the vulnerability
    let mut engine = VulnEngine::new();
    engine.insert_vuln(vuln);
    engine.finalize();

    // Step 3: Match service "apache" version "2.4.38"
    let matches = engine.match_service("apache", "2.4.38", &Severity::None);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].id, "CVE-2021-41773");
    assert_eq!(matches[0].exploits.len(), 1);
    assert_eq!(matches[0].exploits[0].edb_id, 51193);

    // Step 4: Verify fixed version does not match
    let matches = engine.match_service("apache", "2.4.39", &Severity::High);
    assert!(!matches.iter().any(|r| r.id == "CVE-2021-41773"));
}

#[test]
fn test_vulndb_import_and_search() {
    let path = temp_db_path();
    let db = VulnDb::open(&path).expect("Failed to open temp DB");

    let exploit = ExploitRecord {
        edb_id: 51193,
        title: "Apache HTTP Server 2.4.49 - Path Traversal".to_string(),
        platform: "linux".to_string(),
        exploit_type: "remote".to_string(),
        verified: true,
        url: "https://www.exploit-db.com/exploits/51193".to_string(),
        author: Some("test".to_string()),
        date: Some("2021-10-05".to_string()),
        cve_ids: vec!["CVE-2021-41773".to_string()],
    };
    db.import_exploit(&exploit).expect("Failed to import exploit");

    assert_eq!(db.exploit_count().unwrap(), 1);

    let results = db.search_exploits("Apache", 10).expect("Search failed");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].edb_id, 51193);
    assert_eq!(results[0].cve_ids, vec!["CVE-2021-41773"]);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_vulndb_empty() {
    let path = temp_db_path();
    let db = VulnDb::open(&path).expect("Failed to open temp DB");
    assert_eq!(db.exploit_count().unwrap(), 0);
    assert_eq!(db.cve_count().unwrap(), 0);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_vulndb_cve_cache() {
    let path = temp_db_path();
    let db = VulnDb::open(&path).expect("Failed to open temp DB");

    assert!(db.cache_get("nonexistent").is_none());

    db.cache_set("test-key", r#"{"data": "test"}"#).expect("Cache set failed");
    let cached = db.cache_get("test-key");
    assert!(cached.is_some());
    assert_eq!(cached.unwrap(), r#"{"data": "test"}"#);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_version_interval_binary_search() {
    // Verify that sorted version_intervals allow correct binary search
    let mut engine = VulnEngine::new();

    // Insert CVEs with version intervals across a range
    for (i, ver) in ["1.0.0", "1.1.0", "1.2.0", "2.0.0", "2.1.0"].iter().enumerate() {
        engine.insert_vuln(VulnRecord {
            id: format!("CVE-2021-{:04}", i + 1),
            description: format!("Bug in version {}", ver),
            severity: Severity::Medium,
            cvss_score: None,
            cvss_vector: None,
            affected_cpe: vec![format!(
                "cpe:2.3:a:test:product:{}:*:*:*:*:*:*:*",
                ver
            )],
            fixed_cpe: vec![],
            references: vec![],
            published_date: None,
            last_modified: None,
            exploits: vec![],
        });
    }
    engine.finalize();

    // Query a version that falls between two CVEs
    let results = engine.match_service("test", "1.1.5", &Severity::None);
    // 1.1.0 affected_cpe means start=1.1.0, end=Unbounded → 1.1.5 > 1.1.0 should match
    assert!(results.iter().any(|r| r.id == "CVE-2021-0002"));

    // Query a version before all CVEs
    let results = engine.match_service("test", "0.5.0", &Severity::None);
    // 0.5.0 < 1.0.0 → no intervals have start <= 0.5.0
    assert!(!results.iter().any(|r| r.id.starts_with("CVE-2021-")));
}

#[test]
fn test_search_by_cve_id() {
    let path = temp_db_path();
    let db = VulnDb::open(&path).expect("Failed to open temp DB");

    let exploit = ExploitRecord {
        edb_id: 51193,
        title: "Apache Path Traversal".to_string(),
        platform: "linux".to_string(),
        exploit_type: "remote".to_string(),
        verified: true,
        url: "https://example.com/51193".to_string(),
        author: None,
        date: None,
        cve_ids: vec!["CVE-2021-41773".to_string()],
    };
    db.import_exploit(&exploit).expect("import failed");

    let results = db.search_by_cve("CVE-2021-41773").expect("search failed");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].edb_id, 51193);
    assert_eq!(results[0].cve_ids, vec!["CVE-2021-41773"]);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_search_by_cve_no_match() {
    let path = temp_db_path();
    let db = VulnDb::open(&path).expect("Failed to open temp DB");

    let results = db.search_by_cve("CVE-9999-99999").expect("search failed");
    assert!(results.is_empty());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_search_by_cve_case_insensitive() {
    let path = temp_db_path();
    let db = VulnDb::open(&path).expect("Failed to open temp DB");

    let exploit = ExploitRecord {
        edb_id: 51193,
        title: "Test".to_string(),
        platform: "linux".to_string(),
        exploit_type: "remote".to_string(),
        verified: true,
        url: "https://example.com".to_string(),
        author: None,
        date: None,
        cve_ids: vec!["CVE-2021-41773".to_string()],
    };
    db.import_exploit(&exploit).expect("import failed");

    // search_by_cve uses LIKE which is case-insensitive for ASCII by default
    let results = db.search_by_cve("cve-2021-41773").expect("search failed");
    assert_eq!(results.len(), 1, "LIKE should match case-insensitively");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_vulnerability_info_struct() {
    let v = port_sniffer::VulnerabilityInfo {
        cve_id: "CVE-2021-41773".to_string(),
        severity: "High".to_string(),
        cvss_score: Some(7.5),
        description: "Path traversal".to_string(),
        exploit_count: 2,
    };
    assert_eq!(v.cve_id, "CVE-2021-41773");
    assert_eq!(v.severity, "High");
    assert_eq!(v.cvss_score, Some(7.5));
}

#[test]
fn test_engine_match_service_wired_to_port_result() {
    // Verify that the engine can be populated from DB and used for matching
    // (simulates what the scan pipeline does)
    let path = temp_db_path();
    let db = VulnDb::open(&path).expect("Failed to open temp DB");

    // Import an exploit with CVE
    let exploit = ExploitRecord {
        edb_id: 51193,
        title: "Apache 2.4.38 Path Traversal".to_string(),
        platform: "linux".to_string(),
        exploit_type: "remote".to_string(),
        verified: true,
        url: "https://example.com/51193".to_string(),
        author: None,
        date: None,
        cve_ids: vec!["CVE-2021-41773".to_string()],
    };
    db.import_exploit(&exploit).expect("import failed");

    // Import a CVE (the cve_index table stores NVD-like data)
    let vuln = VulnRecord {
        id: "CVE-2021-41773".to_string(),
        description: "Apache HTTP Server path traversal".to_string(),
        severity: Severity::High,
        cvss_score: Some(7.5),
        cvss_vector: None,
        affected_cpe: vec!["cpe:2.3:a:apache:http_server:2.4.38:*:*:*:*:*:*:*".to_string()],
        fixed_cpe: vec!["cpe:2.3:a:apache:http_server:2.4.39:*:*:*:*:*:*:*".to_string()],
        references: vec![],
        published_date: None,
        last_modified: None,
        exploits: vec![exploit],
    };
    db.import_cve(&vuln).expect("CVE import failed");

    // Verify CVE was imported
    assert_eq!(db.cve_count().unwrap(), 1, "CVE should be in the database");

    // Build engine from DB (same as scan pipeline)
    let mut engine = VulnEngine::new();
    port_sniffer::vuln::exploit::import_into_engine(&mut engine, &db);
    let engine = std::sync::Arc::new(engine);
    port_sniffer::vuln::exploit::set_engine(engine);

    // Access engine and match service
    let engine = port_sniffer::vuln::exploit::get_engine().expect("engine not set");
    let results = engine.match_service("apache", "2.4.38", &Severity::None);
    assert_eq!(results.len(), 1, "Should match Apache 2.4.38 to CVE-2021-41773");
    assert_eq!(results[0].id, "CVE-2021-41773");

    // Exploit is linked via cve_exploit_index, not embedded in VulnRecord
    let exploits = engine.exploits_by_cve("CVE-2021-41773");
    assert_eq!(exploits.len(), 1);
    assert_eq!(exploits[0].edb_id, 51193);

    // Simulate building a PortResult with matched CVEs (realistic product name)
    let mut port_result = port_sniffer::PortResult::new(
        80, true,
        Some(port_sniffer::ServiceInfo {
            name: "HTTP".to_string(),
            version: Some("2.4.38".to_string()),
            product: Some("Apache HTTP Server".to_string()),
            extrainfo: None,
            cpe: None,
        }),
        None, None, vec![],
    );
    for v in engine.match_service("Apache HTTP Server", "2.4.38", &Severity::None) {
        port_result.vulnerabilities.push(port_sniffer::VulnerabilityInfo {
            cve_id: v.id.clone(),
            severity: format!("{:?}", v.severity),
            cvss_score: v.cvss_score,
            description: v.description.clone(),
            exploit_count: exploits.len(),
        });
    }
    assert_eq!(port_result.vulnerabilities.len(), 1);
    assert_eq!(port_result.vulnerabilities[0].cve_id, "CVE-2021-41773");
    assert_eq!(port_result.vulnerabilities[0].exploit_count, 1);

    let _ = std::fs::remove_file(&path);
}
