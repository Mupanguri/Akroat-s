use std::env;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process;
use std::str::FromStr;
use std::time::Duration;
use ipnetwork::IpNetwork;
use tracing_subscriber::EnvFilter;
use serde_json::Value;

use std::sync::Arc;
use port_sniffer::{config::Config, scan_ports, ScanConfig};
use port_sniffer::vuln::{db::VulnDb, engine::VulnEngine, search::{SploitQuery, parse_query}};

fn usage(program: &str) {
    eprintln!(
        "Usage:
  {program} [options] <ipaddr>           Scan target IP
  {program} search <query>               Search exploit database
  {program} update-db [--file <path>]    Import exploit-db files.csv
  {program} update-db --download-cves    Import CVEs from NVD

Scan options:
  -j <n>              Number of threads (default: 4)
  --port-range <r>    Port range (e.g. 22,80,443 or 1-1000)
  --no-service        Disable service detection
  --deep              Enable deep inspection
  --syn               SYN scan (admin/Npcap required)
  --udp               Enable UDP scan
  --json              Output JSON",
        program = program
    );
}

struct ScanArguments {
    ipaddr: IpAddr,
    threads: u16,
    enable_service_detection: bool,
    deep_inspection: bool,
    syn_scan: bool,
    udp_scan: bool,
    ports: Option<Vec<u16>>,
    output_json: bool,
}

fn parse_port_range(s: &str) -> Result<Vec<u16>, &'static str> {
    let mut ports = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() { continue; }
        if let Some((start, end)) = part.split_once('-') {
            let lo = start.trim().parse::<u16>().map_err(|_| "Invalid port in range")?;
            let hi = end.trim().parse::<u16>().map_err(|_| "Invalid port in range")?;
            if lo > hi { return Err("Range start > end"); }
            for p in lo..=hi { ports.push(p); }
        } else {
            ports.push(part.parse::<u16>().map_err(|_| "Invalid port number")?);
        }
    }
    if ports.is_empty() { return Err("Empty port range"); }
    Ok(ports)
}

impl ScanArguments {
    fn parse(args: &[String], i: &mut usize) -> Result<ScanArguments, &'static str> {
        let mut threads = 4;
        let mut enable_service_detection = true;
        let mut deep_inspection = false;
        let mut syn_scan = false;
        let mut udp_scan = false;
        let mut ipaddr_str = String::new();
        let mut ports: Option<Vec<u16>> = None;
        let mut output_json = false;

        while *i < args.len() {
            match args[*i].as_str() {
                "-j" => {
                    if *i + 1 >= args.len() { return Err("-j requires <threads>"); }
                    threads = args[*i + 1].parse::<u16>().map_err(|_| "Invalid threads")?;
                    *i += 2;
                }
                "--port-range" => {
                    if *i + 1 >= args.len() { return Err("--port-range requires argument"); }
                    ports = Some(parse_port_range(&args[*i + 1])?);
                    *i += 2;
                }
                "--no-service" => { enable_service_detection = false; *i += 1; }
                "--deep" => { deep_inspection = true; *i += 1; }
                "--syn" => { syn_scan = true; *i += 1; }
                "--udp" => { udp_scan = true; *i += 1; }
                "--json" => { output_json = true; *i += 1; }
                arg => {
                    if !ipaddr_str.is_empty() { return Err("Only one IP address allowed"); }
                    ipaddr_str = arg.to_string();
                    *i += 1;
                }
            }
        }

        if ipaddr_str.is_empty() { return Err("No IP address specified"); }
        let ipaddr = IpAddr::from_str(&ipaddr_str).map_err(|_| "Invalid IP address")?;

        Ok(ScanArguments {
            ipaddr, threads, enable_service_detection,
            deep_inspection, syn_scan, udp_scan, ports, output_json,
        })
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_new("info").unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let _cfg = Config::load();
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    if args.len() < 2 {
        usage(&program);
        process::exit(1);
    }

    match args[1].as_str() {
        "search" => cmd_search(&args[2..]),
        "update-db" => cmd_update_db(&args[2..]).await,
        _ => cmd_scan(&program, &args).await,
    }
}

fn cmd_search(query_args: &[String]) {
    if query_args.is_empty() {
        eprintln!("Usage: akroatis search <query>");
        eprintln!("  Queries: CVE-ID (CVE-2021-41773), EDB-ID (EDB-51193),");
        eprintln!("           service:version (apache:2.4.38), keyword (linux rce)");
        process::exit(1);
    }

    let query_str = query_args.join(" ");
    let db_path = port_sniffer::vuln::db::db_path();

    match VulnDb::open(&db_path) {
        Ok(db) => {
            let query = parse_query(&query_str);
            match query {
                SploitQuery::Keyword(kw) | SploitQuery::Combined { text: kw, .. } => {
                    match db.search_exploits(&kw, 20) {
                        Ok(results) => {
                            if results.is_empty() {
                                println!("No results found for '{}'", kw);
                            } else {
                                println!("Found {} result(s) for '{}':\n", results.len(), kw);
                                for r in &results {
                                    let verified = if r.verified { "[VERIFIED]" } else { "" };
                                    println!("  EDB-{} {} {}", r.edb_id, r.title, verified);
                                    println!("         Platform: {} | Type: {}", r.platform, r.exploit_type);
                                    println!("         URL: {}", r.url);
                                    if !r.cve_ids.is_empty() {
                                        println!("         CVEs: {}", r.cve_ids.join(", "));
                                    }
                                    println!();
                                }
                            }
                        }
                        Err(e) => eprintln!("Search error: {}", e),
                    }
                }
                SploitQuery::CveId(ref cve) => {
                    match db.search_by_cve(cve) {
                        Ok(results) => {
                            if results.is_empty() {
                                println!("No exploits found for {}", cve);
                            } else {
                                println!("Found {} exploit(s) for {}:\n", results.len(), cve);
                                for r in &results {
                                    let verified = if r.verified { "[VERIFIED]" } else { "" };
                                    println!("  EDB-{} {} {}", r.edb_id, r.title, verified);
                                    println!("         URL: {}", r.url);
                                    println!();
                                }
                            }
                        }
                        Err(e) => eprintln!("Search error: {}", e),
                    }
                }
                SploitQuery::EdbId(edb) => {
                    match db.search_exploits(&edb.to_string(), 1) {
                        Ok(results) if !results.is_empty() => {
                            let r = &results[0];
                            let verified = if r.verified { "[VERIFIED]" } else { "" };
                            println!("EDB-{} {} {}", r.edb_id, r.title, verified);
                            println!("  Platform: {}", r.platform);
                            println!("  Type: {}", r.exploit_type);
                            println!("  Author: {}", r.author.as_deref().unwrap_or("unknown"));
                            println!("  Date: {}", r.date.as_deref().unwrap_or("unknown"));
                            println!("  URL: {}", r.url);
                            if !r.cve_ids.is_empty() {
                                println!("  CVEs: {}", r.cve_ids.join(", "));
                            }
                        }
                        _ => println!("No exploit found for EDB-{}", edb),
                    }
                }
                SploitQuery::ServiceVersion { ref product, ref version } => {
                    let mut engine = VulnEngine::new();
                    port_sniffer::vuln::exploit::import_into_engine(&mut engine, &db);
                    let results = engine.match_service(product, version, &port_sniffer::vuln::engine::Severity::None);
                    if !results.is_empty() {
                        println!("Found {} vulnerability(ies) for {} {}:\n", results.len(), product, version);
                        for v in &results {
                            let score_str = v.cvss_score.map(|s| format!("{:.1}", s)).unwrap_or_default();
                            println!("  {} ({:?}) CVSS:{}", v.id, v.severity, score_str);
                            println!("         {}", v.description);
                            let exploits = engine.exploits_by_cve(&v.id);
                            if !exploits.is_empty() {
                                println!("         {} exploit(s) available", exploits.len());
                                for e in &exploits {
                                    println!("           EDB-{} {}", e.edb_id, e.title);
                                }
                            }
                            println!();
                        }
                    } else if engine.version_intervals.is_empty() {
                        // No NVD CVE data — fall back to FTS5 exploit title search
                        let kw = format!("{} {}", product, version);
                        match db.search_exploits(&kw, 20) {
                            Ok(results) if !results.is_empty() => {
                                println!("No structured CVE data available. Showing {} exploit(s) matching '{}':\n",
                                    results.len(), kw);
                                for r in &results {
                                    let verified = if r.verified { "[VERIFIED]" } else { "" };
                                    println!("  EDB-{} {} {}", r.edb_id, r.title, verified);
                                    println!("         Platform: {} | Type: {}", r.platform, r.exploit_type);
                                    println!("         URL: {}", r.url);
                                    if !r.cve_ids.is_empty() {
                                        println!("         CVEs: {}", r.cve_ids.join(", "));
                                    }
                                    println!();
                                }
                            }
                            Ok(_) => println!("No exploits or vulnerabilities found for {} {}", product, version),
                            Err(e) => eprintln!("Search error: {}", e),
                        }
                    } else {
                        println!("No vulnerabilities found for {} {}", product, version);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to open database: {}", e);
            eprintln!("Run 'akroatis update-db' to initialize the database.");
            process::exit(1);
        }
    }
}

/// Simple CSV line parser that handles quoted fields
fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if chars.peek() == Some(&'"') => { current.push('"'); chars.next(); }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                fields.push(current.trim().to_string());
                current = String::new();
            }
            c => current.push(c),
        }
    }
    fields.push(current.trim().to_string());
    fields
}

const EXPLOITDB_URL: &str = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv";

fn download_csv(url: &str) -> Result<String, String> {
    let url = url.to_string();
    // Spawn a thread to avoid tokio runtime conflict (reqwest::blocking
    // creates its own runtime, which can't nest inside #[tokio::main])
    std::thread::spawn(move || -> Result<String, String> {
        let resp = reqwest::blocking::get(&url)
            .map_err(|e| format!("Download failed: {}", e))?;
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }
        resp.text().map_err(|e| format!("Read response failed: {}", e))
    })
    .join()
    .map_err(|_| "Download thread panicked".to_string())?
}

fn import_csv_content(db: &VulnDb, content: &str, source: &str) {
    let mut imported = 0;
    for line in content.lines().skip(1) {
        if line.trim().is_empty() { continue; }

        let fields = parse_csv_line(line);
        if fields.len() < 4 { continue; }

        let edb_id: u32 = match fields[0].trim().parse() {
            Ok(id) => id,
            Err(_) => continue,
        };

        let cve_ids: Vec<String> = fields
            .get(11)
            .map(|codes| {
                codes
                    .split(';')
                    .filter_map(|c| {
                        let c = c.trim();
                        if c.len() >= 10
                            && c[..3].eq_ignore_ascii_case("cve")
                            && c.contains('-')
                        {
                            Some(c.to_uppercase())
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        // files_exploits.csv columns (0-indexed):
        // 0:id, 1:file, 2:description, 3:date, 4:author, 5:platform,
        // 6:type, 7:port, 8:date_added, 9:date_updated, 10:verified,
        // 11:codes(CVE), 12:tags, 13:raw_url
        let record = port_sniffer::vuln::engine::ExploitRecord {
            edb_id,
            title: fields.get(2).cloned().unwrap_or_default(),
            platform: fields.get(5).cloned().unwrap_or_default(),
            exploit_type: fields.get(6).cloned().unwrap_or_default(),
            verified: fields.get(10).map(|s| s.trim() == "1").unwrap_or(false),
            url: format!("https://www.exploit-db.com/exploits/{}", edb_id),
            author: fields.get(4).cloned(),
            date: fields.get(3).cloned(),
            cve_ids,
        };

        if db.import_exploit(&record).is_ok() {
            imported += 1;
        }
    }
    println!("Imported {} exploits from {}", imported, source);
}

async fn cmd_update_db(args: &[String]) {
    let mut file_path: Option<PathBuf> = None;
    let mut download = false;
    let mut download_cves = false;
    let mut since: Option<String> = None;
    let mut api_key: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--file" => {
                if i + 1 >= args.len() {
                    eprintln!("--file requires a path");
                    process::exit(1);
                }
                file_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--download" => {
                download = true;
                i += 1;
            }
            "--download-cves" => {
                download_cves = true;
                i += 1;
            }
            "--since" => {
                if i + 1 >= args.len() {
                    eprintln!("--since requires a date (YYYY-MM-DD)");
                    process::exit(1);
                }
                since = Some(args[i + 1].clone());
                i += 2;
            }
            "--api-key" => {
                if i + 1 >= args.len() {
                    eprintln!("--api-key requires a value");
                    process::exit(1);
                }
                api_key = Some(args[i + 1].clone());
                i += 2;
            }
            "--reset" => {
                println!("Resetting database...");
                let db_path = port_sniffer::vuln::db::db_path();
                let _ = std::fs::remove_file(&db_path);
                let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
                let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
                println!("Database deleted.");
                return;
            }
            "--info" => {
                let db_path = port_sniffer::vuln::db::db_path();
                match VulnDb::open(&db_path) {
                    Ok(db) => print_db_stats(&db),
                    Err(e) => eprintln!("Database not found (run update-db first): {}", e),
                }
                return;
            }
            "-h" | "--help" => {
                println!("Usage: akroatis update-db [options]");
                println!("  --file <path>      Path to exploit-db files_exploits.csv");
                println!("  --download         Download exploits from exploit-db GitLab");
                println!("  --download-cves    Download CVEs from NVD API");
                println!("  --since <date>     Only fetch CVEs published after this date (YYYY-MM-DD)");
                println!("  --api-key <key>    NVD API key (increases rate limit to 50 req/30s)");
                println!("  --info             Show database stats");
                println!("  --reset            Delete the database and start fresh");
                println!();
                println!("Without options, initializes an empty database.");
                return;
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                process::exit(1);
            }
        }
    }

    let db_path = port_sniffer::vuln::db::db_path();
    println!("Initializing vulnerability database at {:?}", db_path);

    match VulnDb::open(&db_path) {
        Ok(db) => {
            if let Some(ref path) = file_path {
                let content = match std::fs::read_to_string(&path) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Failed to read {}: {}", path.display(), e);
                        process::exit(1);
                    }
                };
                import_csv_content(&db, &content, &path.display().to_string());
            } else if download {
                println!("Downloading files.csv from {}", EXPLOITDB_URL);
                match download_csv(EXPLOITDB_URL) {
                    Ok(content) => {
                        println!("Downloaded {} lines. Importing...", content.lines().count());
                        import_csv_content(&db, &content, EXPLOITDB_URL);
                    }
                    Err(e) => {
                        eprintln!("Failed to download exploit database: {}", e);
                        process::exit(1);
                    }
                }
            } else if download_cves {
                import_nvd_cves(&db, since.as_deref(), api_key.as_deref()).await;
            } else {
                println!("Database initialized (empty). Use --file or --download to import exploits.");
            }

            // Rebuild engine after import
            if download_cves || download || file_path.is_some() {
                let mut engine = VulnEngine::new();
                port_sniffer::vuln::exploit::import_into_engine(&mut engine, &db);
                port_sniffer::vuln::exploit::set_engine(Arc::new(engine));
                println!("Engine rebuilt with imported data.");
            }

            print_db_stats(&db);
        }
        Err(e) => {
            eprintln!("Failed to initialize database: {}", e);
            process::exit(1);
        }
    }
}

/// Fetch CVEs from the NVD API 2.0 and import them into the database
async fn import_nvd_cves(db: &VulnDb, since: Option<&str>, api_key: Option<&str>) {
    let delay_secs = if api_key.is_some() { 0.7 } else { 6.5 };
    let results_per_page = 2000;
    let mut start_index = 0;
    let mut total_imported = 0;

    println!("Fetching CVEs from NVD API...");
    if api_key.is_some() {
        println!("  API key provided — rate limit: 50 req/30s");
    } else {
        println!("  No API key — rate limit: 5 req/30s (use --api-key for faster import)");
    }
    if let Some(s) = since {
        println!("  Filtering by publication date >= {}", s);
    }

    loop {
        let url = build_nvd_url(start_index, results_per_page, since, api_key.is_some());
        println!("  Fetching page {} (offset={})...", (start_index / results_per_page) + 1, start_index);

        let client = reqwest::Client::new();
        let mut req = client.get(&url);
        if let Some(key) = api_key {
            req = req.header("apiKey", key);
        }

        let response = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  HTTP request failed: {}", e);
                break;
            }
        };

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            eprintln!("  NVD API error: HTTP {} — {}", status, body);
            break;
        }

        let json: Value = match response.json().await {
            Ok(j) => j,
            Err(e) => {
                eprintln!("  Failed to parse NVD response: {}", e);
                break;
            }
        };

        let total_results = json["totalResults"].as_u64().unwrap_or(0);
        let vulnerabilities = json["vulnerabilities"].as_array().map(|a| a.len()).unwrap_or(0);
        println!("  Got {} vulnerabilities (total: {})", vulnerabilities, total_results);

        if vulnerabilities == 0 {
            break;
        }

        if let Some(items) = json["vulnerabilities"].as_array() {
            for item in items {
                if let Some(cve_obj) = item.get("cve") {
                    if let Some(record) = parse_nvd_cve_item(cve_obj) {
                        if db.import_cve(&record).is_ok() {
                            total_imported += 1;
                        }
                    }
                }
            }
        }

        start_index += results_per_page;
        if start_index as u64 >= total_results {
            break;
        }

        // Rate limiting
        tokio::time::sleep(Duration::from_secs_f64(delay_secs)).await;
    }

    println!("\nImported {} CVEs from NVD.", total_imported);
}

fn build_nvd_url(start_index: usize, results_per_page: usize, since: Option<&str>, _has_key: bool) -> String {
    let mut url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex={}&resultsPerPage={}",
        start_index, results_per_page
    );
    if let Some(s) = since {
        url.push_str(&format!("&pubStartDate={}T00:00:00.000", s));
    }
    url
}

fn parse_nvd_cve_item(cve: &Value) -> Option<port_sniffer::vuln::engine::VulnRecord> {
    let id = cve["id"].as_str()?.to_string();

    // Extract English description
    let description = cve["descriptions"]
        .as_array()
        .and_then(|descs| {
            descs.iter()
                .find(|d| d["lang"].as_str() == Some("en"))
                .and_then(|d| d["value"].as_str().map(|s| s.to_string()))
        })
        .unwrap_or_default();

    // Extract CVSS v3 severity/score (fall back to v2)
    let (severity, cvss_score, cvss_vector) = extract_cvss(cve);

    // Extract CPE configurations for version range matching
    let mut affected_cpe: Vec<String> = Vec::new();
    let mut fixed_cpe: Vec<String> = Vec::new();

    if let Some(configs) = cve["configurations"].as_array() {
        for config in configs {
            if let Some(nodes) = config["nodes"].as_array() {
                for node in nodes {
                    if let Some(matches) = node["cpeMatch"].as_array() {
                        for cpe_match in matches {
                            let vulnerable = cpe_match["vulnerable"].as_bool().unwrap_or(false);
                            if !vulnerable { continue; }

                            let criteria = cpe_match["criteria"].as_str().unwrap_or("");
                            if criteria.is_empty() { continue; }

                            // Check for version range bounds
                            let has_start = cpe_match.get("versionStartIncluding").or_else(|| cpe_match.get("versionStartExcluding")).is_some();
                            let has_end = cpe_match.get("versionEndIncluding").or_else(|| cpe_match.get("versionEndExcluding")).is_some();

                            if has_start || has_end {
                                // Build affected CPE from versionStart
                                if let Some(start_ver) = cpe_match.get("versionStartIncluding").and_then(|v| v.as_str()) {
                                    if let Some(filled) = fill_cpe_version(criteria, start_ver) {
                                        affected_cpe.push(filled);
                                    }
                                }
                                if let Some(start_ver) = cpe_match.get("versionStartExcluding").and_then(|v| v.as_str()) {
                                    if let Some(filled) = fill_cpe_version(criteria, start_ver) {
                                        affected_cpe.push(filled);
                                    }
                                }

                                // Build fixed CPE from versionEnd
                                if let Some(end_ver) = cpe_match.get("versionEndIncluding").and_then(|v| v.as_str()) {
                                    if let Some(filled) = fill_cpe_version(criteria, end_ver) {
                                        fixed_cpe.push(filled);
                                    }
                                }
                                if let Some(end_ver) = cpe_match.get("versionEndExcluding").and_then(|v| v.as_str()) {
                                    if let Some(filled) = fill_cpe_version(criteria, end_ver) {
                                        fixed_cpe.push(filled);
                                    }
                                }
                            } else {
                                // No version bounds — store the wildcard CPE as affected
                                affected_cpe.push(criteria.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // Extract references
    let references: Vec<String> = cve["references"]
        .as_array()
        .map(|refs| {
            refs.iter()
                .filter_map(|r| r["url"].as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Deduplicate CPEs
    affected_cpe.sort();
    affected_cpe.dedup();
    fixed_cpe.sort();
    fixed_cpe.dedup();

    Some(port_sniffer::vuln::engine::VulnRecord {
        id,
        description,
        severity,
        cvss_score,
        cvss_vector,
        affected_cpe,
        fixed_cpe,
        references,
        published_date: cve["published"].as_str().map(|s| s.to_string()),
        last_modified: cve["lastModified"].as_str().map(|s| s.to_string()),
        exploits: Vec::new(),
    })
}

/// Extract CVSS v3 severity/score (fall back to v2)
fn extract_cvss(cve: &Value) -> (port_sniffer::vuln::engine::Severity, Option<f32>, Option<String>) {
    // Try CVSS v3.1 first
    if let Some(metrics) = cve["metrics"]["cvssMetricV31"].as_array().and_then(|a| a.first()) {
        if let Some(data) = metrics["cvssData"].as_object() {
            let sev_str = data.get("baseSeverity").and_then(|v| v.as_str()).unwrap_or("NONE");
            let score = data.get("baseScore").and_then(|v| v.as_f64()).map(|s| s as f32);
            let vector = data.get("vectorString").and_then(|v| v.as_str()).map(|s| s.to_string());
            return (port_sniffer::vuln::engine::Severity::parse(sev_str), score, vector);
        }
    }

    // Fall back to CVSS v3.0
    if let Some(metrics) = cve["metrics"]["cvssMetricV30"].as_array().and_then(|a| a.first()) {
        if let Some(data) = metrics["cvssData"].as_object() {
            let sev_str = data.get("baseSeverity").and_then(|v| v.as_str()).unwrap_or("NONE");
            let score = data.get("baseScore").and_then(|v| v.as_f64()).map(|s| s as f32);
            let vector = data.get("vectorString").and_then(|v| v.as_str()).map(|s| s.to_string());
            return (port_sniffer::vuln::engine::Severity::parse(sev_str), score, vector);
        }
    }

    // Fall back to CVSS v2.0
    if let Some(metrics) = cve["metrics"]["cvssMetricV2"].as_array().and_then(|a| a.first()) {
        if let Some(data) = metrics["cvssData"].as_object() {
            let sev_str = data.get("baseSeverity").and_then(|v| v.as_str()).unwrap_or("NONE");
            let score = data.get("baseScore").and_then(|v| v.as_f64()).map(|s| s as f32);
            let vector = data.get("vectorString").and_then(|v| v.as_str()).map(|s| s.to_string());
            return (port_sniffer::vuln::engine::Severity::parse(sev_str), score, vector);
        }
    }

    (port_sniffer::vuln::engine::Severity::None, None, None)
}

/// Replace the version field (5th colon-delimited segment) in a CPE URI
fn fill_cpe_version(cpe: &str, version: &str) -> Option<String> {
    let parts: Vec<&str> = cpe.split(':').collect();
    if parts.len() < 6 {
        return None;
    }
    let mut out = parts[..5].join(":");
    out.push(':');
    out.push_str(version);
    if parts.len() > 6 {
        out.push(':');
        out.push_str(&parts[6..].join(":"));
    }
    Some(out)
}

fn print_db_stats(db: &VulnDb) {
    println!("Exploits in DB: {}", db.exploit_count().unwrap_or(0));
    println!("CVEs in DB: {}", db.cve_count().unwrap_or(0));
}

async fn cmd_scan(program: &str, args: &[String]) {
    let mut i = 1;
    let arguments = match ScanArguments::parse(args, &mut i) {
        Ok(a) => a,
        Err(e) => {
            if e.contains("No IP") {
                usage(program);
            } else {
                eprintln!("{}: {}", program, e);
            }
            process::exit(1);
        }
    };

    // Initialize the vulnerability engine from the local DB
    let db_path = port_sniffer::vuln::db::db_path();
    if let Ok(db) = VulnDb::open(&db_path) {
        let mut engine = VulnEngine::new();
        port_sniffer::vuln::exploit::import_into_engine(&mut engine, &db);
        port_sniffer::vuln::exploit::set_engine(Arc::new(engine));
        let cve_count = db.cve_count().unwrap_or(0);
        if cve_count == 0 {
            tracing::warn!("Vulnerability engine loaded with {} exploits but 0 CVEs — version-interval matching disabled (only FTS5 exploit search available).",
                db.exploit_count().unwrap_or(0));
        } else {
            tracing::info!("Vulnerability engine loaded ({} exploits, {} CVEs)",
                db.exploit_count().unwrap_or(0), cve_count);
        }
    } else {
        tracing::warn!("No vulnerability database found — CVE matching disabled");
    }

    let config = ScanConfig {
        target: IpNetwork::from(arguments.ipaddr),
        threads: arguments.threads,
        timeout: 1000,
        delay: 0,
        randomize: false,
        enable_service_detection: arguments.enable_service_detection,
        syn_scan: arguments.syn_scan,
        deep_inspection: arguments.deep_inspection,
        ports: arguments.ports,
        udp_scan: arguments.udp_scan,
        result_sender: None,
        cancel_signal: None,
        progress: None,
    };

    let results = scan_ports(config).await.unwrap_or_else(|err| {
        eprintln!("Engagement failed: {}", err);
        process::exit(1);
    });

    if arguments.output_json {
        let json = serde_json::to_string_pretty(&results).unwrap_or_else(|_| "[]".to_string());
        println!("{}", json);
    } else {
        for result in results {
            if let Some(service) = &result.service {
                let version_info = service.version.as_deref().unwrap_or("unknown version");
                let product_info = service.product.as_deref().unwrap_or("unknown product");
                let vuln_count = result.vulnerabilities.len();
                let vuln_suffix = if vuln_count > 0 {
                    format!(" | {} CVE(s)", vuln_count)
                } else {
                    String::new()
                };
                println!("{} is open - {} {} ({}){}", result.port, service.name, version_info, product_info, vuln_suffix);
                for v in &result.vulnerabilities {
                    println!("         [{}] {} (score: {:?}, exploits: {})", v.severity, v.cve_id, v.cvss_score.map(|s| format!("{:.1}", s)).unwrap_or_default(), v.exploit_count);
                }
            } else {
                println!("{} is open", result.port);
            }
        }
    }
}
