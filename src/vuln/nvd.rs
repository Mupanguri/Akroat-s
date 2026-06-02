use reqwest;
use reqwest::Url;
use serde_json::Value;
use serde::{Serialize, Deserialize};
use crate::ServiceInfo;
use crate::vuln::exploit;
use crate::vuln::engine::Severity;
use crate::vuln::cache;

/// Basic structure to hold vulnerability info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub description: String,
    pub severity: String,
    pub has_exploit: bool,
    pub exploit_url: Option<String>,
}

struct CpeEntry {
    vendor: &'static str,
    product_cpe: &'static str,
}

/// Maps service name + product to CPE vendor and product values
fn lookup_cpe(service: &ServiceInfo) -> Option<CpeEntry> {
    let name = service.name.to_lowercase();
    let product = service.product.as_deref().unwrap_or("").to_lowercase();

    match (name.as_str(), product.as_str()) {
        (_, "openssh") | (_, "openbsd") => Some(CpeEntry { vendor: "openbsd", product_cpe: "openssh" }),
        (_, "dropbear") => Some(CpeEntry { vendor: "dropbear_ssh", product_cpe: "dropbear_ssh" }),
        (_, "vsftpd") => Some(CpeEntry { vendor: "vsftpd", product_cpe: "vsftpd" }),
        (_, "proftpd") => Some(CpeEntry { vendor: "proftpd", product_cpe: "proftpd" }),
        (_, "pure-ftpd") => Some(CpeEntry { vendor: "pureftpd", product_cpe: "pure-ftpd" }),
        (_, "microsoft ftp service") => Some(CpeEntry { vendor: "microsoft", product_cpe: "ftp" }),
        (_, "apache") | (_, "apache httpd") | (_, "apache_httpd") => Some(CpeEntry { vendor: "apache", product_cpe: "http_server" }),
        (_, "nginx") => Some(CpeEntry { vendor: "nginx", product_cpe: "nginx" }),
        (_, "microsoft-iis") | (_, "iis") | (_, "microsoft iis") => Some(CpeEntry { vendor: "microsoft", product_cpe: "iis" }),
        (_, "samba") => Some(CpeEntry { vendor: "samba", product_cpe: "samba" }),
        (_, "microsoft windows smb") => Some(CpeEntry { vendor: "microsoft", product_cpe: "windows" }),
        ("ssh", _) => Some(CpeEntry { vendor: "openbsd", product_cpe: "openssh" }),
        ("ftp", _) => Some(CpeEntry { vendor: "vsftpd", product_cpe: "vsftpd" }),
        ("http", _) => Some(CpeEntry { vendor: "apache", product_cpe: "http_server" }),
        ("smtp", _) => Some(CpeEntry { vendor: "exim", product_cpe: "exim" }),
        ("mysql", _) => Some(CpeEntry { vendor: "oracle", product_cpe: "mysql" }),
        ("postgresql", _) => Some(CpeEntry { vendor: "postgresql", product_cpe: "postgresql" }),
        ("telnet", _) => Some(CpeEntry { vendor: "linux", product_cpe: "telnet" }),
        ("dns", _) => Some(CpeEntry { vendor: "isc", product_cpe: "bind" }),
        _ => None,
    }
}

fn build_cpe_uri(cpe: &CpeEntry, version: &str) -> String {
    format!(
        "cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*",
        cpe.vendor, cpe.product_cpe, version
    )
}

/// Query NVD API using CPE name for precise matching
async fn query_nvd_cpe(cpe_uri: &str) -> Result<Vec<Vulnerability>, String> {
    let url = Url::parse_with_params(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        &[("cpeName", cpe_uri)],
    )
    .map_err(|e| e.to_string())?;

    let response = reqwest::get(url).await.map_err(|e| e.to_string())?;
    parse_nvd_response(response).await
}

/// Query NVD API using keyword search (fallback)
#[allow(dead_code)]
async fn query_nvd_keyword(product: &str, version: &str) -> Result<Vec<Vulnerability>, String> {
    let keyword = format!("{} {}", product, version);
    let url = Url::parse_with_params(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        &[("keywordSearch", &keyword)],
    )
    .map_err(|e| e.to_string())?;

    let response = reqwest::get(url).await.map_err(|e| e.to_string())?;
    parse_nvd_response(response).await
}

/// Parse the NVD API response into Vulnerability structs
async fn parse_nvd_response(response: reqwest::Response) -> Result<Vec<Vulnerability>, String> {
    let json: Value = response.json().await.map_err(|e| e.to_string())?;

    let mut vulnerabilities = Vec::new();
    if let Some(vulnerabilities_list) = json["vulnerabilities"].as_array() {
        for vuln in vulnerabilities_list.iter().take(5) {
            let cve_id = vuln["cve"]["id"]
                .as_str()
                .unwrap_or("Unknown")
                .to_string();
            let desc = vuln["cve"]["descriptions"][0]["value"]
                .as_str()
                .unwrap_or("No description")
                .to_string();
            let severity = vuln["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]
                ["baseSeverity"]
                .as_str()
                .unwrap_or("N/A")
                .to_string();

            let (has_exploit, exploit_url) = match exploit::check_exploit(&cve_id).await {
                Ok(exploits) if !exploits.is_empty() => {
                    (true, Some(exploits[0].url.clone()))
                }
                _ => (false, None),
            };

            vulnerabilities.push(Vulnerability {
                id: cve_id,
                description: desc,
                severity,
                has_exploit,
                exploit_url,
            });
        }
    }

    Ok(vulnerabilities)
}

/// Convert engine Arc<VulnRecord> to Vulnerability
fn vuln_record_to_vuln(record: &crate::vuln::engine::VulnRecord) -> Vulnerability {
    Vulnerability {
        id: record.id.clone(),
        description: record.description.clone(),
        severity: format!("{:?}", record.severity),
        has_exploit: !record.exploits.is_empty(),
        exploit_url: record
            .exploits
            .first()
            .filter(|e| e.verified)
            .map(|e| e.url.clone()),
    }
}

/// Query vulnerabilities — engine first (instant), then NVD API (background)
pub async fn fetch_vulnerabilities(service: &ServiceInfo) -> Result<Vec<Vulnerability>, String> {
    let product = service.product.as_deref().unwrap_or(&service.name);
    let version = service.version.as_deref().unwrap_or("");

    if version.is_empty() {
        return Err("No version info available for CVE lookup".to_string());
    }

    // 1. Check local cache first
    if let Some(cached) = cache::get_cached_vulns(product, version) {
        return Ok(cached);
    }

    // 2. Try engine match_service for instant results
    if let Some(engine) = exploit::get_engine() {
        let sev = Severity::None;
        let results = engine.match_service(product, version, &sev);
        if !results.is_empty() {
            let vulns: Vec<Vulnerability> = results
                .iter()
                .map(|r| vuln_record_to_vuln(r.as_ref()))
                .collect();
            if !vulns.is_empty() {
                let _ = cache::update_cache(product, version, vulns.clone());
                return Ok(vulns);
            }
        }
    }

    // 3. Fallback: NVD API
    let vulnerabilities = if let Some(cpe_entry) = lookup_cpe(service) {
        let cpe_uri = build_cpe_uri(&cpe_entry, version);
        let cpe_results = query_nvd_cpe(&cpe_uri).await;
        match cpe_results {
            Ok(results) if !results.is_empty() => results,
            _ => query_nvd_keyword(product, version)
                .await
                .unwrap_or_default(),
        }
    } else {
        query_nvd_keyword(product, version)
            .await
            .unwrap_or_default()
    };

    let _ = cache::update_cache(product, version, vulnerabilities.clone());
    Ok(vulnerabilities)
}
