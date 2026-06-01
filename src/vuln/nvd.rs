use reqwest;
use reqwest::Url;
use serde_json::Value;
use serde::{Serialize, Deserialize};
use crate::ServiceInfo;
use crate::vuln::{cache, exploit::check_exploit};

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

    // Ordered by specificity (product match preferred over service name)
    match (name.as_str(), product.as_str()) {
        // OpenSSH
        (_, "openssh") | (_, "openbsd") => Some(CpeEntry { vendor: "openbsd", product_cpe: "openssh" }),
        // Dropbear SSH
        (_, "dropbear") => Some(CpeEntry { vendor: "dropbear_ssh", product_cpe: "dropbear_ssh" }),
        // vsftpd
        (_, "vsftpd") => Some(CpeEntry { vendor: "vsftpd", product_cpe: "vsftpd" }),
        // ProFTPD
        (_, "proftpd") => Some(CpeEntry { vendor: "proftpd", product_cpe: "proftpd" }),
        // Pure-FTPd
        (_, "pure-ftpd") => Some(CpeEntry { vendor: "pureftpd", product_cpe: "pure-ftpd" }),
        // Microsoft FTP
        (_, "microsoft ftp service") => Some(CpeEntry { vendor: "microsoft", product_cpe: "ftp" }),
        // Apache httpd
        (_, "apache") | (_, "apache httpd") | (_, "apache_httpd") => Some(CpeEntry { vendor: "apache", product_cpe: "http_server" }),
        // Nginx
        (_, "nginx") => Some(CpeEntry { vendor: "nginx", product_cpe: "nginx" }),
        // IIS
        (_, "microsoft-iis") | (_, "iis") | (_, "microsoft iis") => Some(CpeEntry { vendor: "microsoft", product_cpe: "iis" }),
        // Samba
        (_, "samba") => Some(CpeEntry { vendor: "samba", product_cpe: "samba" }),
        // Microsoft Windows SMB
        (_, "microsoft windows smb") => Some(CpeEntry { vendor: "microsoft", product_cpe: "windows" }),
        // By service name
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

/// Build a CPE 2.3 URI string for the given service and version
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
    ).map_err(|e| e.to_string())?;

    let response = reqwest::get(url).await.map_err(|e| e.to_string())?;
    parse_nvd_response(response).await
}

/// Query NVD API using keyword search (fallback)
async fn query_nvd_keyword(product: &str, version: &str) -> Result<Vec<Vulnerability>, String> {
    let keyword = format!("{} {}", product, version);
    let url = Url::parse_with_params(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        &[("keywordSearch", &keyword)],
    ).map_err(|e| e.to_string())?;

    let response = reqwest::get(url).await.map_err(|e| e.to_string())?;
    parse_nvd_response(response).await
}

/// Parse the NVD API response into Vulnerability structs
async fn parse_nvd_response(response: reqwest::Response) -> Result<Vec<Vulnerability>, String> {
    let json: Value = response.json().await.map_err(|e| e.to_string())?;

    let mut vulnerabilities = Vec::new();
    if let Some(vulnerabilities_list) = json["vulnerabilities"].as_array() {
        for vuln in vulnerabilities_list.iter().take(5) {
            let cve_id = vuln["cve"]["id"].as_str().unwrap_or("Unknown").to_string();
            let desc = vuln["cve"]["descriptions"][0]["value"].as_str().unwrap_or("No description").to_string();
            let severity = vuln["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
                .as_str().unwrap_or("N/A").to_string();

            // Check for known exploits via CIRCL API
            let (has_exploit, exploit_url) = match check_exploit(&cve_id).await {
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

/// Query NVD for vulnerabilities based on ServiceInfo
pub async fn fetch_vulnerabilities(service: &ServiceInfo) -> Result<Vec<Vulnerability>, String> {
    let product = service.product.as_deref().unwrap_or(&service.name);
    let version = service.version.as_deref().unwrap_or("");

    if version.is_empty() {
        return Err("No version info available for CVE lookup".to_string());
    }

    // Check local cache first
    if let Some(cached) = cache::get_cached_vulns(product, version) {
        return Ok(cached);
    }

    let vulnerabilities = if let Some(cpe_entry) = lookup_cpe(service) {
        let cpe_uri = build_cpe_uri(&cpe_entry, version);
        let cpe_results = query_nvd_cpe(&cpe_uri).await;
        match cpe_results {
            Ok(results) if !results.is_empty() => results,
            _ => query_nvd_keyword(product, version).await.unwrap_or_default(),
        }
    } else {
        query_nvd_keyword(product, version).await.unwrap_or_default()
    };

    // Update cache with fresh results
    let _ = cache::update_cache(product, version, vulnerabilities.clone());

    Ok(vulnerabilities)
}