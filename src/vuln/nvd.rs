use reqwest;
use serde_json::Value;
use serde::{Serialize, Deserialize};
use crate::ServiceInfo;
use crate::vuln::cache;

/// Basic structure to hold vulnerability info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub description: String,
    pub severity: String,
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

    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={} {}",
        product, version
    );

    let response = reqwest::get(url).await.map_err(|e| e.to_string())?;
    let json: Value = response.json().await.map_err(|e| e.to_string())?;

    let mut vulnerabilities = Vec::new();
    if let Some(vulnerabilities_list) = json["vulnerabilities"].as_array() {
        for vuln in vulnerabilities_list.iter().take(5) { // Limit to top 5
            let cve_id = vuln["cve"]["id"].as_str().unwrap_or("Unknown").to_string();
            let desc = vuln["cve"]["descriptions"][0]["value"].as_str().unwrap_or("No description").to_string();
            let severity = vuln["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
                .as_str().unwrap_or("N/A").to_string();
            
            vulnerabilities.push(Vulnerability { 
                id: cve_id, 
                description: desc, 
                severity 
            });
        }
    }

    // Update cache with fresh results
    let _ = cache::update_cache(product, version, vulnerabilities.clone());

    Ok(vulnerabilities)
}