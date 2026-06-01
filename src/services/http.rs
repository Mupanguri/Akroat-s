use crate::services::banner_grabber::grab_banner;
use crate::ServiceInfo;
use regex::Regex;
use reqwest::blocking::Client;
use std::sync::OnceLock;
use std::time::Duration;

static HTTP_CLIENT: OnceLock<Client> = OnceLock::new();

/// Returns a shared HTTP client with connection pooling enabled
fn get_client() -> &'static Client {
    HTTP_CLIENT.get_or_init(|| {
        Client::builder()
            .user_agent("Akroatis/1.0")
            .timeout(Duration::from_secs(5))
            .danger_accept_invalid_certs(true) // Crucial for security scanning/self-signed certs
            .build()
            .unwrap_or_default()
    })
}

/// Detect HTTP service and extract information
pub fn detect_http(ip: &str, port: u16, deep: bool) -> Option<ServiceInfo> {
    // First try to get a banner
    if let Some(banner) = grab_banner(ip, port, 5000) {
        // Check if it looks like an HTTP response
        if banner.contains("HTTP/") || banner.contains("<html") || banner.contains("<!DOCTYPE") {
            // Extract server header
            let server = extract_server_header(&banner);
            
            // Try to get more info with a proper HTTP request
            if let Some(detailed_info) = probe_http_service(ip, port, deep) {
                return Some(detailed_info);
            }
            
            // Return basic info from banner
            return Some(crate::ServiceInfo {
                name: "HTTP".to_string(),
                version: server,
                product: None,
                extrainfo: Some(format!("Banner: {}", banner.chars().take(100).collect::<String>())),
                cpe: None,
            });
        }
    }
    
    // Try to probe with a proper HTTP request even if no banner
    if let Some(info) = probe_http_service(ip, port, deep) {
        return Some(info);
    }
    
    None
}

/// Probe HTTP service with a proper GET request
fn probe_http_service(ip: &str, port: u16, deep: bool) -> Option<ServiceInfo> {
    let client = get_client();
    
    // Determine scheme based on common ports
    let scheme = match port {
        443 | 8443 | 9443 => "https",
        _ => "http",
    };
    
    let url = format!("{}://{}:{}", scheme, ip, port);
    
    // reqwest::Client handles the connection pool and Keep-Alive automatically
    let response = client.get(&url).send().ok()?;
    
    // Fix: Extract headers BEFORE consuming the response body
    let server = response.headers() 
        .get(reqwest::header::SERVER)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let mut extrainfo_parts = Vec::new();

    if deep {
        // Common headers to inspect
        let interesting_headers = ["X-Powered-By", "Content-Type", "X-Frame-Options", "X-Content-Type-Options"];
        for name in interesting_headers {
            if let Some(val) = response.headers().get(name).and_then(|h| h.to_str().ok()) { // Fix: Use response.headers() before response.text()
                extrainfo_parts.push(format!("{}: {}", name, val));
            }
        }
    }

    // Now consume the response body
    let body = response.text().ok().unwrap_or_default();
    if let Some(title) = extract_html_title(&body) {
        extrainfo_parts.insert(0, format!("Title: {}", title));
    }

    if deep {
        // Fetch robots.txt
        let robots_url = format!("{}://{}:{}/robots.txt", scheme, ip, port);
        if let Ok(robots_res) = client.get(&robots_url).send() {
            if robots_res.status().is_success() {
                if let Ok(text) = robots_res.text() {
                    let preview: String = text.lines().filter(|l| !l.trim().is_empty()).take(2).collect::<Vec<_>>().join(" | ");
                    if !preview.is_empty() {
                        extrainfo_parts.push(format!("Robots: {}", preview));
                    }
                }
            }
        }
    }
    
    Some(ServiceInfo {
        name: "HTTP".to_string(),
        version: server,
        product: None,
        extrainfo: if extrainfo_parts.is_empty() { None } else { Some(extrainfo_parts.join(" | ")) },
        cpe: None,
    })
}

/// Extract Server header from HTTP response
fn extract_server_header(response: &str) -> Option<String> {
    // Look for Server: header
    response.lines()
        .find(|line| line.to_lowercase().starts_with("server:")).map(|server_line| server_line["Server:".len()..].trim().to_string())
}

/// Extract title from HTML response
fn extract_html_title(response: &str) -> Option<String> {
    static TITLE_RE: OnceLock<Regex> = OnceLock::new();
    let re = TITLE_RE.get_or_init(|| {
        Regex::new(r"(?i)<title[^>]*>(.*?)</title>").expect("Invalid title regex")
    });

    re.captures(response).and_then(|cap| {
        cap.get(1).map(|m| m.as_str().to_string())
    })
}