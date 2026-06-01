use crate::services::banner_grabber::grab_banner_with_retries;
use crate::ServiceInfo; // Fix: Ensure ServiceInfo is imported
/// Detect SMB service and extract version information
pub fn detect_smb(ip: &str, port: u16) -> Option<ServiceInfo> {
    // SMB typically runs on ports 445 and 139
    // NetBIOS usually 137, 138, 139
    if port != 445 && port != 139 && port != 137 {
        return None;
    }
    
    // SMB requires sending a specific Negotiate Protocol Request
    // For simplicity, we'll try to get a banner first, then do basic detection
    if let Some(banner) = grab_banner_with_retries(ip, port, 5000, 1) {
        // Some SMB servers might return information in response to malformed requests
        if !banner.is_empty() {
            // Check if it looks like SMB
            let banner_upper = banner.to_uppercase();
            if banner_upper.contains("SMB") || banner_upper.contains("CIFS") || 
               banner_upper.contains("MICROSOFT") || banner_upper.contains("WINDOWS") {
                
                // Extract version from banner
                let version = extract_smb_version(&banner);
                
                // Determine product from banner
                let product = extract_smb_product(&banner);
                
                return Some(ServiceInfo {
                    name: "SMB".to_string(),
                    version,
                    product,
                    extrainfo: Some(banner),
                    cpe: None,
                });
            }
        }
    }
    
    // If we couldn't get a banner but it's a known SMB port, return basic info
    Some(ServiceInfo {
        name: "SMB".to_string(),
        version: None,
        product: None,
        extrainfo: None,
        cpe: None,
    })
}

/// Extract version from SMB banner
fn extract_smb_version(banner: &str) -> Option<String> {
    // Look for version patterns in SMB banners
    // Examples: "Windows 2000", "Windows XP", "Windows Server 2003", "Samba 3.0", etc.
    let patterns = [
        regex::Regex::new(r"Windows\s+([^\s,]+)").ok()?,
        regex::Regex::new(r"Samba\s+([^\s,]+)").ok()?,
        regex::Regex::new(r"(\d+\.\d+\.\d+)").ok()?,
        regex::Regex::new(r"(\d+\.\d+)").ok()?,
    ];
    
    for pattern in patterns {
        if let Some(cap) = pattern.captures(banner) {
            if let Some(m) = cap.get(1) {
                return Some(m.as_str().to_string());
            }
        }
    }
    
    None
}

/// Extract product from SMB banner
fn extract_smb_product(banner: &str) -> Option<String> {
    let banner_lower = banner.to_lowercase();
    
    if banner_lower.contains("windows") {
        Some("Microsoft Windows SMB".to_string())
    } else if banner_lower.contains("samba") {
        Some("Samba".to_string())
    } else if banner_lower.contains("netapp") {
        Some("NetApp SMB".to_string())
    } else if banner_lower.contains("cifs") {
        Some("CIFS".to_string())
    } else {
        None
    }
}