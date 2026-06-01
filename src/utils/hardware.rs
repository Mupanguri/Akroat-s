pub fn get_local_mac_vendors() -> Vec<(String, String)> {
    let interfaces = get_network_interfaces();
    interfaces.into_iter().map(|name| (name.clone(), "N/A (requires Npcap)".to_string())).collect()
}

fn get_network_interfaces() -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(output) = std::process::Command::new("ipconfig").arg("/all").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("Ethernet adapter") || trimmed.starts_with("Wireless LAN adapter") {
                let name = trimmed.trim_end_matches(':').to_string();
                names.push(name);
            }
        }
    }
    if names.is_empty() {
        names.push("localhost".to_string());
    }
    names
}
