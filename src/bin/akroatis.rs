use eframe::egui;
use image::{ImageReader, GenericImageView};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use base64::{Engine as _, engine::general_purpose};
use ipnetwork::IpNetwork;
use futures::future::join_all;
use tracing_subscriber::{EnvFilter, fmt::MakeWriter};


use port_sniffer::{config::Config, scan_ports, PortResult, ScanConfig};
use port_sniffer::vuln::nvd::{Vulnerability, fetch_vulnerabilities};

struct SharedLogWriter {
    buffer: Arc<Mutex<Vec<String>>>,
}

struct SharedLogWriterInner {
    buffer: Arc<Mutex<Vec<String>>>,
}

impl Write for SharedLogWriterInner {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let s = String::from_utf8_lossy(buf);
        let trimmed = s.trim().to_string();
        if !trimmed.is_empty() {
            self.buffer.lock().unwrap().push(trimmed);
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> MakeWriter<'writer> for SharedLogWriter {
    type Writer = SharedLogWriterInner;
    fn make_writer(&'writer self) -> Self::Writer {
        SharedLogWriterInner { buffer: self.buffer.clone() }
    }
}

fn main() -> Result<(), eframe::Error> {
    let mut options = eframe::NativeOptions::default();
    if let Ok(reader) = ImageReader::open("../Akroatis.jpg") {
        if let Ok(img) = reader.decode() {
            let rgba = img.to_rgba8();
            let (width, height) = img.dimensions();
            options.viewport.icon = Some(Arc::new(egui::IconData {
                rgba: rgba.into_raw(),
                width,
                height,
            }));
        }
    }

    let cfg = Config::load();
    eframe::run_native(
        "Akroatis Port Scanner",
        options,
        Box::new(move |_cc| {
            let log_buffer: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let writer = SharedLogWriter { buffer: log_buffer.clone() };
            tracing_subscriber::fmt()
                .with_writer(writer)
                .with_env_filter(EnvFilter::try_new("info").unwrap_or_else(|_| EnvFilter::new("info")))
                .init();
            Ok(Box::new(Akroatis::new(log_buffer, cfg)) as Box<dyn eframe::App>)
        }),
    )
}

struct Akroatis {
    ip_input: String,
    port_range_input: String,
    randomize: bool,
    results: Vec<PortResult>,
    scanning: bool,
    scan_complete: Arc<AtomicBool>,
    cancel_signal: Arc<AtomicBool>,
    ports_scanned: Arc<AtomicU16>,
    total_ports: u16,
    receiver: Option<mpsc::Receiver<PortResult>>,
    result_sender: mpsc::Sender<PortResult>,
    vuln_receiver: mpsc::Receiver<(u16, Vec<Vulnerability>)>,
    vuln_sender: mpsc::Sender<(u16, Vec<Vulnerability>)>,
    vulnerability_map: HashMap<u16, Vec<Vulnerability>>,
    enable_service_detection: bool,
    selected_vulnerability: Option<Vulnerability>,
    filter_vulnerabilities: bool,
    severity_threshold: String,
    deep_inspection: bool,
    udp_scan: bool,
    terminal_logs: Vec<String>,
    log_buffer: Arc<Mutex<Vec<String>>>,
}

#[derive(Serialize, Deserialize)]
struct SessionData {
    results: Vec<PortResult>,
    vulnerability_map: HashMap<u16, Vec<Vulnerability>>,
    ip_input: String,
    port_range_input: String,
}

fn session_path() -> PathBuf {
    let mut p = Config::path();
    p.set_file_name("session.json");
    p
}

impl Akroatis {
    fn new(log_buffer: Arc<Mutex<Vec<String>>>, cfg: Config) -> Self {
        let (v_tx, v_rx) = mpsc::channel();
        let (r_tx, r_rx) = mpsc::channel();
        let mut app = Self {
            ip_input: "127.0.0.1".to_string(),
            port_range_input: cfg.port_range.unwrap_or_default(),
            randomize: cfg.randomize,
            results: Vec::new(),
            scanning: false,
            scan_complete: Arc::new(AtomicBool::new(false)),
            cancel_signal: Arc::new(AtomicBool::new(false)),
            ports_scanned: Arc::new(AtomicU16::new(0)),
            total_ports: 65535,
            receiver: Some(r_rx),
            result_sender: r_tx,
            vuln_receiver: v_rx,
            vuln_sender: v_tx,
            vulnerability_map: HashMap::new(),
            enable_service_detection: cfg.enable_service_detection,
            selected_vulnerability: None,
            filter_vulnerabilities: false,
            severity_threshold: cfg.severity_threshold,
            deep_inspection: cfg.deep_inspection,
            udp_scan: cfg.udp_scan,
            terminal_logs: vec!["> Initializing Akroatis...".to_string()],
            log_buffer,
        };
        app.load_session();
        app
    }
}

impl eframe::App for Akroatis {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Stream results into the UI in real-time
        if let Some(rx) = &self.receiver {
            while let Ok(result) = rx.try_recv() {
                self.results.push(result);
            }
        }

        // Handle incoming vulnerability data
        while let Ok((port, vulns)) = self.vuln_receiver.try_recv() {
            self.vulnerability_map.insert(port, vulns);
        }

        // Drain tracing log buffer into terminal display
        {
            let mut buffer = self.log_buffer.lock().unwrap();
            for log in buffer.drain(..) {
                self.terminal_logs.push(log);
                if self.terminal_logs.len() > 100 {
                    self.terminal_logs.remove(0);
                }
            }
        }

        // Handle vulnerability details window
        let mut is_open = self.selected_vulnerability.is_some();
        if is_open {
            let vuln = self.selected_vulnerability.as_ref().unwrap().clone();
            egui::Window::new(format!("Details for {}", vuln.id))
                .open(&mut is_open)
                .collapsible(false)
                .show(ctx, |ui| {
                    ui.heading(&vuln.id);
                    ui.horizontal(|ui| {
                        ui.label("Severity:");
                        ui.colored_label(get_severity_color(&vuln.severity), &vuln.severity);
                    });
                    if vuln.has_exploit {
                        ui.horizontal(|ui| {
                            ui.colored_label(egui::Color32::RED, "💀 Public exploit available");
                            if let Some(url) = &vuln.exploit_url {
                                if ui.link("View Exploit").clicked() {
                                    let _ = webbrowser::open(url);
                                }
                            }
                        });
                    }
                    ui.separator();
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        ui.label(&vuln.description);
                    });
                });
            if !is_open {
                self.selected_vulnerability = None;
            }
        }

        // Side Panel for Tactical Controls
        egui::SidePanel::left("tactical_controls").resizable(false).default_width(260.0).show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.heading("🛰 TACTICAL CTRL");
            });
            ui.separator();

            ui.group(|ui| {
                ui.label("Target Entry");
                ui.text_edit_singleline(&mut self.ip_input);
                ui.label("Port Range (optional)");
                ui.text_edit_singleline(&mut self.port_range_input);
                ui.checkbox(&mut self.randomize, "🎲 Randomize Scan");
                ui.checkbox(&mut self.enable_service_detection, "🔍 Banner Grab");
                ui.checkbox(&mut self.deep_inspection, "🚀 Deep Inspection");
                ui.checkbox(&mut self.udp_scan, "📡 UDP Scan");
            });

            ui.group(|ui| {
                ui.label("Intelligence Filters");
                let vulnerable_count = self.results.iter().filter(|r| self.vulnerability_map.contains_key(&r.port)).count();
                ui.checkbox(&mut self.filter_vulnerabilities, format!("⚠️ Vulnerabilities ({})", vulnerable_count));
                ui.horizontal(|ui| {
                    ui.label("Min Severity:");
                    egui::ComboBox::from_id_salt("sev_threshold")
                        .selected_text(&self.severity_threshold)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.severity_threshold, "NONE".to_string(), "NONE");
                            ui.selectable_value(&mut self.severity_threshold, "LOW".to_string(), "LOW");
                            ui.selectable_value(&mut self.severity_threshold, "MEDIUM".to_string(), "MEDIUM");
                            ui.selectable_value(&mut self.severity_threshold, "HIGH".to_string(), "HIGH");
                            ui.selectable_value(&mut self.severity_threshold, "CRITICAL".to_string(), "CRITICAL");
                        });
                });
            });

            ui.add_space(10.0);
            if ui.add_enabled(!self.scanning, egui::Button::new("ENGAGE").min_size(egui::vec2(240.0, 40.0))).clicked() {
                self.start_scan();
            }
            if ui.add_enabled(self.scanning, egui::Button::new("■ STOP").min_size(egui::vec2(240.0, 30.0))).clicked() {
                self.cancel_signal.store(true, Ordering::SeqCst);
                tracing::warn!("User requested stop");
            }

            ui.separator();
            ui.label("Export Intelligence");
            if ui.button("📝 Download .txt").clicked() { let _ = self.download_report(); }
            if ui.button("🌐 Download .html").clicked() { let _ = self.download_report_html(); }
            if ui.button("📕 Download .pdf").clicked() { let _ = self.download_report_pdf(); }
            if ui.button("📦 Download .json").clicked() { let _ = self.download_report_json(); }
            
            if ui.button("🗑 Clear View").clicked() { self.results.clear(); self.terminal_logs.clear(); }
        });

        // Bottom Panel: Virtual Terminal
        egui::TopBottomPanel::bottom("terminal").resizable(true).default_height(120.0).show(ctx, |ui| {
            ui.horizontal(|ui| { ui.label("💻 CONSOLE_OUTPUT"); });
            egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
                for log in &self.terminal_logs {
                    ui.add(egui::Label::new(egui::RichText::new(log).monospace().color(egui::Color32::from_rgb(0, 255, 65))));
                }
            });
        });

        // Central Panel: Results Dashboard
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.heading("🛰 AKROATIS INTELLIGENCE DASHBOARD");
                    if self.scanning { ui.spinner(); }
                });
                ui.separator();

                if let Some(os) = self.results.iter().find_map(|r| r.os_guess.as_ref()) {
                    ui.group(|ui| {
                        ui.label(egui::RichText::new(format!("TARGET OS FINGERPRINT: {}", os)).color(egui::Color32::LIGHT_GREEN).strong());
                    });
                }

                if self.scanning {
                    let scanned = self.ports_scanned.load(Ordering::Relaxed);
                    ui.group(|ui| {
                        ui.label(format!("⏳ Scanning... {}/{} ports", scanned, self.total_ports));
                    });
                }

                ui.add_space(10.0);
                ui.label("📋 DISCOVERED ENDPOINTS:");
                egui::ScrollArea::vertical().id_salt("results_scroll").show(ui, |ui| {
                    if self.results.is_empty() && !self.scanning {
                        ui.vertical_centered(|ui| { ui.label("SYSTEM_IDLE: Enter Target to Begin Engagement"); });
                    } else {
                        for result in &self.results {
                            let has_vulns = self.vulnerability_map.contains_key(&result.port);
                            if self.filter_vulnerabilities && !has_vulns {
                                continue;
                            }

                            ui.horizontal(|ui| {
                                ui.strong(format!("Port {}", result.port));
                                ui.label("•");
                                if let Some(svc) = &result.service {
                                    let mut svc_text = svc.name.clone();
                                    if let Some(prod) = &svc.product {
                                        svc_text = format!("{} ({})", svc_text, prod);
                                    }
                                    if let Some(ver) = &svc.version {
                                        svc_text = format!("{} v{}", svc_text, ver);
                                    }
                                    ui.colored_label(egui::Color32::LIGHT_BLUE, svc_text);

                                    if svc.version.is_some() && ui.button("🛡 CVE").clicked() {
                                            let tx = self.vuln_sender.clone();
                                            let svc_clone = svc.clone();
                                            let port = result.port;
                                            thread::spawn(move || {
                                                let rt = tokio::runtime::Runtime::new().unwrap();
                                                rt.block_on(async {
                                                    if let Ok(vulns) = fetch_vulnerabilities(&svc_clone).await {
                                                        let _ = tx.send((port, vulns));
                                                    }
                                                });
                                            });
                                    }
                                } else {
                                    ui.label("Unknown");
                                }
                            });

                            if let Some(vulns) = self.vulnerability_map.get(&result.port) {
                                let threshold = &self.severity_threshold;
                                for v in vulns.iter().filter(|v| meets_threshold(&v.severity, threshold)) {
                                    ui.horizontal(|ui| {
                                        ui.label("  ⚠");
                                        if ui.link(&v.id).clicked() {
                                            self.selected_vulnerability = Some(v.clone());
                                        }
                                        ui.colored_label(get_severity_color(&v.severity), format!(": {}", v.severity));
                                        if v.has_exploit {
                                            ui.colored_label(egui::Color32::RED, " [EXPLOIT AVAILABLE]");
                                        }
                                    });
                                }
                            }
                        }
                    }
                }); // Close ScrollArea
            });
        }); // Close CentralPanel

        // Check if scanning is complete via the atomic signal
        if self.scanning && self.scan_complete.load(Ordering::SeqCst) {
            self.scanning = false;
            self.scan_complete.store(false, Ordering::SeqCst);
        }

        // Trigger vuln lookups for NEW results
        let new_results_with_versions: Vec<_> = self.results.iter()
            .filter(|r| r.service.as_ref().is_some_and(|s| s.version.is_some()))
            .filter(|r| !self.vulnerability_map.contains_key(&r.port))
            .cloned()
            .collect();

        if !new_results_with_versions.is_empty() {
            let tx = self.vuln_sender.clone();
            thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let mut lookup_tasks = Vec::new();
                    for res in new_results_with_versions {
                        let port = res.port;
                        let svc_data = res.service.unwrap();
                        lookup_tasks.push(async move {
                            match fetch_vulnerabilities(&svc_data).await {
                                Ok(vulns) => (port, vulns),
                                Err(_) => (port, Vec::new()),
                            }
                        });
                    }
                    let all_results = join_all(lookup_tasks).await;
                    for (port, vulns) in all_results {
                        if !vulns.is_empty() { let _ = tx.send((port, vulns)); }
                    }
                });
            });
        }
    }
}

impl Akroatis {
    fn start_scan(&mut self) {
        let ip_str = self.ip_input.clone();
        let enable_svc = self.enable_service_detection;
        let randomize = self.randomize;
        let deep_inspection = self.deep_inspection;
        let udp_scan = self.udp_scan;
        let res_tx = self.result_sender.clone();
        let complete = self.scan_complete.clone();
        let cancel = self.cancel_signal.clone();
        let progress = self.ports_scanned.clone();
        let range_str = self.port_range_input.clone();

        let parsed_ports = if range_str.trim().is_empty() {
            None
        } else {
            Some(parse_port_range_gui(&range_str))
        };
        self.total_ports = parsed_ports.as_ref().map_or(65535, |v| v.len() as u16);
        self.ports_scanned.store(0, Ordering::Relaxed);

        self.scanning = true;
        self.cancel_signal.store(false, Ordering::SeqCst);
        self.scan_complete.store(false, Ordering::SeqCst);
        self.results.clear();
        tracing::info!("Session started for {}", ip_str);

        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                if let Ok(net) = IpNetwork::from_str(&ip_str) {
                    let config = ScanConfig {
                        target: net,
                        threads: 100,
                        timeout: 1000,
                        delay: 0,
                        randomize,
                        enable_service_detection: enable_svc,
                        syn_scan: false,
                        deep_inspection,
                        udp_scan,
                        ports: parsed_ports,
                        result_sender: Some(res_tx),
                        cancel_signal: Some(cancel),
                        progress: Some(progress),
                    };
                    let _ = scan_ports(config).await;
                    tracing::info!("Scan complete");
                } else {
                    tracing::error!("Invalid target: {}", ip_str);
                }
                complete.store(true, Ordering::SeqCst);
            });
        });
    }

    fn download_report(&self) -> Result<String, String> {
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let filename = format!("scan_report_{}.txt", timestamp);
        let mut content = format!("Akroatis Scan Report - {}\nTarget: {}\n\n", timestamp, self.ip_input);
        for r in &self.results {
            let has_vulns = self.vulnerability_map.contains_key(&r.port);
            if self.filter_vulnerabilities && !has_vulns {
                continue;
            }

            let svc = r.service.as_ref().map(|s| s.name.as_str()).unwrap_or("Unknown");
            content.push_str(&format!("Port {}: open ({})\n", r.port, svc));
            
            if let Some(vulns) = self.vulnerability_map.get(&r.port) {
                let threshold = &self.severity_threshold;
                for v in vulns.iter().filter(|v| meets_threshold(&v.severity, threshold)) {
                    content.push_str(&format!("  [!] CVE: {} | Severity: {}\n", v.id, v.severity));
                    content.push_str(&format!("      Description: {}\n", v.description.replace('\n', " ")));
                }
            }
            content.push('\n');
        }
        
        fs::write(&filename, content).map_err(|e| e.to_string())?;
        Ok(filename)
    }

    fn download_report_html(&self) -> Result<String, String> {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        let filename = format!("scan_report_{}.html", chrono::Local::now().format("%Y%m%d_%H%M%S"));
        
        // Try to embed logo
        let logo_base64 = if let Ok(bytes) = fs::read("../Akroatis.jpg") {
            general_purpose::STANDARD.encode(bytes)
        } else {
            "".to_string()
        };

        let mut content = format!(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0a0a; color: #00ff41; margin: 0; padding: 40px; }}
        .container {{ max-width: 900px; margin: auto; border: 1px solid #00ff41; padding: 20px; box-shadow: 0 0 20px rgba(0,255,65,0.2); }}
        .header {{ display: flex; align-items: center; border-bottom: 2px solid #00ff41; padding-bottom: 20px; margin-bottom: 30px; }}
        .logo {{ width: 80px; height: 80px; margin-right: 20px; border: 1px solid #00ff41; }}
        h1 {{ margin: 0; letter-spacing: 2px; }}
        .meta {{ color: #888; font-family: monospace; margin-bottom: 30px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ border: 1px solid #333; padding: 12px; text-align: left; }}
        th {{ background: #1a1a1a; text-transform: uppercase; font-size: 0.8em; }}
        tr:hover {{ background: rgba(0,255,65,0.05); }}
        .port {{ font-weight: bold; color: #fff; }}
        .cve-box {{ background: #111; border-left: 3px solid #ff4141; margin: 10px 0; padding: 10px; font-size: 0.9em; }}
        .severity {{ padding: 2px 6px; border-radius: 3px; font-size: 0.8em; font-weight: bold; }}
        .CRITICAL {{ background: #ff4141; color: #000; }}
        .HIGH {{ background: #ff8c00; color: #000; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <img src="data:image/jpeg;base64,{}" class="logo">
            <div>
                <h1>AKROATIS INTELLIGENCE</h1>
                <div class="meta">ENGAGEMENT REPORT</div>
            </div>
        </div>
        <div class="meta">
            TARGET: {}<br>
            TIMESTAMP: {}<br>
            STATUS: COMPLETED
        </div>
        <table>
            <thead><tr><th>Port</th><th>Service</th><th>Version</th><th>Vulnerabilities</th></tr></thead>
            <tbody>"#, logo_base64, self.ip_input, timestamp);

        for r in &self.results {
            let svc = r.service.as_ref();
            let port_str = format!("<td class='port'>{}</td>", r.port);
            let name_str = format!("<td>{}</td>", svc.map(|s| s.name.as_str()).unwrap_or("unknown"));
            let ver_str = format!("<td>{}</td>", svc.and_then(|s| s.version.as_deref()).unwrap_or("-"));
            
            let mut v_str = "<td>".to_string();
            if let Some(vulns) = self.vulnerability_map.get(&r.port) {
                let threshold = &self.severity_threshold;
                for v in vulns.iter().filter(|v| meets_threshold(&v.severity, threshold)) {
                    v_str.push_str(&format!(
                        r#"<div class="cve-box"><span class="severity {}">{}</span> <strong>{}</strong><br>{}</div>"#,
                        v.severity.to_uppercase(), v.severity, v.id, v.description
                    ));
                }
            }
            v_str.push_str("</td>");
            
            content.push_str(&format!("<tr>{}{}{}{}</tr>", port_str, name_str, ver_str, v_str));
        }

        content.push_str("</tbody></table></div></body></html>");
        fs::write(&filename, content).map_err(|e| e.to_string())?;
        Ok(filename)
    }

    fn download_report_pdf(&self) -> Result<String, String> {
        use printpdf::*;
        let filename = format!("scan_report_{}.pdf", chrono::Local::now().format("%Y%m%d_%H%M%S"));
        
        let (doc, page1, layer1) = PdfDocument::new("Akroatis Report", Mm(210.0), Mm(297.0), "Layer 1");
        let current_layer = doc.get_page(page1).get_layer(layer1);

        // Use a built-in font
        let font = doc.add_builtin_font(BuiltinFont::HelveticaBold).map_err(|e| e.to_string())?;

        current_layer.use_text("AKROATIS SCAN REPORT", 24.0, Mm(20.0), Mm(270.0), &font);
        
        let font_regular = doc.add_builtin_font(BuiltinFont::Helvetica).map_err(|e| e.to_string())?;
        current_layer.use_text(format!("Target: {}", self.ip_input), 12.0, Mm(20.0), Mm(260.0), &font_regular);
        current_layer.use_text(format!("Date: {}", chrono::Local::now()), 10.0, Mm(20.0), Mm(255.0), &font_regular);

        let mut y_pos = 240.0;
        for r in &self.results {
            if y_pos < 30.0 { break; } // Simple overflow check
            
            let svc_name = r.service.as_ref().map(|s| s.name.as_str()).unwrap_or("Unknown");
            let text = format!("Port {}: Open | Service: {}", r.port, svc_name);
            current_layer.use_text(text, 10.0, Mm(20.0), Mm(y_pos), &font_regular);
            y_pos -= 7.0;

            if let Some(vulns) = self.vulnerability_map.get(&r.port) {
                let threshold = &self.severity_threshold;
                for v in vulns.iter().filter(|v| meets_threshold(&v.severity, threshold)).take(2) {
                    if y_pos < 30.0 { break; }
                    current_layer.use_text(format!("  [!] {} ({})", v.id, v.severity), 8.0, Mm(25.0), Mm(y_pos), &font_regular);
                    y_pos -= 5.0;
                }
            }
            y_pos -= 5.0;
        }

        let mut file = std::fs::File::create(&filename).map_err(|e| e.to_string())?;
        doc.save(&mut std::io::BufWriter::new(&mut file)).map_err(|e| e.to_string())?;

        Ok(filename)
    }

    fn download_report_json(&self) -> Result<String, String> {
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let filename = format!("scan_report_{}.json", timestamp);
        let json = serde_json::to_string_pretty(&self.results).map_err(|e| e.to_string())?;
        fs::write(&filename, json).map_err(|e| e.to_string())?;
        Ok(filename)
    }

    fn save_session(&self) {
        let data = SessionData {
            results: self.results.clone(),
            vulnerability_map: self.vulnerability_map.clone(),
            ip_input: self.ip_input.clone(),
            port_range_input: self.port_range_input.clone(),
        };
        if let Ok(json) = serde_json::to_string_pretty(&data) {
            let path = session_path();
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(&path, json);
        }
    }

    fn load_session(&mut self) {
        let path = session_path();
        if path.exists() {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(data) = serde_json::from_str::<SessionData>(&content) {
                    self.results = data.results;
                    self.vulnerability_map = data.vulnerability_map;
                    self.ip_input = data.ip_input;
                    self.port_range_input = data.port_range_input;
                    tracing::info!("Session restored from {}", path.display());
                }
            }
        }
    }
}

impl Drop for Akroatis {
    fn drop(&mut self) {
        self.save_session();
    }
}

fn severity_score(severity: &str) -> u8 {
    match severity.to_uppercase().as_str() {
        "CRITICAL" => 5,
        "HIGH" => 4,
        "MEDIUM" => 3,
        "LOW" => 2,
        "NONE" => 1,
        _ => 0,
    }
}

fn meets_threshold(vuln_severity: &str, threshold: &str) -> bool {
    severity_score(vuln_severity) >= severity_score(threshold)
}

fn parse_port_range_gui(s: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() { continue; }
        if let Some((start, end)) = part.split_once('-') {
            let lo = start.trim().parse::<u16>().unwrap_or(1);
            let hi = end.trim().parse::<u16>().unwrap_or(65535);
            if lo <= hi { for p in lo..=hi { ports.push(p); } }
        } else if let Ok(p) = part.parse::<u16>() {
            ports.push(p);
        }
    }
    if ports.is_empty() { (1..=65535).collect() } else { ports }
}

/// Returns a Color32 corresponding to the CVSS severity level
fn get_severity_color(severity: &str) -> egui::Color32 {
    match severity.to_uppercase().as_str() {
        "CRITICAL" => egui::Color32::RED,
        "HIGH" => egui::Color32::from_rgb(255, 165, 0), // Orange
        "MEDIUM" => egui::Color32::YELLOW,
        "LOW" => egui::Color32::GREEN,
        "NONE" => egui::Color32::GRAY,
        _ => egui::Color32::GOLD,
    }
}
