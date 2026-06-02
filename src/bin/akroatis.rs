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
use std::time::Instant;
use base64::{Engine as _, engine::general_purpose};
use ipnetwork::IpNetwork;
use futures::future::join_all;
use tracing_subscriber::{EnvFilter, fmt::MakeWriter};
use tokio::runtime::Runtime;
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

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Scan,
    Results,
    Vulnerabilities,
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
    // Scan fields
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
    scan_start_time: Option<Instant>,
    scan_elapsed: f64,

    // Vulnerability fields
    vuln_receiver: mpsc::Receiver<(u16, Vec<Vulnerability>)>,
    vuln_sender: mpsc::Sender<(u16, Vec<Vulnerability>)>,
    vulnerability_map: HashMap<u16, Vec<Vulnerability>>,
    selected_vulnerability: Option<Vulnerability>,

    // Service detection fields
    enable_service_detection: bool,
    deep_inspection: bool,
    udp_scan: bool,

    // Nmap integration
    nmap_enabled: bool,
    nmap_pending: bool,

    // Filter fields
    filter_vulnerabilities: bool,
    severity_threshold: String,

    // UI fields
    active_tab: Tab,
    terminal_logs: Vec<String>,
    log_buffer: Arc<Mutex<Vec<String>>>,
    runtime: Arc<Runtime>,

    // Notifications: message, color, expiry
    notification: Option<(String, egui::Color32, Instant)>,
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
        let runtime = Arc::new(Runtime::new().expect("Failed to create Tokio runtime"));

        // Initialize vulnerability engine
        let rt = runtime.clone();
        rt.spawn(async move {
            let db_path = port_sniffer::vuln::db::db_path();
            match port_sniffer::vuln::db::VulnDb::open(&db_path) {
                Ok(db) => {
                    let mut engine = port_sniffer::vuln::engine::VulnEngine::new();
                    port_sniffer::vuln::exploit::import_into_engine(&mut engine, &db);
                    port_sniffer::vuln::exploit::set_engine(std::sync::Arc::new(engine));
                    tracing::info!("Vulnerability engine initialized ({} exploits, {} CVEs)",
                        db.exploit_count().unwrap_or(0), db.cve_count().unwrap_or(0));
                    port_sniffer::vuln::cache::init_cache(db);
                }
                Err(e) => tracing::warn!("Failed to open vulnerability database: {}", e),
            }
        });

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
            scan_start_time: None,
            scan_elapsed: 0.0,

            vuln_receiver: v_rx,
            vuln_sender: v_tx,
            vulnerability_map: HashMap::new(),
            selected_vulnerability: None,

            enable_service_detection: cfg.enable_service_detection,
            deep_inspection: cfg.deep_inspection,
            udp_scan: cfg.udp_scan,

            nmap_enabled: false,
            nmap_pending: false,

            filter_vulnerabilities: false,
            severity_threshold: cfg.severity_threshold,

            active_tab: Tab::Scan,
            terminal_logs: vec!["> Initializing Akroatis...".to_string()],
            log_buffer,
            runtime,
            notification: None,
        };
        app.load_session();
        app
    }

    fn notify(&mut self, msg: impl Into<String>, color: egui::Color32) {
        self.notification = Some((msg.into(), color, Instant::now()));
    }
}

impl eframe::App for Akroatis {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Tick elapsed time
        if self.scanning {
            if let Some(start) = self.scan_start_time {
                self.scan_elapsed = start.elapsed().as_secs_f64();
            }
        }

        // Stream results into the UI in real-time
        if let Some(rx) = &self.receiver {
            while let Ok(result) = rx.try_recv() {
                self.results.push(result);
            }
        }

        // Handle incoming vulnerability data
        while let Ok((port, vulns)) = self.vuln_receiver.try_recv() {
            self.vulnerability_map.entry(port).or_default().extend(vulns);
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

        // Check if scanning is complete
        if self.scanning && self.scan_complete.load(Ordering::SeqCst) {
            self.scanning = false;
            self.scan_complete.store(false, Ordering::SeqCst);

            // Trigger nmap enhancement if enabled
            if self.nmap_enabled {
                let target = self.ip_input.clone();
                let rt = self.runtime.clone();
                let res_tx = self.result_sender.clone();
                let complete = self.scan_complete.clone();
                let _cancel = self.cancel_signal.clone();
                let _progress = self.ports_scanned.clone();
                let parsed_ports = if self.port_range_input.trim().is_empty() {
                    None
                } else {
                    Some(parse_port_range_gui(&self.port_range_input))
                };
                let total = parsed_ports.as_ref().map_or(65535, |v| v.len() as u16);
                self.total_ports = total;
                self.nmap_pending = true;
                self.notify("🧭 Nmap enhancement starting...", egui::Color32::YELLOW);
                rt.spawn(async move {
                    let ports = parsed_ports.unwrap_or_else(|| (1..=total).collect());
                    match Self::run_nmap(&target, &ports).await {
                        Ok(nmap_results) => {
                            tracing::info!("Nmap found {} open ports", nmap_results.len());
                            for r in nmap_results {
                                let _ = res_tx.send(r);
                            }
                        }
                        Err(e) => {
                            tracing::error!("Nmap error: {}", e);
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    complete.store(true, Ordering::SeqCst);
                });
            }
        }

        // Handle second completion (nmap done)
        if self.nmap_pending && self.scan_complete.load(Ordering::SeqCst) {
            self.nmap_pending = false;
            self.scan_complete.store(false, Ordering::SeqCst);
            self.notify("✅ Scan complete (with Nmap enhancement)", egui::Color32::LIGHT_GREEN);
        }

        // Handle vulnerability details window
        let mut is_open = self.selected_vulnerability.is_some();
        if is_open {
            let vuln = self.selected_vulnerability.as_ref().unwrap().clone();
            egui::Window::new(format!("Details for {}", vuln.id))
                .open(&mut is_open)
                .collapsible(false)
                .resizable(true)
                .default_width(500.0)
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

        // ==================== LEFT SIDEBAR (Controls) ====================
        egui::SidePanel::left("tactical_controls")
            .resizable(false)
            .default_width(260.0)
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.heading("🛰 TACTICAL CTRL");
                });
                ui.separator();

                // Target configuration
                ui.group(|ui| {
                    ui.label("Target Entry");
                    ui.add(egui::TextEdit::singleline(&mut self.ip_input)
                        .hint_text("192.168.1.0/24"));
                    ui.label("Port Range (optional)");
                    ui.add(egui::TextEdit::singleline(&mut self.port_range_input)
                        .hint_text("22,80,443 or 1-1000"));
                });

                // Scan options
                ui.group(|ui| {
                    ui.label("Scan Options");
                    ui.checkbox(&mut self.randomize, "🎲 Randomize Scan");
                    ui.checkbox(&mut self.enable_service_detection, "🔍 Banner Grab");
                    ui.checkbox(&mut self.deep_inspection, "🚀 Deep Inspection");
                    ui.checkbox(&mut self.udp_scan, "📡 UDP Scan");
                    ui.separator();
                    ui.checkbox(&mut self.nmap_enabled, "🧭 Nmap Enhancement");
                    if self.nmap_enabled {
                        ui.label(egui::RichText::new("Requires nmap on PATH").size(10.0).color(egui::Color32::GRAY));
                    }
                });

                // Intelligence filters
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
                if ui.add_enabled(!self.scanning && !self.nmap_pending, egui::Button::new("ENGAGE").min_size(egui::vec2(240.0, 40.0))).clicked() {
                    self.start_scan();
                }
                if ui.add_enabled(self.scanning || self.nmap_pending, egui::Button::new("■ STOP").min_size(egui::vec2(240.0, 30.0))).clicked() {
                    self.cancel_signal.store(true, Ordering::SeqCst);
                    self.notify("🛑 Scan stopped by user", egui::Color32::RED);
                    tracing::warn!("User requested stop");
                }

                ui.separator();
                ui.label("Export Intelligence");
                if ui.button("📝 Download .txt").clicked() {
                    match self.download_report() {
                        Ok(f) => self.notify(format!("📝 Saved: {}", f), egui::Color32::LIGHT_GREEN),
                        Err(e) => self.notify(format!("❌ TXT error: {}", e), egui::Color32::RED),
                    }
                }
                if ui.button("🌐 Download .html").clicked() {
                    match self.download_report_html() {
                        Ok(f) => self.notify(format!("🌐 Saved: {}", f), egui::Color32::LIGHT_GREEN),
                        Err(e) => self.notify(format!("❌ HTML error: {}", e), egui::Color32::RED),
                    }
                }
                if ui.button("📕 Download .pdf").clicked() {
                    match self.download_report_pdf() {
                        Ok(f) => self.notify(format!("📕 Saved: {}", f), egui::Color32::LIGHT_GREEN),
                        Err(e) => self.notify(format!("❌ PDF error: {}", e), egui::Color32::RED),
                    }
                }
                if ui.button("📦 Download .json").clicked() {
                    match self.download_report_json() {
                        Ok(f) => self.notify(format!("📦 Saved: {}", f), egui::Color32::LIGHT_GREEN),
                        Err(e) => self.notify(format!("❌ JSON error: {}", e), egui::Color32::RED),
                    }
                }

                if ui.button("🗑 Clear All").clicked() {
                    self.results.clear();
                    self.vulnerability_map.clear();
                    self.terminal_logs.clear();
                    self.notify("🗑 Cleared all data", egui::Color32::GRAY);
                }
            });

        // ==================== BOTTOM CONSOLE ====================
        egui::TopBottomPanel::bottom("terminal")
            .resizable(true)
            .default_height(120.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("💻 CONSOLE_OUTPUT");
                    if ui.button("Clear").clicked() {
                        self.terminal_logs.clear();
                    }
                });
                egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
                    for log in &self.terminal_logs {
                        ui.add(egui::Label::new(
                            egui::RichText::new(log).monospace().color(egui::Color32::from_rgb(0, 255, 65))
                        ));
                    }
                });
            });

        // ==================== MAIN CENTRAL PANEL (Tabbed) ====================
        egui::CentralPanel::default().show(ctx, |ui| {
            // Header
            ui.horizontal(|ui| {
                ui.heading("🛰 AKROATIS INTELLIGENCE DASHBOARD");
                if self.scanning || self.nmap_pending {
                    ui.spinner();
                    let elapsed = if self.scanning {
                        if let Some(start) = self.scan_start_time {
                            format!("{:6.1}s", start.elapsed().as_secs_f64())
                        } else {
                            "...".to_string()
                        }
                    } else {
                        format!("{:6.1}s", self.scan_elapsed)
                    };
                    ui.label(egui::RichText::new(elapsed).monospace());
                }
            });

            // OS fingerprint banner
            if let Some(os) = self.results.iter().find_map(|r| r.os_guess.as_ref()) {
                ui.group(|ui| {
                    ui.label(egui::RichText::new(format!("🎯 TARGET OS: {}", os)).color(egui::Color32::LIGHT_GREEN).strong());
                });
            }

            // Progress bar
            if self.scanning || self.nmap_pending {
                let scanned = self.ports_scanned.load(Ordering::Relaxed);
                let pct = if self.total_ports > 0 { scanned as f32 / self.total_ports as f32 } else { 0.0 };
                ui.group(|ui| {
                    let label = if self.nmap_pending {
                        "🧭 Nmap enhancing...".to_string()
                    } else {
                        format!("⏳ Scanning... {}/{} ports ({:.1}%)", scanned, self.total_ports, pct * 100.0)
                    };
                    ui.label(label);
                    let pb = egui::ProgressBar::new(pct)
                        .animate(self.scanning || self.nmap_pending)
                        .fill(egui::Color32::from_rgb(0, 180, 50));
                    ui.add(pb);
                });
                ui.add_space(5.0);
            }

            ui.separator();

            // Tab bar
            ui.horizontal(|ui| {
                let tabs = [("📡 Scan", Tab::Scan), ("📋 Results", Tab::Results), ("⚠️ Vulnerabilities", Tab::Vulnerabilities)];
                for (label, tab) in &tabs {
                    let is_active = self.active_tab == *tab;
                    let mut btn = egui::Button::new(egui::RichText::new(*label).size(14.0));
                    if is_active {
                        btn = btn.fill(egui::Color32::from_rgb(0, 80, 20));
                    }
                    if ui.add(btn).clicked() {
                        self.active_tab = *tab;
                    }
                }
            });
            ui.separator();

            // Tab content
            match self.active_tab {
                Tab::Scan => self.ui_scan_tab(ui),
                Tab::Results => self.ui_results_tab(ui),
                Tab::Vulnerabilities => self.ui_vulns_tab(ui),
            }

            // ==================== TOAST NOTIFICATION OVERLAY ====================
            if let Some((msg, color, start)) = &self.notification.clone() {
                if start.elapsed() < std::time::Duration::from_secs(4) {
                    egui::Area::new(egui::Id::new("toast"))
                        .anchor(egui::Align2::RIGHT_TOP, egui::vec2(-10.0, 40.0))
                        .show(ctx, |ui| {
                            let frame = egui::Frame::NONE
                                .fill(egui::Color32::from_black_alpha(200))
                                .corner_radius(egui::CornerRadius::same(6))
                                .stroke(egui::Stroke::new(1.0, *color));
                            frame.show(ui, |ui: &mut egui::Ui| {
                                ui.add(egui::Label::new(
                                    egui::RichText::new(msg.clone()).color(*color).size(13.0)
                                ));
                            });
                        });
                    ctx.request_repaint();
                } else {
                    self.notification = None;
                }
            }

            // Trigger vuln lookups for NEW results (debounced)
            let new_results_with_versions: Vec<_> = self.results.iter()
                .filter(|r| r.service.as_ref().is_some_and(|s| s.version.is_some()))
                .filter(|r| !self.vulnerability_map.contains_key(&r.port))
                .cloned()
                .collect();

            if !new_results_with_versions.is_empty() {
                let tx = self.vuln_sender.clone();
                let rt = self.runtime.clone();
                rt.spawn(async move {
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
            }
        });
    }
}

// ==================== UI TAB METHODS ====================
impl Akroatis {
    fn ui_scan_tab(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().id_salt("scan_scroll").show(ui, |ui| {
            if self.results.is_empty() && !self.scanning {
                ui.vertical_centered(|ui| {
                    ui.add_space(60.0);
                    ui.label(egui::RichText::new("SYSTEM IDLE").size(24.0).color(egui::Color32::DARK_GRAY));
                    ui.label(egui::RichText::new("Configure target in the left panel and press ENGAGE").size(14.0).color(egui::Color32::GRAY));
                    if !self.nmap_enabled {
                        ui.label(egui::RichText::new("Enable 🧭 Nmap Enhancement for deeper service detection").size(12.0).color(egui::Color32::DARK_GRAY));
                    }
                });
                return;
            }

            ui.label(format!("📋 LIVE RESULTS ({} endpoints)", self.results.len()));
            ui.add_space(5.0);

            for result in &self.results {
                let has_vulns = self.vulnerability_map.contains_key(&result.port);
                if self.filter_vulnerabilities && !has_vulns {
                    continue;
                }

                // Card background
                let card_color = if has_vulns {
                    egui::Color32::from_rgba_premultiplied(40, 10, 10, 180)
                } else {
                    egui::Color32::from_rgba_premultiplied(10, 10, 10, 180)
                };

                egui::Frame::NONE
                    .fill(card_color)
                    .corner_radius(egui::CornerRadius::same(4))
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(40, 40, 40)))
                    .show(ui, |ui: &mut egui::Ui| {
                        ui.horizontal(|ui: &mut egui::Ui| {
                            // Port number badge
                            egui::Frame::NONE
                                .fill(egui::Color32::from_rgb(0, 60, 20))
                                .corner_radius(egui::CornerRadius::same(3))
                                .inner_margin(egui::Margin::symmetric(6, 2))
                                .show(ui, |ui: &mut egui::Ui| {
                                    ui.strong(format!("Port {}", result.port));
                                });
                            ui.label("•");

                            // Service info
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
                                    let rt = self.runtime.clone();
                                    rt.spawn(async move {
                                        if let Ok(vulns) = fetch_vulnerabilities(&svc_clone).await {
                                            let _ = tx.send((port, vulns));
                                        }
                                    });
                                }
                            } else {
                                ui.label("Unknown");
                            }

                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui: &mut egui::Ui| {
                                if has_vulns {
                                    if let Some(vulns) = self.vulnerability_map.get(&result.port) {
                                        let count = vulns.len();
                                        ui.colored_label(egui::Color32::LIGHT_RED, format!("⚠ {} vulns", count));
                                    }
                                }
                                if result.service.as_ref().and_then(|s| s.version.as_ref()).is_some() {
                                    ui.colored_label(egui::Color32::GREEN, "✓ version");
                                }
                            });
                        });

                        // Vulnerabilities under this port
                        if let Some(vulns) = self.vulnerability_map.get(&result.port) {
                            let threshold = &self.severity_threshold;
                            for v in vulns.iter().filter(|v| meets_threshold(&v.severity, threshold)) {
                                ui.horizontal(|ui: &mut egui::Ui| {
                                    ui.add_space(16.0);
                                    ui.label("⚠");
                                    if ui.link(&v.id).clicked() {
                                        self.selected_vulnerability = Some(v.clone());
                                    }
                                    ui.colored_label(get_severity_color(&v.severity), format!("{}", v.severity));
                                    if v.has_exploit {
                                        ui.colored_label(egui::Color32::RED, "[EXPLOIT]");
                                    }
                                });
                            }
                        }
                    });
                ui.add_space(4.0);
            }
        });
    }

    fn ui_results_tab(&mut self, ui: &mut egui::Ui) {
        if self.results.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(60.0);
                ui.label(egui::RichText::new("No results yet").size(18.0).color(egui::Color32::GRAY));
                ui.label("Run a scan first, then view detailed results here");
            });
            return;
        }

        // Summary bar
        let total = self.results.len();
        let vulnerable_count = self.results.iter().filter(|r| self.vulnerability_map.contains_key(&r.port)).count();
        let total_vulns: usize = self.vulnerability_map.values().map(|v| v.len()).sum();
        ui.horizontal(|ui| {
            ui.label(format!("📊 Summary: {} ports open, {} vulnerable, {} CVEs", total, vulnerable_count, total_vulns));
        });
        ui.add_space(5.0);

        // Filters
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.filter_vulnerabilities, "Vulnerable only");
            ui.separator();
            ui.label("Sort:");
            if ui.selectable_label(true, "Port").clicked() { }
            if ui.selectable_label(false, "Severity").clicked() { }
        });
        ui.separator();

        egui::ScrollArea::vertical().id_salt("results_scroll").show(ui, |ui| {
            let mut display_results: Vec<_> = self.results.iter().collect();
            if self.filter_vulnerabilities {
                display_results.retain(|r| self.vulnerability_map.contains_key(&r.port));
            }

            // Table header
            egui::Grid::new("results_grid")
                .striped(true)
                .min_col_width(60.0)
                .show(ui, |ui| {
                    ui.strong("Port");
                    ui.strong("Service");
                    ui.strong("Version");
                    ui.strong("Product");
                    ui.strong("Vulnerabilities");
                    ui.strong("Exploits");
                    ui.end_row();

                    for result in &display_results {
                        let svc = result.service.as_ref();
                        let has_vulns = self.vulnerability_map.contains_key(&result.port);

                        let row_color = if has_vulns {
                            egui::Color32::from_rgba_premultiplied(50, 15, 15, 200)
                        } else {
                            egui::Color32::from_rgba_premultiplied(15, 15, 15, 200)
                        };

                        egui::Frame::NONE
                            .fill(row_color)
                            .show(ui, |ui: &mut egui::Ui| {
                                ui.label(egui::RichText::new(result.port.to_string()).strong());
                                ui.label(svc.map(|s| s.name.as_str()).unwrap_or("-"));
                                ui.label(svc.and_then(|s| s.version.as_deref()).unwrap_or("-"));
                                ui.label(svc.and_then(|s| s.product.as_deref()).unwrap_or("-"));

                                if let Some(vulns) = self.vulnerability_map.get(&result.port) {
                                    let threshold = &self.severity_threshold;
                                    let filtered: Vec<_> = vulns.iter().filter(|v| meets_threshold(&v.severity, threshold)).collect();
                                    let mut v_text = String::new();
                                    for v in &filtered {
                                        v_text.push_str(&format!("{} ({}), ", v.id, v.severity));
                                    }
                                    ui.label(v_text.trim_end_matches(", "));
                                } else {
                                    ui.label("-");
                                }

                                if let Some(vulns) = self.vulnerability_map.get(&result.port) {
                                    let exploit_count = vulns.iter().filter(|v| v.has_exploit).count();
                                    let txt = if exploit_count > 0 {
                                        format!("{} available", exploit_count)
                                    } else {
                                        "-".to_string()
                                    };
                                    ui.colored_label(if exploit_count > 0 { egui::Color32::RED } else { egui::Color32::GRAY }, txt);
                                } else {
                                    ui.label("-");
                                }
                            });
                        ui.end_row();
                    }
                });
        });
    }

    fn ui_vulns_tab(&mut self, ui: &mut egui::Ui) {
        if self.vulnerability_map.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(60.0);
                ui.label(egui::RichText::new("No vulnerabilities identified").size(18.0).color(egui::Color32::GRAY));
                ui.label("Vulnerabilities appear here once services are fingerprinted");
            });
            return;
        }

        let total_vulns: usize = self.vulnerability_map.values().map(|v| v.len()).sum();
        ui.label(format!("⚠️ Total Vulnerabilities: {}", total_vulns));
        ui.separator();

        egui::ScrollArea::vertical().id_salt("vulns_scroll").show(ui, |ui| {
            // Collect all vulns with their port
            let mut all_vulns: Vec<(u16, &Vulnerability)> = Vec::new();
            for (port, vulns) in &self.vulnerability_map {
                let threshold = &self.severity_threshold;
                for v in vulns.iter().filter(|v| meets_threshold(&v.severity, threshold)) {
                    all_vulns.push((*port, v));
                }
            }

            // Sort by severity (critical first)
            all_vulns.sort_by(|a, b| severity_score(&b.1.severity).cmp(&severity_score(&a.1.severity)));

            for (port, v) in &all_vulns {
                let sev_color = get_severity_color(&v.severity);
                egui::Frame::NONE
                    .fill(egui::Color32::from_rgba_premultiplied(20, 10, 10, 200))
                    .corner_radius(egui::CornerRadius::same(4))
                    .stroke(egui::Stroke::new(1.0, sev_color.gamma_multiply(0.4)))
                    .show(ui, |ui: &mut egui::Ui| {
                        ui.horizontal(|ui: &mut egui::Ui| {
                            ui.colored_label(sev_color, format!("[{}]", v.severity));
                            if ui.link(&v.id).clicked() {
                                self.selected_vulnerability = Some((*v).clone());
                            }
                            ui.label(format!("on port {}", port));
                            if v.has_exploit {
                                ui.colored_label(egui::Color32::RED, "[EXPLOIT]");
                            }
                            if let Some(url) = &v.exploit_url {
                                if ui.button("Open Exploit").clicked() {
                                    let _ = webbrowser::open(url);
                                }
                            }
                        });
                        ui.label(egui::RichText::new(
                            v.description.chars().take(200).collect::<String>()
                        ).size(11.0).color(egui::Color32::LIGHT_GRAY));
                    });
                ui.add_space(3.0);
            }
        });
    }
}

// ==================== NMAP INTEGRATION ====================
impl Akroatis {
    async fn run_nmap(target: &str, ports: &[u16]) -> Result<Vec<PortResult>, String> {
        // Build port string: group consecutive ports into ranges
        let port_str = if ports.len() == 1 {
            ports[0].to_string()
        } else if ports.len() <= 10 {
            ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",")
        } else {
            // Use ranges to keep command short
            format!("{}-{}", ports[0], ports[ports.len() - 1])
        };

        let args = &[
            "-sV",
            "-p", &port_str,
            target,
            "-oX", "-",
            "--open",
        ];

        tracing::info!("Running nmap with: nmap {}", args.join(" "));

        let output = tokio::process::Command::new("nmap")
            .args(args)
            .output()
            .await
            .map_err(|e| format!("Failed to execute nmap: {}. Is nmap installed and on PATH?", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("nmap exited with error: {}", stderr));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Self::parse_nmap_xml(&stdout)
    }

    fn parse_nmap_xml(xml: &str) -> Result<Vec<PortResult>, String> {
        use quick_xml::events::Event;
        use quick_xml::Reader;

        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut results = Vec::new();
        let mut buf = Vec::new();
        let mut in_port = false;
        let mut port: u16 = 0;
        let mut port_open = false;
        let mut svc_name = String::new();
        let mut svc_product = String::new();
        let mut svc_version = String::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Empty(ref e)) | Ok(Event::Start(ref e)) => {
                    match e.name().as_ref() {
                        b"port" => {
                            in_port = true;
                            port = 0;
                            port_open = false;
                            svc_name.clear();
                            svc_product.clear();
                            svc_version.clear();
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"portid" {
                                    port = std::str::from_utf8(&attr.value)
                                        .unwrap_or("0")
                                        .parse()
                                        .unwrap_or(0);
                                }
                            }
                        }
                        b"state" => {
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"state" {
                                    port_open = attr.value.as_ref() == b"open";
                                }
                            }
                        }
                        b"service" => {
                            for attr in e.attributes().flatten() {
                                match attr.key.as_ref() {
                                    b"name" => {
                                        svc_name = std::str::from_utf8(&attr.value)
                                            .unwrap_or("")
                                            .to_string();
                                    }
                                    b"product" => {
                                        svc_product = std::str::from_utf8(&attr.value)
                                            .unwrap_or("")
                                            .to_string();
                                    }
                                    b"version" => {
                                        svc_version = std::str::from_utf8(&attr.value)
                                            .unwrap_or("")
                                            .to_string();
                                    }
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(ref e)) => {
                    if e.name().as_ref() == b"port" && in_port && port_open && port > 0 {
                        let service = if svc_name.is_empty() && svc_version.is_empty() {
                            None
                        } else {
                            Some(port_sniffer::ServiceInfo {
                                name: if svc_name.is_empty() { "unknown".to_string() } else { svc_name.clone() },
                                product: if svc_product.is_empty() { None } else { Some(svc_product.clone()) },
                                version: if svc_version.is_empty() { None } else { Some(svc_version.clone()) },
                                extrainfo: None,
                                cpe: None,
                            })
                        };
                        results.push(PortResult {
                            port,
                            is_open: true,
                            service,
                            os_guess: None,
                            tcp_window: None,
                            tcp_options: Vec::new(),
                            vulnerabilities: Vec::new(),
                        });
                    }
                    if e.name().as_ref() == b"port" {
                        in_port = false;
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(format!("XML parse error: {}", e)),
                _ => {}
            }
            buf.clear();
        }

        Ok(results)
    }
}

// ==================== REPORT DOWNLOAD METHODS ====================
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
        self.scan_complete.store(false, Ordering::SeqCst);
        self.cancel_signal.store(false, Ordering::SeqCst);
        self.results.clear();
        self.vulnerability_map.clear();
        self.scan_start_time = Some(Instant::now());
        self.nmap_pending = false;
        tracing::info!("Session started for {}", ip_str);

        let rt = self.runtime.clone();
        rt.spawn(async move {
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
                tracing::info!("Initial scan complete");
            } else {
                tracing::error!("Invalid target: {}", ip_str);
            }
            complete.store(true, Ordering::SeqCst);
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
        .MEDIUM {{ background: #ffd700; color: #000; }}
        .LOW {{ background: #00ff41; color: #000; }}
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

        let font = doc.add_builtin_font(BuiltinFont::HelveticaBold).map_err(|e| e.to_string())?;

        current_layer.use_text("AKROATIS SCAN REPORT", 24.0, Mm(20.0), Mm(270.0), &font);

        let font_regular = doc.add_builtin_font(BuiltinFont::Helvetica).map_err(|e| e.to_string())?;
        current_layer.use_text(format!("Target: {}", self.ip_input), 12.0, Mm(20.0), Mm(260.0), &font_regular);
        current_layer.use_text(format!("Date: {}", chrono::Local::now()), 10.0, Mm(20.0), Mm(255.0), &font_regular);

        let mut y_pos = 240.0;
        for r in &self.results {
            if y_pos < 30.0 { break; }

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

        let file = std::fs::File::create(&filename).map_err(|e| e.to_string())?;
        let mut writer = std::io::BufWriter::new(file);
        doc.save(&mut writer).map_err(|e| e.to_string())?;

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

fn get_severity_color(severity: &str) -> egui::Color32 {
    match severity.to_uppercase().as_str() {
        "CRITICAL" => egui::Color32::RED,
        "HIGH" => egui::Color32::from_rgb(255, 165, 0),
        "MEDIUM" => egui::Color32::YELLOW,
        "LOW" => egui::Color32::GREEN,
        "NONE" => egui::Color32::GRAY,
        _ => egui::Color32::GOLD,
    }
}
