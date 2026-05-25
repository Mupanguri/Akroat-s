use chrono;
use eframe::egui;
use image::{ImageReader, GenericImageView};
use std::fs;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{mpsc, Arc};
use std::thread;

use port_sniffer::{scan_ports, PortResult, ScanConfig};

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
    eframe::run_native(
        "Akroatis Port Scanner",
        options,
        Box::new(|_cc| Ok(Box::new(Akroatis::default()) as Box<dyn eframe::App>)),
    )
}

#[derive(Default)]
struct Akroatis {
    ip_input: String,
    randomize: bool,
    syn_scan: bool,
    results: Vec<String>,
    scanning: bool,
    error_message: Option<String>,
    success_message: Option<String>,
    receiver: Option<mpsc::Receiver<Result<Vec<PortResult>, String>>>,
}

impl eframe::App for Akroatis {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
    ui.heading("Akroatis Port Scanner");

    ui.horizontal(|ui| {
        ui.label("IP Address:");
        ui.text_edit_singleline(&mut self.ip_input);
    });

    ui.checkbox(&mut self.randomize, "Randomize Ports");
    ui.checkbox(&mut self.syn_scan, "Use SYN Scan");

    ui.horizontal(|ui| {
        let button_text = if self.scanning {
            "Scanning..."
        } else {
            "Engage"
        };
        let button_enabled = !self.scanning && !self.ip_input.is_empty();

        if ui
            .add_enabled(button_enabled, egui::Button::new(button_text))
            .clicked()
        {
            self.start_scan();
        }

        if ui.add_enabled(!self.results.is_empty() && !self.scanning, egui::Button::new("Download .txt")).clicked() {
            match self.download_report() {
                Ok(filename) => {
                    self.success_message = Some(format!("✅ Report saved as: {}", filename));
                    self.error_message = None;
                }
                Err(e) => {
                    self.error_message = Some(format!("Failed to save report: {}", e));
                    self.success_message = None;
                }
            }
        }

        if ui.button("Clear").clicked() {
            self.results.clear();
            self.error_message = None;
            self.success_message = None;
            self.receiver = None;
        }
    });

    // Status bar
    ui.separator();
    let status_text = if self.scanning {
        "🔄 Scanning in progress... Please wait."
    } else if !self.results.is_empty() {
        "✅ Scan completed successfully."
    } else if self.error_message.is_some() {
        "❌ Scan failed. Check error message below."
    } else {
        "⏸️ Ready to scan. Enter an IP address and click 'Engage'."
    };
    ui.colored_label(
        if self.scanning { egui::Color32::BLUE }
        else if !self.results.is_empty() { egui::Color32::GREEN }
        else if self.error_message.is_some() { egui::Color32::RED }
        else { egui::Color32::GRAY },
        status_text
    );

    // Detailed progress information
    if self.scanning {
        ui.label("📊 Scanning ports 1-1024 with TCP connect method...");
        ui.label("⏳ This may take up to 2 minutes depending on network conditions.");
        ui.label("🔍 Checking each port individually for open connections.");
    } else if !self.results.is_empty() {
        ui.label(&format!("📈 Found {} open ports out of 1024 scanned.", self.results.len()));
        if !self.randomize {
            ui.label("🔢 Ports scanned in sequential order.");
        } else {
            ui.label("🎲 Ports scanned in randomized order.");
        }
    }

    if let Some(error) = &self.error_message {
        ui.colored_label(egui::Color32::RED, format!("❌ Error: {}", error));
    }

    if let Some(success) = &self.success_message {
        ui.colored_label(egui::Color32::GREEN, success.clone());
    }

    ui.separator();
    ui.label("📋 Results:");
    egui::ScrollArea::vertical().show(ui, |ui| {
        if self.results.is_empty() && !self.scanning {
            ui.label("No results yet. Click 'Engage' to start scanning.");
        } else {
            for result in &self.results {
                ui.label(result);
            }
        }
    });
        });

        // Check for scan results
        if let Some(rx) = &self.receiver {
            match rx.try_recv() {
                Ok::<Result<Vec<PortResult>, String>, _>(Ok(port_results)) => {
                    self.results = port_results
                        .into_iter()
                        .map(|r| {
                            let service = r.service.unwrap_or_else(|| "-".to_string());
                            format!("Port: {}, Status: open, Service: {}", r.port, service)
                        })
                        .collect();
                    self.scanning = false;
                    self.receiver = None;
                }
                Ok(Err(e)) => {
                    self.error_message = Some(e);
                    self.scanning = false;
                    self.receiver = None;
                }
                Err(_) => {} // not ready
            }
        }
    }
}

impl Akroatis {
    fn start_scan(&mut self) {
        let ip_input = self.ip_input.clone();
        let randomize = self.randomize;
        self.scanning = true;
        self.results.clear();
        self.error_message = None;

        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);

        thread::spawn(move || match IpAddr::from_str(&ip_input) {
            Ok(ipaddr) => {
                let config = ScanConfig {
                    ipaddr,
                    threads: 4,
                    timeout: 1000,
                    delay: 0,
                    randomize,
                };

                let results = scan_ports(config);
                let _ = tx.send(Ok(results));
            }
            Err(e) => {
                let _ = tx.send(Err(format!("Invalid IP address: {}", e)));
            }
        });
    }

    fn download_report(&self) -> Result<String, String> {
        let mut content = String::new();
        content.push_str("Akroatis Port Scanner Report\n");
        content.push_str("===========================\n\n");
        content.push_str(&format!("Target IP: {}\n", self.ip_input));
        content.push_str(&format!("Scan Time: {}\n", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));
        content.push_str(&format!("Randomize: {}\n", if self.randomize { "Yes" } else { "No" }));
        content.push_str(&format!("SYN Scan: {}\n\n", if self.syn_scan { "Yes" } else { "No" }));

        content.push_str("Results:\n");
        content.push_str("--------\n");

        if self.results.is_empty() {
            content.push_str("No open ports found.\n");
        } else {
            for result in &self.results {
                content.push_str(&format!("{}\n", result));
            }
            content.push_str(&format!("\nTotal open ports: {}\n", self.results.len()));
        }

        let filename = format!("akroatis_scan_{}_{}.txt",
                             self.ip_input.replace(".", "_"),
                             chrono::Utc::now().format("%Y%m%d_%H%M%S"));

        fs::write(&filename, content)
            .map_err(|e| format!("Failed to save report: {}", e))
            .map(|_| filename)
    }
}
