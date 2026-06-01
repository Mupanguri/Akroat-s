# Akroatis Port Scanner — Gap Analysis

**Date:** 2026-05-30
**Project:** Akroatis Port Scanner v0.1.0 (tagged v1.0.0)
**Language:** Rust (edition 2021)
**Repo:** https://github.com/Mupanguri/Akroat-s.git

---

## 1. Current Capabilities

| Capability | Status | Details |
|---|---|---|
| TCP Connect Scan | Implemented | Async via `tokio::net::TcpStream`, ports 1–65535 |
| SYN (Half-Open) Scan | Implemented | Raw sockets via `pnet`, requires admin + Npcap on Windows |
| ARP Sweep (L2 Discovery) | Implemented | `src/discovery/arp.rs` — sends ARP requests, collects active hosts |
| OS Fingerprinting | Basic | TTL + window size heuristic (Linux 3.x–5.x, Windows 10/Server, Infra) |
| Service Detection | Partial | Specialized: SSH, FTP, HTTP, SMB — Generic: SMTP, IMAP, POP3, Telnet, MySQL, PostgreSQL |
| Banner Grabbing | Implemented | `grab_banner()` and `grab_banner_with_retries()` with exponential backoff |
| HTTP Deep Inspection | Implemented | Server header, HTML title, robots.txt, X-Powered-By, security headers |
| NVD CVE Lookups | Implemented | Keyword-based via NVD REST API v2.0, local JSON cache (7-day expiry) |
| GUI (eframe/egui) | Implemented | Real-time results, console, vulnerability display, report download |
| CLI | Implemented | Manual arg parsing, configurable threads, SYN/deep flags |
| Report Export | TXT/HTML/PDF | HTML has styled CVE table with severity badges; PDF via `printpdf` |

---

## 2. Functional Gaps

### 2.1 Scanning Capabilities

| Gap | Severity | Description |
|---|---|---|
| No UDP scanning | **High** | Only TCP is scanned; many critical services run on UDP (DNS 53, SNMP 161, DHCP 67/68) |
| No IPv6 SYN scan | **Medium** | `scan_single_port_syn_shared()` falls back to TCP connect for IPv6 |
| Port range not configurable | **Medium** | Always scans all 65535 ports; users cannot specify custom ranges (e.g. "22,80,443" or "1-1000") |
| No timing profiles | **Low** | No "polite/normal/aggressive" presets; only a single timeout value |
| Interface selection is heuristic | **Medium** | `find_interface_for_target()` matches on first 3 octets only — fails on non-/24 networks |
| ARP sweep blocks per-host | **Low** | Sequential sleep (10ms) per host — slow on large subnets |
| No service/probe customisation | **Low** | Probe list is hardcoded; users cannot add custom probe patterns |
| SYN scan missing rate-limit on ARP | **Low** | ARP sweep is not rate-limited like port scan |

### 2.2 Service Detection

| Gap | Severity | Description |
|---|---|---|
| DNS detection skipped | **Medium** | Explicitly skipped — comment says "would require UDP" |
| No TLS/SSL certificate analysis | **High** | Cannot extract cert info, expiry, issuer, SANs — critical for HTTPS/IMAPS/POP3S |
| No SSH key exchange analysis | **Low** | Only banner version extracted; no host key algo or KEX info |
| No SMB share enumeration | **Medium** | Basic SMB detection only; no share listing, OS version via SMB |
| No database deep probing | **Medium** | MySQL/PostgreSQL detected by banner only; no SQL probe or auth test |
| No HTTP technology stack detection | **Medium** | Missing CMS/framework detection (WordPress, nginx vs Apache, etc.) |
| No SNMP service probing | **Low** | No community string brute-force or MIB walking |
| No RDP detection | **Low** | Port 3389 not handled specifically |
| Banner grabbing uses blocking I/O | **Low** | `grab_banner()` uses `std::net::TcpStream`, blocking within async context |

### 2.3 Vulnerability Intelligence

| Gap | Severity | Description |
|---|---|---|
| No CPE-based matching | **High** | NVD queries are keyword-based, causing false positives/negatives; proper CPE matching needed |
| No severity filtering/threshold | **Medium** | All CVEs returned; no option to show only HIGH/CRITICAL |
| No Exploit-DB integration | **Medium** | Cannot indicate if public exploit exists |
| No CVSS v3 vector scoring | **Low** | Base severity only; no vector string breakdown |
| No vendor advisory feeds | **Low** | Microsoft, Cisco, Adobe, Oracle not included |
| Cache has no eviction policy | **Low** | Only time-based expiry; no max-size enforcement |
| Rate limiting on NVD API | **Low** | No retry/backoff for NVD rate limits (5 req/30s without key) |

### 2.4 Reporting

| Gap | Severity | Description |
|---|---|---|
| No JSON/XML export | **Medium** | Only TXT/HTML/PDF available — JSON needed for automation/pipe |
| No executive summary | **Low** | Reports are raw results; no risk scoring or summary |
| No remediation guidance | **Low** | CVEs shown without fix recommendations |
| PDF truncates results | **Low** | Hardcoded Y-position limit; multi-page not supported |
| HTML report not saved to user-chosen path | **Low** | Always saved to CWD |

### 2.5 GUI

| Gap | Severity | Description |
|---|---|---|
| Scanning state never resets | **High** | `scanning: true` is never set back to `false` — the README notes this bug |
| No scan cancellation | **Medium** | No "Stop" button; once started the scan cannot be interrupted in the GUI |
| No progress bar / percentage | **Medium** | Only an infinite spinner; no "43/65535 ports scanned" |
| No history persistence | **Low** | Results lost on close; no session save/load |
| CVE button spawns blocking thread | **Low** | `thread::spawn` + `rt.block_on` inside the UI frame — could lag |

### 2.6 CLI

| Gap | Severity | Description |
|---|---|---|
| `clap` dependency unused | **Medium** | `clap 4.5.54` included in Cargo.toml but not used; manual arg parsing instead |
| No output format flags | **Low** | CLI always prints to stdout; no `-o` / `--output` flag |
| No CSV/JSON output mode | **Low** | CLI cannot pipe structured data to other tools |
| Help text mentions incomplete options | **Low** | README shows `--help` output missing `--syn`, `--deep`, `--no-service` |

---

## 3. Technical Gaps

### 3.1 Code Quality

| Gap | Severity | Description |
|---|---|---|
| Test coverage ~0.2% | **High** | Only 3 service-detection unit tests + 1 placeholder; no integration tests |
| No CI pipeline | **High** | No `.github/` or CI config; no automated build/test/lint |
| Untracked source files | **High** | 10+ source files not in git (`src/discovery/*`, `src/services/*`, etc.) |
| Redundant/stale files | **Medium** | Root `arp.rs` and `src/mod.rs` contain only "redundant" comments |
| Empty module file | **Low** | `src/bin/mod.rs` is 0 lines |
| Runtime unwraps | **Medium** | Several `.unwrap()` and `.ok()?` calls that will panic on error (e.g. `NonZeroU32::new().unwrap()`) |
| No error logging | **Medium** | Failed packets dropped silently in listener thread (line 167: `continue`) |
| `src/services/tests.rs` imports from wrong scope | **Low** | `use super::*` but `extract_ssh_version`, `extract_ftp_version`, `detect_service` not in scope |
| `src/services/generic.rs` uses `crate::services::ServiceInfo` path | **Low** | Sometimes uses `crate::ServiceInfo`, sometimes `crate::services::ServiceInfo` — inconsistent |

### 3.2 Architecture

| Gap | Severity | Description |
|---|---|---|
| Service detection logic is port-switched | **Medium** | `detect_service()` uses a large `match port {...}` block — not extensible without modifying the function |
| No trait abstractions for services | **Medium** | Service detectors are free functions; no `ServiceDetector` trait for plugins |
| GUI tightly coupled to library internals | **Medium** | GUI imports `vuln::nvd` and `utils::hardware` directly |
| No configuration system | **Medium** | Config is hardcoded struct; no config file (TOML/YAML/JSON) support |
| No logging framework | **Low** | Uses hand-rolled `mpsc::Sender<String>` channel, not `log`/`tracing`/`env_logger` |
| Rate-limiter can panic | **Low** | `NonZeroU32::new(pps as u32).unwrap()` on line 106; if `pps == 0`, panics |

### 3.3 Security

| Gap | Severity | Description |
|---|---|---|
| No privilege checking | **Medium** | SYN scan fails cryptically without admin; no graceful degradation or warning before scan |
| NVD API key not supported | **Low** | Public API has tighter rate limits; no `--api-key` flag |
| No scan authorization prompts | **Low** | No "Are you sure you want to scan X?" confirmation |
| No scan logging | **Low** | No audit trail of scans performed |
| Hardcoded cert acceptance | **Low** | `danger_accept_invalid_certs(true)` in HTTP client — correct for scanning but worth noting |

---

## 4. Infrastructure Gaps

| Gap | Severity | Description |
|---|---|---|
| No CI/CD | **High** | No GitHub Actions, no automated testing on push/PR |
| No Docker image | **Low** | Containerised deployment not supported |
| No pre-built binaries in releases | **Low** | Releases page exists but no binaries attached |
| No cross-platform build config | **Low** | No `.cargo/config.toml` for cross-compilation |
| No benchmark suite | **Low** | No performance benchmarks to track regression |

---

## 5. Documentation Gaps

| Gap | Severity | Description |
|---|---|---|
| README project structure outdated | **Medium** | Shows only 3 source files; actual has 20+ |
| Module structure diagram shows old layout | **Medium** | README structure doesn't reflect `discovery/`, `services/`, `vuln/`, `utils/` |
| No API documentation | **Medium** | `lib.rs` public API has minimal doc comments; no `cargo doc` guidance |
| No CLI `--help` in README matches code | **Low** | README `--help` output missing `--syn`, `--deep`, `--no-service` flags |
| No contributing guide | **Low** | Brief section in README but no detailed CONTRIBUTING.md |

---

## 6. Prioritised Action Plan

### Phase A — Critical Fixes (1–2 days)
| # | Action | Reason |
|---|---|---|
| A1 | Set `scanning = false` when scan completes | GUI stuck spinning forever — affects UX severely |
| A2 | Add `--syn`/`--deep`/`--no-service` to CLI help | Consistency with actual behaviour |
| A3 | Remove `clap` from dependencies or migrate to it | Unused dep bloats build |
| A4 | Add `#[cfg(test)]` module for `extract_*` functions | Tests don't compile — `super::*` doesn't reach those fns |
| A5 | Handle `pps == 0` before `NonZeroU32::new` | Prevents runtime panic |

### Phase B — High Priority (1 week)
| # | Action | Reason |
|---|---|---|
| B1 | Git-track all source files | 10+ files missing from version control |
| B2 | Add GitHub Actions (build + test + clippy) | No automation; quality risks |
| B3 | Add scan cancellation to GUI | Usability; long scans cannot be interrupted |
| B4 | Add JSON export format | Required for automation/pipe workflows |
| B5 | Delete stale files (`arp.rs`, `src/mod.rs`, `src/bin/mod.rs`) | Dead code clutter |
| B6 | Add `--port-range` CLI flag + `ports: Vec<u16>` in ScanConfig | Users need custom ranges |
| B7 | Add progress reporting back to GUI | Current spinner is vague |

### Phase C — Medium Priority (2–3 weeks)
| # | Action | Reason |
|---|---|---|
| C1 | Implement CPE-based NVD matching | Reduces false positives significantly |
| C2 | Add TLS/SSL certificate analysis | Critical for HTTPS/IMAPS/POP3S |
| C3 | Replace `match port {...}` with trait-based dispatch | Enables plugin-style extensibility |
| C4 | Add UDP scanning (DNS, SNMP, DHCP) | Broadens scan scope significantly |
| C5 | Add Exploit-DB integration | Indicates exploitability |
| C6 | Add `--severity-threshold` for vulnerability display | Filter noise |
| C7 | Migrate to `log`/`tracing` instead of hand-rolled channels | Standard logging practice |

### Phase D — Low Priority / Future (1–2 months)
| # | Action | Reason |
|---|---|---|
| D1 | Config file support (TOML/YAML) | Persistent settings |
| D2 | HTTP tech-stack detection (Wappalyzer-style) | Deeper service intel |
| D3 | SMB share enumeration | Lateral movement info |
| D4 | OS fingerprinting via TCP/IP stack (p0f-style) | More accurate than TTL heuristic |
| D5 | Docker image | Containerised deployment |
| D6 | Session save/load in GUI | Persistence of results |
| D7 | Pre-built binary releases | Distribution |

---

## 7. Risk Assessment Summary

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| GUI scanning state never resets | Certain | Medium | A1 (1-hour fix) |
| Untracked source files lost | High | High | B1 (immediate git add) |
| Runtime panic from unwrap | Medium | High | A5 (guard before unwrap) |
| NVD API false positives | High | Medium | C1 (CPE matching) |
| Tests don't compile | High | Low | A4 (fix imports) |
| No CI — regressions undetected | High | Medium | B2 (add CI in 1 day) |
| UDP services invisible | High | Medium | C4 (add UDP scan) |

---

## 8. Effort Estimate

| Phase | Effort | Scope |
|---|---|---|
| **Phase A** (Critical) | ~1–2 days | GUI state, CLI help, dep cleanup, test fix, panic guard |
| **Phase B** (High) | ~1 week | Git hygiene, CI, cancellation, JSON export, progress, range flag |
| **Phase C** (Medium) | ~2–3 weeks | CPE matching, TLS, trait refactor, UDP scan, Exploit-DB, logging |
| **Phase D** (Low) | ~1–2 months | Config file, tech detection, SMB, OS fingerprinting, Docker |
| **Total** | ~2–3 months | To reach production-grade maturity |
