# 🛰 Akroatis — Offline Vulnerability Intelligence Engine

[![Rust](https://img.shields.io/badge/Rust-1.70%2B-dea584?logo=rust)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://gitlab.com/YOUR_USERNAME/Akroat-s/badges/main/pipeline.svg)](https://gitlab.com/YOUR_USERNAME/Akroat-s/-/pipelines)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker)](Dockerfile)

> **Akroatis** is an offline vulnerability intelligence engine packed into a port scanner. It ingests public exploit and CVE data, builds ranked in-memory indexes (BM25 + binary-search version intervals), and surfaces relevant threats for every detected service — with **zero runtime API calls** after initialization.

```
Target: 192.168.1.0/24
  ├─ Port  22  → OpenSSH 8.9p1       ⚠ CVE-2023-38408  (HIGH)   [EXPLOIT]
  ├─ Port  80  → Apache 2.4.38       ⚠ CVE-2021-41773  (CRITICAL)
  └─ Port 443  → nginx 1.24.0        ⚠ CVE-2023-44487  (MEDIUM)  [EXPLOIT]
```

---

## Table of Contents

- [Why? — Motivation](#-why--motivation)
- [What? — Objective](#-what--core-objective)
- [How? — Architecture](#-how--architecture)
- [Where? — Deployment](#-where--deployment)
- [Benefits & Advantages](#-benefits--advantages)
- [Skill Gaps & Learning Journey](#-skill-gaps--learning-journey)
- [Problems Faced & Solutions](#-problems-faced--solutions)
- [Disadvantages & Limitations](#-disadvantages--limitations)
- [Future Prospects](#-future-prospects)
- [CI/CD Pipeline (GitLab)](#-cicd-pipeline-gitlab)
- [Quality Standards](#-quality-standards)
- [Quick Start](#quick-start)
- [Development](#development)

---

## 🧠 Why? — Motivation

Every penetration tester knows the workflow: run `nmap -sV`, grep the output, copy-paste service strings into a browser, and manually cross-reference CVEs. This is brittle, slow, and prone to oversight.

I wanted to build a tool that:

1. **Works fully on the machine** — no API key, no further internet cve hunting dependency during a scan
2. **Merges exploit intelligence + CVE data** into one query surface
3. **Ranks results** so the most critical, exploitable vulnerabilities surface first
4. **Scales** to class-C subnets without drowning the analyst in noise

This project started as a simple TCP connect scanner and evolved into a self-contained vulnerability intelligence platform — my attempt to close the gap between scanning and actionable threat data, entirely in Rust.

---

## 🎯 What? — Core Objective

**Build an reliale, self-contained vulnerability intelligence engine that:**

- Ingests exploit-db and NVD CVE data into a local SQLite database
- Indexes everything into ranked in-memory structures (BM25 for text search, binary-sorted version intervals for exact version matching)
- Surfaces matched CVEs + associated exploit-db entries for every detected service
- Runs as a **CLI tool** (headless, Docker-friendly) and a **GUI application** (egui, real-time)
- Requires **zero web scouring calls during a scan** — all lookups are in-memory after initialization

---

## ⚙️ How? — Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                         CLI / GUI                             │
├──────────────────────────────────────────────────────────────┤
│  ┌─────────┐   ┌──────────┐   ┌────────────┐                │
│  │ Scanner │──▶│ Service  │──▶│  Vuln      │                │
│  │ (TCP+UDP)│  │Detection │   │  Engine    │                │
│  └─────────┘   └──────────┘   └─────┬──────┘                │
│       │                                │                      │
│       ▼                                ▼                      │
│  ┌─────────┐                   ┌──────────────┐              │
│  │  Nmap   │                   │  BM25 Search  │              │
│  │Enhance  │                   │  + Version    │              │
│  │(subproc)│                   │   Intervals   │              │
│  └─────────┘                   └──────┬───────┘              │
│                                       │                       │
└───────────────────────────────────────┼───────────────────────┘
                                        │
                              ┌─────────▼─────────┐
                              │  SQLite (WAL mode)  │
                              │  ├─ exploits         │
                              │  ├─ exploits_fts     │
                              │  ├─ cve_index        │
                              │  └─ cpe_mappings     │
                              └─────────────────────┘
```

### Data Pipeline

```
exploit-db CSV ──→ SQLite exploits table ──→ VulnEngine (BM25 + CVE↔EDB index)
NVD API 2.0    ──→ SQLite cve_index table  ──→ VulnEngine (CPE index + version intervals)
```

### Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **BM25 ranking** (k₁=1.2, b=0.75) | Industry-standard text ranking; ~5 MB index for 200K documents |
| **Binary-search version intervals** | O(log n + k) per service — cache-friendly, no DB query per port |
| **SQLite bundled via rusqlite** | Zero external dependencies; WAL mode for concurrent reads |
| **String interning via lasso** | Reduces CPE index memory by deduplicating vendor:product keys |
| **Async Tokio runtime** | Non-blocking I/O for thousands of concurrent scan targets |
| **Bounded channels + governor** | Backpressure and global rate limiting per second |

---

## 📡 Where? — Deployment

### CLI (Linux, macOS, Windows, Docker)

```bash
# Native
cargo run --release --bin port_sniffer -- 192.168.1.0/24 --port-range 22,80,443

# Docker (recommended for CI/headless)
docker compose run --rm akroatis 192.168.1.0/24
```

### GUI (Desktop only — requires display server)

```bash
cargo run --release --bin akroatis
```

### CI/CD Integration

The CLI binary is designed to run inside GitLab CI pipelines (see [CI/CD Pipeline](#-cicd-pipeline-gitlab) for full `.gitlab-ci.yml`).

---

## ✅ Benefits & Advantages

- **Fully hosted on users machine runtime** — after `update-db --download`, all lookups hit local memory
- **Combined exploit + CVE search** — one query returns both
- **BM25 relevance ranking** — most critical results bubble up first
- **Version-interval matching** — engine parses version strings (`2.4.38`) and matches against CVE version ranges via binary search
- **Nmap enhancement** — optional subprocess for deeper service fingerprinting
- **Real-time GUI** — streaming results, progress bar, live vulnerability fetching
- **Multiple export formats** — TXT, HTML, PDF, JSON
- **Session persistence** — GUI saves/restores state across restarts
- **Docker-ready** — multi-stage build, ~100 MB runtime image
- **36 unit + integration tests** — clippy-clean, zero warnings

---

## 📚 Skill Gaps & Learning Journey

This project was built as a learning vehicle. Here is an honest accounting of where I pushed my comfort zone and where gaps remain:

### Areas Developed

| Area | What I Learned |
|------|----------------|
| **Async Rust** | Tokio runtime, `futures::stream::iter`, `buffer_unordered`, bounded channels |
| **SQLite + FTS5** | WAL mode, virtual tables, LRU/TTL caching, `rusqlite` with bundled compile |
| **Information Retrieval** | BM25 ranking algorithm, inverted index construction, tokenization with stop-word filtering |
| **Binary search on custom types** | `partition_point` on `Version` intervals; derived `Ord` for `Version` (lexicographic with zero-fill) |
| **GUI with egui** | Immediate-mode layout, `SidePanel`/`CentralPanel`/`TopBottomPanel`, toast notifications, progress bars |
| **String interning** | `lasso::Rodeo` for memory-efficient CPE index keys |
| **Serde + JSON** | Session serialization, CVE JSON parsing from NVD API |
| **Nmap integration** | Subprocess spawning, XML parsing with `quick-xml` |
| **Docker multi-stage** | `rust:bookworm` → `debian:bookworm-slim` — avoiding Alpine musl pitfalls with `ring` and bundled SQLite |

### Current Knowledge Gaps

1. **Raw socket / packet injection** — SYN scan is currently a stub; real implementation requires `pnet` or raw AF_PACKET sockets (platform-specific, root/admin)
2. **NVD API rate-limit strategies** — current implementation is a naive `sleep(6.5s)` without retry/backoff
3. **Fuzz testing** — no `cargo-fuzz` or property-based testing yet
4. **Benchmarking** — no `criterion` benchmarks for the engine or scanner throughput
5. **Cross-compilation** — only tested on x86_64 Windows; no ARM/aarch64 or musl targets validated
6. **True headless GUI** — the egui app needs `X11`/`Wayland`; no `headless` rendering mode

### How I Addressed Gaps

- **Async experience**: started with blocking `std::net::TcpStream`, migrated to `tokio::net::TcpStream`, then introduced `futures::stream`
- **SQLite**: began with a simple JSON file cache, graduated to a proper SQLite schema with FTS5 and indexes
- **Version parsing**: initially used naive string comparison; rewrote with `Version` struct, `Ord`, and `partition_point` binary search after studying how package managers handle versions

---

## 🚧 Problems Faced & Solutions

| Problem | Solution |
|---------|----------|
| `rusqlite` compile failure on Windows (bundled SQLite needs C compiler) | Added `vcpkg` fallback in build script; switched to `bundled` feature with proper MSVC toolchain |
| `ring` crate needs `perl` and `make` during build | Documented build deps; Dockerfile installs `build-essential` + `perl` explicitly |
| `references` is a SQLite reserved word | Renamed column to `refs` |
| NVD API rate limiting (5 req/30s without key) | Added `--api-key` flag; dynamic sleep based on key presence (0.7s with, 6.5s without) |
| Version intervals from NVD are complex (versionStart* + versionEnd*) | Simplified to a single `[min_affected, min_fixed)` interval per CVE; acceptable for 90% of cases |
| egui 0.33 API changes (`Rounding` → `CornerRadius`, `Frame::none()` deprecated) | Audited all `Frame`/`Rounding` usage; used `Frame::NONE` + `.corner_radius()` |
| Exploit-db CSV has multi-line quoted descriptions | Built a `parse_csv_line()` parser instead of using `csv` crate (kept dependency count low) |
| Tokio runtime conflicts with `reqwest::blocking` | Spawn blocking calls in a dedicated thread; used async `reqwest` in the NVD import path |
| GUI PDF download silently failed (no user feedback) | Added toast notification system showing saved filename or error |
| 0 CVEs in database after exploit import | Added `--download-cves` flag; NVD CVE data now powers version-interval matching |

---

## ⚠️ Disadvantages & Limitations

- **No SYN scan** — uses TCP connect scans only (slower, more detectable, requires no raw sockets)
- **CVE data requires explicit download** — not bundled; must run `update-db --download-cves`
- **NVD rate limiting** — downloading the full CVE corpus (~200K records) takes ~10 minutes without an API key
- **Version interval matching is simplified** — handles the `[start, end)` case well but not complex multi-range or `AND`/`OR` CPE configurations
- **GUI requires desktop** — not suitable for headless/SSH environments
- **Windows-only testing** — not validated on macOS or Linux (though Rust is cross-platform by design)
- **No IPv6 scanning** — parses IPv6 but `IpNetwork::iter()` yields only IPv4
- **Memory at scan time** — engine loads all CVE data (~40 MB); acceptable but not zero-cost

---

## 🔭 Future Prospects

| Feature | Priority | Notes |
|---------|----------|-------|
| **SYN scan via raw sockets** | High | Requires `pnet` on Linux / WinPcap on Windows; needs platform-specific code |
| **Nmap NSE script integration** | Medium | Run `nmap --script vuln` and merge results |
| **Incremental CVE updates** | Medium | `--since` already wired in NVD API — just needs a scheduled cron/trigger |
| **Cargo benchmark suite** | Medium | `criterion` benchmarks for scan throughput and engine query latency |
| **OpenAPI / gRPC service** | Low | Wrap the engine in a microservice for integration with other tools |
| **Web UI (WASM)** | Low | egui can compile to WebAssembly — one codebase for desktop + browser |
| **CVSS 4.0 support** | Low | NVD API already ships CVSS 4.0; parser needs updating |
| **Plugin system for service detectors** | Low | Currently hard-coded `lookup_cpe()` table — could be hot-reloadable |

---

## 🔄 CI/CD Pipeline (GitLab)

Below is a complete `.gitlab-ci.yml` configuration. It runs linting, compilation, tests, Docker build, and publishes the image to the GitLab Container Registry.

### Pipeline Stages

| Stage | Purpose |
|-------|---------|
| `lint` | `cargo fmt --check` + `cargo clippy -- -D warnings` |
| `build` | Compile all targets in release mode |
| `test` | Run all 36 unit + integration tests |
| `docker` | Build and push multi-stage Docker image |
| `scan` | (Optional) smoke-test the CLI binary against localhost |

### `.gitlab-ci.yml`

```yaml
image: rust:bookworm

variables:
  CARGO_HOME: ${CI_PROJECT_DIR}/.cargo
  CARGO_INCREMENTAL: 0
  RUSTFLAGS: "-C link-arg=-fuse-ld=lld"
  DOCKER_IMAGE: ${CI_REGISTRY_IMAGE}:${CI_COMMIT_SHORT_SHA}
  DOCKER_IMAGE_LATEST: ${CI_REGISTRY_IMAGE}:latest

cache:
  key: ${CI_JOB_NAME}
  paths:
    - .cargo/
    - target/

stages:
  - lint
  - build
  - test
  - docker
  - scan

# ── Lint ───────────────────────────────────────────────────────
rustfmt:
  stage: lint
  script:
    - rustup component add rustfmt clippy
    - cargo fmt --check
    - cargo clippy --all-targets -- -D warnings
  except:
    - main

# ── Build ──────────────────────────────────────────────────────
build-cli:
  stage: build
  script:
    - apt-get update && apt-get install -y build-essential pkg-config libssl-dev perl
    - cargo build --release --bin port_sniffer
  artifacts:
    paths:
      - target/release/port_sniffer
    expire_in: 1 week

build-gui:
  stage: build
  script:
    - apt-get update && apt-get install -y build-essential pkg-config libssl-dev perl
      libgtk-3-dev libxcb1-dev libxkbcommon-dev libfontconfig1-dev
    - cargo build --release --bin akroatis
  artifacts:
    paths:
      - target/release/akroatis
    expire_in: 1 week

# ── Test ────────────────────────────────────────────────────────
test:
  stage: test
  script:
    - apt-get update && apt-get install -y build-essential pkg-config libssl-dev perl
    - cargo test --all-targets

# ── Docker ──────────────────────────────────────────────────────
docker:
  stage: docker
  image: docker:latest
  services:
    - docker:dind
  variables:
    DOCKER_TLS_CERTDIR: ""
  before_script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
  script:
    - docker build -t $DOCKER_IMAGE -t $DOCKER_IMAGE_LATEST .
    - docker push $DOCKER_IMAGE
    - docker push $DOCKER_IMAGE_LATEST
  only:
    - main

# ── Smoke test ──────────────────────────────────────────────────
smoke-test:
  stage: scan
  needs: ["docker"]
  image: $DOCKER_IMAGE_LATEST
  script:
    - port_sniffer --help
    - port_sniffer 127.0.0.1 --port-range 22,80,443
  only:
    - main
```

### Setup Instructions

1. **Push to GitLab**:
   ```bash
   git remote add gitlab https://gitlab.com/your-username/akroatis.git
   git push -u gitlab main
   ```

2. **Configure CI/CD variables** (Settings → CI/CD → Variables):
   - `CI_REGISTRY_USER` — GitLab username or deploy token
   - `CI_REGISTRY_PASSWORD` — GitLab personal access token / deploy token password

3. **Enable Container Registry** in your GitLab project settings.

4. **Optional — weekly CVE update via scheduled pipeline**:
   ```yaml
   # Add to .gitlab-ci.yml
   weekly-cve-update:
     stage: scan
     image: $DOCKER_IMAGE_LATEST
     script:
       - port_sniffer update-db --download-cves --since $(date -d '7 days ago' '+%Y-%m-%d')
     only:
       - schedules
   ```
   Then create a schedule in GitLab: Settings → CI/CD → Schedules → "Weekly CVE sync".

---

## 📏 Quality Standards

| Criterion | How It's Met |
|-----------|--------------|
| **No compiler warnings** | `cargo clippy -- -D warnings` enforces zero warnings in CI |
| **Formatting** | `cargo fmt --check` ensures consistent style |
| **Test coverage** | 36 tests (9 unit + 27 integration) covering engine, DB, search, CVE pipeline, full scan path |
| **Error handling** | No `unwrap()` in production paths; `Result` types throughout; `VulnError` enum with 10 variants |
| **Dependency audit** | `cargo audit` (see `ci.yml`) checks for known CVEs in dependencies |
| **Security** | No secrets in code; API keys via CLI flags or environment variables only |
| **Documentation** | Public API documented; architecture diagram above; this README |
| **CI/CD** | Lint → Build → Test → Docker → Smoke-test pipeline |

---

## Quick Start

### Prerequisites

- **Rust** 1.70+ (`rustup install stable`)
- **C compiler** (MSVC on Windows, `build-essential` on Linux, Xcode CLT on macOS)
- **Nmap** (optional, for `🧭 Nmap Enhancement`)

### 1. Clone & Build

```bash
git clone https://github.com/Mupanguri/Akroat-s.git
cd Akroat-s
cargo build --release
```

### 2. Download Intelligence Data

```bash
# Download exploit-db (required for exploit search)
cargo run --release --bin port_sniffer -- update-db --download

# Download NVD CVE data (required for version-interval matching)
# Without --api-key: ~10 min; with: ~1 min
cargo run --release --bin port_sniffer -- update-db --download-cves --api-key YOUR_NVD_API_KEY
```

### 3. Scan

```bash
# CLI
cargo run --release --bin port_sniffer -- 192.168.1.0/24 --port-range 22,80,443

# GUI
cargo run --release --bin akroatis
```

### Docker

```bash
docker compose build
docker compose run --rm akroatis update-db --download
docker compose run --rm akroatis 192.168.1.0/24
```

### Search

```bash
# By CVE ID
cargo run --release --bin port_sniffer -- search CVE-2023-44487

# By EDB ID
cargo run --release --bin port_sniffer -- search EDB-51193

# By service:version (uses engine then FTS5 fallback)
cargo run --release --bin port_sniffer -- search apache:2.4.38

# Keyword
cargo run --release --bin port_sniffer -- search "linux kernel rce"
```

---

## Development

### Project Structure

```
src/
├── lib.rs                  # Core scanner + scan_stream! macro + PortSeq
├── main.rs                 # CLI entrypoint + NVD CVE import
├── bin/
│   └── akroatis.rs         # GUI (eframe/egui) with tabs, notifications, nmap
├── vuln/
│   ├── engine.rs           # VulnEngine — BM25, CPE index, version intervals
│   ├── db.rs               # VulnDb — SQLite with FTS5, LRU+TTL cache
│   ├── exploit.rs          # Global engine static, exploit lookup
│   ├── nvd.rs              # NVD API client + CVE-lookup-per-service
│   ├── cache.rs            # VulnDb-backed cache
│   ├── search.rs           # Query parser (CVE-/EDB-/service:version/keyword)
│   └── error.rs            # VulnError enum with 10 variants
├── services/
│   ├── mod.rs              # Service detection router
│   ├── banner_grabber.rs   # TCP banner grabber
│   ├── http.rs             # HTTP server detection
│   ├── ssh.rs              # SSH version extraction
│   ├── ftp.rs              # FTP version extraction
│   └── ...                 # SMTP, generic, etc.
├── config.rs               # TOML config loader
└── utils.rs                # Helpers
```

### Commands

```bash
cargo test                  # Run 36 tests
cargo clippy -- -D warnings # Lint (must pass CI)
cargo fmt --check           # Format check
cargo build --release       # Optimized build
cargo run --release --bin akroatis   # GUI
cargo run --release --bin port_sniffer -- <IP>  # CLI
```

---

**Disclaimer**: This tool is for educational and authorized security testing only. Users are responsible for complying with all applicable laws and obtaining explicit permission before scanning any network or system.
