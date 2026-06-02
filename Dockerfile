# =============================================================================
# Stage 1: Build the CLI binary
# Debian-based (not Alpine) to avoid musl / ring / SQLite build headaches
# =============================================================================
FROM rust:bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libssl-dev \
    perl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Build only the CLI binary — the GUI (akroatis) requires display libraries
# and is intended for native desktop use.
RUN cargo build --release --bin port_sniffer && \
    cp target/release/port_sniffer /port_sniffer

# =============================================================================
# Stage 2: Minimal runtime image
# =============================================================================
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    nmap \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /port_sniffer /usr/local/bin/port_sniffer

# Default data directory — mount a volume here to persist the exploit DB
ENV AKROATIS_DATA=/var/lib/akroatis
RUN mkdir -p "$AKROATIS_DATA"

WORKDIR "$AKROATIS_DATA"

ENTRYPOINT ["port_sniffer"]
CMD ["--help"]
