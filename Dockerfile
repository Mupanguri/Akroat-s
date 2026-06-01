# Build stage
FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev pkgconfig openssl-dev

WORKDIR /app
COPY . .

RUN cargo build --release --bin port_sniffer --bin akroatis

# Runtime stage
FROM alpine:latest

RUN apk add --no-cache ca-certificates

COPY --from=builder /app/target/release/port_sniffer /usr/local/bin/
COPY --from=builder /app/target/release/akroatis /usr/local/bin/

ENTRYPOINT ["port_sniffer"]
