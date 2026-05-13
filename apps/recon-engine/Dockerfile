FROM rust:1.77-slim AS builder

WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev cmake && rm -rf /var/lib/apt/lists/*

COPY apps/recon-engine/Cargo.toml apps/recon-engine/Cargo.lock* ./
# Create dummy src for dependency caching
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release 2>/dev/null || true

COPY apps/recon-engine/src ./src
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/reconx-engine .

EXPOSE 50052
CMD ["./reconx-engine"]
