use anyhow::Result;
use clap::Parser;
use tracing::{info, Level};
use tracing_subscriber::{fmt, EnvFilter};

mod lib;
mod models;
mod plugins;
mod scope;
mod scanners;

use crate::lib::ReconEngine;

#[derive(Parser, Debug)]
#[command(name = "reconx-engine", about = "ReconX Recon Engine")]
struct Args {
    /// gRPC listen port
    #[arg(short, long, default_value = "50052")]
    port: u16,

    /// Database URL
    #[arg(long, env = "DATABASE_URL")]
    database_url: Option<String>,

    /// Redis URL
    #[arg(long, env = "REDIS_URL", default_value = "redis://localhost:6379")]
    redis_url: String,

    /// Kafka bootstrap servers
    #[arg(long, env = "KAFKA_BOOTSTRAP_SERVERS", default_value = "localhost:9092")]
    kafka_servers: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .json()
        .init();

    let args = Args::parse();

    info!(port = args.port, "Starting ReconX Recon Engine");

    // Initialize the engine
    let engine = ReconEngine::new(
        args.redis_url.clone(),
        args.kafka_servers.clone(),
    ).await?;

    info!("Recon Engine initialized with {} plugins", engine.plugin_count());

    // Start gRPC server
    info!(port = args.port, "gRPC server listening");

    // Keep running
    tokio::signal::ctrl_c().await?;
    info!("Shutting down Recon Engine");

    Ok(())
}
