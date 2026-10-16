//! `convesso-relay`: a convesso relay, from a configuration file.
//!
//! ```text
//! convesso-relay [relay.toml]
//! ```
//!
//! On first start it creates its identity and prints its address, which
//! clients pin.

use std::process::ExitCode;

use convesso_tokio::relay_config::{hex, parse, start};

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "relay.toml".into());
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("convesso-relay: reading {path}: {error}");
            return ExitCode::FAILURE;
        }
    };
    let config = match parse(&text) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("convesso-relay: {path}: {error}");
            return ExitCode::FAILURE;
        }
    };
    let started = match start(&config).await {
        Ok(started) => started,
        Err(error) => {
            eprintln!("convesso-relay: {error}");
            return ExitCode::FAILURE;
        }
    };
    if started.created {
        println!("created a new identity in {}", config.identity.display());
    }
    println!("convesso relay {}", hex(&started.address));
    let tls = if started.tls { ", TLS too" } else { "" };
    println!(
        "listening on udp {} and tcp {}{tls}",
        started.udp, started.tcp
    );
    match started.serve().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("convesso-relay: {error}");
            ExitCode::FAILURE
        }
    }
}
