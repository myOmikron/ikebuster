//! # ikebuster
//!
//! A little utility to scan your IKE servers for insecure ciphers

#![warn(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use std::env;

use clap::Parser;

use crate::cli::Cli;

mod cli;

#[tokio::main]
async fn main() {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
}
