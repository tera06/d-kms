use std::env;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::key::create_keys;
use crate::network::{client_sign, start_server};

mod encryption;
mod key;
mod network;
mod types;
#[derive(Parser)]
#[command(name = "dkms")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init { threshold: usize, n: usize },
    Server { index: usize },
    Client { message: String, threshold: usize },
}

#[tokio::main]
async fn main() -> Result<()> {
    if env::var("RUST_LOG").is_err() {
        unsafe {
            env::set_var("RUST_LOG", "info");
        }
    }
    env_logger::init();

    let cli = Cli::parse();

    match cli.cmd {
        Commands::Init { threshold, n } => {
            create_keys(threshold, n).await?;
        }
        Commands::Server { index } => {
            start_server(index).await?;
        }
        Commands::Client { message, threshold } => {
            client_sign(&message, threshold).await?;
        }
    }

    Ok(())
}
