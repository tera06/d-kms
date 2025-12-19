use std::env;

use anyhow::Result;
use clap::Parser;

use crate::app::runner;
use crate::ui::cli;

mod app;
mod domain;
mod encryption;
mod key;
mod network;
mod types;
mod ui;

#[tokio::main]
async fn main() -> Result<()> {
    if env::var("RUST_LOG").is_err() {
        unsafe {
            env::set_var("RUST_LOG", "info");
        }
    }
    env_logger::init();

    let cli = cli::Cli::parse();

    let app_action = cli.cmd.into();

    runner::AppRunner::run(app_action).await?;

    Ok(())
}
