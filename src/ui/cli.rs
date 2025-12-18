use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "dkms")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init { threshold: usize, n: usize },
    Server { index: usize },
    Client { message: String, threshold: usize },
}
