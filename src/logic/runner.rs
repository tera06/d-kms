use crate::{key, network};

pub enum AppAction {
    Init { threshold: usize, n: usize },
    Server { index: usize },
    Client { message: String, threshold: usize },
}

pub struct AppRunner;

impl AppRunner {
    pub async fn run(action: AppAction) -> anyhow::Result<()> {
        match action {
            AppAction::Init { threshold, n } => {
                key::create_keys(threshold, n).await?;
            }
            AppAction::Server { index } => {
                network::start_server(index).await?;
            }
            AppAction::Client { message, threshold } => {
                network::client_sign(&message, threshold).await?;
            }
        }
        Ok(())
    }
}
