//! QuickTunnel production CLI binary

use anyhow::Result;
use clap::Parser;

pub mod cli;

use cli::{Cli, Commands};

/// Executes the parsed CLI command.
pub async fn run_app(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Server(args) => {
            cli::run_server(args).await?;
        }
        Commands::Client(args) => {
            cli::run_client(args).await?;
        }
        Commands::Genkey => {
            let key = cli::generate_token();
            println!("{key}");
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    run_app(cli).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_run_app_genkey() {
        let cli = Cli::parse_from(["quicktunnel", "genkey"]);
        assert!(run_app(cli).await.is_ok());
    }

    #[tokio::test]
    async fn test_run_app_server_invalid() {
        let cli = Cli::parse_from([
            "quicktunnel",
            "server",
            "--secret",
            "sec",
            "--tcp-port-range",
            "invalid",
        ]);
        assert!(run_app(cli).await.is_err());
    }

    #[tokio::test]
    async fn test_run_app_client_invalid() {
        let cli = Cli::parse_from([
            "quicktunnel",
            "client",
            "--local",
            "invalid",
            "--secret",
            "s",
        ]);
        assert!(run_app(cli).await.is_err());
    }

    #[tokio::test]
    async fn test_run_app_server_aborted() {
        let cli = Cli::parse_from([
            "quicktunnel",
            "server",
            "--control-bind",
            "127.0.0.1:0",
            "--http-bind",
            "127.0.0.1:0",
            "--secret",
            "s",
        ]);
        let handle = tokio::spawn(async move {
            let _ = run_app(cli).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        handle.abort();
    }

    #[tokio::test]
    async fn test_run_app_client_aborted() {
        let cli = Cli::parse_from([
            "quicktunnel",
            "client",
            "--local",
            "3000",
            "--secret",
            "s",
            "--no-inspect",
        ]);
        let handle = tokio::spawn(async move {
            let _ = run_app(cli).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        handle.abort();
    }
}
