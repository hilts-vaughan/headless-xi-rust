use std::net::SocketAddr;
use std::time::Duration;

use clap::{Parser, Subcommand};
use headless_xi::SearchClient;

#[derive(Debug, Parser)]
#[command(name = "headless-xi")]
#[command(about = "Headless Final Fantasy XI query client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// List online players via the search server.
    SeaAll {
        /// Search server address, for example.
        #[arg(long, default_value = "")]
        server: SocketAddr,

        /// Socket timeout in seconds.
        #[arg(long, default_value_t = 10)]
        timeout: u64,
    },
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::SeaAll { server, timeout } => {
            let client = SearchClient::new(server).with_timeout(Duration::from_secs(timeout));
            match client.list_online_players() {
                Ok(players) => {
                    for player in players {
                        println!(
                            "{}\tzone={}\tjob={}/{}\tlv={}/{}\tid={}",
                            player.name,
                            player.zone.map(display).unwrap_or_else(|| "-".to_string()),
                            player
                                .main_job
                                .map(display)
                                .unwrap_or_else(|| "-".to_string()),
                            player
                                .sub_job
                                .map(display)
                                .unwrap_or_else(|| "-".to_string()),
                            player
                                .main_level
                                .map(display)
                                .unwrap_or_else(|| "-".to_string()),
                            player
                                .sub_level
                                .map(display)
                                .unwrap_or_else(|| "-".to_string()),
                            player.id.map(display).unwrap_or_else(|| "-".to_string())
                        );
                    }
                    Ok(())
                }
                Err(err) => Err(err.to_string()),
            }
        }
    };

    if let Err(err) = result {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn display<T: std::fmt::Display>(value: T) -> String {
    value.to_string()
}
