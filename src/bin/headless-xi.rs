use std::net::SocketAddr;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use headless_xi::{names, OnlinePlayer, SearchClient, SearchVariant};

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
        /// Search server address, for example 66.85.159.114:54002.
        #[arg(long, default_value = "66.85.159.114:54002")]
        server: SocketAddr,

        /// Protocol variant to use.
        #[arg(long, value_enum, default_value_t = CliVariant::Lsb)]
        variant: CliVariant,

        /// Socket timeout in seconds.
        #[arg(long, default_value_t = 10)]
        timeout: u64,

        /// Restrict results to a specific zone ID.
        #[arg(long, value_parser = parse_zone_id)]
        zone: Option<u16>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliVariant {
    Lsb,
    Horizon,
}

impl From<CliVariant> for SearchVariant {
    fn from(value: CliVariant) -> Self {
        match value {
            CliVariant::Lsb => SearchVariant::Lsb,
            CliVariant::Horizon => SearchVariant::Horizon,
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::SeaAll {
            server,
            variant,
            timeout,
            zone,
        } => {
            let mut client = SearchClient::new(server)
                .with_timeout(Duration::from_secs(timeout))
                .with_variant(variant.into());
            if let Some(zone) = zone {
                client = client.with_zone_filter(zone);
            }
            match client.list_online_players() {
                Ok(players) => {
                    print_players(&players);
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

fn parse_zone_id(value: &str) -> Result<u16, String> {
    let zone = value
        .parse::<u16>()
        .map_err(|_| format!("invalid zone ID `{value}`"))?;
    if zone > 1023 {
        return Err(format!("zone ID `{zone}` is too large; expected 0..=1023"));
    }
    Ok(zone)
}

struct PlayerRow {
    name: String,
    zone: String,
    job: String,
    level: String,
    id: String,
}

fn print_players(players: &[OnlinePlayer]) {
    let rows: Vec<_> = players.iter().map(player_row).collect();
    let name_width = column_width("NAME", rows.iter().map(|row| row.name.as_str()));
    let zone_width = column_width("ZONE", rows.iter().map(|row| row.zone.as_str()));
    let job_width = column_width("JOB", rows.iter().map(|row| row.job.as_str()));
    let level_width = column_width("LV", rows.iter().map(|row| row.level.as_str()));
    let id_width = column_width("ID", rows.iter().map(|row| row.id.as_str()));

    println!(
        "{:<name_width$}  {:<zone_width$}  {:<job_width$}  {:>level_width$}  {:>id_width$}",
        "NAME", "ZONE", "JOB", "LV", "ID"
    );
    println!(
        "{:-<name_width$}  {:-<zone_width$}  {:-<job_width$}  {:-<level_width$}  {:-<id_width$}",
        "", "", "", "", ""
    );

    for row in rows {
        println!(
            "{:<name_width$}  {:<zone_width$}  {:<job_width$}  {:>level_width$}  {:>id_width$}",
            row.name, row.zone, row.job, row.level, row.id
        );
    }
}

fn player_row(player: &OnlinePlayer) -> PlayerRow {
    PlayerRow {
        name: player.name.clone(),
        zone: player
            .zone
            .map(format_zone)
            .unwrap_or_else(|| "-".to_string()),
        job: format_job_pair(player.main_job, player.sub_job),
        level: format_optional_pair(player.main_level, player.sub_level),
        id: player
            .id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "-".to_string()),
    }
}

fn column_width<'a>(header: &str, values: impl Iterator<Item = &'a str>) -> usize {
    values
        .map(str::len)
        .max()
        .unwrap_or_default()
        .max(header.len())
}

fn format_zone(zone: u16) -> String {
    match names::zone_name(zone) {
        Some(name) => format!("{name} ({zone})"),
        None => format!("#{zone}"),
    }
}

fn format_job_pair(main: Option<u8>, sub: Option<u8>) -> String {
    match (main, sub) {
        (Some(main), Some(sub)) => format!("{}/{}", format_job(main), format_job(sub)),
        (Some(main), None) => format!("{}/-", format_job(main)),
        (None, Some(sub)) => format!("-/{}", format_job(sub)),
        (None, None) => "-".to_string(),
    }
}

fn format_job(job: u8) -> String {
    names::job_name(job)
        .map(str::to_string)
        .unwrap_or_else(|| format!("#{job}"))
}

fn format_optional_pair<T: std::fmt::Display>(main: Option<T>, sub: Option<T>) -> String {
    match (main, sub) {
        (Some(main), Some(sub)) => format!("{main}/{sub}"),
        (Some(main), None) => format!("{main}/-"),
        (None, Some(sub)) => format!("-/{sub}"),
        (None, None) => "-".to_string(),
    }
}
