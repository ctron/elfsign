use crate::cli::{sign, verify};
use clap::{Parser, Subcommand};
use log::LevelFilter;
use simplelog::{ColorChoice, ConfigBuilder, TermLogger, TerminalMode};
use std::ffi::OsString;

mod cli;
pub(crate) mod signature;
mod utils;
pub(crate) mod verification;

#[derive(Parser, Debug)]
struct Cli {
    /// Don't output anything
    #[arg(global = true, short, long, default_value = "false")]
    quiet: bool,

    /// Increase verbosity level
    #[arg(global = true, short, long, action=clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Sign {
        #[arg()]
        input: OsString,
        #[arg()]
        output: OsString,
    },
    Verify {
        #[arg()]
        input: OsString,
    },
}

fn setup_logger(cli: &Cli) {
    let log_level = match (cli.quiet, cli.verbose) {
        (true, _) => LevelFilter::Off,
        (_, 0) => LevelFilter::Warn,
        (_, 1) => LevelFilter::Info,
        (_, 2) => LevelFilter::Debug,
        (_, _) => LevelFilter::Trace,
    };

    TermLogger::init(
        log_level,
        ConfigBuilder::new()
            .set_time_level(LevelFilter::Debug)
            .set_max_level(LevelFilter::Debug)
            .build(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    )
    .expect("Unable to setup logging");

    log::debug!("Log Level: {log_level}");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    setup_logger(&cli);

    match cli.command {
        Command::Sign { input, output } => sign::run(sign::Options { input, output }).await?,
        Command::Verify { input } => verify::run(verify::Options { input }).await?,
    }

    Ok(())
}
