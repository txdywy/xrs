#![forbid(unsafe_code)]

use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::{EnvFilter, fmt};
use xrs_config::RootConfig;
use xrs_core::Runtime;

#[derive(Debug, Parser)]
#[command(
    name = "xrs",
    version,
    about = "Rust proxy core aiming for Xray-core compatibility"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Run(RunArgs),
    Test(ConfigArgs),
    Dump(ConfigArgs),
    Version,
    Uuid,
}

#[derive(Clone, Debug, Args)]
struct RunArgs {
    #[command(flatten)]
    config: ConfigArgs,
    #[arg(long = "test")]
    test: bool,
    #[arg(long = "dump")]
    dump: bool,
}

#[derive(Clone, Debug, Args)]
struct ConfigArgs {
    #[arg(short = 'c', long = "config")]
    config: Vec<PathBuf>,
    #[arg(long = "confdir")]
    confdir: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    match Cli::parse_from(normalized_args())
        .command
        .unwrap_or(Command::Run(RunArgs {
            config: ConfigArgs {
                config: Vec::new(),
                confdir: None,
            },
            test: false,
            dump: false,
        })) {
        Command::Run(args) => run(args).await,
        Command::Test(args) => test_config(args),
        Command::Dump(args) => dump_config(args),
        Command::Version => {
            println!("xrs {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Uuid => {
            println!("{}", uuid::Uuid::new_v4());
            Ok(())
        }
    }
}

async fn run(args: RunArgs) -> anyhow::Result<()> {
    if args.test {
        return test_config(args.config);
    }
    if args.dump {
        return dump_config(args.config);
    }

    let config = load_config(&args.config)?;
    Runtime::new(config)?.run().await?;
    Ok(())
}

fn test_config(args: ConfigArgs) -> anyhow::Result<()> {
    load_config(&args)?;
    println!("configuration OK");
    Ok(())
}

fn dump_config(args: ConfigArgs) -> anyhow::Result<()> {
    let config = load_config(&args)?;
    println!("{}", serde_json::to_string_pretty(&config)?);
    Ok(())
}

fn load_config(args: &ConfigArgs) -> anyhow::Result<RootConfig> {
    if let Some(confdir) = &args.confdir {
        return RootConfig::load_dir(confdir)
            .with_context(|| format!("loading config directory {}", confdir.display()));
    }

    let paths = if args.config.is_empty() {
        vec![PathBuf::from("config.json")]
    } else {
        args.config.clone()
    };

    RootConfig::load_files(&paths).with_context(|| {
        let joined = paths
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        format!("loading config {joined}")
    })
}

fn normalized_args() -> Vec<String> {
    let args = std::env::args()
        .map(|arg| match arg.as_str() {
            "-config" => "--config".to_owned(),
            "-confdir" => "--confdir".to_owned(),
            "-test" => "--test".to_owned(),
            "-dump" => "--dump".to_owned(),
            _ => arg,
        })
        .collect::<Vec<_>>();

    if args.len() > 1 && args[1].starts_with('-') {
        let mut normalized = Vec::with_capacity(args.len() + 1);
        normalized.push(args[0].clone());
        normalized.push("run".to_owned());
        normalized.extend(args.into_iter().skip(1));
        return normalized;
    }

    args
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();
}
