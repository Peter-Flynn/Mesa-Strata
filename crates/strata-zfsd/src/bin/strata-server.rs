use std::path::PathBuf;

use clap::{Parser, Subcommand};
use strata_zfsd::admin;
use strata_zfsd::config::ServerConfig;

#[derive(Parser)]
#[command(about = "Strata server administration")]
struct Args {
    #[arg(long, default_value = "/etc/strata/server.json")]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Prints the key for a client's keyFile; reads the password from stdin.
    DeriveKey { client: String },
    /// Lists every source with its newest snapshot.
    Status,
    /// Logs stale sources and exits 1 if there are any.
    CheckStale {
        /// Also writes node_exporter textfile metrics here.
        #[arg(long)]
        textfile: Option<PathBuf>,
    },
    /// Destroys a source's dataset and every snapshot of it.
    Forget {
        target: String,
        #[arg(long)]
        yes: bool,
    },
}

fn main() -> anyhow::Result<()> {
    strata_zfsd::init_logging();
    let args = Args::parse();
    let cfg = ServerConfig::load(&args.config)?;
    let zfs = strata_zfs::Real::default();
    match args.cmd {
        Cmd::DeriveKey { client } => println!("{}", admin::derive_key(&cfg, &client)?),
        Cmd::Status => print!("{}", admin::status_table(&admin::collect(&cfg, &zfs)?, strata_zfsd::ops::now())),
        Cmd::CheckStale { textfile } => {
            if admin::check_stale(&cfg, &zfs, textfile.as_deref())? {
                std::process::exit(1);
            }
        }
        Cmd::Forget { target, yes } => admin::forget(&cfg, &zfs, &target, yes)?,
    }
    Ok(())
}
