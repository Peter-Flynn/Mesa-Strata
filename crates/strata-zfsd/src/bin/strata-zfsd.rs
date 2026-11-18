use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;

#[derive(Parser)]
#[command(about = "Strata server ZFS helper: authenticates clients and runs validated ZFS operations")]
struct Args {
    #[arg(long, default_value = "/etc/strata/server.json")]
    config: PathBuf,
}

fn main() -> anyhow::Result<()> {
    strata_zfsd::init_logging();
    let args = Args::parse();
    strata_zfsd::run(&args.config, Arc::new(strata_zfs::Real::default()))
}
