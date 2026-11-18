use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(about = "Creates the Strata dataset tree and delegates zfsd's permissions (run as root)")]
struct Args {
    #[arg(long, default_value = "/etc/strata/server.json")]
    config: PathBuf,
    #[arg(long, default_value = "strata-zfs")]
    zfsd_user: String,
}

fn main() -> anyhow::Result<()> {
    strata_zfsd::init_logging();
    let args = Args::parse();
    let cfg = strata_zfsd::config::ServerConfig::load(&args.config)?;
    strata_zfsd::init::init(&cfg, &strata_zfs::Real::default(), &args.zfsd_user)
}
