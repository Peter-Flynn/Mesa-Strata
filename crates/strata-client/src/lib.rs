pub mod backup;
pub mod config;
pub mod interval;
pub mod ipc;
pub mod net;
pub mod restore;
pub mod spawn;

pub fn init_logging() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).format_timestamp(None).init();
}
