pub mod admin;
pub mod audit;
pub mod config;
pub mod context;
pub mod exec;
pub mod executions;
pub mod hosts;
pub mod plan;
pub mod risk;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("storage error: {0}")]
    Storage(#[from] agus_storage::StorageError),
    #[error("ssh error: {0}")]
    Ssh(#[from] agus_ssh::SshError),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("admin config not found; run 'asda admin set' first")]
    AdminMissing,
    #[error("authentication failed")]
    AuthFailed,
    #[error("config error: {0}")]
    Config(String),
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::{Mutex, MutexGuard, OnceLock};

    pub fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock")
    }
}
