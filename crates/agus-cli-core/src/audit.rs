use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use chrono::{Datelike, Local};

use crate::{config, CliError};

const LOG_ROTATE_BYTES: u64 = 20 * 1024 * 1024;

pub fn write_audit_log(category: &str, message: &str) -> Result<(), CliError> {
    let base_path = config::ensure_home_dir()?;
    let log_dir = base_path.join("logs").join(category);
    fs::create_dir_all(&log_dir)?;

    let now = Local::now();
    let filename = format!("{}-{:02}-{:02}.log", now.year(), now.month(), now.day());
    let log_path = log_dir.join(filename);

    rotate_if_needed(&log_path, now.timestamp())?;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    writeln!(file, "[{}] {}", timestamp, message)?;
    Ok(())
}

fn rotate_if_needed(path: &PathBuf, ts: i64) -> Result<(), CliError> {
    if let Ok(metadata) = fs::metadata(path) {
        if metadata.is_file() && metadata.len() > LOG_ROTATE_BYTES {
            let rotated_name = format!("{}.{}.old", path.to_string_lossy(), ts);
            let _ = fs::rename(path, rotated_name);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn writes_log_to_temp_dir() {
        let _guard = crate::test_support::env_lock();
        let temp_dir = tempfile::tempdir().expect("temp dir");
        env::set_var("AGUS_HOME", temp_dir.path().to_string_lossy().to_string());
        write_audit_log("system", "cli test log").expect("write log");
        let log_dir = temp_dir.path().join("logs").join("system");
        let entries = fs::read_dir(log_dir).expect("log dir exists");
        assert!(entries.into_iter().flatten().next().is_some());
        env::remove_var("AGUS_HOME");
    }
}
