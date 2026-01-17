use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use agus_core_domain::ExecutionRecord;
use serde::{Deserialize, Serialize};

use crate::{config, CliError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionSessionInfo {
    pub execution_id: String,
    pub mode: String,
    pub host_id: Option<String>,
    pub plan_path: Option<String>,
    pub started_at: u64,
    pub finished_at: Option<u64>,
}

pub fn execution_root() -> Result<PathBuf, CliError> {
    Ok(config::ensure_home_dir()?.join("executions"))
}

pub fn execution_dir(execution_id: &str) -> Result<PathBuf, CliError> {
    Ok(execution_root()?.join(execution_id))
}

pub fn ensure_execution_dir(execution_id: &str) -> Result<PathBuf, CliError> {
    let dir = execution_dir(execution_id)?;
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn session_info_path(execution_id: &str) -> Result<PathBuf, CliError> {
    Ok(execution_dir(execution_id)?.join("summary.json"))
}

pub fn records_path(execution_id: &str) -> Result<PathBuf, CliError> {
    Ok(execution_dir(execution_id)?.join("records.jsonl"))
}

pub fn checkpoint_path(execution_id: &str) -> Result<PathBuf, CliError> {
    Ok(execution_dir(execution_id)?.join("checkpoint.json"))
}

pub fn write_session_info(info: &ExecutionSessionInfo) -> Result<(), CliError> {
    ensure_execution_dir(&info.execution_id)?;
    let path = session_info_path(&info.execution_id)?;
    let content = serde_json::to_string_pretty(info)?;
    std::fs::write(path, content)?;
    Ok(())
}

pub fn load_session_info(execution_id: &str) -> Result<ExecutionSessionInfo, CliError> {
    let path = session_info_path(execution_id)?;
    let content = std::fs::read_to_string(path)?;
    let info = serde_json::from_str(&content)?;
    Ok(info)
}

pub fn append_record(execution_id: &str, record: &ExecutionRecord) -> Result<(), CliError> {
    ensure_execution_dir(execution_id)?;
    let path = records_path(execution_id)?;
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let line = serde_json::to_string(record)?;
    writeln!(file, "{}", line)?;
    Ok(())
}

pub fn load_records(execution_id: &str) -> Result<Vec<ExecutionRecord>, CliError> {
    let path = records_path(execution_id)?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut records = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(record) = serde_json::from_str::<ExecutionRecord>(trimmed) {
            records.push(record);
        }
    }
    Ok(records)
}

pub fn update_finished_at(execution_id: &str, finished_at: u64) -> Result<(), CliError> {
    let mut info = load_session_info(execution_id)?;
    info.finished_at = Some(finished_at);
    write_session_info(&info)
}

pub fn list_sessions() -> Result<Vec<ExecutionSessionInfo>, CliError> {
    let root = execution_root()?;
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut sessions = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if !entry.path().is_dir() {
            continue;
        }
        let id = match entry.file_name().to_str() {
            Some(value) => value.to_string(),
            None => continue,
        };
        if let Ok(info) = load_session_info(&id) {
            sessions.push(info);
        }
    }
    sessions.sort_by(|a, b| b.started_at.cmp(&a.started_at));
    Ok(sessions)
}

pub fn execution_exists(execution_id: &str) -> Result<bool, CliError> {
    Ok(session_info_path(execution_id)?.exists())
}

pub fn records_exist(execution_id: &str) -> Result<bool, CliError> {
    Ok(records_path(execution_id)?.exists())
}

pub fn checkpoint_exists(execution_id: &str) -> Result<bool, CliError> {
    Ok(checkpoint_path(execution_id)?.exists())
}

pub fn read_checkpoint(execution_id: &str) -> Result<String, CliError> {
    let path = checkpoint_path(execution_id)?;
    let content = std::fs::read_to_string(path)?;
    Ok(content)
}

pub fn write_checkpoint(execution_id: &str, content: &str) -> Result<(), CliError> {
    ensure_execution_dir(execution_id)?;
    let path = checkpoint_path(execution_id)?;
    std::fs::write(path, content)?;
    Ok(())
}

pub fn delete_execution(execution_id: &str) -> Result<(), CliError> {
    let dir = execution_dir(execution_id)?;
    if dir.exists() {
        std::fs::remove_dir_all(dir)?;
    }
    Ok(())
}

pub fn record_file_path(execution_id: &str) -> Result<PathBuf, CliError> {
    records_path(execution_id)
}

pub fn summary_file_path(execution_id: &str) -> Result<PathBuf, CliError> {
    session_info_path(execution_id)
}

pub fn resolve_execution_path(path: &Path) -> Result<PathBuf, CliError> {
    let root = execution_root()?;
    Ok(root.join(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tempfile::TempDir;

    #[test]
    fn stores_and_reads_records() {
        let _guard = crate::test_support::env_lock();
        let temp_dir = TempDir::new().expect("temp dir");
        env::set_var("AGUS_HOME", temp_dir.path().to_string_lossy().to_string());

        let record = ExecutionRecord {
            step_id: "step-1".to_string(),
            status: agus_core_domain::ExecutionStatus::Succeeded,
            started_at: Some(1),
            finished_at: Some(2),
            logs: vec!["ok".to_string()],
            error: None,
        };

        append_record("exec-1", &record).expect("append");
        let records = load_records("exec-1").expect("load");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].step_id, "step-1");

        let record_path = records_path("exec-1").expect("records path");
        assert!(record_path.exists());
        env::remove_var("AGUS_HOME");
    }
}
