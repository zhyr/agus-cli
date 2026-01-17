use std::path::PathBuf;
use std::{env, fs};

use serde::Deserialize;

use crate::CliError;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppConfig {
    #[serde(default)]
    data_dir: Option<String>,
}

fn resolve_home_dir() -> Result<PathBuf, CliError> {
    env::var("HOME")
        .or_else(|_| env::var("USERPROFILE"))
        .map(PathBuf::from)
        .map_err(|_| CliError::Config("home directory not found".to_string()))
}

fn normalize_data_dir(value: &str, home: &PathBuf) -> Result<PathBuf, CliError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(CliError::Config("data directory is empty".to_string()));
    }
    let mut path = if trimmed.starts_with("~/") {
        home.join(&trimmed[2..])
    } else {
        PathBuf::from(trimmed)
    };
    if path.is_relative() {
        path = env::current_dir()?.join(path);
    }
    Ok(path)
}

fn data_dir_from_app_config(home: &PathBuf) -> Option<PathBuf> {
    let config_dir = config_home_dir().ok()?;
    let path = config_dir.join("app_config.json");
    let content = fs::read_to_string(path).ok()?;
    let config: AppConfig = serde_json::from_str(&content).ok()?;
    let dir = config.data_dir?;
    normalize_data_dir(&dir, home).ok()
}

pub fn config_home_dir() -> Result<PathBuf, CliError> {
    Ok(resolve_home_dir()?.join(".agus"))
}

pub fn agus_home() -> Result<PathBuf, CliError> {
    let home = resolve_home_dir()?;
    if let Ok(custom) = env::var("AGUS_HOME") {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            return normalize_data_dir(trimmed, &home).or_else(|_| Ok(PathBuf::from(trimmed)));
        }
    }
    if let Some(path) = data_dir_from_app_config(&home) {
        return Ok(path);
    }
    Ok(home.join(".agus"))
}

pub fn ensure_home_dir() -> Result<PathBuf, CliError> {
    let path = agus_home()?;
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

pub fn admin_config_path() -> Result<PathBuf, CliError> {
    Ok(agus_home()?.join("cli_admin.json"))
}

pub fn context_path() -> Result<PathBuf, CliError> {
    Ok(agus_home()?.join("cli_context.json"))
}
