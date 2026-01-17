use std::io::{self, Write};
use std::path::PathBuf;

use agus_cli_core::{admin, audit, CliError};
use agus_secret_store::create_secret_store;
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(name = "asda")]
#[command(about = "Agus admin CLI", long_about = None)]
struct AsdaCli {
    #[command(subcommand)]
    command: AsdaCommand,
}

#[derive(Subcommand)]
enum AsdaCommand {
    Admin(AdminCommand),
    Audit(AuditCommand),
    Config(ConfigCommand),
    Secrets(SecretsCommand),
    Unlock,
}

#[derive(Parser)]
struct AdminCommand {
    #[command(subcommand)]
    command: AdminSubcommand,
}

#[derive(Subcommand)]
enum AdminSubcommand {
    Set {
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        password_env: Option<String>,
    },
    Status,
    Reset,
}

#[derive(Parser)]
struct AuditCommand {
    #[command(subcommand)]
    command: AuditSubcommand,
}

#[derive(Subcommand)]
enum AuditSubcommand {
    Export {
        #[arg(long)]
        category: Option<String>,
        #[arg(long)]
        out: Option<String>,
    },
    Stats,
}

#[derive(Parser)]
struct ConfigCommand {
    #[command(subcommand)]
    command: ConfigSubcommand,
}

#[derive(Subcommand)]
enum ConfigSubcommand {
    Show,
    Set(ConfigSetCommand),
    SetLlm(ConfigSetLlmCommand),
}

#[derive(Args)]
struct ConfigSetCommand {
    #[arg(long)]
    http_proxy_enabled: Option<bool>,
}

#[derive(Args)]
struct ConfigSetLlmCommand {
    #[arg(long)]
    provider: Option<String>,
    #[arg(long)]
    model: Option<String>,
    #[arg(long)]
    base_url: Option<String>,
}

#[derive(Parser)]
struct SecretsCommand {
    #[command(subcommand)]
    command: SecretsSubcommand,
}

#[derive(Subcommand)]
enum SecretsSubcommand {
    List,
    Get {
        key: String,
    },
    Set {
        key: String,
        value: Option<String>,
        value_env: Option<String>,
    },
    Delete {
        key: String,
    },
    Rotate {
        key: String,
        value: Option<String>,
        value_env: Option<String>,
        keep_old: bool,
    },
    Versions {
        key: String,
    },
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), CliError> {
    let cli = AsdaCli::parse();
    match cli.command {
        AsdaCommand::Admin(cmd) => match cmd.command {
            AdminSubcommand::Set { user, password_env } => admin_set(user, password_env),
            AdminSubcommand::Status => admin_status(),
            AdminSubcommand::Reset => admin_reset(),
        },
        AsdaCommand::Audit(cmd) => match cmd.command {
            AuditSubcommand::Export { category, out } => audit_export(category, out),
            AuditSubcommand::Stats => audit_stats(),
        },
        AsdaCommand::Config(cmd) => match cmd.command {
            ConfigSubcommand::Show => config_show(),
            ConfigSubcommand::Set(cmd) => config_set(cmd),
            ConfigSubcommand::SetLlm(cmd) => config_set_llm(cmd),
        },
        AsdaCommand::Secrets(cmd) => match cmd.command {
            SecretsSubcommand::List => secrets_list(),
            SecretsSubcommand::Get { key } => secrets_get(&key),
            SecretsSubcommand::Set {
                key,
                value,
                value_env,
            } => secrets_set(&key, value, value_env),
            SecretsSubcommand::Delete { key } => secrets_delete(&key),
            SecretsSubcommand::Rotate {
                key,
                value,
                value_env,
                keep_old,
            } => secrets_rotate(&key, value, value_env, keep_old),
            SecretsSubcommand::Versions { key } => secrets_versions(&key),
        },
        AsdaCommand::Unlock => admin_unlock(),
    }
}

fn admin_set(user: Option<String>, password_env: Option<String>) -> Result<(), CliError> {
    let username = match user {
        Some(value) => value,
        None => prompt_line("Admin username: ")?,
    };
    if username.trim().is_empty() {
        return Err(CliError::InvalidInput(
            "username cannot be empty".to_string(),
        ));
    }
    let password = if let Some(env_key) = password_env {
        std::env::var(&env_key)
            .map_err(|_| CliError::InvalidInput(format!("missing password env: {env_key}")))?
    } else {
        let password = rpassword::prompt_password("Admin password: ")?;
        let confirm = rpassword::prompt_password("Confirm password: ")?;
        if password != confirm {
            return Err(CliError::InvalidInput("passwords do not match".to_string()));
        }
        password
    };
    let hash = admin::hash_password(&password)?;
    let config = admin::AdminConfig {
        username: username.trim().to_string(),
        password_hash: hash,
    };
    admin::save_admin_config(&config)?;
    let _ = audit::write_audit_log("system", &format!("cli admin set user={}", config.username));
    println!("Admin credentials saved.");
    Ok(())
}

fn admin_status() -> Result<(), CliError> {
    let config = admin::load_admin_config()?;
    match config {
        Some(cfg) => {
            println!("Admin configured: {}", cfg.username);
        }
        None => {
            println!("Admin not configured.");
        }
    }
    Ok(())
}

fn admin_reset() -> Result<(), CliError> {
    let config = admin::load_admin_config()?;
    let Some(cfg) = config else {
        println!("Admin not configured.");
        return Ok(());
    };
    println!("Reset admin credentials for {}", cfg.username);
    let username = prompt_line("Admin username: ")?;
    let password = rpassword::prompt_password("Admin password: ")?;
    let verified = admin::verify_admin(&username, &password)?;
    if !verified {
        return Err(CliError::AuthFailed);
    }
    admin::remove_admin_config()?;
    let _ = audit::write_audit_log("system", &format!("cli admin reset user={}", username));
    println!("Admin credentials removed.");
    Ok(())
}

fn audit_export(category: Option<String>, out: Option<String>) -> Result<(), CliError> {
    let base = agus_cli_core::config::agus_home()?;
    let log_dir = base.join("logs");
    let selected = match category.as_deref() {
        Some("system") => vec!["system".to_string()],
        Some("behavior") => vec!["behavior".to_string()],
        Some(other) => {
            return Err(CliError::InvalidInput(format!("unknown category: {other}")));
        }
        None => vec!["system".to_string(), "behavior".to_string()],
    };

    let output_path = out
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| base.join("audit_export.log"));
    let mut output = std::fs::File::create(&output_path)?;

    for cat in selected {
        let dir = log_dir.join(&cat);
        if !dir.exists() {
            continue;
        }
        writeln!(output, "=== {} ===", cat)?;
        let mut entries: Vec<_> = std::fs::read_dir(dir)?
            .flatten()
            .filter(|entry| entry.path().is_file())
            .collect();
        entries.sort_by_key(|entry| entry.path());
        for entry in entries {
            let content = std::fs::read_to_string(entry.path())?;
            output.write_all(content.as_bytes())?;
        }
    }
    let _ = audit::write_audit_log(
        "system",
        &format!("cli audit export path={}", output_path.display()),
    );
    println!("Audit exported: {}", output_path.display());
    Ok(())
}

fn audit_stats() -> Result<(), CliError> {
    let base = agus_cli_core::config::agus_home()?;
    let log_dir = base.join("logs");
    for category in ["system", "behavior"] {
        let dir = log_dir.join(category);
        if !dir.exists() {
            continue;
        }
        let mut latest: Option<(PathBuf, u64, u64)> = None;
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            if !metadata.is_file() {
                continue;
            }
            let mtime = metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let size = metadata.len();
            if latest.as_ref().map_or(true, |(_, _, last)| mtime > *last) {
                latest = Some((entry.path(), size, mtime));
            }
        }
        if let Some((path, size, mtime)) = latest {
            println!(
                "{}\t{}\t{:.2}MB\t{}",
                category,
                path.display(),
                (size as f64) / (1024.0 * 1024.0),
                mtime
            );
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppConfig {
    http_proxy_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LlmConfigFile {
    provider: String,
    api_key: String,
    model: String,
    base_url: Option<String>,
}

fn config_show() -> Result<(), CliError> {
    let app = load_app_config()?;
    let llm = load_llm_config()?;
    let store = create_secret_store();
    let has_key = store.get_secret("llm.api_key").is_ok();
    println!("app_config.http_proxy_enabled={}", app.http_proxy_enabled);
    println!("llm_config.provider={}", llm.provider);
    println!("llm_config.model={}", llm.model);
    println!(
        "llm_config.base_url={}",
        llm.base_url.clone().unwrap_or_else(|| "none".to_string())
    );
    println!("llm_config.api_key_present={}", has_key);
    Ok(())
}

fn config_set(cmd: ConfigSetCommand) -> Result<(), CliError> {
    let mut config = load_app_config()?;
    if let Some(enabled) = cmd.http_proxy_enabled {
        config.http_proxy_enabled = enabled;
    }
    save_app_config(&config)?;
    println!("App config updated.");
    Ok(())
}

fn config_set_llm(cmd: ConfigSetLlmCommand) -> Result<(), CliError> {
    let mut config = load_llm_config()?;
    if let Some(provider) = cmd.provider {
        config.provider = provider.trim().to_string();
    }
    if let Some(model) = cmd.model {
        config.model = model.trim().to_string();
    }
    if let Some(base_url) = cmd.base_url {
        let trimmed = base_url.trim();
        config.base_url = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
    }
    save_llm_config(&config)?;
    println!("LLM config updated.");
    Ok(())
}

fn secrets_list() -> Result<(), CliError> {
    let store = create_secret_store();
    match store.list_secrets() {
        Ok(keys) => {
            for key in keys {
                println!("{key}");
            }
            Ok(())
        }
        Err(err) => Err(CliError::Config(err.to_string())),
    }
}

fn secrets_get(key: &str) -> Result<(), CliError> {
    let store = create_secret_store();
    match store.get_secret(key) {
        Ok(value) => {
            println!("{value}");
            Ok(())
        }
        Err(err) => Err(CliError::Config(err.to_string())),
    }
}

fn secrets_set(
    key: &str,
    value: Option<String>,
    value_env: Option<String>,
) -> Result<(), CliError> {
    let store = create_secret_store();
    let value = if let Some(env_key) = value_env {
        std::env::var(&env_key)
            .map_err(|_| CliError::InvalidInput(format!("missing value env: {env_key}")))?
    } else if let Some(value) = value {
        value
    } else {
        rpassword::prompt_password("Secret value: ")?
    };
    store
        .store_secret(key, &value)
        .map_err(|err| CliError::Config(err.to_string()))?;
    println!("Secret stored.");
    Ok(())
}

fn secrets_delete(key: &str) -> Result<(), CliError> {
    let store = create_secret_store();
    store
        .delete_secret(key)
        .map_err(|err| CliError::Config(err.to_string()))?;
    println!("Secret deleted.");
    Ok(())
}

fn secrets_rotate(
    key: &str,
    value: Option<String>,
    value_env: Option<String>,
    keep_old: bool,
) -> Result<(), CliError> {
    let store = create_secret_store();
    let value = if let Some(env_key) = value_env {
        std::env::var(&env_key)
            .map_err(|_| CliError::InvalidInput(format!("missing value env: {env_key}")))?
    } else if let Some(value) = value {
        value
    } else {
        rpassword::prompt_password("Secret value: ")?
    };
    store
        .rotate_secret(key, &value, keep_old)
        .map_err(|err| CliError::Config(err.to_string()))?;
    println!("Secret rotated.");
    Ok(())
}

fn secrets_versions(key: &str) -> Result<(), CliError> {
    let store = create_secret_store();
    match store.list_secret_versions(key) {
        Ok(keys) => {
            for key in keys {
                println!("{key}");
            }
            Ok(())
        }
        Err(err) => Err(CliError::Config(err.to_string())),
    }
}

fn admin_unlock() -> Result<(), CliError> {
    let username = prompt_line("Admin username: ")?;
    let password = rpassword::prompt_password("Admin password: ")?;
    let verified = admin::verify_admin(&username, &password)?;
    if !verified {
        return Err(CliError::AuthFailed);
    }
    println!("Admin unlock successful.");
    Ok(())
}

fn app_config_path() -> Result<PathBuf, CliError> {
    Ok(agus_cli_core::config::config_home_dir()?.join("app_config.json"))
}

fn llm_config_path() -> Result<PathBuf, CliError> {
    Ok(agus_cli_core::config::ensure_home_dir()?.join("llm_config.json"))
}

fn load_app_config() -> Result<AppConfig, CliError> {
    let default_config = AppConfig {
        http_proxy_enabled: true,
    };
    let path = app_config_path()?;
    if !path.exists() {
        return Ok(default_config);
    }
    let content = std::fs::read_to_string(path)?;
    let config: AppConfig = serde_json::from_str(&content).unwrap_or(default_config);
    Ok(config)
}

fn save_app_config(config: &AppConfig) -> Result<(), CliError> {
    let path = app_config_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(config)?;
    std::fs::write(path, content)?;
    Ok(())
}

fn load_llm_config() -> Result<LlmConfigFile, CliError> {
    let default_config = LlmConfigFile {
        provider: "openai".to_string(),
        api_key: String::new(),
        model: "gpt-4".to_string(),
        base_url: None,
    };
    let path = llm_config_path()?;
    if !path.exists() {
        return Ok(default_config);
    }
    let content = std::fs::read_to_string(path)?;
    let config: LlmConfigFile = serde_json::from_str(&content).unwrap_or(default_config);
    Ok(config)
}

fn save_llm_config(config: &LlmConfigFile) -> Result<(), CliError> {
    let path = llm_config_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let config = LlmConfigFile {
        api_key: String::new(),
        ..config.clone()
    };
    let content = serde_json::to_string_pretty(&config)?;
    std::fs::write(path, content)?;
    Ok(())
}

fn prompt_line(label: &str) -> Result<String, CliError> {
    let mut input = String::new();
    print!("{label}");
    io::stdout().flush()?;
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}
