use serde::{Deserialize, Serialize};

use crate::{config, CliError};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CliContext {
    pub current_host: Option<String>,
}

pub fn load_context() -> Result<CliContext, CliError> {
    let path = config::context_path()?;
    if !path.exists() {
        return Ok(CliContext::default());
    }
    let content = std::fs::read_to_string(path)?;
    let ctx = serde_json::from_str(&content)?;
    Ok(ctx)
}

pub fn save_context(context: &CliContext) -> Result<(), CliError> {
    let base = config::ensure_home_dir()?;
    let path = base.join("cli_context.json");
    let content = serde_json::to_string_pretty(context)?;
    std::fs::write(path, content)?;
    Ok(())
}
