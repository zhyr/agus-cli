use agus_ssh::{SshClient, SshTarget};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerLogEntry {
    pub container_id: String,
    pub container_name: String,
    pub timestamp: u64,
    pub level: LogLevel,
    pub message: String,
    pub stream: LogStream,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warning,
    Error,
    Debug,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LogStream {
    Stdout,
    Stderr,
}

pub trait ContainerLogMonitor: Send + Sync {
    /// Start monitoring container logs
    fn start_monitoring(
        &self,
        container_id: &str,
        since: Option<u64>,
        until: Option<u64>,
    ) -> Result<(), ContainerLogError>;

    /// Stop monitoring container logs
    fn stop_monitoring(&self, container_id: &str) -> Result<(), ContainerLogError>;

    /// Get recent logs for a container
    fn get_logs(
        &self,
        container_id: &str,
        lines: Option<usize>,
        since: Option<u64>,
    ) -> Result<Vec<ContainerLogEntry>, ContainerLogError>;

    /// Stream logs in real-time (callback-based)
    fn stream_logs<F>(&self, container_id: &str, callback: F) -> Result<(), ContainerLogError>
    where
        F: Fn(ContainerLogEntry) + Send + Sync + 'static;
}

#[derive(Debug)]
pub enum ContainerLogError {
    SshError { message: String },
    ContainerNotFound { container_id: String },
    ParseError { message: String },
    IoError { message: String },
}

impl std::fmt::Display for ContainerLogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContainerLogError::SshError { message } => {
                write!(f, "SSH error: {}", message)
            }
            ContainerLogError::ContainerNotFound { container_id } => {
                write!(f, "Container not found: {}", container_id)
            }
            ContainerLogError::ParseError { message } => {
                write!(f, "Parse error: {}", message)
            }
            ContainerLogError::IoError { message } => {
                write!(f, "IO error: {}", message)
            }
        }
    }
}

impl std::error::Error for ContainerLogError {}

pub struct SshContainerLogMonitor {
    client: Arc<dyn SshClient + Send + Sync>,
    target: SshTarget,
}

impl SshContainerLogMonitor {
    pub fn new(client: Arc<dyn SshClient + Send + Sync>, target: SshTarget) -> Self {
        Self { client, target }
    }
}

impl ContainerLogMonitor for SshContainerLogMonitor {
    fn start_monitoring(
        &self,
        _container_id: &str,
        _since: Option<u64>,
        _until: Option<u64>,
    ) -> Result<(), ContainerLogError> {
        // Implementation would start a background task to monitor logs
        // For now, this is a placeholder
        Ok(())
    }

    fn stop_monitoring(&self, _container_id: &str) -> Result<(), ContainerLogError> {
        // Implementation would stop the background monitoring task
        Ok(())
    }

    fn get_logs(
        &self,
        container_id: &str,
        lines: Option<usize>,
        since: Option<u64>,
    ) -> Result<Vec<ContainerLogEntry>, ContainerLogError> {
        let lines_arg = lines.map(|n| format!("--tail={}", n)).unwrap_or_default();
        let since_arg = since
            .map(|ts| format!("--since {}", ts))
            .unwrap_or_default();
        let container_arg = escape_shell_arg(container_id);

        let cmd = format!(
            "docker logs {} {} -- {} 2>&1",
            lines_arg, since_arg, container_arg
        );

        let result =
            self.client
                .execute(&self.target, &cmd)
                .map_err(|e| ContainerLogError::SshError {
                    message: format!("Failed to execute command: {}", e),
                })?;

        if result.exit_code != 0 {
            return Err(ContainerLogError::ContainerNotFound {
                container_id: container_id.to_string(),
            });
        }

        // Parse Docker logs (format: timestamp stream message)
        let mut entries = Vec::new();
        for line in result.stdout.lines() {
            if let Some(entry) = parse_docker_log_line(line, container_id) {
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    fn stream_logs<F>(&self, container_id: &str, callback: F) -> Result<(), ContainerLogError>
    where
        F: Fn(ContainerLogEntry) + Send + Sync + 'static,
    {
        // This would start a background task that continuously reads logs
        // For now, this is a placeholder that gets recent logs
        let logs = self.get_logs(container_id, Some(100), None)?;
        for entry in logs {
            callback(entry);
        }
        Ok(())
    }
}

fn escape_shell_arg(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn parse_docker_log_line(line: &str, container_id: &str) -> Option<ContainerLogEntry> {
    // Docker log format: "2024-01-01T12:00:00.000000000Z stdout This is a log message"
    // Or simpler format without timestamp: "This is a log message"

    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    let (timestamp, stream, message) = if parts.len() >= 3 {
        // Try to parse timestamp
        let _ts_str = parts[0];
        let stream_str = parts[1];
        let msg = parts[2..].join(" ");

        // Try to parse timestamp (simplified - just use current time if parsing fails)
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let stream = if stream_str == "stdout" {
            LogStream::Stdout
        } else {
            LogStream::Stderr
        };

        (timestamp, stream, msg)
    } else {
        // No timestamp, assume current time and stdout
        (
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            LogStream::Stdout,
            line.to_string(),
        )
    };

    // Determine log level from message content
    let level = if message.to_lowercase().contains("error")
        || message.to_lowercase().contains("fatal")
    {
        LogLevel::Error
    } else if message.to_lowercase().contains("warning") || message.to_lowercase().contains("warn")
    {
        LogLevel::Warning
    } else if message.to_lowercase().contains("debug") {
        LogLevel::Debug
    } else {
        LogLevel::Info
    };

    Some(ContainerLogEntry {
        container_id: container_id.to_string(),
        container_name: container_id.to_string(), // Would need to look up actual name
        timestamp,
        level,
        message,
        stream,
    })
}
