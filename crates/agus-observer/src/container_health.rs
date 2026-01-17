use agus_ssh::{SshClient, SshTarget};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerHealth {
    pub container_id: String,
    pub container_name: String,
    pub status: ContainerStatus,
    pub health_status: Option<String>, // "healthy", "unhealthy", "starting", "none"
    pub restart_count: u32,
    pub uptime_seconds: Option<u64>,
    pub cpu_usage_percent: Option<f64>,
    pub memory_usage_mb: Option<f64>,
    pub memory_limit_mb: Option<f64>,
    pub last_check: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContainerStatus {
    Running,
    Exited,
    Paused,
    Restarting,
    Dead,
    Unknown,
}

impl ContainerStatus {
    pub fn from_docker_status(status: &str) -> Self {
        let status_lower = status.to_lowercase();
        if status_lower.contains("up") || status_lower == "running" {
            ContainerStatus::Running
        } else if status_lower.contains("exited") {
            ContainerStatus::Exited
        } else if status_lower.contains("paused") {
            ContainerStatus::Paused
        } else if status_lower.contains("restarting") {
            ContainerStatus::Restarting
        } else if status_lower.contains("dead") {
            ContainerStatus::Dead
        } else {
            ContainerStatus::Unknown
        }
    }

    pub fn is_healthy(&self) -> bool {
        matches!(self, ContainerStatus::Running)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerHealthCheckResult {
    pub container_id: String,
    pub container_name: String,
    pub is_healthy: bool,
    pub issues: Vec<String>,
    pub health: ContainerHealth,
}

pub fn check_container_health(
    client: &dyn SshClient,
    target: &SshTarget,
    container_id_or_name: &str,
) -> Result<ContainerHealthCheckResult, String> {
    // Get container inspect information
    // 使用 if 条件来处理可选的 Health.Status 字段
    // 策略:
    // 1. 首先尝试获取完整信息(包含 Health 状态)
    // 2. 如果失败(可能是容器没有 Health 配置导致的模板错误),则降级尝试不获取 Health 状态

    let full_inspect_cmd = format!(
        "docker inspect --format '{{{{.Id}}}}|||{{{{.Name}}}}|||{{{{.State.Status}}}}|||{{{{if .State.Health}}}}{{{{.State.Health.Status}}}}{{{{else}}}}<no-health>{{{{end}}}}|||{{{{.RestartCount}}}}|||{{{{.State.StartedAt}}}}' {}",
        container_id_or_name
    );

    let inspect_result = match client.execute(target, &full_inspect_cmd) {
        Ok(res) => res,
        Err(_) => {
            // 第一次尝试失败,尝试使用不带 Health 字段的简化命令
            // 这通常解决 "map has no entry for key Health" 的问题
            let simple_inspect_cmd = format!(
                "docker inspect --format '{{{{.Id}}}}|||{{{{.Name}}}}|||{{{{.State.Status}}}}|||<no-health>|||{{{{.RestartCount}}}}|||{{{{.State.StartedAt}}}}' {}",
                container_id_or_name
            );

            match client.execute(target, &simple_inspect_cmd) {
                Ok(res) => res,
                Err(_) => {
                    // 如果简单命令也失败,尝试使用 sudo (只尝试简单命令)
                    let sudo_inspect_cmd = format!("sudo {}", simple_inspect_cmd);
                    client.execute(target, &sudo_inspect_cmd).map_err(|e| {
                        format!(
                            "Failed to inspect container (even with fallback and sudo): {}",
                            e
                        )
                    })?
                }
            }
        }
    };

    if !inspect_result.stdout.trim().is_empty() {
        // 使用自定义分隔符 ||| 进行分割,这比 \t 更可靠,不容易受 SSH 转义影响
        let parts: Vec<&str> = inspect_result.stdout.trim().split("|||").collect();
        if parts.len() >= 6 {
            let container_id = parts[0].trim().to_string();
            let container_name = parts[1].trim().trim_start_matches('/').to_string();
            let status_str = parts[2].trim();
            let health_status =
                if parts[3].trim() == "<no value>" || parts[3].trim() == "<no-health>" {
                    None
                } else {
                    Some(parts[3].trim().to_string())
                };
            let restart_count = parts[4].trim().parse::<u32>().unwrap_or(0);
            let started_at_str = parts[5].trim();

            let status = ContainerStatus::from_docker_status(status_str);

            // Calculate uptime
            let uptime_seconds = if started_at_str != "<no value>" && !started_at_str.is_empty() {
                // Parse Docker timestamp (RFC3339 format)
                if let Ok(started_at) = parse_docker_timestamp(started_at_str) {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let started = started_at.duration_since(UNIX_EPOCH).unwrap().as_secs();
                    Some(now.saturating_sub(started))
                } else {
                    None
                }
            } else {
                None
            };

            // Get container stats (CPU and memory)
            let stats_cmd = format!("docker stats --no-stream --format '{{{{.CPUPerc}}}}\\t{{{{.MemUsage}}}}\\t{{{{.MemPerc}}}}' {}", container_id_or_name);
            let stats_result = match client.execute(target, &stats_cmd) {
                Ok(res) => Some(res),
                Err(_) => {
                    let sudo_stats_cmd = format!("sudo {}", stats_cmd);
                    client.execute(target, &sudo_stats_cmd).ok()
                }
            };

            let (cpu_usage, memory_usage, memory_limit) = if let Some(stats) = stats_result {
                parse_container_stats(&stats.stdout)
            } else {
                (None, None, None)
            };

            let health = ContainerHealth {
                container_id: container_id.clone(),
                container_name: container_name.clone(),
                status,
                health_status,
                restart_count,
                uptime_seconds,
                cpu_usage_percent: cpu_usage,
                memory_usage_mb: memory_usage,
                memory_limit_mb: memory_limit,
                last_check: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            };

            // Determine if container is healthy
            let mut issues = Vec::new();
            let is_healthy = check_health_issues(&health, &mut issues);

            Ok(ContainerHealthCheckResult {
                container_id,
                container_name,
                is_healthy,
                issues,
                health,
            })
        } else {
            Err(format!(
                "Failed to parse container inspect output. Expected 6 parts, got {}. Content: '{}'",
                parts.len(),
                inspect_result.stdout.trim()
            ))
        }
    } else {
        Err("Container not found".to_string())
    }
}

fn parse_docker_timestamp(timestamp: &str) -> Result<SystemTime, String> {
    // Docker uses RFC3339 format: 2024-01-01T12:00:00.123456789Z
    // For simplicity, we'll parse it manually
    use std::time::Duration;

    // Try to parse as RFC3339
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(timestamp) {
        let secs = dt.timestamp() as u64;
        let nsecs = dt.timestamp_subsec_nanos();
        Ok(UNIX_EPOCH + Duration::new(secs, nsecs))
    } else {
        Err("Invalid timestamp format".to_string())
    }
}

fn parse_container_stats(stats_output: &str) -> (Option<f64>, Option<f64>, Option<f64>) {
    let parts: Vec<&str> = stats_output.trim().split('\t').collect();
    if parts.len() >= 3 {
        let cpu_str = parts[0].trim().trim_end_matches('%');
        let mem_usage_str = parts[1].trim(); // Format: "100MiB / 2GiB"

        let cpu_usage = cpu_str.parse::<f64>().ok();

        // Parse memory usage: "100MiB / 2GiB"
        let (memory_usage, memory_limit) = if let Some(slash_pos) = mem_usage_str.find(" / ") {
            let used_str = mem_usage_str[..slash_pos].trim();
            let limit_str = mem_usage_str[slash_pos + 3..].trim();
            (parse_memory_size(used_str), parse_memory_size(limit_str))
        } else if let Some(slash_pos) = mem_usage_str.find('/') {
            // Fallback for tight formatting e.g. "100B/200B"
            let used_str = mem_usage_str[..slash_pos].trim();
            let limit_str = mem_usage_str[slash_pos + 1..].trim();
            (parse_memory_size(used_str), parse_memory_size(limit_str))
        } else {
            eprintln!(
                "[Stats Error] Memory string format mismatch: '{}'",
                mem_usage_str
            );
            (None, None)
        };

        (cpu_usage, memory_usage, memory_limit)
    } else {
        eprintln!(
            "[Stats Error] Unexpected stats format (parts < 3). Content: '{}'",
            stats_output
        );
        (None, None, None)
    }
}

fn parse_memory_size(size_str: &str) -> Option<f64> {
    let size_str = size_str.trim();
    if size_str.is_empty() || size_str == "--" {
        return None;
    }

    // Split numeric part and unit part
    // e.g. "100MiB" -> "100" and "MiB"
    let number_part = size_str.trim_end_matches(|c: char| c.is_alphabetic());
    let unit_part = size_str[number_part.len()..].trim();
    let number_part = number_part.trim();

    let number = number_part.parse::<f64>().ok()?;

    // Normalize unit check
    let multiplier = match unit_part {
        "KiB" | "KB" | "kB" => 1.0 / 1024.0,
        "MiB" | "MB" | "mB" => 1.0,
        "GiB" | "GB" | "gB" => 1024.0,
        "TiB" | "TB" | "tB" => 1024.0 * 1024.0,
        "B" | "b" => 1.0 / (1024.0 * 1024.0), // Convert Bytes to MB
        _ => {
            // Log unknown unit
            eprintln!(
                "[Memory Parse Warning] Unknown unit '{}' in '{}'",
                unit_part, size_str
            );
            return None;
        }
    };

    Some(number * multiplier)
}

fn check_health_issues(health: &ContainerHealth, issues: &mut Vec<String>) -> bool {
    let mut is_healthy = true;

    // Check container status
    if !health.status.is_healthy() {
        is_healthy = false;
        issues.push(format!("Container status: {:?}", health.status));
    }

    // Check health status (if available)
    if let Some(ref health_status) = health.health_status {
        match health_status.as_str() {
            "unhealthy" => {
                is_healthy = false;
                issues.push("Docker health check reports unhealthy".to_string());
            }
            "starting" => {
                issues.push("Container health check is still starting".to_string());
            }
            _ => {}
        }
    }

    // Check restart count
    if health.restart_count > 10 {
        is_healthy = false;
        issues.push(format!("High restart count: {}", health.restart_count));
    }

    // Check CPU usage
    if let Some(cpu) = health.cpu_usage_percent {
        if cpu > 90.0 {
            is_healthy = false;
            issues.push(format!("High CPU usage: {:.1}%", cpu));
        } else if cpu > 80.0 {
            issues.push(format!("Elevated CPU usage: {:.1}%", cpu));
        }
    }

    // Check memory usage
    if let (Some(used), Some(limit)) = (health.memory_usage_mb, health.memory_limit_mb) {
        let usage_percent = (used / limit) * 100.0;
        if usage_percent > 90.0 {
            is_healthy = false;
            issues.push(format!(
                "High memory usage: {:.1}% ({:.1}MB / {:.1}MB)",
                usage_percent, used, limit
            ));
        } else if usage_percent > 80.0 {
            issues.push(format!("Elevated memory usage: {:.1}%", usage_percent));
        }
    }

    // Check uptime (if container just started, might be initializing)
    if let Some(uptime) = health.uptime_seconds {
        if uptime < 30 {
            issues.push(format!("Container recently started ({}s ago)", uptime));
        }
    }

    is_healthy
}

pub fn check_all_containers_health(
    client: &dyn SshClient,
    target: &SshTarget,
    container_names: Option<&[String]>,
) -> Result<Vec<ContainerHealthCheckResult>, String> {
    let mut container_list: Vec<(String, String)> = Vec::new();

    // 如果提供了容器列表，直接使用；否则从服务器获取
    if let Some(names) = container_names {
        // 使用提供的容器名称列表，直接使用名称进行健康检查
        for name in names {
            container_list.push((name.clone(), name.clone()));
        }
    } else {
        // Get list of all running containers from server
        let ps_cmd = "docker ps --format '{{.ID}}\t{{.Names}}'";
        let ps_result = match client.execute(target, ps_cmd) {
            Ok(res) => res,
            Err(_) => {
                let sudo_ps_cmd = format!("sudo {}", ps_cmd);
                client
                    .execute(target, &sudo_ps_cmd)
                    .map_err(|e| format!("Failed to list containers (tried sudo): {}", e))?
            }
        };

        for line in ps_result.stdout.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 2 {
                let container_id = parts[0].trim().to_string();
                let container_name = parts[1].trim().to_string();
                container_list.push((container_id, container_name));
            }
        }
    }

    let mut results = Vec::new();
    for (container_id, container_name) in container_list {
        // Check health for each container
        // 优先使用容器ID,如果失败则使用名称
        match check_container_health(client, target, &container_id) {
            Ok(health_result) => {
                results.push(health_result);
            }
            Err(e1) => {
                // 第一次失败,尝试使用容器名称
                match check_container_health(client, target, &container_name) {
                    Ok(health_result) => {
                        results.push(health_result);
                    }
                    Err(e2) => {
                        // 两次都失败,打印错误日志
                        eprintln!(
                            "[容器健康检查] 无法检查容器 '{}': 使用ID失败({}), 使用名称失败({})",
                            container_name, e1, e2
                        );
                    }
                }
            }
        }
    }

    Ok(results)
}
