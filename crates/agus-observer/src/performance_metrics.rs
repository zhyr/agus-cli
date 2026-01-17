use agus_ssh::{SshClient, SshError, SshTarget};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub host_id: String,
    pub timestamp: u64,
    pub cpu: CpuMetrics,
    pub memory: MemoryMetrics,
    pub disk: Vec<DiskMetrics>,
    pub network: NetworkMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuMetrics {
    pub usage_percent: f64,
    pub cores: u32,
    pub load_average: LoadAverage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadAverage {
    pub one_min: f64,
    pub five_min: f64,
    pub fifteen_min: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryMetrics {
    pub total_mb: f64,
    pub used_mb: f64,
    pub free_mb: f64,
    pub cached_mb: f64,
    pub buffers_mb: f64,
    pub usage_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskMetrics {
    pub device: String,
    pub mount_point: String,
    pub total_gb: f64,
    pub used_gb: f64,
    pub available_gb: f64,
    pub usage_percent: f64,
    pub filesystem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub interfaces: Vec<NetworkInterface>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

/// 采集系统性能指标
pub fn collect_system_metrics<C: SshClient>(
    client: &C,
    target: &SshTarget,
    host_id: &str,
) -> Result<SystemMetrics, SshError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // 采集CPU指标
    let cpu = collect_cpu_metrics(client, target)?;

    // 采集内存指标
    let memory = collect_memory_metrics(client, target)?;

    // 采集磁盘指标
    let disk = collect_disk_metrics(client, target)?;

    // 采集网络指标
    let network = collect_network_metrics(client, target)?;

    Ok(SystemMetrics {
        host_id: host_id.to_string(),
        timestamp,
        cpu,
        memory,
        disk,
        network,
    })
}

fn collect_cpu_metrics<C: SshClient>(
    client: &C,
    target: &SshTarget,
) -> Result<CpuMetrics, SshError> {
    // 获取CPU核心数
    let cores_cmd = "nproc";
    let cores_result = client.execute(target, cores_cmd)?;
    let cores = cores_result.stdout.trim().parse::<u32>().unwrap_or(1);

    // 获取CPU使用率（使用top命令，取1秒的平均值）
    let cpu_cmd = "top -bn1 | grep 'Cpu(s)' | sed 's/.*, *\\([0-9.]*\\)%* id.*/\\1/' | awk '{print 100 - $1}'";
    let cpu_result = client.execute(target, cpu_cmd).ok();
    let usage_percent = if let Some(result) = cpu_result {
        result.stdout.trim().parse::<f64>().unwrap_or(0.0)
    } else {
        // 备用方法：使用vmstat
        let vmstat_cmd = "vmstat 1 2 | tail -1 | awk '{print 100 - $15}'";
        if let Ok(vmstat_result) = client.execute(target, vmstat_cmd) {
            vmstat_result.stdout.trim().parse::<f64>().unwrap_or(0.0)
        } else {
            0.0
        }
    };

    // 获取负载平均值
    let loadavg_cmd = "cat /proc/loadavg | awk '{print $1, $2, $3}'";
    let loadavg_result = client.execute(target, loadavg_cmd)?;
    let load_parts: Vec<&str> = loadavg_result.stdout.trim().split_whitespace().collect();
    let load_average = if load_parts.len() >= 3 {
        LoadAverage {
            one_min: load_parts[0].parse().unwrap_or(0.0),
            five_min: load_parts[1].parse().unwrap_or(0.0),
            fifteen_min: load_parts[2].parse().unwrap_or(0.0),
        }
    } else {
        LoadAverage {
            one_min: 0.0,
            five_min: 0.0,
            fifteen_min: 0.0,
        }
    };

    Ok(CpuMetrics {
        usage_percent,
        cores,
        load_average,
    })
}

fn collect_memory_metrics<C: SshClient>(
    client: &C,
    target: &SshTarget,
) -> Result<MemoryMetrics, SshError> {
    // 使用free命令获取内存信息
    let free_cmd = "free -m | grep '^Mem:' | awk '{print $2, $3, $4, $6, $7}'";
    let free_result = client.execute(target, free_cmd)?;
    let parts: Vec<&str> = free_result.stdout.trim().split_whitespace().collect();

    if parts.len() >= 5 {
        let total_mb = parts[0].parse().unwrap_or(0.0);
        let used_mb = parts[1].parse().unwrap_or(0.0);
        let free_mb = parts[2].parse().unwrap_or(0.0);
        let buffers_mb = parts[3].parse().unwrap_or(0.0);
        let cached_mb = parts[4].parse().unwrap_or(0.0);

        let usage_percent = if total_mb > 0.0 {
            (used_mb / total_mb) * 100.0
        } else {
            0.0
        };

        Ok(MemoryMetrics {
            total_mb,
            used_mb,
            free_mb,
            cached_mb,
            buffers_mb,
            usage_percent,
        })
    } else {
        // 备用方法：使用更简单的free命令
        let free_simple_cmd = "free -m";
        let free_simple_result = client.execute(target, free_simple_cmd)?;
        parse_memory_from_free(&free_simple_result.stdout)
    }
}

fn parse_memory_from_free(output: &str) -> Result<MemoryMetrics, SshError> {
    let mut total_mb = 0.0;
    let mut used_mb = 0.0;
    let mut free_mb = 0.0;
    let mut buffers_mb = 0.0;
    let mut cached_mb = 0.0;

    for line in output.lines() {
        if line.starts_with("Mem:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                total_mb = parts[1].parse().unwrap_or(0.0);
                used_mb = parts[2].parse().unwrap_or(0.0);
                free_mb = parts[3].parse().unwrap_or(0.0);
                if parts.len() >= 6 {
                    buffers_mb = parts[5].parse().unwrap_or(0.0);
                }
                if parts.len() >= 7 {
                    cached_mb = parts[6].parse().unwrap_or(0.0);
                }
            }
        }
    }

    let usage_percent = if total_mb > 0.0 {
        (used_mb / total_mb) * 100.0
    } else {
        0.0
    };

    Ok(MemoryMetrics {
        total_mb,
        used_mb,
        free_mb,
        cached_mb,
        buffers_mb,
        usage_percent,
    })
}

fn collect_disk_metrics<C: SshClient>(
    client: &C,
    target: &SshTarget,
) -> Result<Vec<DiskMetrics>, SshError> {
    // 使用df命令获取磁盘使用情况
    let df_cmd =
        "df -h | grep -vE '^Filesystem|tmpfs|cdrom' | awk '{print $1, $2, $3, $4, $5, $6}'";
    let df_result = client.execute(target, df_cmd)?;

    let mut disks = Vec::new();
    for line in df_result.stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 6 {
            let device = parts[0].to_string();
            let total_str = parts[1];
            let used_str = parts[2];
            let available_str = parts[3];
            let usage_percent_str = parts[4].trim_end_matches('%');
            let mount_point = parts[5].to_string();

            let total_gb = parse_size_to_gb(total_str);
            let used_gb = parse_size_to_gb(used_str);
            let available_gb = parse_size_to_gb(available_str);
            let usage_percent = usage_percent_str.parse().unwrap_or(0.0);

            disks.push(DiskMetrics {
                device,
                mount_point,
                total_gb,
                used_gb,
                available_gb,
                usage_percent,
                filesystem: "ext4".to_string(), // 默认值，实际可以通过其他命令获取
            });
        }
    }

    Ok(disks)
}

fn parse_size_to_gb(size_str: &str) -> f64 {
    let size_str = size_str.trim();
    if size_str.is_empty() {
        return 0.0;
    }

    let (number_str, unit) = if size_str.ends_with('T') || size_str.ends_with('t') {
        (&size_str[..size_str.len() - 1], 'T')
    } else if size_str.ends_with('G') || size_str.ends_with('g') {
        (&size_str[..size_str.len() - 1], 'G')
    } else if size_str.ends_with('M') || size_str.ends_with('m') {
        (&size_str[..size_str.len() - 1], 'M')
    } else if size_str.ends_with('K') || size_str.ends_with('k') {
        (&size_str[..size_str.len() - 1], 'K')
    } else {
        (size_str, 'B')
    };

    let number = number_str.parse::<f64>().unwrap_or(0.0);

    match unit {
        'T' => number * 1024.0,
        'G' => number,
        'M' => number / 1024.0,
        'K' => number / (1024.0 * 1024.0),
        _ => number / (1024.0 * 1024.0 * 1024.0),
    }
}

fn collect_network_metrics<C: SshClient>(
    client: &C,
    target: &SshTarget,
) -> Result<NetworkMetrics, SshError> {
    // 使用cat /proc/net/dev获取网络统计
    let net_cmd =
        "cat /proc/net/dev | grep -v 'lo:' | awk 'NR>2 {print $1, $2, $10, $3, $11, $4, $12}'";
    let net_result = client.execute(target, net_cmd)?;

    let mut interfaces = Vec::new();
    for line in net_result.stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 7 {
            let name = parts[0].trim_end_matches(':').to_string();
            let rx_bytes = parts[1].parse().unwrap_or(0);
            let rx_packets = parts[2].parse().unwrap_or(0);
            let rx_errors = parts[3].parse().unwrap_or(0);
            let tx_bytes = parts[4].parse().unwrap_or(0);
            let tx_packets = parts[5].parse().unwrap_or(0);
            let tx_errors = parts[6].parse().unwrap_or(0);

            interfaces.push(NetworkInterface {
                name,
                rx_bytes,
                tx_bytes,
                rx_packets,
                tx_packets,
                rx_errors,
                tx_errors,
            });
        }
    }

    Ok(NetworkMetrics { interfaces })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_size_to_gb() {
        assert_eq!(parse_size_to_gb("100G"), 100.0);
        assert_eq!(parse_size_to_gb("1T"), 1024.0);
        assert_eq!(parse_size_to_gb("512M"), 512.0 / 1024.0);
    }
}
