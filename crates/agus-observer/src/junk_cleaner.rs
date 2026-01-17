use agus_ssh::{SshClient, SshError, SshTarget};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JunkFileItem {
    pub id: String,
    pub path: String,
    pub name: String,
    pub size_mb: f64,
    pub category: String, // "System Cache", "Large Log", "Docker Image", "Docker Volume", "Temp File"
    pub description: String,
    pub removable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskUsageReport {
    pub root_fs_used_percent: String,
    pub root_fs_used: String,
    pub root_fs_size: String,
    pub docker_space: DockerSpaceInfo,
    pub tmp_size: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerSpaceInfo {
    pub images: String,
    pub containers: String,
    pub local_volumes: String,
    pub build_cache: String,
}

pub fn scan_junk_files<C: SshClient>(
    client: &C,
    target: &SshTarget,
) -> Result<Vec<JunkFileItem>, SshError> {
    let mut items = Vec::new();

    // 1. Scan APT Cache (Debian/Ubuntu)
    let apt_cache_cmd = "du -sm /var/cache/apt/archives 2>/dev/null | awk '{print $1}'";
    if let Ok(res) = client.execute(target, apt_cache_cmd) {
        if let Ok(size_mb) = res.stdout.trim().parse::<f64>() {
            if size_mb > 10.0 {
                items.push(JunkFileItem {
                    id: "apt_cache".to_string(),
                    path: "/var/cache/apt/archives".to_string(),
                    name: "APT Package Cache".to_string(),
                    size_mb,
                    category: "System Cache".to_string(),
                    description: "Downloaded package files for installation".to_string(),
                    removable: true,
                });
            }
        }
    }

    // 2. Scan Large Log Files (>50MB)
    let log_cmd = "find /var/log -type f -size +50M -exec ls -lh --block-size=M {} \\; | awk '{print $9, $5}' | head -n 10";
    if let Ok(res) = client.execute(target, log_cmd) {
        for (idx, line) in res.stdout.lines().enumerate() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let path = parts[0].to_string();
                let size_str = parts[1].trim_end_matches('M');
                if let Ok(size_mb) = size_str.parse::<f64>() {
                    items.push(JunkFileItem {
                        id: format!("log_{}", idx),
                        path: path.clone(),
                        name: Path::new(&path)
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string(),
                        size_mb,
                        category: "Large Log".to_string(),
                        description: "Large system log file".to_string(),
                        removable: true, // Be careful, user decision
                    });
                }
            }
        }
    }

    // 3. Docker Dangling Images
    let docker_img_cmd = "docker images -f \"dangling=true\" --format \"{{.ID}}|{{.Size}}\"";
    if let Ok(res) = client.execute(target, docker_img_cmd) {
        for (_idx, line) in res.stdout.lines().enumerate() {
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 2 {
                let id = parts[0];
                let size_raw = parts[1];
                let size_mb = parse_docker_size(size_raw);
                items.push(JunkFileItem {
                    id: format!("docker_img_{}", id),
                    path: id.to_string(),
                    name: format!("Dangling Image {}", id),
                    size_mb,
                    category: "Docker".to_string(),
                    description: "Unused (dangling) docker image".to_string(),
                    removable: true,
                });
            }
        }
    }

    // 4. Docker Stopped Containers
    let docker_cont_cmd =
        "docker ps -a -f \"status=exited\" --format \"{{.ID}}|{{.Names}}|{{.Size}}\" | head -n 10";
    if let Ok(res) = client.execute(target, docker_cont_cmd) {
        for (_idx, line) in res.stdout.lines().enumerate() {
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 3 {
                let id = parts[0];
                let name = parts[1];
                let size_raw = parts[2].split_whitespace().next().unwrap_or("0B");
                let size_mb = parse_docker_size(size_raw);
                if size_mb > 0.0 {
                    items.push(JunkFileItem {
                        id: format!("docker_cont_{}", id),
                        path: id.to_string(),
                        name: format!("Stopped Container {}", name),
                        size_mb,
                        category: "Docker".to_string(),
                        description: "Stopped docker container".to_string(),
                        removable: true,
                    });
                }
            }
        }
    }

    // 5. Docker Builder Cache & Volumes (via system df)
    let docker_df_cmd = "docker system df --format \"{{.Type}}|{{.Size}}|{{.Reclaimable}}\"";
    if let Ok(res) = client.execute(target, docker_df_cmd) {
        for line in res.stdout.lines() {
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 3 {
                let item_type = parts[0].trim();
                let size_raw = parts[2].trim(); // Reclaimable size
                let size_mb = parse_docker_size(size_raw);

                if size_mb > 10.0 {
                    if item_type == "Build Cache" {
                        items.push(JunkFileItem {
                            id: "docker_builder_cache".to_string(),
                            path: "docker_builder_cache".to_string(),
                            name: "Docker Build Cache".to_string(),
                            size_mb,
                            category: "Docker".to_string(),
                            description: "Cache from previous docker builds".to_string(),
                            removable: true,
                        });
                    } else if item_type == "Local Volumes" {
                        items.push(JunkFileItem {
                            id: "docker_volumes".to_string(),
                            path: "docker_volumes".to_string(),
                            name: "Unused Docker Volumes".to_string(),
                            size_mb,
                            category: "Docker".to_string(),
                            description: "Dangling data volumes (not used by any container)"
                                .to_string(),
                            removable: true,
                        });
                    }
                }
            }
        }
    }

    // 6. Old Kernels (Non-running)
    let current_kernel_cmd = "uname -r";
    if let Ok(k_res) = client.execute(target, current_kernel_cmd) {
        let current_k = k_res.stdout.trim();
        let list_kernel_cmd = "ls /boot/vmlinuz-* 2>/dev/null";
        if let Ok(list_res) = client.execute(target, list_kernel_cmd) {
            for path in list_res.stdout.lines() {
                if !path.contains(current_k) {
                    items.push(JunkFileItem {
                        id: format!("kernel_{}", path.replace("/", "_")),
                        path: path.to_string(),
                        name: format!(
                            "Old Kernel ({})",
                            path.split('-').last().unwrap_or("unknown")
                        ),
                        size_mb: 50.0, // Approximation
                        category: "System".to_string(),
                        description: "Old, non-running Linux kernel file".to_string(),
                        removable: true,
                    });
                }
            }
        }
    }

    // 7. Core Dumps & Crash Reports
    let crash_cmd = "find /var/lib/systemd/coredump /var/crash -type f -size +1M 2>/dev/null -exec ls -lh --block-size=M {} \\; | awk '{print $9, $5}'";
    if let Ok(res) = client.execute(target, crash_cmd) {
        for (idx, line) in res.stdout.lines().enumerate() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let path = parts[0].to_string();
                let size_mb = parts[1].trim_end_matches('M').parse::<f64>().unwrap_or(0.0);
                items.push(JunkFileItem {
                    id: format!("crash_{}", idx),
                    path: path.clone(),
                    name: Path::new(&path)
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string(),
                    size_mb,
                    category: "Diagnostics".to_string(),
                    description: "Application crash dump or error report".to_string(),
                    removable: true,
                });
            }
        }
    }

    // 8. Unused Package Dependencies (APT Autoremove)
    let autoremove_cmd = "apt-get -s autoremove | grep '^Inst' | wc -l";
    if let Ok(res) = client.execute(target, autoremove_cmd) {
        if let Ok(count) = res.stdout.trim().parse::<i32>() {
            if count > 0 {
                items.push(JunkFileItem {
                    id: "apt_autoremove".to_string(),
                    path: "apt_autoremove".to_string(),
                    name: format!("{} Unused Packages", count),
                    size_mb: (count as f64) * 20.0, // Heuristic: 20MB per package
                    category: "Package Manager".to_string(),
                    description:
                        "Packages that were automatically installed and are no longer required"
                            .to_string(),
                    removable: true,
                });
            }
        }
    }

    // 9. Broken Symlinks
    let symlink_cmd = "find /usr/local/bin /usr/bin /etc -xtype l 2>/dev/null | head -n 20 | wc -l";
    if let Ok(res) = client.execute(target, symlink_cmd) {
        if let Ok(count) = res.stdout.trim().parse::<i32>() {
            if count > 0 {
                items.push(JunkFileItem {
                    id: "broken_symlinks".to_string(),
                    path: "broken_symlinks".to_string(),
                    name: format!("{} Broken Symlinks", count),
                    size_mb: 0.1, // Near zero, but metadata cleaning helps performance
                    category: "Filesystem".to_string(),
                    description: "Symbolic links pointing to non-existent files".to_string(),
                    removable: true,
                });
            }
        }
    }

    // 10. /tmp Old Files (older than 7 days)
    let tmp_cmd = "find /tmp -type f -mtime +7 2>/dev/null | wc -l";
    if let Ok(res) = client.execute(target, tmp_cmd) {
        if let Ok(count) = res.stdout.trim().parse::<i32>() {
            if count > 10 {
                // Estimate size: 10 files * 1MB each
                items.push(JunkFileItem {
                    id: "tmp_old_files".to_string(),
                    path: "/tmp".to_string(),
                    name: format!("{} Old Temp Files (>7 days)", count),
                    size_mb: (count as f64).min(100.0), // Cap at 100MB estimate
                    category: "Temp File".to_string(),
                    description: "Files in /tmp older than 7 days".to_string(),
                    removable: true,
                });
            }
        }
    }

    // 11. Docker System Prune (comprehensive cleanup)
    let docker_system_cmd = "docker system df --format '{{.Reclaimable}}' | grep -v '0B' | wc -l";
    if let Ok(res) = client.execute(target, docker_system_cmd) {
        if let Ok(count) = res.stdout.trim().parse::<i32>() {
            if count > 0 {
                // Estimate total reclaimable space
                let space_cmd = "docker system df --format '{{.Reclaimable}}' | grep -v '0B' | sed 's/GB/*1024/;s/MB//;s/KB//;s/B//' | awk '{s+=$1} END {print s*10}' 2>/dev/null || echo '0'";
                if let Ok(space_res) = client.execute(target, space_cmd) {
                    if let Ok(space_mb) = space_res.stdout.trim().parse::<f64>() {
                        if space_mb > 50.0 {
                            items.push(JunkFileItem {
                                id: "docker_system_prune".to_string(),
                                path: "docker_system_prune".to_string(),
                                name: "Docker System Cleanup".to_string(),
                                size_mb: space_mb,
                                category: "Docker".to_string(),
                                description: "Comprehensive cleanup of unused docker resources (images, containers, volumes, build cache)".to_string(),
                                removable: true,
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(items)
}

pub fn clean_junk_files<C: SshClient>(
    client: &C,
    target: &SshTarget,
    item_paths: Vec<String>,
) -> Result<(), SshError> {
    for path in item_paths {
        if path == "/var/cache/apt/archives" {
            client.execute(target, "sudo apt-get clean")?;
        } else if path == "apt_autoremove" {
            client.execute(target, "sudo apt-get autoremove -y")?;
        } else if path == "docker_builder_cache" {
            client.execute(target, "docker builder prune -af")?;
        } else if path == "docker_volumes" {
            client.execute(target, "docker volume prune -f")?;
        } else if path == "docker_system_prune" {
            // Comprehensive Docker cleanup: images, containers, volumes, build cache
            client.execute(target, "docker system prune -af --volumes")?;
        } else if path == "/tmp" || path == "tmp_old_files" {
            // Clean /tmp directory (files older than 7 days)
            client.execute(
                target,
                "find /tmp -type f -mtime +7 -delete 2>/dev/null || true",
            )?;
            client.execute(
                target,
                "find /tmp -type d -empty -delete 2>/dev/null || true",
            )?;
        } else if path == "broken_symlinks" {
            client.execute(
                target,
                "find /usr/local/bin /usr/bin /etc -xtype l 2>/dev/null -delete",
            )?;
        } else if path.starts_with('/') {
            // File path, use rm
            client.execute(target, &format!("sudo rm -rf {}", path))?;
        } else {
            // Likely docker ID (Image or Container)
            if client
                .execute(target, &format!("docker rmi {}", path))
                .is_err()
            {
                client.execute(target, &format!("docker rm -f {}", path))?;
            }
        }
    }
    Ok(())
}

fn parse_docker_size(size_str: &str) -> f64 {
    let size_str = size_str.trim();
    if size_str.ends_with("GB") {
        size_str
            .trim_end_matches("GB")
            .parse::<f64>()
            .unwrap_or(0.0)
            * 1024.0
    } else if size_str.ends_with("MB") {
        size_str
            .trim_end_matches("MB")
            .parse::<f64>()
            .unwrap_or(0.0)
    } else if size_str.ends_with("KB") {
        size_str
            .trim_end_matches("KB")
            .parse::<f64>()
            .unwrap_or(0.0)
            / 1024.0
    } else if size_str.ends_with("B") {
        size_str.trim_end_matches("B").parse::<f64>().unwrap_or(0.0) / (1024.0 * 1024.0)
    } else {
        0.0
    }
}

pub fn get_disk_usage_report<C: SshClient>(
    client: &C,
    target: &SshTarget,
) -> Result<DiskUsageReport, SshError> {
    // Get root filesystem usage
    let df_cmd = "df -h / | tail -1 | awk '{print $3 \" / \" $2 \" (\" $5 \")\"}'";
    let df_output = client.execute(target, df_cmd)?;
    let df_parts: Vec<&str> = df_output.stdout.trim().split('(').collect();
    let (used, size, percent) = if df_parts.len() >= 2 {
        let usage_parts: Vec<&str> = df_parts[0].split(" / ").collect();
        let used_str = usage_parts.get(0).unwrap_or(&"0G").trim();
        let size_str = usage_parts.get(1).unwrap_or(&"0G").trim();
        let percent_str = df_parts[1].trim_end_matches(')');
        (
            used_str.to_string(),
            size_str.to_string(),
            percent_str.to_string(),
        )
    } else {
        ("0G".to_string(), "0G".to_string(), "0%".to_string())
    };

    // Get Docker space info
    let docker_cmd = "docker system df --format '{{.Type}}|{{.TotalCount}}|{{.Size}}'";
    let docker_output = client.execute(target, docker_cmd)?;
    let mut docker_info = DockerSpaceInfo {
        images: "0B".to_string(),
        containers: "0B".to_string(),
        local_volumes: "0B".to_string(),
        build_cache: "0B".to_string(),
    };

    for line in docker_output.stdout.lines() {
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() >= 3 {
            let item_type = parts[0].trim();
            let size = parts[2].trim();
            match item_type {
                "Images" => docker_info.images = size.to_string(),
                "Containers" => docker_info.containers = size.to_string(),
                "Local Volumes" => docker_info.local_volumes = size.to_string(),
                "Build Cache" => docker_info.build_cache = size.to_string(),
                _ => {}
            }
        }
    }

    // Get /tmp directory size
    let tmp_cmd = "du -sh /tmp 2>/dev/null | awk '{print $1}'";
    let tmp_output = client.execute(target, tmp_cmd)?;
    let tmp_size = if tmp_output.stdout.trim().is_empty() {
        "0B".to_string()
    } else {
        tmp_output.stdout.trim().to_string()
    };

    Ok(DiskUsageReport {
        root_fs_used_percent: percent,
        root_fs_used: used,
        root_fs_size: size,
        docker_space: docker_info,
        tmp_size,
    })
}

use std::path::Path;
