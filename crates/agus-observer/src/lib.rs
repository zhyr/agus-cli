pub mod alerting;
pub mod container_health;
pub mod container_logs;
pub mod junk_cleaner;
pub mod nginx;
pub mod performance_metrics;
pub mod vulnerability;

pub use alerting::{
    Alert, AlertError, AlertManager, AlertMetrics, AlertRule, AlertSeverity, Comparison,
    InMemoryAlertManager, MetricType,
};
pub use container_health::{ContainerHealth, ContainerHealthCheckResult, ContainerStatus};
pub use container_logs::{
    ContainerLogEntry, ContainerLogError, ContainerLogMonitor, LogLevel, LogStream,
    SshContainerLogMonitor,
};
pub use junk_cleaner::{
    clean_junk_files, get_disk_usage_report, scan_junk_files, DiskUsageReport, DockerSpaceInfo,
    JunkFileItem,
};
pub use nginx::{scan_nginx_status, NginxServerBlock, NginxStatusReport};
pub use performance_metrics::{
    collect_system_metrics, CpuMetrics, DiskMetrics, LoadAverage, MemoryMetrics, NetworkInterface,
    NetworkMetrics, SystemMetrics,
};
pub use vulnerability::{scan_vulnerability_context, SystemVulnerabilityContext};

use agus_core_domain::{
    Column, DatabaseSchema, DatabaseType, DbConnectionConfig, Index, RiskLevel, SchemaChange,
    SchemaDiff, SchemaObject, ServerScanReport, Service, ServiceDependencyEdge,
    ServiceDependencyGraph, ServiceKind, Table,
};
use agus_ssh::{SshClient, SshError, SshTarget};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ObserverError {
    Connection { message: String },
    Command { exit_code: i32, stderr: String },
    Parse { message: String },
}

impl std::fmt::Display for ObserverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ObserverError::Connection { message } => write!(f, "connection error: {message}"),
            ObserverError::Command { exit_code, stderr } => {
                write!(f, "command error (exit {exit_code}): {stderr}")
            }
            ObserverError::Parse { message } => write!(f, "parse error: {message}"),
        }
    }
}

impl std::error::Error for ObserverError {}

impl From<SshError> for ObserverError {
    fn from(err: SshError) -> Self {
        match err {
            SshError::Connection { message } => ObserverError::Connection { message },
            SshError::Command { exit_code, stderr } => ObserverError::Command { exit_code, stderr },
            SshError::Timeout { message } => ObserverError::Connection { 
                message: format!("timeout: {}", message) 
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum DbSchemaError {
    InvalidConfig { message: String },
    Connection { message: String },
    Command { exit_code: i32, stderr: String },
    Parse { message: String },
    Io { message: String },
}

impl std::fmt::Display for DbSchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbSchemaError::InvalidConfig { message } => write!(f, "invalid config: {message}"),
            DbSchemaError::Connection { message } => write!(f, "connection error: {message}"),
            DbSchemaError::Command { exit_code, stderr } => {
                write!(f, "command error (exit {exit_code}): {stderr}")
            }
            DbSchemaError::Parse { message } => write!(f, "parse error: {message}"),
            DbSchemaError::Io { message } => write!(f, "io error: {message}"),
        }
    }
}

impl std::error::Error for DbSchemaError {}

impl From<SshError> for DbSchemaError {
    fn from(err: SshError) -> Self {
        match err {
            SshError::Connection { message } => DbSchemaError::Connection { message },
            SshError::Command { exit_code, stderr } => DbSchemaError::Command { exit_code, stderr },
            SshError::Timeout { message } => DbSchemaError::Connection { 
                message: format!("timeout: {}", message) 
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DesiredSchemaSource {
    Sql { sql: String },
    SqlFile { path: String },
    Declarative { schema: DatabaseSchema },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnameInfo {
    pub os: String,
    pub kernel: String,
    pub cpu_arch: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnameParseError {
    Empty,
    InsufficientFields { found: usize },
    MissingCpuArch,
}

impl std::fmt::Display for UnameParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnameParseError::Empty => write!(f, "uname output is empty"),
            UnameParseError::InsufficientFields { found } => {
                write!(f, "uname output has too few fields: {found}")
            }
            UnameParseError::MissingCpuArch => write!(f, "uname output missing cpu arch"),
        }
    }
}

impl std::error::Error for UnameParseError {}

impl From<UnameParseError> for ObserverError {
    fn from(err: UnameParseError) -> Self {
        ObserverError::Parse {
            message: err.to_string(),
        }
    }
}

pub fn scan_host_basic<C: SshClient>(
    client: &C,
    target: &SshTarget,
) -> Result<ServerScanReport, ObserverError> {
    // 1. Basic Hostname
    let hostname = client
        .execute(target, "hostname")?
        .stdout
        .trim()
        .to_string();
    if hostname.is_empty() {
        return Err(ObserverError::Parse {
            message: "hostname output was empty".to_string(),
        });
    }

    // 2. OS/Kernel/Arch (uname -a)
    let uname_output = client.execute(target, "uname -a")?;
    let uname_info = parse_uname_a(&uname_output.stdout)?;

    // 3. Platform / Manufacturer
    // Attempt to read product name from sysfs
    let platform = client
        .execute(
            target,
            "cat /sys/class/dmi/id/product_name 2>/dev/null || echo 'Unknown'",
        )
        .map(|res| res.stdout.trim().to_string())
        .unwrap_or_else(|_| "Unknown".to_string());

    // 4. Timezone & System Time
    // Using timedatectl if available, else date
    let time_info_cmd = "timedatectl status 2>/dev/null || date +'%Z %H:%M:%S'";
    let time_output = client
        .execute(target, time_info_cmd)
        .map(|res| res.stdout)
        .unwrap_or_default();

    let (timezone, system_time) = parse_time_info(&time_output);

    // 5. CPU Info
    // Try lscpu first, fallback to /proc/cpuinfo
    let cpu_info = client
        .execute(target, "lscpu | grep 'Model name' | cut -d':' -f2 | xargs || grep 'model name' /proc/cpuinfo | head -1 | cut -d':' -f2 | xargs")
        .map(|res| res.stdout.trim().to_string())
        .unwrap_or_default();
    let cpu_info = if cpu_info.is_empty() {
        "Unknown CPU".to_string()
    } else {
        cpu_info
    };

    // 6. GPU Info
    // Check nvidia-smi
    let gpu_info = client
        .execute(
            target,
            "nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null || echo ''",
        )
        .ok()
        .and_then(|res| {
            let s = res.stdout.trim().to_string();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        });

    // 7. Docker Version
    let docker_version = client
        .execute(target, "docker --version 2>/dev/null || echo ''")
        .ok()
        .and_then(|res| {
            let s = res.stdout.trim().to_string();
            if s.is_empty() {
                None
            } else {
                Some(s.replace("Docker version ", ""))
            }
        });

    // 8. Compose Version
    let compose_version = client
        .execute(
            target,
            "docker compose version 2>/dev/null || docker-compose --version 2>/dev/null || echo ''",
        )
        .ok()
        .and_then(|res| {
            let s = res.stdout.trim().to_string();
            if s.is_empty() {
                None
            } else {
                Some(
                    s.replace("Docker Compose version ", "")
                        .replace("docker-compose version ", ""),
                )
            }
        });

    // 9. K8s Version
    let k8s_version = client
        .execute(
            target,
            "kubectl version --client --short 2>/dev/null || echo ''",
        )
        .ok()
        .and_then(|res| {
            let s = res.stdout.trim().to_string();
            if s.is_empty() {
                None
            } else {
                Some(s.replace("Client Version: ", ""))
            }
        });

    Ok(ServerScanReport {
        hostname,
        os: uname_info.os,
        kernel: uname_info.kernel,
        cpu_arch: uname_info.cpu_arch,
        platform,
        timezone,
        system_time,
        cpu_info,
        gpu_info,
        docker_version,
        compose_version,
        k8s_version,
    })
}

fn parse_time_info(output: &str) -> (String, String) {
    if output.contains("Time zone:") {
        // Parse timedatectl output
        let mut timezone = "Unknown".to_string();
        let mut time = "Unknown".to_string();
        for line in output.lines() {
            if line.trim().starts_with("Time zone:") {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() > 1 {
                    timezone = parts[1]
                        .trim()
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .to_string();
                }
            }
            if line.trim().starts_with("Local time:") {
                let parts: Vec<&str> = line.split("Local time:").collect();
                if parts.len() > 1 {
                    time = parts[1].trim().to_string();
                }
            }
        }
        (timezone, time)
    } else {
        // Fallback date output: e.g., "UTC 12:00:00"
        let parts: Vec<&str> = output.trim().split_whitespace().collect();
        if parts.len() >= 2 {
            (parts[0].to_string(), parts[1].to_string())
        } else {
            ("Unknown".to_string(), output.trim().to_string())
        }
    }
}

pub fn parse_uname_a(output: &str) -> Result<UnameInfo, UnameParseError> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return Err(UnameParseError::Empty);
    }

    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.len() < 3 {
        return Err(UnameParseError::InsufficientFields {
            found: tokens.len(),
        });
    }

    let os = tokens[0].to_string();
    let kernel = tokens[2].to_string();
    let cpu_arch = find_cpu_arch(&tokens).ok_or(UnameParseError::MissingCpuArch)?;

    Ok(UnameInfo {
        os,
        kernel,
        cpu_arch,
    })
}

fn find_cpu_arch(tokens: &[&str]) -> Option<String> {
    let known_arches = [
        "x86_64", "amd64", "aarch64", "arm64", "armv7l", "armv6l", "i386", "i686", "ppc64le",
        "s390x", "riscv64",
    ];

    for token in tokens.iter().rev() {
        if known_arches
            .iter()
            .any(|arch| token.eq_ignore_ascii_case(arch))
        {
            return Some((*token).to_string());
        }
    }

    if tokens.len() >= 5 {
        return Some(tokens[4].to_string());
    }

    None
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum RepoScanError {
    InvalidPath { message: String },
    Io { message: String },
    Parse { message: String },
    DuplicateService { name: String },
    CycleDetected { message: String },
}

impl std::fmt::Display for RepoScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RepoScanError::InvalidPath { message } => write!(f, "invalid path: {message}"),
            RepoScanError::Io { message } => write!(f, "io error: {message}"),
            RepoScanError::Parse { message } => write!(f, "parse error: {message}"),
            RepoScanError::DuplicateService { name } => {
                write!(f, "duplicate service name: {name}")
            }
            RepoScanError::CycleDetected { message } => write!(f, "cycle detected: {message}"),
        }
    }
}

impl std::error::Error for RepoScanError {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ComposeServiceInfo {
    ports: Vec<u16>,
    references: Vec<String>,
}

pub fn scan_repo_basic(path: &Path) -> Result<ServiceDependencyGraph, RepoScanError> {
    if !path.exists() {
        return Err(RepoScanError::InvalidPath {
            message: "path does not exist".to_string(),
        });
    }
    if !path.is_dir() {
        return Err(RepoScanError::InvalidPath {
            message: "path is not a directory".to_string(),
        });
    }

    let mut dockerfiles = Vec::new();
    let mut compose_files = Vec::new();
    collect_repo_files(path, &mut dockerfiles, &mut compose_files)?;

    let mut services_by_name: HashMap<String, Service> = HashMap::new();
    let mut compose_info_by_name: HashMap<String, ComposeServiceInfo> = HashMap::new();

    for compose_path in compose_files {
        let contents = fs::read_to_string(&compose_path).map_err(|err| RepoScanError::Io {
            message: format!("failed to read {}: {err}", compose_path.display()),
        })?;
        let parsed = parse_compose_services(&contents)?;
        for (name, info) in parsed {
            if compose_info_by_name.contains_key(&name) {
                return Err(RepoScanError::DuplicateService { name });
            }
            compose_info_by_name.insert(name, info);
        }
    }

    for (name, info) in &compose_info_by_name {
        let service = Service {
            name: name.clone(),
            kind: ServiceKind::ComposeService,
            exposed_ports: info.ports.clone(),
        };
        insert_service(&mut services_by_name, service)?;
    }

    for dockerfile in dockerfiles {
        let name = derive_service_name(path, &dockerfile)?;
        let service = Service {
            name,
            kind: ServiceKind::Dockerfile,
            exposed_ports: Vec::new(),
        };
        insert_service(&mut services_by_name, service)?;
    }

    let edges = build_dependency_edges(&compose_info_by_name, &services_by_name);
    let graph = ServiceDependencyGraph {
        nodes: services_by_name.into_values().collect(),
        edges,
    };

    validate_acyclic(&graph)?;

    Ok(graph)
}

fn insert_service(
    services: &mut HashMap<String, Service>,
    service: Service,
) -> Result<(), RepoScanError> {
    if services.contains_key(&service.name) {
        return Err(RepoScanError::DuplicateService { name: service.name });
    }
    services.insert(service.name.clone(), service);
    Ok(())
}

fn collect_repo_files(
    root: &Path,
    dockerfiles: &mut Vec<PathBuf>,
    compose_files: &mut Vec<PathBuf>,
) -> Result<(), RepoScanError> {
    let entries = fs::read_dir(root).map_err(|err| RepoScanError::Io {
        message: format!("failed to read directory {}: {err}", root.display()),
    })?;

    for entry in entries {
        let entry = entry.map_err(|err| RepoScanError::Io {
            message: format!("failed to read directory entry: {err}"),
        })?;
        let path = entry.path();
        if path.is_dir() {
            collect_repo_files(&path, dockerfiles, compose_files)?;
            continue;
        }
        if !path.is_file() {
            continue;
        }
        if let Some(file_name) = path.file_name().and_then(|name| name.to_str()) {
            if file_name == "Dockerfile" {
                dockerfiles.push(path);
            } else if file_name == "docker-compose.yml" || file_name == "docker-compose.yaml" {
                compose_files.push(path);
            }
        }
    }

    Ok(())
}

fn derive_service_name(root: &Path, dockerfile_path: &Path) -> Result<String, RepoScanError> {
    let parent = dockerfile_path
        .parent()
        .ok_or_else(|| RepoScanError::Parse {
            message: "dockerfile missing parent directory".to_string(),
        })?;
    let name = if parent == root {
        root.file_name()
    } else {
        parent.file_name()
    };

    name.and_then(|value| value.to_str())
        .map(|value| value.to_string())
        .ok_or_else(|| RepoScanError::Parse {
            message: format!(
                "failed to derive service name from {}",
                dockerfile_path.display()
            ),
        })
}

fn parse_compose_services(
    contents: &str,
) -> Result<HashMap<String, ComposeServiceInfo>, RepoScanError> {
    let doc: serde_yaml::Value =
        serde_yaml::from_str(contents).map_err(|err| RepoScanError::Parse {
            message: format!("invalid compose yaml: {err}"),
        })?;
    let services_value = doc.get("services").ok_or_else(|| RepoScanError::Parse {
        message: "compose file missing services section".to_string(),
    })?;
    let services_map = services_value
        .as_mapping()
        .ok_or_else(|| RepoScanError::Parse {
            message: "compose services must be a mapping".to_string(),
        })?;

    let mut services = HashMap::new();
    for (name_value, service_value) in services_map {
        let name = name_value
            .as_str()
            .ok_or_else(|| RepoScanError::Parse {
                message: "compose service name must be a string".to_string(),
            })?
            .to_string();
        let service_map = service_value
            .as_mapping()
            .ok_or_else(|| RepoScanError::Parse {
                message: format!("compose service {name} must be a mapping"),
            })?;

        let ports = service_map
            .get(&serde_yaml::Value::String("ports".to_string()))
            .map(parse_ports)
            .unwrap_or_default();

        let mut references = Vec::new();
        if let Some(depends_on) =
            service_map.get(&serde_yaml::Value::String("depends_on".to_string()))
        {
            references.extend(parse_service_references(depends_on));
        }
        if let Some(links) = service_map.get(&serde_yaml::Value::String("links".to_string())) {
            references.extend(parse_service_references(links));
        }

        references.sort();
        references.dedup();

        services.insert(name, ComposeServiceInfo { ports, references });
    }

    Ok(services)
}

fn parse_service_references(value: &serde_yaml::Value) -> Vec<String> {
    match value {
        serde_yaml::Value::Sequence(seq) => seq
            .iter()
            .filter_map(|item| item.as_str().map(|value| value.to_string()))
            .collect(),
        serde_yaml::Value::Mapping(map) => map
            .keys()
            .filter_map(|key| key.as_str().map(|value| value.to_string()))
            .collect(),
        serde_yaml::Value::String(value) => vec![value.to_string()],
        _ => Vec::new(),
    }
}

fn parse_ports(value: &serde_yaml::Value) -> Vec<u16> {
    match value {
        serde_yaml::Value::Sequence(seq) => {
            let mut ports = Vec::new();
            for item in seq {
                if let Some(port) = parse_port_value(item) {
                    ports.push(port);
                }
            }
            ports.sort();
            ports.dedup();
            ports
        }
        _ => Vec::new(),
    }
}

fn parse_port_value(value: &serde_yaml::Value) -> Option<u16> {
    match value {
        serde_yaml::Value::Number(number) => {
            number.as_u64().and_then(|value| u16::try_from(value).ok())
        }
        serde_yaml::Value::String(value) => parse_port_string(value),
        serde_yaml::Value::Mapping(map) => map
            .get(&serde_yaml::Value::String("target".to_string()))
            .and_then(parse_port_value),
        _ => None,
    }
}

fn parse_port_string(value: &str) -> Option<u16> {
    let without_proto = value.split('/').next().unwrap_or(value);
    let last_segment = without_proto.rsplit(':').next().unwrap_or(without_proto);
    last_segment.parse::<u16>().ok()
}

fn build_dependency_edges(
    compose_info: &HashMap<String, ComposeServiceInfo>,
    services: &HashMap<String, Service>,
) -> Vec<ServiceDependencyEdge> {
    let mut edges = HashSet::new();
    for (service_name, info) in compose_info {
        for reference in &info.references {
            if let Some(target) = services.get(reference) {
                if !target.exposed_ports.is_empty() {
                    edges.insert(ServiceDependencyEdge {
                        from: service_name.clone(),
                        to: reference.clone(),
                    });
                }
            }
        }
    }

    edges.into_iter().collect()
}

fn validate_acyclic(graph: &ServiceDependencyGraph) -> Result<(), RepoScanError> {
    let mut indegree: HashMap<&str, usize> = HashMap::new();
    let mut adjacency: HashMap<&str, Vec<&str>> = HashMap::new();

    for node in &graph.nodes {
        indegree.insert(node.name.as_str(), 0);
        adjacency.insert(node.name.as_str(), Vec::new());
    }

    for edge in &graph.edges {
        if let (Some(from_list), Some(to_degree)) = (
            adjacency.get_mut(edge.from.as_str()),
            indegree.get_mut(edge.to.as_str()),
        ) {
            from_list.push(edge.to.as_str());
            *to_degree += 1;
        }
    }

    let mut queue = VecDeque::new();
    for (name, degree) in &indegree {
        if *degree == 0 {
            queue.push_back(*name);
        }
    }

    let mut visited = 0usize;
    while let Some(node) = queue.pop_front() {
        visited += 1;
        if let Some(neighbors) = adjacency.get(node) {
            for neighbor in neighbors {
                if let Some(degree) = indegree.get_mut(neighbor) {
                    *degree -= 1;
                    if *degree == 0 {
                        queue.push_back(neighbor);
                    }
                }
            }
        }
    }

    if visited != indegree.len() {
        let cycle_nodes: Vec<&str> = indegree
            .iter()
            .filter_map(|(name, degree)| if *degree > 0 { Some(*name) } else { None })
            .collect();
        let message = if cycle_nodes.is_empty() {
            "cycle detected in dependency graph".to_string()
        } else {
            format!("cycle detected among services: {}", cycle_nodes.join(", "))
        };
        return Err(RepoScanError::CycleDetected { message });
    }

    Ok(())
}

pub fn scan_db_schema<C: SshClient>(
    client: &C,
    target: &SshTarget,
    config: &DbConnectionConfig,
) -> Result<DatabaseSchema, DbSchemaError> {
    validate_db_connection_config(config)?;
    match config.db_type {
        DatabaseType::Postgres => scan_postgres_schema(client, target, config),
        DatabaseType::MySQL => scan_mysql_schema(client, target, config),
    }
}

pub fn load_desired_schema(source: &DesiredSchemaSource) -> Result<DatabaseSchema, DbSchemaError> {
    match source {
        DesiredSchemaSource::Sql { sql } => parse_sql_schema(sql),
        DesiredSchemaSource::SqlFile { path } => {
            let contents = fs::read_to_string(path).map_err(|err| DbSchemaError::Io {
                message: format!("failed to read schema file: {err}"),
            })?;
            parse_sql_schema(&contents)
        }
        DesiredSchemaSource::Declarative { schema } => Ok(schema.clone()),
    }
}

pub fn diff_db_schema(current: &DatabaseSchema, desired: &DatabaseSchema) -> SchemaDiff {
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut modified = Vec::new();

    let current_tables = collect_table_names(current);
    let desired_tables = collect_table_names(desired);

    for table in desired_tables.difference(&current_tables) {
        added.push(SchemaObject::Table(Table {
            name: table.clone(),
        }));
    }

    for table in current_tables.difference(&desired_tables) {
        removed.push(SchemaObject::Table(Table {
            name: table.clone(),
        }));
    }

    let current_columns = group_columns_by_table(&current.columns);
    let desired_columns = group_columns_by_table(&desired.columns);

    for table in current_tables.intersection(&desired_tables) {
        let current_map = current_columns.get(table.as_str());
        let desired_map = desired_columns.get(table.as_str());
        let current_map = current_map.cloned().unwrap_or_default();
        let desired_map = desired_map.cloned().unwrap_or_default();

        for (name, current_col) in &current_map {
            if let Some(desired_col) = desired_map.get(name) {
                if current_col.data_type != desired_col.data_type {
                    modified.push(SchemaChange::ColumnTypeChange {
                        table: table.clone(),
                        column: name.clone(),
                        from: current_col.data_type.clone(),
                        to: desired_col.data_type.clone(),
                    });
                }
            }
        }

        let mut removed_cols: Vec<Column> = current_map
            .values()
            .filter(|col| !desired_map.contains_key(&col.name))
            .cloned()
            .collect();
        let mut added_cols: Vec<Column> = desired_map
            .values()
            .filter(|col| !current_map.contains_key(&col.name))
            .cloned()
            .collect();

        let mut rename_pairs = Vec::new();
        let removed_by_type = group_columns_by_type(&removed_cols);
        let added_by_type = group_columns_by_type(&added_cols);
        for (data_type, removed_list) in &removed_by_type {
            if let Some(added_list) = added_by_type.get(data_type) {
                if removed_list.len() == 1 && added_list.len() == 1 {
                    rename_pairs.push((removed_list[0].clone(), added_list[0].clone()));
                }
            }
        }

        for (from_col, to_col) in rename_pairs {
            removed_cols.retain(|col| col.name != from_col.name);
            added_cols.retain(|col| col.name != to_col.name);
            modified.push(SchemaChange::ColumnRename {
                table: table.clone(),
                from: from_col.name,
                to: to_col.name,
            });
        }

        for col in added_cols {
            added.push(SchemaObject::Column(col));
        }

        for col in removed_cols {
            removed.push(SchemaObject::Column(col));
        }
    }

    let current_indexes = index_map(&current.indexes);
    let desired_indexes = index_map(&desired.indexes);

    for key in desired_indexes.keys() {
        if !current_indexes.contains_key(key) {
            if let Some(index) = desired_indexes.get(key) {
                added.push(SchemaObject::Index(index.clone()));
            }
        }
    }

    for key in current_indexes.keys() {
        if !desired_indexes.contains_key(key) {
            if let Some(index) = current_indexes.get(key) {
                removed.push(SchemaObject::Index(index.clone()));
            }
        }
    }

    sort_schema_objects(&mut added);
    sort_schema_objects(&mut removed);
    sort_schema_changes(&mut modified);

    let risk_level = calculate_risk_level(&added, &removed, &modified);

    SchemaDiff {
        added,
        removed,
        modified,
        risk_level,
    }
}

pub fn explain_db_diff(diff: &SchemaDiff) -> String {
    if diff.added.is_empty() && diff.removed.is_empty() && diff.modified.is_empty() {
        return format!("No schema changes detected. Risk: {:?}.", diff.risk_level);
    }

    let mut lines = Vec::new();
    lines.push(format!("Risk level: {:?}.", diff.risk_level));
    lines.push(format!(
        "Added: {}, Removed: {}, Modified: {}.",
        diff.added.len(),
        diff.removed.len(),
        diff.modified.len()
    ));

    for change in &diff.modified {
        lines.push(format!("Change: {}", describe_schema_change(change)));
    }
    for obj in &diff.added {
        lines.push(format!("Added: {}", describe_schema_object(obj)));
    }
    for obj in &diff.removed {
        lines.push(format!("Removed: {}", describe_schema_object(obj)));
    }

    lines.join("\n")
}

fn scan_postgres_schema<C: SshClient>(
    client: &C,
    target: &SshTarget,
    config: &DbConnectionConfig,
) -> Result<DatabaseSchema, DbSchemaError> {
    let columns_command = build_postgres_columns_command(config)?;
    let columns_output = client.execute(target, &columns_command)?;
    let columns = parse_postgres_columns(&columns_output.stdout)?;

    let index_command = build_postgres_indexes_command(config)?;
    let index_output = client.execute(target, &index_command)?;
    let indexes = parse_postgres_indexes(&index_output.stdout)?;

    Ok(build_schema(columns, indexes))
}

fn scan_mysql_schema<C: SshClient>(
    client: &C,
    target: &SshTarget,
    config: &DbConnectionConfig,
) -> Result<DatabaseSchema, DbSchemaError> {
    let columns_command = build_mysql_columns_command(config)?;
    let columns_output = client.execute(target, &columns_command)?;
    let columns = parse_mysql_columns(&columns_output.stdout)?;

    let index_command = build_mysql_indexes_command(config)?;
    let index_output = client.execute(target, &index_command)?;
    let indexes = parse_mysql_indexes(&index_output.stdout)?;

    Ok(build_schema(columns, indexes))
}

fn build_postgres_columns_command(config: &DbConnectionConfig) -> Result<String, DbSchemaError> {
    validate_db_connection_config(config)?;
    let query = "SELECT table_name, column_name, data_type, is_nullable \
FROM information_schema.columns \
WHERE table_schema = 'public' \
ORDER BY table_name, ordinal_position;";
    Ok(format!(
        "psql -h {} -p {} -U {} -d {} -t -A -F '|' -c \"{}\"",
        config.host, config.port, config.user, config.database, query
    ))
}

fn build_postgres_indexes_command(config: &DbConnectionConfig) -> Result<String, DbSchemaError> {
    validate_db_connection_config(config)?;
    let query = "SELECT tablename, indexname, indexdef \
FROM pg_indexes \
WHERE schemaname = 'public' \
ORDER BY tablename, indexname;";
    Ok(format!(
        "psql -h {} -p {} -U {} -d {} -t -A -F '|' -c \"{}\"",
        config.host, config.port, config.user, config.database, query
    ))
}

fn build_mysql_columns_command(config: &DbConnectionConfig) -> Result<String, DbSchemaError> {
    validate_db_connection_config(config)?;
    let query = format!(
        "SELECT table_name, column_name, column_type, is_nullable \
FROM information_schema.columns \
WHERE table_schema = '{}' \
ORDER BY table_name, ordinal_position;",
        config.database
    );
    Ok(format!(
        "mysql -h {} -P {} -u {} -D {} -N -B -e \"{}\"",
        config.host, config.port, config.user, config.database, query
    ))
}

fn build_mysql_indexes_command(config: &DbConnectionConfig) -> Result<String, DbSchemaError> {
    validate_db_connection_config(config)?;
    let query = format!(
        "SELECT table_name, index_name, non_unique, column_name, seq_in_index \
FROM information_schema.statistics \
WHERE table_schema = '{}' \
ORDER BY table_name, index_name, seq_in_index;",
        config.database
    );
    Ok(format!(
        "mysql -h {} -P {} -u {} -D {} -N -B -e \"{}\"",
        config.host, config.port, config.user, config.database, query
    ))
}

fn parse_postgres_columns(output: &str) -> Result<Vec<Column>, DbSchemaError> {
    let mut columns = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split('|').collect();
        if parts.len() != 4 {
            return Err(DbSchemaError::Parse {
                message: format!("invalid postgres column row: {trimmed}"),
            });
        }
        columns.push(Column {
            table: parts[0].to_string(),
            name: parts[1].to_string(),
            data_type: parts[2].to_string(),
            nullable: parts[3].eq_ignore_ascii_case("yes"),
        });
    }
    Ok(columns)
}

fn parse_postgres_indexes(output: &str) -> Result<Vec<Index>, DbSchemaError> {
    let mut indexes = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split('|').collect();
        if parts.len() != 3 {
            return Err(DbSchemaError::Parse {
                message: format!("invalid postgres index row: {trimmed}"),
            });
        }
        let table = parts[0].to_string();
        let name = parts[1].to_string();
        let indexdef = parts[2];
        let unique = indexdef.to_ascii_uppercase().contains("UNIQUE");
        let columns = parse_index_columns(indexdef);
        indexes.push(Index {
            table,
            name,
            columns,
            unique,
        });
    }
    Ok(indexes)
}

fn parse_mysql_columns(output: &str) -> Result<Vec<Column>, DbSchemaError> {
    let mut columns = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split('\t').collect();
        if parts.len() != 4 {
            return Err(DbSchemaError::Parse {
                message: format!("invalid mysql column row: {trimmed}"),
            });
        }
        columns.push(Column {
            table: parts[0].to_string(),
            name: parts[1].to_string(),
            data_type: parts[2].to_string(),
            nullable: parts[3].eq_ignore_ascii_case("yes"),
        });
    }
    Ok(columns)
}

fn parse_mysql_indexes(output: &str) -> Result<Vec<Index>, DbSchemaError> {
    let mut indexes: BTreeMap<(String, String), (bool, Vec<String>)> = BTreeMap::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split('\t').collect();
        if parts.len() != 5 {
            return Err(DbSchemaError::Parse {
                message: format!("invalid mysql index row: {trimmed}"),
            });
        }
        let table = parts[0].to_string();
        let index_name = parts[1].to_string();
        let non_unique = parts[2].parse::<u32>().unwrap_or(1);
        let column_name = parts[3].to_string();
        let unique = non_unique == 0;

        let entry = indexes
            .entry((table.clone(), index_name.clone()))
            .or_insert((unique, Vec::new()));
        entry.1.push(column_name);
    }

    let mut results = Vec::new();
    for ((table, name), (unique, columns)) in indexes {
        results.push(Index {
            table,
            name,
            columns,
            unique,
        });
    }
    Ok(results)
}

fn parse_index_columns(definition: &str) -> Vec<String> {
    let start = match definition.find('(') {
        Some(value) => value,
        None => return Vec::new(),
    };
    let end = match definition.rfind(')') {
        Some(value) if value > start => value,
        _ => return Vec::new(),
    };
    let inner = &definition[start + 1..end];
    split_sql_items(inner)
        .into_iter()
        .map(|value| value.trim_matches('"').trim().to_string())
        .filter(|value| !value.is_empty())
        .collect()
}

fn parse_sql_schema(sql: &str) -> Result<DatabaseSchema, DbSchemaError> {
    let mut columns = Vec::new();
    let mut indexes = Vec::new();

    for statement in sql.split(';') {
        let stmt = statement.trim();
        if stmt.is_empty() {
            continue;
        }
        let lower = stmt.to_ascii_lowercase();
        if lower.starts_with("create table") {
            let (_table, table_columns) = parse_create_table(stmt)?;
            columns.extend(table_columns);
        } else if lower.starts_with("create index") || lower.starts_with("create unique index") {
            if let Some(index) = parse_create_index(stmt)? {
                indexes.push(index);
            }
        }
    }

    let schema = build_schema(columns, indexes);
    Ok(schema)
}

fn parse_create_table(statement: &str) -> Result<(Table, Vec<Column>), DbSchemaError> {
    let open = statement.find('(').ok_or_else(|| DbSchemaError::Parse {
        message: "create table missing '('".to_string(),
    })?;
    let close = statement.rfind(')').ok_or_else(|| DbSchemaError::Parse {
        message: "create table missing ')'".to_string(),
    })?;
    if close <= open {
        return Err(DbSchemaError::Parse {
            message: "create table has invalid column block".to_string(),
        });
    }

    let header = &statement[..open];
    let table_name = parse_table_name(header).ok_or_else(|| DbSchemaError::Parse {
        message: "unable to parse table name".to_string(),
    })?;

    let columns_block = &statement[open + 1..close];
    let mut columns = Vec::new();
    for item in split_sql_items(columns_block) {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("constraint")
            || lower.starts_with("primary")
            || lower.starts_with("unique")
            || lower.starts_with("foreign")
            || lower.starts_with("check")
        {
            continue;
        }

        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.len() < 2 {
            continue;
        }
        let name = normalize_identifier(tokens[0]);
        let (data_type, nullable) = parse_column_type_and_nullability(&tokens[1..]);
        if data_type.is_empty() {
            continue;
        }
        columns.push(Column {
            table: table_name.clone(),
            name,
            data_type,
            nullable,
        });
    }

    Ok((Table { name: table_name }, columns))
}

fn parse_column_type_and_nullability(tokens: &[&str]) -> (String, bool) {
    let mut data_parts = Vec::new();
    let mut nullable = true;
    let mut i = 0;
    while i < tokens.len() {
        let token_lower = tokens[i].to_ascii_lowercase();
        if token_lower == "not"
            && tokens
                .get(i + 1)
                .map_or(false, |next| next.eq_ignore_ascii_case("null"))
        {
            nullable = false;
            break;
        }
        if matches!(
            token_lower.as_str(),
            "null" | "default" | "primary" | "unique" | "references" | "check"
        ) {
            break;
        }
        data_parts.push(tokens[i]);
        i += 1;
    }
    (data_parts.join(" "), nullable)
}

fn parse_create_index(statement: &str) -> Result<Option<Index>, DbSchemaError> {
    let lower = statement.to_ascii_lowercase();
    let unique = lower.starts_with("create unique index");
    let open = match statement.find('(') {
        Some(value) => value,
        None => return Ok(None),
    };
    let close = match statement.rfind(')') {
        Some(value) => value,
        None => return Ok(None),
    };
    let header = &statement[..open];
    let columns_block = &statement[open + 1..close];

    let tokens: Vec<&str> = header.split_whitespace().collect();
    let mut index_name = None;
    let mut table_name = None;
    for (idx, token) in tokens.iter().enumerate() {
        if token.eq_ignore_ascii_case("index") {
            index_name = tokens.get(idx + 1).map(|value| normalize_identifier(value));
        }
        if token.eq_ignore_ascii_case("on") {
            table_name = tokens.get(idx + 1).map(|value| normalize_identifier(value));
        }
    }
    let index_name = match index_name {
        Some(value) => value,
        None => return Ok(None),
    };
    let table_name = match table_name {
        Some(value) => value,
        None => return Ok(None),
    };

    let columns = split_sql_items(columns_block)
        .into_iter()
        .map(|value| normalize_identifier(&value))
        .filter(|value| !value.is_empty())
        .collect();

    Ok(Some(Index {
        table: table_name,
        name: index_name,
        columns,
        unique,
    }))
}

fn parse_table_name(header: &str) -> Option<String> {
    let tokens: Vec<&str> = header.split_whitespace().collect();
    let mut last = None;
    let mut seen_table = false;
    for token in tokens {
        if token.eq_ignore_ascii_case("table") {
            seen_table = true;
            continue;
        }
        if !seen_table {
            continue;
        }
        if token.eq_ignore_ascii_case("if")
            || token.eq_ignore_ascii_case("not")
            || token.eq_ignore_ascii_case("exists")
        {
            continue;
        }
        last = Some(token);
    }
    last.map(normalize_identifier)
}

fn normalize_identifier(value: &str) -> String {
    let trimmed = value.trim_matches('"').trim_matches('`');
    trimmed.split('.').last().unwrap_or(trimmed).to_string()
}

fn split_sql_items(input: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut depth = 0u32;
    for ch in input.chars() {
        match ch {
            '(' => {
                depth += 1;
                current.push(ch);
            }
            ')' => {
                if depth > 0 {
                    depth -= 1;
                }
                current.push(ch);
            }
            ',' if depth == 0 => {
                items.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        items.push(current.trim().to_string());
    }
    items
}

fn build_schema(columns: Vec<Column>, indexes: Vec<Index>) -> DatabaseSchema {
    let mut tables_set: HashSet<String> = HashSet::new();
    for column in &columns {
        tables_set.insert(column.table.clone());
    }
    for index in &indexes {
        tables_set.insert(index.table.clone());
    }
    let mut tables: Vec<Table> = tables_set.into_iter().map(|name| Table { name }).collect();
    tables.sort_by(|a, b| a.name.cmp(&b.name));

    let mut columns_sorted = columns;
    columns_sorted.sort_by(|a, b| a.table.cmp(&b.table).then_with(|| a.name.cmp(&b.name)));

    let mut indexes_sorted = indexes;
    indexes_sorted.sort_by(|a, b| a.table.cmp(&b.table).then_with(|| a.name.cmp(&b.name)));

    DatabaseSchema {
        tables,
        columns: columns_sorted,
        indexes: indexes_sorted,
    }
}

fn collect_table_names(schema: &DatabaseSchema) -> HashSet<String> {
    let mut tables: HashSet<String> = schema
        .tables
        .iter()
        .map(|table| table.name.clone())
        .collect();
    for column in &schema.columns {
        tables.insert(column.table.clone());
    }
    for index in &schema.indexes {
        tables.insert(index.table.clone());
    }
    tables
}

fn group_columns_by_table(columns: &[Column]) -> HashMap<String, HashMap<String, Column>> {
    let mut map: HashMap<String, HashMap<String, Column>> = HashMap::new();
    for column in columns {
        map.entry(column.table.clone())
            .or_default()
            .insert(column.name.clone(), column.clone());
    }
    map
}

fn group_columns_by_type(columns: &[Column]) -> HashMap<String, Vec<Column>> {
    let mut map: HashMap<String, Vec<Column>> = HashMap::new();
    for column in columns {
        map.entry(column.data_type.clone())
            .or_default()
            .push(column.clone());
    }
    map
}

fn index_map(indexes: &[Index]) -> HashMap<(String, String), Index> {
    let mut map = HashMap::new();
    for index in indexes {
        map.insert((index.table.clone(), index.name.clone()), index.clone());
    }
    map
}

fn sort_schema_objects(objects: &mut [SchemaObject]) {
    objects.sort_by(|a, b| schema_object_key(a).cmp(&schema_object_key(b)));
}

fn schema_object_key(object: &SchemaObject) -> (u8, String, String) {
    match object {
        SchemaObject::Table(table) => (0, table.name.clone(), String::new()),
        SchemaObject::Column(column) => (1, column.table.clone(), column.name.clone()),
        SchemaObject::Index(index) => (2, index.table.clone(), index.name.clone()),
    }
}

fn sort_schema_changes(changes: &mut [SchemaChange]) {
    changes.sort_by(|a, b| schema_change_key(a).cmp(&schema_change_key(b)));
}

fn schema_change_key(change: &SchemaChange) -> (String, String) {
    match change {
        SchemaChange::ColumnRename { table, from, .. } => (table.clone(), from.clone()),
        SchemaChange::ColumnTypeChange { table, column, .. } => (table.clone(), column.clone()),
    }
}

fn calculate_risk_level(
    added: &[SchemaObject],
    removed: &[SchemaObject],
    modified: &[SchemaChange],
) -> RiskLevel {
    let mut risk = RiskLevel::Low;

    for obj in added {
        risk = risk.max(risk_for_added_object(obj));
    }
    for obj in removed {
        risk = risk.max(risk_for_removed_object(obj));
    }
    for change in modified {
        risk = risk.max(risk_for_change(change));
    }

    risk
}

fn risk_for_added_object(obj: &SchemaObject) -> RiskLevel {
    match obj {
        SchemaObject::Table(_) | SchemaObject::Column(_) | SchemaObject::Index(_) => RiskLevel::Low,
    }
}

fn risk_for_removed_object(obj: &SchemaObject) -> RiskLevel {
    match obj {
        SchemaObject::Table(_) | SchemaObject::Column(_) => RiskLevel::High,
        SchemaObject::Index(_) => RiskLevel::Medium,
    }
}

fn risk_for_change(change: &SchemaChange) -> RiskLevel {
    match change {
        SchemaChange::ColumnRename { .. } => RiskLevel::Medium,
        SchemaChange::ColumnTypeChange { .. } => RiskLevel::High,
    }
}

fn describe_schema_object(object: &SchemaObject) -> String {
    match object {
        SchemaObject::Table(table) => format!("table {}", table.name),
        SchemaObject::Column(column) => {
            format!("column {}.{}", column.table, column.name)
        }
        SchemaObject::Index(index) => format!("index {}.{}", index.table, index.name),
    }
}

fn describe_schema_change(change: &SchemaChange) -> String {
    match change {
        SchemaChange::ColumnRename { table, from, to } => {
            format!("rename column {table}.{from} to {to}")
        }
        SchemaChange::ColumnTypeChange {
            table,
            column,
            from,
            to,
        } => format!("change type {table}.{column} from {from} to {to}"),
    }
}

fn validate_db_connection_config(config: &DbConnectionConfig) -> Result<(), DbSchemaError> {
    if config.port == 0 {
        return Err(DbSchemaError::InvalidConfig {
            message: "db port is invalid".to_string(),
        });
    }
    validate_db_host(&config.host)?;
    validate_db_identifier("db user", &config.user)?;
    validate_db_identifier("database", &config.database)?;
    Ok(())
}

fn validate_db_host(host: &str) -> Result<(), DbSchemaError> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Err(DbSchemaError::InvalidConfig {
            message: "db host is empty".to_string(),
        });
    }
    if trimmed
        .chars()
        .any(|ch| !(ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_')))
    {
        return Err(DbSchemaError::InvalidConfig {
            message: "db host contains invalid characters".to_string(),
        });
    }
    Ok(())
}

fn validate_db_identifier(label: &str, value: &str) -> Result<(), DbSchemaError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(DbSchemaError::InvalidConfig {
            message: format!("{label} is empty"),
        });
    }
    if trimmed
        .chars()
        .any(|ch| !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_')))
    {
        return Err(DbSchemaError::InvalidConfig {
            message: format!("{label} contains invalid characters"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn create_temp_dir(prefix: &str) -> PathBuf {
        let mut base = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir_name = format!("agus_observer_{prefix}_{}_{}", std::process::id(), nanos);
        base.push(dir_name);
        fs::create_dir_all(&base).unwrap();
        base
    }

    fn write_file(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    #[test]
    fn parse_uname_a_linux_output() {
        let output = "Linux ip-10-0-0-1 5.15.0-52-generic #58-Ubuntu SMP Tue Oct 11 18:00:00 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux";
        let info = parse_uname_a(output).expect("parse uname output");
        assert_eq!(info.os, "Linux");
        assert_eq!(info.kernel, "5.15.0-52-generic");
        assert_eq!(info.cpu_arch, "x86_64");
    }

    #[test]
    fn detects_dockerfile_services() {
        let dir = create_temp_dir("dockerfile");
        let dockerfile_path = dir.join("service-a").join("Dockerfile");
        write_file(&dockerfile_path, "FROM alpine:3.18\n");

        let graph = scan_repo_basic(&dir).expect("scan repo");

        assert!(graph.nodes.iter().any(|service| {
            service.name == "service-a" && service.kind == ServiceKind::Dockerfile
        }));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parses_compose_services_and_ports() {
        let contents = r#"
services:
  api:
    ports:
      - "8080:80"
      - "443"
  db:
    image: postgres:15
"#;
        let services = parse_compose_services(contents).expect("parse compose");
        let api = services.get("api").expect("api service");
        assert_eq!(api.ports, vec![80, 443]);
    }

    #[test]
    fn builds_dependency_edges_from_compose() {
        let dir = create_temp_dir("compose");
        let compose_path = dir.join("docker-compose.yml");
        let contents = r#"
services:
  api:
    ports:
      - "8080:80"
    depends_on:
      - db
      - cache
  db:
    ports:
      - "5432:5432"
  cache:
    image: redis:7
"#;
        write_file(&compose_path, contents);

        let graph = scan_repo_basic(&dir).expect("scan repo");

        assert!(graph
            .edges
            .iter()
            .any(|edge| edge.from == "api" && edge.to == "db"));
        assert!(!graph
            .edges
            .iter()
            .any(|edge| edge.from == "api" && edge.to == "cache"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_cycles_in_dependency_graph() {
        let dir = create_temp_dir("cycle");
        let compose_path = dir.join("docker-compose.yml");
        let contents = r#"
services:
  api:
    ports:
      - "8080:80"
    depends_on:
      - worker
  worker:
    ports:
      - "9090:90"
    depends_on:
      - api
"#;
        write_file(&compose_path, contents);

        let result = scan_repo_basic(&dir);
        assert!(matches!(result, Err(RepoScanError::CycleDetected { .. })));

        fs::remove_dir_all(&dir).ok();
    }

    fn schema_with_columns(table: &str, columns: &[(&str, &str)]) -> DatabaseSchema {
        let mut schema = DatabaseSchema::default();
        schema.tables.push(Table {
            name: table.to_string(),
        });
        for (name, data_type) in columns {
            schema.columns.push(Column {
                table: table.to_string(),
                name: (*name).to_string(),
                data_type: (*data_type).to_string(),
                nullable: true,
            });
        }
        schema
    }

    #[test]
    fn detects_column_rename() {
        let current = schema_with_columns("users", &[("name", "text")]);
        let desired = schema_with_columns("users", &[("full_name", "text")]);

        let diff = diff_db_schema(&current, &desired);
        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert!(diff.modified.iter().any(|change| matches!(
            change,
            SchemaChange::ColumnRename {
                table,
                from,
                to
            } if table == "users" && from == "name" && to == "full_name"
        )));
    }

    #[test]
    fn detects_column_type_change() {
        let current = schema_with_columns("users", &[("age", "integer")]);
        let desired = schema_with_columns("users", &[("age", "bigint")]);

        let diff = diff_db_schema(&current, &desired);
        assert!(diff.modified.iter().any(|change| matches!(
            change,
            SchemaChange::ColumnTypeChange {
                table,
                column,
                from,
                to
            } if table == "users" && column == "age" && from == "integer" && to == "bigint"
        )));
    }

    #[test]
    fn assigns_risk_levels_deterministically() {
        let current = schema_with_columns("users", &[("name", "text")]);
        let desired_add = schema_with_columns("users", &[("name", "text"), ("email", "text")]);
        let add_diff = diff_db_schema(&current, &desired_add);
        assert!(matches!(add_diff.risk_level, RiskLevel::Low));

        let desired_rename = schema_with_columns("users", &[("full_name", "text")]);
        let rename_diff = diff_db_schema(&current, &desired_rename);
        assert!(matches!(rename_diff.risk_level, RiskLevel::Medium));

        let desired_drop = DatabaseSchema::default();
        let drop_diff = diff_db_schema(&current, &desired_drop);
        assert!(matches!(drop_diff.risk_level, RiskLevel::High));
    }
}
