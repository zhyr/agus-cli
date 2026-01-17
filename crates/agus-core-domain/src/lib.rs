use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerScanReport {
    pub hostname: String,
    pub os: String,
    pub kernel: String,
    pub cpu_arch: String,
    pub platform: String,
    pub timezone: String,
    pub system_time: String,
    pub cpu_info: String,
    pub gpu_info: Option<String>,
    pub docker_version: Option<String>,
    pub compose_version: Option<String>,
    pub k8s_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceKind {
    Dockerfile,
    ComposeService,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    pub name: String,
    pub kind: ServiceKind,
    pub exposed_ports: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServiceDependencyEdge {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceDependencyGraph {
    pub nodes: Vec<Service>,
    pub edges: Vec<ServiceDependencyEdge>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Environment {
    Dev,
    Test,
    Staging,
    Prod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Viewer,
    Operator,
    Approver,
    Admin,
}

impl Role {
    pub fn can_execute(self) -> bool {
        matches!(self, Role::Operator | Role::Admin)
    }

    pub fn can_approve(self) -> bool {
        matches!(self, Role::Approver | Role::Admin)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    pub id: String,
    pub address: String,
    pub environment: Environment,
    pub labels: Vec<String>,
    #[serde(default = "default_ssh_user")]
    pub user: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub identity_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub group_id: Option<String>,
}

fn default_ssh_user() -> String {
    "root".to_string()
}

fn default_ssh_port() -> u16 {
    22
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DatabaseType {
    Postgres,
    MySQL,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbConnectionConfig {
    pub db_type: DatabaseType,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub database: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Table {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Column {
    pub table: String,
    pub name: String,
    pub data_type: String,
    pub nullable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Index {
    pub table: String,
    pub name: String,
    pub columns: Vec<String>,
    pub unique: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DatabaseSchema {
    pub tables: Vec<Table>,
    pub columns: Vec<Column>,
    pub indexes: Vec<Index>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SchemaObject {
    Table(Table),
    Column(Column),
    Index(Index),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SchemaChange {
    ColumnRename {
        table: String,
        from: String,
        to: String,
    },
    ColumnTypeChange {
        table: String,
        column: String,
        from: String,
        to: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaDiff {
    pub added: Vec<SchemaObject>,
    pub removed: Vec<SchemaObject>,
    pub modified: Vec<SchemaChange>,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NginxLocation {
    pub path: String,
    pub proxy_pass: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NginxProjectConfig {
    pub project: String,
    pub server_name: String,
    pub listen: u16,
    pub locations: Vec<NginxLocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssl_domain: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SslProjectConfig {
    pub project: String,
    pub domain: String,
    pub email: String,
    pub webroot: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeploymentAction {
    DeployService,
    VerifyService,
    RunSshCommand { command: String },
    DockerPs,
    DockerInspect { target: String },
    DockerLogs { container: String, tail: u32 },
    ComposeUp { project_dir: String },
    ComposeDown { project_dir: String },
    NginxApply { project: String },
    NginxRollback { project: String },
    SslIssue { project: String },
    SslRenew { project: String },
    SslRollback { project: String },
    DbMigrate { plan_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentStep {
    pub id: String,
    pub service_name: String,
    pub action: DeploymentAction,
    pub depends_on: Vec<String>,
    pub approval_required: bool,
    pub memo: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentPlan {
    pub steps: Vec<DeploymentStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostContext {
    pub host: String,
    pub user: String,
    pub port: u16,
    pub environment: Environment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionStatus {
    Pending,
    Running,
    WaitingApproval,
    Succeeded,
    Failed,
    Skipped,
    RolledBack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalDecision {
    Approved,
    Rejected,
}

pub fn render_nginx_config(config: &NginxProjectConfig) -> String {
    let mut output = String::new();
    output.push_str("server {\n");
    if config.ssl_domain.is_some() && config.listen == 443 {
        output.push_str("    listen 443 ssl;\n");
    } else {
        output.push_str(&format!("    listen {};\n", config.listen));
        if config.ssl_domain.is_some() {
            output.push_str("    listen 443 ssl;\n");
        }
    }
    output.push_str(&format!("    server_name {};\n", config.server_name));
    if let Some(domain) = &config.ssl_domain {
        output.push_str(&format!(
            "    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;\n"
        ));
        output.push_str(&format!(
            "    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;\n"
        ));
    }
    for location in &config.locations {
        output.push_str(&format!("    location {} {{\n", location.path));
        output.push_str(&format!("        proxy_pass {};\n", location.proxy_pass));
        output.push_str("    }\n");
    }
    output.push_str("}\n");
    output
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRecord {
    pub step_id: String,
    pub status: ExecutionStatus,
    pub started_at: Option<u64>,
    pub finished_at: Option<u64>,
    pub logs: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsEvent {
    pub id: String,
    pub execution_id: String,
    pub step_id: String,
    pub service_name: String,
    pub action: Option<DeploymentAction>,
    pub status: ExecutionStatus,
    pub recorded_at: u64,
    pub started_at: Option<u64>,
    pub finished_at: Option<u64>,
    pub logs: Vec<String>,
    pub error: Option<String>,
    pub host_id: String,
    pub host_address: String,
    pub environment: Environment,
    pub project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpsKnowledgeOutcome {
    Observed,
    Succeeded,
    Failed,
    RolledBack,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsKnowledgeEntry {
    pub id: String,
    pub recorded_at: u64,
    pub diff: SchemaDiff,
    pub outcome: OpsKnowledgeOutcome,
    pub rollback_reason: Option<String>,
    pub execution_id: Option<String>,
    pub project: Option<String>,
    pub host_id: String,
    pub host_address: String,
    pub environment: Environment,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpsKnowledgeMatch {
    pub entry: OpsKnowledgeEntry,
    pub similarity: f32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsMemoryCount {
    pub key: String,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsMemorySummary {
    pub total_events: usize,
    pub status_counts: Vec<OpsMemoryCount>,
    pub approval_waiting: usize,
    pub approval_rejected: usize,
    pub rollback_count: usize,
    pub failure_reasons: Vec<OpsMemoryCount>,
    pub failing_projects: Vec<OpsMemoryCount>,
    pub diff_outcomes: Vec<OpsMemoryCount>,
    pub window_start: Option<u64>,
    pub window_end: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsMemoryInsight {
    pub summary: OpsMemorySummary,
    pub narrative: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlanValidationError {
    MissingDependency {
        step_id: String,
        dependency_id: String,
    },
    CycleDetected {
        message: String,
    },
}

impl std::fmt::Display for PlanValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanValidationError::MissingDependency {
                step_id,
                dependency_id,
            } => write!(f, "step {step_id} depends on missing step {dependency_id}"),
            PlanValidationError::CycleDetected { message } => {
                write!(f, "cycle detected: {message}")
            }
        }
    }
}

impl std::error::Error for PlanValidationError {}

impl DeploymentPlan {
    pub fn validate(&self) -> Result<(), PlanValidationError> {
        let mut step_ids: HashSet<String> = HashSet::new();
        for step in &self.steps {
            step_ids.insert(step.id.clone());
        }

        for step in &self.steps {
            for dependency in &step.depends_on {
                if !step_ids.contains(dependency) {
                    return Err(PlanValidationError::MissingDependency {
                        step_id: step.id.clone(),
                        dependency_id: dependency.clone(),
                    });
                }
            }
        }

        let mut indegree: HashMap<&str, usize> = HashMap::new();
        let mut adjacency: HashMap<&str, Vec<&str>> = HashMap::new();
        for step in &self.steps {
            indegree.insert(step.id.as_str(), 0);
            adjacency.insert(step.id.as_str(), Vec::new());
        }

        for step in &self.steps {
            for dependency in &step.depends_on {
                if let (Some(neighbors), Some(degree)) = (
                    adjacency.get_mut(dependency.as_str()),
                    indegree.get_mut(step.id.as_str()),
                ) {
                    neighbors.push(step.id.as_str());
                    *degree += 1;
                }
            }
        }

        let mut queue = VecDeque::new();
        for (id, degree) in &indegree {
            if *degree == 0 {
                queue.push_back(*id);
            }
        }

        let mut visited = 0usize;
        while let Some(id) = queue.pop_front() {
            visited += 1;
            if let Some(neighbors) = adjacency.get(id) {
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
                .filter_map(|(id, degree)| if *degree > 0 { Some(*id) } else { None })
                .collect();
            let message = if cycle_nodes.is_empty() {
                "cycle detected in deployment plan".to_string()
            } else {
                format!("cycle detected among steps: {}", cycle_nodes.join(", "))
            };
            return Err(PlanValidationError::CycleDetected { message });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_validation_rejects_missing_dependency() {
        let plan = DeploymentPlan {
            steps: vec![DeploymentStep {
                id: "deploy:api".to_string(),
                service_name: "api".to_string(),
                action: DeploymentAction::DeployService,
                depends_on: vec!["missing".to_string()],
                approval_required: false,
                memo: None,
            }],
        };

        let result = plan.validate();
        assert!(matches!(
            result,
            Err(PlanValidationError::MissingDependency { .. })
        ));
    }

    #[test]
    fn plan_validation_rejects_cycles() {
        let plan = DeploymentPlan {
            steps: vec![
                DeploymentStep {
                    id: "deploy:api".to_string(),
                    service_name: "api".to_string(),
                    action: DeploymentAction::DeployService,
                    depends_on: vec!["deploy:worker".to_string()],
                    approval_required: false,
                    memo: None,
                },
                DeploymentStep {
                    id: "deploy:worker".to_string(),
                    service_name: "worker".to_string(),
                    action: DeploymentAction::DeployService,
                    depends_on: vec!["deploy:api".to_string()],
                    approval_required: false,
                    memo: None,
                },
            ],
        };

        let result = plan.validate();
        assert!(matches!(
            result,
            Err(PlanValidationError::CycleDetected { .. })
        ));
    }

    #[test]
    fn renders_nginx_config_deterministically() {
        let config = NginxProjectConfig {
            project: "demo".to_string(),
            server_name: "example.com".to_string(),
            listen: 80,
            locations: vec![
                NginxLocation {
                    path: "/".to_string(),
                    proxy_pass: "http://localhost:3000".to_string(),
                },
                NginxLocation {
                    path: "/api".to_string(),
                    proxy_pass: "http://localhost:4000".to_string(),
                },
            ],
            ssl_domain: None,
        };

        let rendered = render_nginx_config(&config);
        let expected = concat!(
            "server {\n",
            "    listen 80;\n",
            "    server_name example.com;\n",
            "    location / {\n",
            "        proxy_pass http://localhost:3000;\n",
            "    }\n",
            "    location /api {\n",
            "        proxy_pass http://localhost:4000;\n",
            "    }\n",
            "}\n"
        );
        assert_eq!(rendered, expected);
    }

    #[test]
    fn renders_nginx_config_with_ssl() {
        let config = NginxProjectConfig {
            project: "demo".to_string(),
            server_name: "example.com".to_string(),
            listen: 80,
            locations: vec![NginxLocation {
                path: "/".to_string(),
                proxy_pass: "http://localhost:3000".to_string(),
            }],
            ssl_domain: Some("example.com".to_string()),
        };

        let rendered = render_nginx_config(&config);
        let expected = concat!(
            "server {\n",
            "    listen 80;\n",
            "    listen 443 ssl;\n",
            "    server_name example.com;\n",
            "    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;\n",
            "    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;\n",
            "    location / {\n",
            "        proxy_pass http://localhost:3000;\n",
            "    }\n",
            "}\n"
        );
        assert_eq!(rendered, expected);
    }
}
