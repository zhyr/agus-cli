use agus_core_domain::ServiceDependencyGraph;
use futures_util::Stream;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LlmProviderType {
    OpenAI,
    Claude,
    Ollama,
    Gemini,
    OpenRouter,
    AlibabaQwen,
    DeepSeek,
    Zhipu,
}

#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub provider: LlmProviderType,
    pub api_key: String,
    pub model: String,
    pub base_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAnalysis {
    pub performance_notes: Vec<String>,
    pub security_concerns: Vec<String>,
    pub deployment_order_suggestions: Vec<String>,
    pub resource_requirements: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub risk_level: String,
    pub concerns: Vec<String>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDiagnosis {
    pub error_type: String,
    pub root_cause: String,
    pub severity: String, // "Low", "Medium", "High", "Critical"
    pub possible_causes: Vec<String>,
    pub suggested_fixes: Vec<String>,
    pub prevention_tips: Vec<String>,
    #[serde(default)]
    pub fix_commands: Vec<String>,
    #[serde(default)]
    pub verification_steps: Vec<String>,
    #[serde(default)]
    pub rollback_steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceEvaluation {
    pub service_name: String,
    pub overall_score: f64, // 0.0 - 100.0
    pub cpu_usage_analysis: String,
    pub memory_usage_analysis: String,
    pub network_analysis: String,
    pub bottlenecks: Vec<String>,
    pub optimization_suggestions: Vec<String>,
    pub scalability_assessment: String,
    pub resource_recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyAnalysis {
    pub service_name: String,
    pub dependencies: Vec<DependencyInfo>,
    pub dependents: Vec<String>,
    pub critical_path: Vec<String>,
    pub circular_risk: bool,
    pub deployment_order: Vec<String>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyInfo {
    pub service_name: String,
    pub dependency_type: String, // "required", "optional", "weak"
    pub impact_level: String,    // "critical", "high", "medium", "low"
    pub description: String,
}

// P0-2: 部署计划制定相关数据结构

/// 部署计划上下文，包含生成部署计划所需的所有信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentPlanContext {
    pub project_name: String,
    pub project_id: String,
    pub host_id: String,
    pub host_address: String,
    pub environment: String, // "dev", "test", "staging", "prod"
    pub local_repo_path: String,
    pub remote_repo_path: String,
    pub sync_status: String,
    pub code_consistency_status: String,
    pub last_sync_time: String,
    pub dependency_graph: ServiceDependencyGraph,
    pub remote_state: RemoteEnvironmentState,
}

/// 远程环境状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteEnvironmentState {
    pub docker_version: String,
    pub compose_version: String,
    pub running_containers_count: usize,
    pub available_images_count: usize,
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
}

/// LLM 返回的部署计划响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMDeploymentPlanResponse {
    pub deployment_plan: DeploymentPlanDraft,
    pub risk_assessment: RiskAssessment,
    pub dry_run_analysis: DryRunAnalysis,
    pub validation_checklist: Vec<String>,
}

/// 部署计划草案
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentPlanDraft {
    pub steps: Vec<DeploymentStepDraft>,
    pub total_estimated_duration: String,
}

/// 部署步骤草案
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentStepDraft {
    pub id: String,
    pub service_name: String,
    pub action: String, // "deploy", "verify", "rollback"
    pub description: String,
    pub command: String,
    pub depends_on: Vec<String>,
    pub estimated_duration: String,
    pub rollback_command: Option<String>,
}

/// 推演分析结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DryRunAnalysis {
    pub simulated_steps: Vec<String>,
    pub potential_issues: Vec<String>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum LlmError {
    ApiError { message: String },
    NetworkError { message: String },
    ParseError { message: String },
    ConfigError { message: String },
}

impl fmt::Display for LlmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LlmError::ApiError { message } => write!(f, "LLM API error: {}", message),
            LlmError::NetworkError { message } => write!(f, "Network error: {}", message),
            LlmError::ParseError { message } => write!(f, "Parse error: {}", message),
            LlmError::ConfigError { message } => write!(f, "Config error: {}", message),
        }
    }
}

impl Error for LlmError {}

static LLM_RUNTIME: OnceLock<Result<tokio::runtime::Runtime, LlmError>> = OnceLock::new();

fn llm_runtime() -> Result<&'static tokio::runtime::Runtime, LlmError> {
    let result = LLM_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| LlmError::ConfigError {
                message: format!("Failed to create tokio runtime: {}", e),
            })
    });
    match result {
        Ok(runtime) => Ok(runtime),
        Err(err) => Err(err.clone()),
    }
}

fn run_async<F, T>(future: F) -> Result<T, LlmError>
where
    F: Future<Output = Result<T, LlmError>>,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        tokio::task::block_in_place(|| handle.block_on(future))
    } else {
        llm_runtime()?.block_on(future)
    }
}

pub trait LlmProvider: Send + Sync {
    fn analyze_services(&self, graph: &ServiceDependencyGraph)
        -> Result<ServiceAnalysis, LlmError>;

    fn generate_memo(&self, service_name: &str, action: &str) -> Result<String, LlmError>;

    fn assess_risk(&self, service_name: &str, action: &str) -> Result<RiskAssessment, LlmError>;

    fn diagnose_error(
        &self,
        error_message: &str,
        error_logs: &[String],
        context: Option<&str>,
    ) -> Result<ErrorDiagnosis, LlmError>;

    fn evaluate_performance(
        &self,
        service_name: &str,
        metrics: &PerformanceMetrics,
    ) -> Result<PerformanceEvaluation, LlmError>;

    fn analyze_dependencies(
        &self,
        service_name: &str,
        graph: &ServiceDependencyGraph,
    ) -> Result<DependencyAnalysis, LlmError>;

    fn complete_prompt(&self, prompt: &str) -> Result<String, LlmError> {
        let _ = prompt;
        Err(LlmError::ConfigError {
            message: "LLM provider does not support prompt completion".to_string(),
        })
    }

    /// Stream a response from the LLM for a given prompt.
    /// Returns a stream of text chunks. Default implementation returns an empty stream.
    /// Providers should implement this for streaming support.
    fn stream_response(
        &self,
        _prompt: &str,
    ) -> Pin<Box<dyn Stream<Item = Result<String, LlmError>> + Send + '_>> {
        Box::pin(futures_util::stream::empty())
    }

    /// Generate deployment plan based on scan results and context
    /// P0-2: 部署计划制定 - LLM 调用
    fn generate_deployment_plan(
        &self,
        context: &DeploymentPlanContext,
    ) -> Result<LLMDeploymentPlanResponse, LlmError> {
        // Default implementation uses complete_prompt
        // Note: build_deployment_plan_prompt and parse_llm_plan_response are defined later in this file
        let prompt = crate::llm::build_deployment_plan_prompt(context)?;
        let response = self.complete_prompt(&prompt)?;
        crate::llm::parse_llm_plan_response(&response)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub cpu_usage_percent: Option<f64>,
    pub memory_usage_mb: Option<f64>,
    pub memory_limit_mb: Option<f64>,
    pub network_rx_bytes: Option<u64>,
    pub network_tx_bytes: Option<u64>,
    pub request_count: Option<u64>,
    pub error_rate: Option<f64>,
    pub response_time_ms: Option<f64>,
}

pub struct OpenAILlmProvider {
    config: LlmConfig,
    client: reqwest::Client,
}

impl OpenAILlmProvider {
    pub fn new(config: LlmConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    #[allow(dead_code)]
    async fn call_api(&self, prompt: &str) -> Result<String, LlmError> {
        self.call_api_with_retry(prompt, 3).await
    }

    async fn call_api_with_retry(
        &self,
        prompt: &str,
        max_retries: u32,
    ) -> Result<String, LlmError> {
        let url = "https://api.openai.com/v1/chat/completions";
        let body = serde_json::json!({
            "model": self.config.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are an expert DevOps engineer helping with deployment planning."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.7,
            "max_tokens": 1000
        });

        let mut last_error = None;

        for attempt in 0..max_retries {
            let request = self
                .client
                .post(url)
                .header("Authorization", format!("Bearer {}", self.config.api_key))
                .header("Content-Type", "application/json")
                .json(&body)
                .timeout(std::time::Duration::from_secs(30)); // 30秒超时

            match request.send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        match response.json::<serde_json::Value>().await {
                            Ok(json) => {
                                if let Some(content) =
                                    json["choices"][0]["message"]["content"].as_str()
                                {
                                    return Ok(content.to_string());
                                } else {
                                    last_error = Some(LlmError::ParseError {
                                        message: "Invalid response format".to_string(),
                                    });
                                }
                            }
                            Err(e) => {
                                last_error = Some(LlmError::ParseError {
                                    message: e.to_string(),
                                });
                            }
                        }
                    } else {
                        let status = response.status();
                        // 对于 4xx 错误（客户端错误），不重试
                        if status.is_client_error() {
                            return Err(LlmError::ApiError {
                                message: format!(
                                    "API returned status: {} (client error, not retrying)",
                                    status
                                ),
                            });
                        }
                        // 对于 5xx 错误（服务器错误），重试
                        last_error = Some(LlmError::ApiError {
                            message: format!(
                                "API returned status: {} (attempt {}/{})",
                                status,
                                attempt + 1,
                                max_retries
                            ),
                        });
                    }
                }
                Err(e) => {
                    // 网络错误，重试
                    last_error = Some(LlmError::NetworkError {
                        message: format!(
                            "Network error (attempt {}/{}): {}",
                            attempt + 1,
                            max_retries,
                            e
                        ),
                    });
                }
            }

            // 如果不是最后一次尝试，等待后重试
            if attempt < max_retries - 1 {
                let delay = std::time::Duration::from_millis(500 * (attempt + 1) as u64); // 指数退避：500ms, 1000ms, 1500ms
                tokio::time::sleep(delay).await;
            }
        }

        Err(last_error.unwrap())
    }
}

impl LlmProvider for OpenAILlmProvider {
    fn analyze_services(
        &self,
        graph: &ServiceDependencyGraph,
    ) -> Result<ServiceAnalysis, LlmError> {
        if self.config.api_key.is_empty() {
            return Ok(ServiceAnalysis {
                performance_notes: vec!["LLM analysis requires API key configuration".to_string()],
                security_concerns: vec![],
                deployment_order_suggestions: vec![],
                resource_requirements: vec![],
            });
        }

        let service_names: Vec<String> = graph.nodes.iter().map(|s| s.name.clone()).collect();
        let prompt = format!(
            "Analyze the following microservices for deployment planning:\n\nServices: {}\n\nProvide analysis in JSON format with fields: performance_notes (array of strings), security_concerns (array of strings), deployment_order_suggestions (array of strings), resource_requirements (array of strings).",
            service_names.join(", ")
        );

        let response = run_async(self.call_api(&prompt))?;

        // Try to parse JSON response, fallback to simple text parsing
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response) {
            Ok(ServiceAnalysis {
                performance_notes: json["performance_notes"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default(),
                security_concerns: json["security_concerns"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default(),
                deployment_order_suggestions: json["deployment_order_suggestions"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default(),
                resource_requirements: json["resource_requirements"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default(),
            })
        } else {
            // Fallback: parse simple text response
            Ok(ServiceAnalysis {
                performance_notes: vec![response.clone()],
                security_concerns: vec![],
                deployment_order_suggestions: vec![],
                resource_requirements: vec![],
            })
        }
    }

    fn generate_memo(&self, service_name: &str, action: &str) -> Result<String, LlmError> {
        if self.config.api_key.is_empty() {
            return Ok(format!(
                "Deploy service {} with action {}",
                service_name, action
            ));
        }

        let prompt = format!(
            "Generate a deployment memo for service '{}' with action '{}'. The memo should be concise (2-3 sentences) and explain what this step does and why it's important.",
            service_name, action
        );

        run_async(self.call_api(&prompt))
    }

    fn assess_risk(&self, service_name: &str, action: &str) -> Result<RiskAssessment, LlmError> {
        if self.config.api_key.is_empty() {
            return Ok(RiskAssessment {
                risk_level: "Medium".to_string(),
                concerns: vec!["LLM risk assessment requires API key configuration".to_string()],
                recommendations: vec![],
            });
        }

        let prompt = format!(
            "Assess the risk level for deploying service '{}' with action '{}'. Respond in JSON format with fields: risk_level (one of: Low, Medium, High, Critical), concerns (array of strings), recommendations (array of strings).",
            service_name, action
        );

        let response = run_async(self.call_api(&prompt))?;

        // Try to parse JSON response
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response) {
            Ok(RiskAssessment {
                risk_level: json["risk_level"].as_str().unwrap_or("Medium").to_string(),
                concerns: json["concerns"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default(),
                recommendations: json["recommendations"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default(),
            })
        } else {
            // Fallback: default risk assessment
            Ok(RiskAssessment {
                risk_level: "Medium".to_string(),
                concerns: vec![response],
                recommendations: vec![],
            })
        }
    }

    fn diagnose_error(
        &self,
        error_message: &str,
        error_logs: &[String],
        context: Option<&str>,
    ) -> Result<ErrorDiagnosis, LlmError> {
        if self.config.api_key.is_empty() {
            return Ok(ErrorDiagnosis {
                error_type: "Unknown".to_string(),
                root_cause: "LLM API key not configured".to_string(),
                severity: "Medium".to_string(),
                possible_causes: vec![],
                suggested_fixes: vec![],
                prevention_tips: vec![],
                fix_commands: vec![],
                verification_steps: vec![],
                rollback_steps: vec![],
            });
        }

        let logs_summary = if error_logs.len() > 20 {
            format!(
                "{} logs (showing last 20):\n{}",
                error_logs.len(),
                error_logs
                    .iter()
                    .rev()
                    .take(20)
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        } else {
            error_logs.join("\n")
        };

        let context_str = context.unwrap_or("No additional context provided");

        let prompt = format!(
            r#"You are an expert DevOps engineer diagnosing a deployment error. Analyze the following error and provide a detailed diagnosis.

Error Message: {}
Context: {}
Error Logs:
{}

Please provide a comprehensive diagnosis in JSON format with the following fields:
- error_type: A brief classification of the error (e.g., "Connection Error", "Permission Denied", "Resource Exhaustion")
- root_cause: A detailed explanation of what likely caused this error
- severity: One of "Low", "Medium", "High", or "Critical"
- possible_causes: An array of possible root causes (at least 3 items)
- suggested_fixes: An array of specific, actionable fixes (at least 3 items)
- prevention_tips: An array of tips to prevent this error in the future (at least 2 items)
- fix_commands: An array of concrete shell commands to apply the fix safely (empty if unsafe/unknown)
- verification_steps: An array of steps or commands to verify the fix
- rollback_steps: An array of rollback steps or commands if the fix fails

Respond ONLY with valid JSON, no markdown formatting."#,
            error_message, context_str, logs_summary
        );

        let response = run_async(self.call_api_with_retry(&prompt, 3))?;

        match serde_json::from_str::<ErrorDiagnosis>(&response) {
            Ok(diagnosis) => Ok(diagnosis),
            Err(_) => {
                let json_start = response.find('{');
                let json_end = response.rfind('}');
                if let (Some(start), Some(end)) = (json_start, json_end) {
                    let json_str = &response[start..=end];
                    serde_json::from_str(json_str).map_err(|e| LlmError::ParseError {
                        message: format!("Failed to parse error diagnosis: {}", e),
                    })
                } else {
                    Ok(ErrorDiagnosis {
                        error_type: "Unknown".to_string(),
                        root_cause: "Failed to parse LLM response".to_string(),
                        severity: "Medium".to_string(),
                        possible_causes: vec!["Unable to analyze error".to_string()],
                        suggested_fixes: vec!["Check logs manually".to_string()],
                        prevention_tips: vec![],
                        fix_commands: vec![],
                        verification_steps: vec![],
                        rollback_steps: vec![],
                    })
                }
            }
        }
    }

    fn evaluate_performance(
        &self,
        service_name: &str,
        metrics: &PerformanceMetrics,
    ) -> Result<PerformanceEvaluation, LlmError> {
        if self.config.api_key.is_empty() {
            return Ok(PerformanceEvaluation {
                service_name: service_name.to_string(),
                overall_score: 50.0,
                cpu_usage_analysis: "LLM API key not configured".to_string(),
                memory_usage_analysis: String::new(),
                network_analysis: String::new(),
                bottlenecks: vec![],
                optimization_suggestions: vec![],
                scalability_assessment: String::new(),
                resource_recommendations: vec![],
            });
        }

        let metrics_json = serde_json::to_string(metrics).unwrap_or_default();
        let prompt = format!(
            r#"You are an expert performance engineer analyzing a microservice. Evaluate the performance metrics and provide a comprehensive assessment.

Service Name: {}
Performance Metrics:
{}

Please provide a detailed performance evaluation in JSON format with the following fields:
- overall_score: A number between 0.0 and 100.0 representing overall performance
- cpu_usage_analysis: Analysis of CPU usage patterns
- memory_usage_analysis: Analysis of memory usage patterns
- network_analysis: Analysis of network traffic patterns
- bottlenecks: Array of identified performance bottlenecks
- optimization_suggestions: Array of specific optimization recommendations
- scalability_assessment: Assessment of service scalability
- resource_recommendations: Array of resource allocation recommendations

Respond ONLY with valid JSON, no markdown formatting."#,
            service_name, metrics_json
        );

        let response = run_async(self.call_api_with_retry(&prompt, 3))?;

        match serde_json::from_str::<PerformanceEvaluation>(&response) {
            Ok(evaluation) => Ok(evaluation),
            Err(_) => {
                let json_start = response.find('{');
                let json_end = response.rfind('}');
                if let (Some(start), Some(end)) = (json_start, json_end) {
                    let json_str = &response[start..=end];
                    serde_json::from_str(json_str).map_err(|e| LlmError::ParseError {
                        message: format!("Failed to parse performance evaluation: {}", e),
                    })
                } else {
                    Ok(PerformanceEvaluation {
                        service_name: service_name.to_string(),
                        overall_score: 50.0,
                        cpu_usage_analysis: "Failed to parse LLM response".to_string(),
                        memory_usage_analysis: String::new(),
                        network_analysis: String::new(),
                        bottlenecks: vec![],
                        optimization_suggestions: vec![],
                        scalability_assessment: String::new(),
                        resource_recommendations: vec![],
                    })
                }
            }
        }
    }

    fn analyze_dependencies(
        &self,
        service_name: &str,
        graph: &ServiceDependencyGraph,
    ) -> Result<DependencyAnalysis, LlmError> {
        if self.config.api_key.is_empty() {
            // Fallback: extract dependencies from graph
            let dependencies: Vec<DependencyInfo> = graph
                .edges
                .iter()
                .filter(|e| e.from == service_name)
                .map(|e| DependencyInfo {
                    service_name: e.to.clone(),
                    dependency_type: "required".to_string(),
                    impact_level: "medium".to_string(),
                    description: String::new(),
                })
                .collect();

            let dependents: Vec<String> = graph
                .edges
                .iter()
                .filter(|e| e.to == service_name)
                .map(|e| e.from.clone())
                .collect();

            return Ok(DependencyAnalysis {
                service_name: service_name.to_string(),
                dependencies,
                dependents,
                critical_path: vec![],
                circular_risk: false,
                deployment_order: vec![],
                recommendations: vec![],
            });
        }

        let graph_json = serde_json::to_string(graph).unwrap_or_default();
        let prompt = format!(
            r#"You are an expert DevOps engineer analyzing service dependencies. Analyze the dependency graph and provide a comprehensive dependency analysis.

Service Name: {}
Dependency Graph:
{}

Please provide a detailed dependency analysis in JSON format with the following fields:
- dependencies: Array of objects with fields: service_name, dependency_type ("required"/"optional"/"weak"), impact_level ("critical"/"high"/"medium"/"low"), description
- dependents: Array of service names that depend on this service
- critical_path: Array of service names in the critical deployment path
- circular_risk: Boolean indicating if there's a risk of circular dependencies
- deployment_order: Recommended deployment order for this service and its dependencies
- recommendations: Array of dependency management recommendations

Respond ONLY with valid JSON, no markdown formatting."#,
            service_name, graph_json
        );

        let response = run_async(self.call_api_with_retry(&prompt, 3))?;

        match serde_json::from_str::<DependencyAnalysis>(&response) {
            Ok(analysis) => Ok(analysis),
            Err(_) => {
                let json_start = response.find('{');
                let json_end = response.rfind('}');
                if let (Some(start), Some(end)) = (json_start, json_end) {
                    let json_str = &response[start..=end];
                    serde_json::from_str(json_str).map_err(|e| LlmError::ParseError {
                        message: format!("Failed to parse dependency analysis: {}", e),
                    })
                } else {
                    // Fallback: extract from graph
                    let dependencies: Vec<DependencyInfo> = graph
                        .edges
                        .iter()
                        .filter(|e| e.from == service_name)
                        .map(|e| DependencyInfo {
                            service_name: e.to.clone(),
                            dependency_type: "required".to_string(),
                            impact_level: "medium".to_string(),
                            description: String::new(),
                        })
                        .collect();

                    let dependents: Vec<String> = graph
                        .edges
                        .iter()
                        .filter(|e| e.to == service_name)
                        .map(|e| e.from.clone())
                        .collect();

                    Ok(DependencyAnalysis {
                        service_name: service_name.to_string(),
                        dependencies,
                        dependents,
                        critical_path: vec![],
                        circular_risk: false,
                        deployment_order: vec![],
                        recommendations: vec![],
                    })
                }
            }
        }
    }

    fn complete_prompt(&self, prompt: &str) -> Result<String, LlmError> {
        if self.config.api_key.is_empty() {
            return Err(LlmError::ConfigError {
                message: "LLM API key not configured".to_string(),
            });
        }
        run_async(self.call_api_with_retry(prompt, 3))
    }

    fn stream_response(
        &self,
        prompt: &str,
    ) -> Pin<Box<dyn Stream<Item = Result<String, LlmError>> + Send + '_>> {
        if self.config.api_key.is_empty() {
            return Box::pin(futures_util::stream::empty());
        }

        // Clone necessary data for the async task
        let client = self.client.clone();
        let api_key = self.config.api_key.clone();
        let model = self.config.model.clone();
        let prompt = prompt.to_string();

        // Create a channel to bridge sync and async
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        // Spawn async task to handle streaming
        tokio::spawn(async move {
            let url = "https://api.openai.com/v1/chat/completions";
            let body = serde_json::json!({
                "model": model,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are an expert DevOps engineer helping with deployment planning."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "temperature": 0.7,
                "max_tokens": 1000,
                "stream": true
            });

            let request = client
                .post(url)
                .header("Authorization", format!("Bearer {}", api_key))
                .header("Content-Type", "application/json")
                .json(&body)
                .timeout(std::time::Duration::from_secs(60));

            match request.send().await {
                Ok(response) => {
                    if !response.status().is_success() {
                        let _ = tx.send(Err(LlmError::ApiError {
                            message: format!("API returned status: {}", response.status()),
                        }));
                        return;
                    }

                    let mut stream = response.bytes_stream();
                    let mut buffer = String::new();

                    use futures_util::StreamExt as _;
                    while let Some(item) = stream.next().await {
                        match item {
                            Ok(bytes) => {
                                let text = match String::from_utf8(bytes.to_vec()) {
                                    Ok(t) => t,
                                    Err(e) => {
                                        let _ = tx.send(Err(LlmError::ParseError {
                                            message: format!("Invalid UTF-8: {}", e),
                                        }));
                                        continue;
                                    }
                                };

                                buffer.push_str(&text);

                                // Process complete lines (SSE format: "data: {...}\n\n")
                                while let Some(newline_pos) = buffer.find("\n\n") {
                                    let line = buffer[..newline_pos].trim().to_string();
                                    buffer = buffer[newline_pos + 2..].to_string();

                                    if line.starts_with("data: ") {
                                        let json_str = &line[6..];

                                        // Check for [DONE] marker
                                        if json_str.trim() == "[DONE]" {
                                            return;
                                        }

                                        match serde_json::from_str::<serde_json::Value>(json_str) {
                                            Ok(json) => {
                                                if let Some(choices) =
                                                    json.get("choices").and_then(|c| c.as_array())
                                                {
                                                    if let Some(choice) = choices.first() {
                                                        if let Some(delta) = choice.get("delta") {
                                                            if let Some(content) = delta
                                                                .get("content")
                                                                .and_then(|c| c.as_str())
                                                            {
                                                                if !content.is_empty() {
                                                                    let _ = tx.send(Ok(
                                                                        content.to_string()
                                                                    ));
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            Err(_) => {
                                                // Skip invalid JSON lines (e.g., keep-alive messages)
                                                continue;
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                let _ = tx.send(Err(LlmError::NetworkError {
                                    message: format!("Stream error: {}", e),
                                }));
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(LlmError::NetworkError {
                        message: format!("Network error: {}", e),
                    }));
                }
            }
        });

        // Convert receiver to stream
        Box::pin(tokio_stream::wrappers::UnboundedReceiverStream::new(rx))
    }
}

pub struct OllamaLlmProvider {
    config: LlmConfig,
    client: reqwest::Client,
}

impl OllamaLlmProvider {
    pub fn new(config: LlmConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    async fn call_api(&self, prompt: &str) -> Result<String, LlmError> {
        self.call_api_with_retry(prompt, 3).await
    }

    async fn call_api_with_retry(
        &self,
        prompt: &str,
        max_retries: u32,
    ) -> Result<String, LlmError> {
        let default_url = "http://localhost:11434".to_string();
        let base_url = self.config.base_url.as_ref().unwrap_or(&default_url);
        let url = format!("{}/api/generate", base_url);

        let body = serde_json::json!({
            "model": self.config.model,
            "prompt": prompt,
            "stream": false
        });

        let mut last_error = None;

        for attempt in 0..max_retries {
            let request = self
                .client
                .post(&url)
                .json(&body)
                .timeout(std::time::Duration::from_secs(60)); // 60秒超时（本地模型可能较慢）

            match request.send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        match response.json::<serde_json::Value>().await {
                            Ok(json) => {
                                if let Some(content) = json["response"].as_str() {
                                    return Ok(content.to_string());
                                } else {
                                    last_error = Some(LlmError::ParseError {
                                        message: "Invalid response format".to_string(),
                                    });
                                }
                            }
                            Err(e) => {
                                last_error = Some(LlmError::ParseError {
                                    message: e.to_string(),
                                });
                            }
                        }
                    } else {
                        let status = response.status();
                        // 对于 4xx 错误，不重试
                        if status.is_client_error() {
                            return Err(LlmError::ApiError {
                                message: format!(
                                    "API returned status: {} (client error, not retrying)",
                                    status
                                ),
                            });
                        }
                        last_error = Some(LlmError::ApiError {
                            message: format!(
                                "API returned status: {} (attempt {}/{})",
                                status,
                                attempt + 1,
                                max_retries
                            ),
                        });
                    }
                }
                Err(e) => {
                    last_error = Some(LlmError::NetworkError {
                        message: format!(
                            "Network error (attempt {}/{}): {}",
                            attempt + 1,
                            max_retries,
                            e
                        ),
                    });
                }
            }

            // 如果不是最后一次尝试，等待后重试
            if attempt < max_retries - 1 {
                let delay = std::time::Duration::from_millis(500 * (attempt + 1) as u64);
                tokio::time::sleep(delay).await;
            }
        }

        Err(last_error.unwrap())
    }
}

impl LlmProvider for OllamaLlmProvider {
    fn analyze_services(
        &self,
        graph: &ServiceDependencyGraph,
    ) -> Result<ServiceAnalysis, LlmError> {
        let service_names: Vec<String> = graph.nodes.iter().map(|s| s.name.clone()).collect();
        let prompt = format!(
            "Analyze the following microservices for deployment planning:\n\nServices: {}\n\nProvide analysis in JSON format with fields: performance_notes (array of strings), security_concerns (array of strings), deployment_order_suggestions (array of strings), resource_requirements (array of strings).",
            service_names.join(", ")
        );

        match run_async(self.call_api(&prompt)) {
            Ok(response) => {
                // Try to parse JSON response
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response) {
                    Ok(ServiceAnalysis {
                        performance_notes: json["performance_notes"]
                            .as_array()
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        security_concerns: json["security_concerns"]
                            .as_array()
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        deployment_order_suggestions: json["deployment_order_suggestions"]
                            .as_array()
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        resource_requirements: json["resource_requirements"]
                            .as_array()
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default(),
                    })
                } else {
                    Ok(ServiceAnalysis {
                        performance_notes: vec![response],
                        security_concerns: vec![],
                        deployment_order_suggestions: vec![],
                        resource_requirements: vec![],
                    })
                }
            }
            Err(e) => {
                // If Ollama is not available, return a basic analysis
                Ok(ServiceAnalysis {
                    performance_notes: vec![format!(
                        "Ollama analysis failed: {}. Please ensure Ollama is running locally.",
                        e
                    )],
                    security_concerns: vec![],
                    deployment_order_suggestions: vec![],
                    resource_requirements: vec![],
                })
            }
        }
    }

    fn generate_memo(&self, service_name: &str, action: &str) -> Result<String, LlmError> {
        let prompt = format!(
            "Generate a deployment memo for service '{}' with action '{}'. The memo should be concise (2-3 sentences) and explain what this step does and why it's important.",
            service_name, action
        );

        match run_async(self.call_api(&prompt)) {
            Ok(response) => Ok(response),
            Err(_) => Ok(format!(
                "Deploy service {} with action {}",
                service_name, action
            )),
        }
    }

    fn assess_risk(&self, service_name: &str, action: &str) -> Result<RiskAssessment, LlmError> {
        let prompt = format!(
            "Assess the risk level for deploying service '{}' with action '{}'. Respond in JSON format with fields: risk_level (one of: Low, Medium, High, Critical), concerns (array of strings), recommendations (array of strings).",
            service_name, action
        );

        let response = run_async(self.call_api_with_retry(&prompt, 3))?;

        // Try to parse JSON response
        match serde_json::from_str::<RiskAssessment>(&response) {
            Ok(assessment) => Ok(assessment),
            Err(_) => {
                // Fallback: try to extract JSON from markdown code blocks
                let json_start = response.find('{');
                let json_end = response.rfind('}');
                if let (Some(start), Some(end)) = (json_start, json_end) {
                    let json_str = &response[start..=end];
                    serde_json::from_str(json_str).map_err(|e| LlmError::ParseError {
                        message: format!("Failed to parse risk assessment: {}", e),
                    })
                } else {
                    Ok(RiskAssessment {
                        risk_level: "Medium".to_string(),
                        concerns: vec![],
                        recommendations: vec![],
                    })
                }
            }
        }
    }

    fn diagnose_error(
        &self,
        error_message: &str,
        error_logs: &[String],
        context: Option<&str>,
    ) -> Result<ErrorDiagnosis, LlmError> {
        if self.config.api_key.is_empty() {
            return Ok(ErrorDiagnosis {
                error_type: "Unknown".to_string(),
                root_cause: "LLM API key not configured".to_string(),
                severity: "Medium".to_string(),
                possible_causes: vec![],
                suggested_fixes: vec![],
                prevention_tips: vec![],
                fix_commands: vec![],
                verification_steps: vec![],
                rollback_steps: vec![],
            });
        }

        let logs_summary = if error_logs.len() > 20 {
            format!(
                "{} logs (showing last 20):\n{}",
                error_logs.len(),
                error_logs
                    .iter()
                    .rev()
                    .take(20)
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        } else {
            error_logs.join("\n")
        };

        let context_str = context.unwrap_or("No additional context provided");

        let prompt = format!(
            r#"You are an expert DevOps engineer diagnosing a deployment error. Analyze the following error and provide a detailed diagnosis.

Error Message: {}
Context: {}
Error Logs:
{}

Please provide a comprehensive diagnosis in JSON format with the following fields:
- error_type: A brief classification of the error (e.g., "Connection Error", "Permission Denied", "Resource Exhaustion")
- root_cause: A detailed explanation of what likely caused this error
- severity: One of "Low", "Medium", "High", or "Critical"
- possible_causes: An array of possible root causes (at least 3 items)
- suggested_fixes: An array of specific, actionable fixes (at least 3 items)
- prevention_tips: An array of tips to prevent this error in the future (at least 2 items)
- fix_commands: An array of concrete shell commands to apply the fix safely (empty if unsafe/unknown)
- verification_steps: An array of steps or commands to verify the fix
- rollback_steps: An array of rollback steps or commands if the fix fails

Respond ONLY with valid JSON, no markdown formatting."#,
            error_message, context_str, logs_summary
        );

        let response = run_async(self.call_api_with_retry(&prompt, 3))?;

        // Try to parse JSON response
        match serde_json::from_str::<ErrorDiagnosis>(&response) {
            Ok(diagnosis) => Ok(diagnosis),
            Err(_) => {
                // Fallback: try to extract JSON from markdown code blocks
                let json_start = response.find('{');
                let json_end = response.rfind('}');
                if let (Some(start), Some(end)) = (json_start, json_end) {
                    let json_str = &response[start..=end];
                    serde_json::from_str(json_str).map_err(|e| LlmError::ParseError {
                        message: format!("Failed to parse error diagnosis: {}", e),
                    })
                } else {
                    Ok(ErrorDiagnosis {
                        error_type: "Unknown".to_string(),
                        root_cause: "Failed to parse LLM response".to_string(),
                        severity: "Medium".to_string(),
                        possible_causes: vec!["Unable to analyze error".to_string()],
                        suggested_fixes: vec!["Check logs manually".to_string()],
                        prevention_tips: vec![],
                        fix_commands: vec![],
                        verification_steps: vec![],
                        rollback_steps: vec![],
                    })
                }
            }
        }
    }

    fn evaluate_performance(
        &self,
        service_name: &str,
        metrics: &PerformanceMetrics,
    ) -> Result<PerformanceEvaluation, LlmError> {
        if self.config.api_key.is_empty() {
            return Ok(PerformanceEvaluation {
                service_name: service_name.to_string(),
                overall_score: 50.0,
                cpu_usage_analysis: "LLM API key not configured".to_string(),
                memory_usage_analysis: String::new(),
                network_analysis: String::new(),
                bottlenecks: vec![],
                optimization_suggestions: vec![],
                scalability_assessment: String::new(),
                resource_recommendations: vec![],
            });
        }

        let metrics_json = serde_json::to_string(metrics).unwrap_or_default();
        let prompt = format!(
            r#"You are an expert performance engineer analyzing a microservice. Evaluate the performance metrics and provide a comprehensive assessment.

Service Name: {}
Performance Metrics:
{}

Please provide a detailed performance evaluation in JSON format with the following fields:
- overall_score: A number between 0.0 and 100.0 representing overall performance
- cpu_usage_analysis: Analysis of CPU usage patterns
- memory_usage_analysis: Analysis of memory usage patterns
- network_analysis: Analysis of network traffic patterns
- bottlenecks: Array of identified performance bottlenecks
- optimization_suggestions: Array of specific optimization recommendations
- scalability_assessment: Assessment of service scalability
- resource_recommendations: Array of resource allocation recommendations

Respond ONLY with valid JSON, no markdown formatting."#,
            service_name, metrics_json
        );

        let response = run_async(self.call_api_with_retry(&prompt, 3))?;

        match serde_json::from_str::<PerformanceEvaluation>(&response) {
            Ok(evaluation) => Ok(evaluation),
            Err(_) => {
                let json_start = response.find('{');
                let json_end = response.rfind('}');
                if let (Some(start), Some(end)) = (json_start, json_end) {
                    let json_str = &response[start..=end];
                    serde_json::from_str(json_str).map_err(|e| LlmError::ParseError {
                        message: format!("Failed to parse performance evaluation: {}", e),
                    })
                } else {
                    Ok(PerformanceEvaluation {
                        service_name: service_name.to_string(),
                        overall_score: 50.0,
                        cpu_usage_analysis: "Failed to parse LLM response".to_string(),
                        memory_usage_analysis: String::new(),
                        network_analysis: String::new(),
                        bottlenecks: vec![],
                        optimization_suggestions: vec![],
                        scalability_assessment: String::new(),
                        resource_recommendations: vec![],
                    })
                }
            }
        }
    }

    fn analyze_dependencies(
        &self,
        service_name: &str,
        graph: &ServiceDependencyGraph,
    ) -> Result<DependencyAnalysis, LlmError> {
        if self.config.api_key.is_empty() {
            // Fallback: extract dependencies from graph
            let dependencies: Vec<DependencyInfo> = graph
                .edges
                .iter()
                .filter(|e| e.from == service_name)
                .map(|e| DependencyInfo {
                    service_name: e.to.clone(),
                    dependency_type: "required".to_string(),
                    impact_level: "medium".to_string(),
                    description: String::new(),
                })
                .collect();

            let dependents: Vec<String> = graph
                .edges
                .iter()
                .filter(|e| e.to == service_name)
                .map(|e| e.from.clone())
                .collect();

            return Ok(DependencyAnalysis {
                service_name: service_name.to_string(),
                dependencies,
                dependents,
                critical_path: vec![],
                circular_risk: false,
                deployment_order: vec![],
                recommendations: vec![],
            });
        }

        let graph_json = serde_json::to_string(graph).unwrap_or_default();
        let prompt = format!(
            r#"You are an expert DevOps engineer analyzing service dependencies. Analyze the dependency graph and provide a comprehensive dependency analysis.

Service Name: {}
Dependency Graph:
{}

Please provide a detailed dependency analysis in JSON format with the following fields:
- dependencies: Array of objects with fields: service_name, dependency_type ("required"/"optional"/"weak"), impact_level ("critical"/"high"/"medium"/"low"), description
- dependents: Array of service names that depend on this service
- critical_path: Array of service names in the critical deployment path
- circular_risk: Boolean indicating if there's a risk of circular dependencies
- deployment_order: Recommended deployment order for this service and its dependencies
- recommendations: Array of dependency management recommendations

Respond ONLY with valid JSON, no markdown formatting."#,
            service_name, graph_json
        );

        let response = run_async(self.call_api_with_retry(&prompt, 3))?;

        match serde_json::from_str::<DependencyAnalysis>(&response) {
            Ok(analysis) => Ok(analysis),
            Err(_) => {
                let json_start = response.find('{');
                let json_end = response.rfind('}');
                if let (Some(start), Some(end)) = (json_start, json_end) {
                    let json_str = &response[start..=end];
                    serde_json::from_str(json_str).map_err(|e| LlmError::ParseError {
                        message: format!("Failed to parse dependency analysis: {}", e),
                    })
                } else {
                    // Fallback: extract from graph
                    let dependencies: Vec<DependencyInfo> = graph
                        .edges
                        .iter()
                        .filter(|e| e.from == service_name)
                        .map(|e| DependencyInfo {
                            service_name: e.to.clone(),
                            dependency_type: "required".to_string(),
                            impact_level: "medium".to_string(),
                            description: String::new(),
                        })
                        .collect();

                    let dependents: Vec<String> = graph
                        .edges
                        .iter()
                        .filter(|e| e.to == service_name)
                        .map(|e| e.from.clone())
                        .collect();

                    Ok(DependencyAnalysis {
                        service_name: service_name.to_string(),
                        dependencies,
                        dependents,
                        critical_path: vec![],
                        circular_risk: false,
                        deployment_order: vec![],
                        recommendations: vec![],
                    })
                }
            }
        }
    }

    fn complete_prompt(&self, prompt: &str) -> Result<String, LlmError> {
        run_async(self.call_api_with_retry(prompt, 3))
    }

    fn stream_response(
        &self,
        prompt: &str,
    ) -> Pin<Box<dyn Stream<Item = Result<String, LlmError>> + Send + '_>> {
        // Clone necessary data for the async task
        let client = self.client.clone();
        let base_url = self
            .config
            .base_url
            .clone()
            .unwrap_or_else(|| "http://localhost:11434".to_string());
        let model = self.config.model.clone();
        let prompt = prompt.to_string();

        // Create a channel to bridge sync and async
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        // Spawn async task to handle streaming
        tokio::spawn(async move {
            let url = format!("{}/api/generate", base_url);
            let body = serde_json::json!({
                "model": model,
                "prompt": prompt,
                "stream": true
            });

            let request = client
                .post(&url)
                .header("Content-Type", "application/json")
                .json(&body)
                .timeout(std::time::Duration::from_secs(60));

            match request.send().await {
                Ok(response) => {
                    if !response.status().is_success() {
                        let _ = tx.send(Err(LlmError::ApiError {
                            message: format!("API returned status: {}", response.status()),
                        }));
                        return;
                    }

                    let mut stream = response.bytes_stream();
                    let mut buffer = String::new();

                    use futures_util::StreamExt as _;
                    while let Some(item) = stream.next().await {
                        match item {
                            Ok(bytes) => {
                                let text = match String::from_utf8(bytes.to_vec()) {
                                    Ok(t) => t,
                                    Err(e) => {
                                        let _ = tx.send(Err(LlmError::ParseError {
                                            message: format!("Invalid UTF-8: {}", e),
                                        }));
                                        continue;
                                    }
                                };

                                buffer.push_str(&text);

                                // Process complete lines (Ollama sends JSON lines)
                                while let Some(newline_pos) = buffer.find('\n') {
                                    let line = buffer[..newline_pos].trim().to_string();
                                    buffer = buffer[newline_pos + 1..].to_string();

                                    if line.is_empty() {
                                        continue;
                                    }

                                    match serde_json::from_str::<serde_json::Value>(&line) {
                                        Ok(json) => {
                                            // Ollama streaming format: {"response": "chunk", "done": false}
                                            if let Some(response) =
                                                json.get("response").and_then(|r| r.as_str())
                                            {
                                                if !response.is_empty() {
                                                    let _ = tx.send(Ok(response.to_string()));
                                                }
                                            }

                                            // Check if done
                                            if json
                                                .get("done")
                                                .and_then(|d| d.as_bool())
                                                .unwrap_or(false)
                                            {
                                                return;
                                            }
                                        }
                                        Err(_) => {
                                            // Skip invalid JSON lines
                                            continue;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                let _ = tx.send(Err(LlmError::NetworkError {
                                    message: format!("Stream error: {}", e),
                                }));
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(LlmError::NetworkError {
                        message: format!("Network error: {}", e),
                    }));
                }
            }
        });

        // Convert receiver to stream
        Box::pin(tokio_stream::wrappers::UnboundedReceiverStream::new(rx))
    }
}

// Claude (Anthropic) Provider
pub struct ClaudeLlmProvider {
    config: LlmConfig,
    client: reqwest::Client,
}

impl ClaudeLlmProvider {
    pub fn new(config: LlmConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    async fn call_api(&self, prompt: &str) -> Result<String, LlmError> {
        self.call_api_with_retry(prompt, 3).await
    }

    async fn call_api_with_retry(
        &self,
        prompt: &str,
        max_retries: u32,
    ) -> Result<String, LlmError> {
        let url = "https://api.anthropic.com/v1/messages";
        let body = serde_json::json!({
            "model": self.config.model,
            "max_tokens": 1000,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "system": "You are an expert DevOps engineer helping with deployment planning."
        });

        let mut last_error = None;

        for attempt in 0..max_retries {
            let request = self
                .client
                .post(url)
                .header("x-api-key", &self.config.api_key)
                .header("anthropic-version", "2023-06-01")
                .header("Content-Type", "application/json")
                .json(&body)
                .timeout(std::time::Duration::from_secs(30));

            match request.send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        match response.json::<serde_json::Value>().await {
                            Ok(json) => {
                                if let Some(content) = json["content"]
                                    .as_array()
                                    .and_then(|arr| arr.first())
                                    .and_then(|item| item["text"].as_str())
                                {
                                    return Ok(content.to_string());
                                } else {
                                    last_error = Some(LlmError::ParseError {
                                        message: "Invalid response format".to_string(),
                                    });
                                }
                            }
                            Err(e) => {
                                last_error = Some(LlmError::ParseError {
                                    message: e.to_string(),
                                });
                            }
                        }
                    } else {
                        let status = response.status();
                        if status.is_client_error() {
                            return Err(LlmError::ApiError {
                                message: format!(
                                    "API returned status: {} (client error, not retrying)",
                                    status
                                ),
                            });
                        }
                        last_error = Some(LlmError::ApiError {
                            message: format!(
                                "API returned status: {} (attempt {}/{})",
                                status,
                                attempt + 1,
                                max_retries
                            ),
                        });
                    }
                }
                Err(e) => {
                    last_error = Some(LlmError::NetworkError {
                        message: format!(
                            "Network error (attempt {}/{}): {}",
                            attempt + 1,
                            max_retries,
                            e
                        ),
                    });
                }
            }

            if attempt < max_retries - 1 {
                let delay = std::time::Duration::from_millis(500 * (attempt + 1) as u64);
                tokio::time::sleep(delay).await;
            }
        }

        Err(last_error.unwrap())
    }
}

impl LlmProvider for ClaudeLlmProvider {
    fn analyze_services(
        &self,
        graph: &ServiceDependencyGraph,
    ) -> Result<ServiceAnalysis, LlmError> {
        if self.config.api_key.is_empty() {
            return Ok(ServiceAnalysis {
                performance_notes: vec!["LLM analysis requires API key configuration".to_string()],
                security_concerns: vec![],
                deployment_order_suggestions: vec![],
                resource_requirements: vec![],
            });
        }

        let service_names: Vec<String> = graph.nodes.iter().map(|s| s.name.clone()).collect();
        let prompt = format!(
            "Analyze the following microservices for deployment planning:\n\nServices: {}\n\nProvide analysis in JSON format with fields: performance_notes (array of strings), security_concerns (array of strings), deployment_order_suggestions (array of strings), resource_requirements (array of strings).",
            service_names.join(", ")
        );

        let response = run_async(self.call_api(&prompt))?;

        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response) {
            Ok(ServiceAnalysis {
                performance_notes: json["performance_notes"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default(),
                security_concerns: json["security_concerns"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default(),
                deployment_order_suggestions: json["deployment_order_suggestions"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default(),
                resource_requirements: json["resource_requirements"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default(),
            })
        } else {
            Ok(ServiceAnalysis {
                performance_notes: vec![response.clone()],
                security_concerns: vec![],
                deployment_order_suggestions: vec![],
                resource_requirements: vec![],
            })
        }
    }

    fn generate_memo(&self, service_name: &str, action: &str) -> Result<String, LlmError> {
        if self.config.api_key.is_empty() {
            return Ok(format!(
                "Deploy service {} with action {}",
                service_name, action
            ));
        }

        let prompt = format!(
            "Generate a deployment memo for service '{}' with action '{}'. The memo should be concise (2-3 sentences) and explain what this step does and why it's important.",
            service_name, action
        );

        run_async(self.call_api(&prompt))
    }

    fn assess_risk(&self, service_name: &str, action: &str) -> Result<RiskAssessment, LlmError> {
        if self.config.api_key.is_empty() {
            return Ok(RiskAssessment {
                risk_level: "Medium".to_string(),
                concerns: vec!["LLM risk assessment requires API key configuration".to_string()],
                recommendations: vec![],
            });
        }

        let prompt = format!(
            "Assess the risk level for deploying service '{}' with action '{}'. Respond in JSON format with fields: risk_level (one of: Low, Medium, High, Critical), concerns (array of strings), recommendations (array of strings).",
            service_name, action
        );

        let response = run_async(self.call_api(&prompt))?;

        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response) {
            Ok(RiskAssessment {
                risk_level: json["risk_level"].as_str().unwrap_or("Medium").to_string(),
                concerns: json["concerns"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default(),
                recommendations: json["recommendations"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default(),
            })
        } else {
            Ok(RiskAssessment {
                risk_level: "Medium".to_string(),
                concerns: vec![response],
                recommendations: vec![],
            })
        }
    }

    fn diagnose_error(
        &self,
        error_message: &str,
        error_logs: &[String],
        context: Option<&str>,
    ) -> Result<ErrorDiagnosis, LlmError> {
        if self.config.api_key.is_empty() {
            return Ok(ErrorDiagnosis {
                error_type: "Unknown".to_string(),
                root_cause: "LLM API key not configured".to_string(),
                severity: "Medium".to_string(),
                possible_causes: vec![],
                suggested_fixes: vec![],
                prevention_tips: vec![],
                fix_commands: vec![],
                verification_steps: vec![],
                rollback_steps: vec![],
            });
        }

        let logs_summary = if error_logs.len() > 20 {
            format!(
                "{} logs (showing last 20):\n{}",
                error_logs.len(),
                error_logs
                    .iter()
                    .rev()
                    .take(20)
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        } else {
            error_logs.join("\n")
        };

        let context_str = context.unwrap_or("No additional context provided");

        let prompt = format!(
            r#"You are an expert DevOps engineer diagnosing a deployment error. Analyze the following error and provide a detailed diagnosis.

Error Message: {}
Context: {}
Error Logs:
{}

Please provide a comprehensive diagnosis in JSON format with the following fields:
- error_type: A brief classification of the error (e.g., "Connection Error", "Permission Denied", "Resource Exhaustion")
- root_cause: A detailed explanation of what likely caused this error
- severity: One of "Low", "Medium", "High", or "Critical"
- possible_causes: An array of possible root causes (at least 3 items)
- suggested_fixes: An array of specific, actionable fixes (at least 3 items)
- prevention_tips: An array of tips to prevent this error in the future (at least 2 items)
- fix_commands: An array of concrete shell commands to apply the fix safely (empty if unsafe/unknown)
- verification_steps: An array of steps or commands to verify the fix
- rollback_steps: An array of rollback steps or commands if the fix fails

Respond ONLY with valid JSON, no markdown formatting."#,
            error_message, context_str, logs_summary
        );

        let response = run_async(self.call_api_with_retry(&prompt, 3))?;

        match serde_json::from_str::<ErrorDiagnosis>(&response) {
            Ok(diagnosis) => Ok(diagnosis),
            Err(_) => {
                let json_start = response.find('{');
                let json_end = response.rfind('}');
                if let (Some(start), Some(end)) = (json_start, json_end) {
                    let json_str = &response[start..=end];
                    serde_json::from_str(json_str).map_err(|e| LlmError::ParseError {
                        message: format!("Failed to parse error diagnosis: {}", e),
                    })
                } else {
                    Ok(ErrorDiagnosis {
                        error_type: "Unknown".to_string(),
                        root_cause: "Failed to parse LLM response".to_string(),
                        severity: "Medium".to_string(),
                        possible_causes: vec!["Unable to analyze error".to_string()],
                        suggested_fixes: vec!["Check logs manually".to_string()],
                        prevention_tips: vec![],
                        fix_commands: vec![],
                        verification_steps: vec![],
                        rollback_steps: vec![],
                    })
                }
            }
        }
    }

    fn evaluate_performance(
        &self,
        service_name: &str,
        metrics: &PerformanceMetrics,
    ) -> Result<PerformanceEvaluation, LlmError> {
        if self.config.api_key.is_empty() {
            return Ok(PerformanceEvaluation {
                service_name: service_name.to_string(),
                overall_score: 50.0,
                cpu_usage_analysis: "LLM API key not configured".to_string(),
                memory_usage_analysis: String::new(),
                network_analysis: String::new(),
                bottlenecks: vec![],
                optimization_suggestions: vec![],
                scalability_assessment: String::new(),
                resource_recommendations: vec![],
            });
        }

        let metrics_json = serde_json::to_string(metrics).unwrap_or_default();
        let prompt = format!(
            r#"You are an expert performance engineer analyzing a microservice. Evaluate the performance metrics and provide a comprehensive assessment.

Service Name: {}
Performance Metrics:
{}

Please provide a detailed performance evaluation in JSON format with the following fields:
- overall_score: A number between 0.0 and 100.0 representing overall performance
- cpu_usage_analysis: Analysis of CPU usage patterns
- memory_usage_analysis: Analysis of memory usage patterns
- network_analysis: Analysis of network traffic patterns
- bottlenecks: Array of identified performance bottlenecks
- optimization_suggestions: Array of specific optimization recommendations
- scalability_assessment: Assessment of service scalability
- resource_recommendations: Array of resource allocation recommendations

Respond ONLY with valid JSON, no markdown formatting."#,
            service_name, metrics_json
        );

        let response = run_async(self.call_api_with_retry(&prompt, 3))?;

        match serde_json::from_str::<PerformanceEvaluation>(&response) {
            Ok(evaluation) => Ok(evaluation),
            Err(_) => {
                let json_start = response.find('{');
                let json_end = response.rfind('}');
                if let (Some(start), Some(end)) = (json_start, json_end) {
                    let json_str = &response[start..=end];
                    serde_json::from_str(json_str).map_err(|e| LlmError::ParseError {
                        message: format!("Failed to parse performance evaluation: {}", e),
                    })
                } else {
                    Ok(PerformanceEvaluation {
                        service_name: service_name.to_string(),
                        overall_score: 50.0,
                        cpu_usage_analysis: "Failed to parse LLM response".to_string(),
                        memory_usage_analysis: String::new(),
                        network_analysis: String::new(),
                        bottlenecks: vec![],
                        optimization_suggestions: vec![],
                        scalability_assessment: String::new(),
                        resource_recommendations: vec![],
                    })
                }
            }
        }
    }

    fn analyze_dependencies(
        &self,
        service_name: &str,
        graph: &ServiceDependencyGraph,
    ) -> Result<DependencyAnalysis, LlmError> {
        if self.config.api_key.is_empty() {
            let dependencies: Vec<DependencyInfo> = graph
                .edges
                .iter()
                .filter(|e| e.from == service_name)
                .map(|e| DependencyInfo {
                    service_name: e.to.clone(),
                    dependency_type: "required".to_string(),
                    impact_level: "medium".to_string(),
                    description: String::new(),
                })
                .collect();

            let dependents: Vec<String> = graph
                .edges
                .iter()
                .filter(|e| e.to == service_name)
                .map(|e| e.from.clone())
                .collect();

            return Ok(DependencyAnalysis {
                service_name: service_name.to_string(),
                dependencies,
                dependents,
                critical_path: vec![],
                circular_risk: false,
                deployment_order: vec![],
                recommendations: vec![],
            });
        }

        let graph_json = serde_json::to_string(graph).unwrap_or_default();
        let prompt = format!(
            r#"You are an expert DevOps engineer analyzing service dependencies. Analyze the dependency graph and provide a comprehensive dependency analysis.

Service Name: {}
Dependency Graph:
{}

Please provide a detailed dependency analysis in JSON format with the following fields:
- dependencies: Array of objects with fields: service_name, dependency_type ("required"/"optional"/"weak"), impact_level ("critical"/"high"/"medium"/"low"), description
- dependents: Array of service names that depend on this service
- critical_path: Array of service names in the critical deployment path
- circular_risk: Boolean indicating if there's a risk of circular dependencies
- deployment_order: Recommended deployment order for this service and its dependencies
- recommendations: Array of dependency management recommendations

Respond ONLY with valid JSON, no markdown formatting."#,
            service_name, graph_json
        );

        let response = run_async(self.call_api_with_retry(&prompt, 3))?;

        match serde_json::from_str::<DependencyAnalysis>(&response) {
            Ok(analysis) => Ok(analysis),
            Err(_) => {
                let json_start = response.find('{');
                let json_end = response.rfind('}');
                if let (Some(start), Some(end)) = (json_start, json_end) {
                    let json_str = &response[start..=end];
                    serde_json::from_str(json_str).map_err(|e| LlmError::ParseError {
                        message: format!("Failed to parse dependency analysis: {}", e),
                    })
                } else {
                    let dependencies: Vec<DependencyInfo> = graph
                        .edges
                        .iter()
                        .filter(|e| e.from == service_name)
                        .map(|e| DependencyInfo {
                            service_name: e.to.clone(),
                            dependency_type: "required".to_string(),
                            impact_level: "medium".to_string(),
                            description: String::new(),
                        })
                        .collect();

                    let dependents: Vec<String> = graph
                        .edges
                        .iter()
                        .filter(|e| e.to == service_name)
                        .map(|e| e.from.clone())
                        .collect();

                    Ok(DependencyAnalysis {
                        service_name: service_name.to_string(),
                        dependencies,
                        dependents,
                        critical_path: vec![],
                        circular_risk: false,
                        deployment_order: vec![],
                        recommendations: vec![],
                    })
                }
            }
        }
    }

    fn complete_prompt(&self, prompt: &str) -> Result<String, LlmError> {
        if self.config.api_key.is_empty() {
            return Err(LlmError::ConfigError {
                message: "LLM API key not configured".to_string(),
            });
        }
        run_async(self.call_api_with_retry(prompt, 3))
    }
}

// Generic OpenAI-compatible provider for OpenRouter, DeepSeek, etc.
pub struct OpenAICompatibleProvider {
    config: LlmConfig,
    client: reqwest::Client,
    api_url: String,
}

impl OpenAICompatibleProvider {
    pub fn new(config: LlmConfig, api_url: String) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
            api_url,
        }
    }

    async fn call_api(&self, prompt: &str) -> Result<String, LlmError> {
        self.call_api_with_retry(prompt, 3).await
    }

    async fn call_api_with_retry(
        &self,
        prompt: &str,
        max_retries: u32,
    ) -> Result<String, LlmError> {
        let body = serde_json::json!({
            "model": self.config.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are an expert DevOps engineer helping with deployment planning."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.7,
            "max_tokens": 1000
        });

        let mut last_error = None;

        for attempt in 0..max_retries {
            let mut request = self
                .client
                .post(&self.api_url)
                .header("Content-Type", "application/json")
                .json(&body)
                .timeout(std::time::Duration::from_secs(30));

            // Add authorization header
            if !self.config.api_key.is_empty() {
                request =
                    request.header("Authorization", format!("Bearer {}", self.config.api_key));
            }

            match request.send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        match response.json::<serde_json::Value>().await {
                            Ok(json) => {
                                if let Some(content) =
                                    json["choices"][0]["message"]["content"].as_str()
                                {
                                    return Ok(content.to_string());
                                } else {
                                    last_error = Some(LlmError::ParseError {
                                        message: "Invalid response format".to_string(),
                                    });
                                }
                            }
                            Err(e) => {
                                last_error = Some(LlmError::ParseError {
                                    message: e.to_string(),
                                });
                            }
                        }
                    } else {
                        let status = response.status();
                        if status.is_client_error() {
                            return Err(LlmError::ApiError {
                                message: format!(
                                    "API returned status: {} (client error, not retrying)",
                                    status
                                ),
                            });
                        }
                        last_error = Some(LlmError::ApiError {
                            message: format!(
                                "API returned status: {} (attempt {}/{})",
                                status,
                                attempt + 1,
                                max_retries
                            ),
                        });
                    }
                }
                Err(e) => {
                    last_error = Some(LlmError::NetworkError {
                        message: format!(
                            "Network error (attempt {}/{}): {}",
                            attempt + 1,
                            max_retries,
                            e
                        ),
                    });
                }
            }

            if attempt < max_retries - 1 {
                let delay = std::time::Duration::from_millis(500 * (attempt + 1) as u64);
                tokio::time::sleep(delay).await;
            }
        }

        Err(last_error.unwrap())
    }
}

// Implement LlmProvider for OpenAICompatibleProvider using delegation
macro_rules! impl_llm_provider_for_openai_compatible {
    () => {
        fn analyze_services(
            &self,
            graph: &ServiceDependencyGraph,
        ) -> Result<ServiceAnalysis, LlmError> {
            if self.config.api_key.is_empty() {
                return Ok(ServiceAnalysis {
                    performance_notes: vec!["LLM analysis requires API key configuration".to_string()],
                    security_concerns: vec![],
                    deployment_order_suggestions: vec![],
                    resource_requirements: vec![],
                });
            }

            let service_names: Vec<String> = graph.nodes.iter().map(|s| s.name.clone()).collect();
            let prompt = format!(
                "Analyze the following microservices for deployment planning:\n\nServices: {}\n\nProvide analysis in JSON format with fields: performance_notes (array of strings), security_concerns (array of strings), deployment_order_suggestions (array of strings), resource_requirements (array of strings).",
                service_names.join(", ")
            );

            let response = run_async(self.call_api(&prompt))?;

            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response) {
                Ok(ServiceAnalysis {
                    performance_notes: json["performance_notes"]
                        .as_array()
                        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default(),
                    security_concerns: json["security_concerns"]
                        .as_array()
                        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default(),
                    deployment_order_suggestions: json["deployment_order_suggestions"]
                        .as_array()
                        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default(),
                    resource_requirements: json["resource_requirements"]
                        .as_array()
                        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default(),
                })
            } else {
                Ok(ServiceAnalysis {
                    performance_notes: vec![response.clone()],
                    security_concerns: vec![],
                    deployment_order_suggestions: vec![],
                    resource_requirements: vec![],
                })
            }
        }

        fn generate_memo(&self, service_name: &str, action: &str) -> Result<String, LlmError> {
            if self.config.api_key.is_empty() {
                return Ok(format!("Deploy service {} with action {}", service_name, action));
            }

            let prompt = format!(
                "Generate a deployment memo for service '{}' with action '{}'. The memo should be concise (2-3 sentences) and explain what this step does and why it's important.",
                service_name, action
            );

            run_async(self.call_api(&prompt))
        }

        fn assess_risk(&self, service_name: &str, action: &str) -> Result<RiskAssessment, LlmError> {
            if self.config.api_key.is_empty() {
                return Ok(RiskAssessment {
                    risk_level: "Medium".to_string(),
                    concerns: vec!["LLM risk assessment requires API key configuration".to_string()],
                    recommendations: vec![],
                });
            }

            let prompt = format!(
                "Assess the risk level for deploying service '{}' with action '{}'. Respond in JSON format with fields: risk_level (one of: Low, Medium, High, Critical), concerns (array of strings), recommendations (array of strings).",
                service_name, action
            );

            let response = run_async(self.call_api(&prompt))?;

            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response) {
                Ok(RiskAssessment {
                    risk_level: json["risk_level"]
                        .as_str()
                        .unwrap_or("Medium")
                        .to_string(),
                    concerns: json["concerns"]
                        .as_array()
                        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default(),
                    recommendations: json["recommendations"]
                        .as_array()
                        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default(),
                })
            } else {
                Ok(RiskAssessment {
                    risk_level: "Medium".to_string(),
                    concerns: vec![response],
                    recommendations: vec![],
                })
            }
        }

        fn diagnose_error(
            &self,
            error_message: &str,
            error_logs: &[String],
            context: Option<&str>,
        ) -> Result<ErrorDiagnosis, LlmError> {
            if self.config.api_key.is_empty() {
                return Ok(ErrorDiagnosis {
                    error_type: "Unknown".to_string(),
                    root_cause: "LLM API key not configured".to_string(),
                    severity: "Medium".to_string(),
                    possible_causes: vec![],
                    suggested_fixes: vec![],
                    prevention_tips: vec![],
                    fix_commands: vec![],
                    verification_steps: vec![],
                    rollback_steps: vec![],
                });
            }

            let logs_summary = if error_logs.len() > 20 {
                format!("{} logs (showing last 20):\n{}", error_logs.len(), error_logs.iter().rev().take(20).map(|s| s.as_str()).collect::<Vec<_>>().join("\n"))
            } else {
                error_logs.join("\n")
            };

            let context_str = context.unwrap_or("No additional context provided");

            let prompt = format!(
                r#"You are an expert DevOps engineer diagnosing a deployment error. Analyze the following error and provide a detailed diagnosis.

Error Message: {}
Context: {}
Error Logs:
{}

Please provide a comprehensive diagnosis in JSON format with the following fields:
- error_type: A brief classification of the error (e.g., "Connection Error", "Permission Denied", "Resource Exhaustion")
- root_cause: A detailed explanation of what likely caused this error
- severity: One of "Low", "Medium", "High", or "Critical"
- possible_causes: An array of possible root causes (at least 3 items)
- suggested_fixes: An array of specific, actionable fixes (at least 3 items)
- prevention_tips: An array of tips to prevent this error in the future (at least 2 items)
- fix_commands: An array of concrete shell commands to apply the fix safely (empty if unsafe/unknown)
- verification_steps: An array of steps or commands to verify the fix
- rollback_steps: An array of rollback steps or commands if the fix fails

Respond ONLY with valid JSON, no markdown formatting."#,
                error_message, context_str, logs_summary
            );

            let response = run_async(self.call_api_with_retry(&prompt, 3))?;

            match serde_json::from_str::<ErrorDiagnosis>(&response) {
                Ok(diagnosis) => Ok(diagnosis),
                Err(_) => {
                    let json_start = response.find('{');
                    let json_end = response.rfind('}');
                    if let (Some(start), Some(end)) = (json_start, json_end) {
                        let json_str = &response[start..=end];
                        serde_json::from_str(json_str).map_err(|e| LlmError::ParseError {
                            message: format!("Failed to parse error diagnosis: {}", e),
                        })
                    } else {
                        Ok(ErrorDiagnosis {
                            error_type: "Unknown".to_string(),
                            root_cause: "Failed to parse LLM response".to_string(),
                            severity: "Medium".to_string(),
                            possible_causes: vec!["Unable to analyze error".to_string()],
                            suggested_fixes: vec!["Check logs manually".to_string()],
                            prevention_tips: vec![],
                            fix_commands: vec![],
                            verification_steps: vec![],
                            rollback_steps: vec![],
                        })
                    }
                }
            }
        }

        fn evaluate_performance(
            &self,
            service_name: &str,
            metrics: &PerformanceMetrics,
        ) -> Result<PerformanceEvaluation, LlmError> {
            if self.config.api_key.is_empty() {
                return Ok(PerformanceEvaluation {
                    service_name: service_name.to_string(),
                    overall_score: 50.0,
                    cpu_usage_analysis: "LLM API key not configured".to_string(),
                    memory_usage_analysis: String::new(),
                    network_analysis: String::new(),
                    bottlenecks: vec![],
                    optimization_suggestions: vec![],
                    scalability_assessment: String::new(),
                    resource_recommendations: vec![],
                });
            }

            let metrics_json = serde_json::to_string(metrics).unwrap_or_default();
            let prompt = format!(
                r#"You are an expert performance engineer analyzing a microservice. Evaluate the performance metrics and provide a comprehensive assessment.

Service Name: {}
Performance Metrics:
{}

Please provide a detailed performance evaluation in JSON format with the following fields:
- overall_score: A number between 0.0 and 100.0 representing overall performance
- cpu_usage_analysis: Analysis of CPU usage patterns
- memory_usage_analysis: Analysis of memory usage patterns
- network_analysis: Analysis of network traffic patterns
- bottlenecks: Array of identified performance bottlenecks
- optimization_suggestions: Array of specific optimization recommendations
- scalability_assessment: Assessment of service scalability
- resource_recommendations: Array of resource allocation recommendations

Respond ONLY with valid JSON, no markdown formatting."#,
                service_name, metrics_json
            );

            let response = run_async(self.call_api_with_retry(&prompt, 3))?;

            match serde_json::from_str::<PerformanceEvaluation>(&response) {
                Ok(evaluation) => Ok(evaluation),
                Err(_) => {
                    let json_start = response.find('{');
                    let json_end = response.rfind('}');
                    if let (Some(start), Some(end)) = (json_start, json_end) {
                        let json_str = &response[start..=end];
                        serde_json::from_str(json_str).map_err(|e| LlmError::ParseError {
                            message: format!("Failed to parse performance evaluation: {}", e),
                        })
                    } else {
                        Ok(PerformanceEvaluation {
                            service_name: service_name.to_string(),
                            overall_score: 50.0,
                            cpu_usage_analysis: "Failed to parse LLM response".to_string(),
                            memory_usage_analysis: String::new(),
                            network_analysis: String::new(),
                            bottlenecks: vec![],
                            optimization_suggestions: vec![],
                            scalability_assessment: String::new(),
                            resource_recommendations: vec![],
                        })
                    }
                }
            }
        }

        fn analyze_dependencies(
            &self,
            service_name: &str,
            graph: &ServiceDependencyGraph,
        ) -> Result<DependencyAnalysis, LlmError> {
            if self.config.api_key.is_empty() {
                let dependencies: Vec<DependencyInfo> = graph
                    .edges
                    .iter()
                    .filter(|e| e.from == service_name)
                    .map(|e| DependencyInfo {
                        service_name: e.to.clone(),
                        dependency_type: "required".to_string(),
                        impact_level: "medium".to_string(),
                        description: String::new(),
                    })
                    .collect();

                let dependents: Vec<String> = graph
                    .edges
                    .iter()
                    .filter(|e| e.to == service_name)
                    .map(|e| e.from.clone())
                    .collect();

                return Ok(DependencyAnalysis {
                    service_name: service_name.to_string(),
                    dependencies,
                    dependents,
                    critical_path: vec![],
                    circular_risk: false,
                    deployment_order: vec![],
                    recommendations: vec![],
                });
            }

            let graph_json = serde_json::to_string(graph).unwrap_or_default();
            let prompt = format!(
                r#"You are an expert DevOps engineer analyzing service dependencies. Analyze the dependency graph and provide a comprehensive dependency analysis.

Service Name: {}
Dependency Graph:
{}

Please provide a detailed dependency analysis in JSON format with the following fields:
- dependencies: Array of objects with fields: service_name, dependency_type ("required"/"optional"/"weak"), impact_level ("critical"/"high"/"medium"/"low"), description
- dependents: Array of service names that depend on this service
- critical_path: Array of service names in the critical deployment path
- circular_risk: Boolean indicating if there's a risk of circular dependencies
- deployment_order: Recommended deployment order for this service and its dependencies
- recommendations: Array of dependency management recommendations

Respond ONLY with valid JSON, no markdown formatting."#,
                service_name, graph_json
            );

            let response = run_async(self.call_api_with_retry(&prompt, 3))?;

            match serde_json::from_str::<DependencyAnalysis>(&response) {
                Ok(analysis) => Ok(analysis),
                Err(_) => {
                    let json_start = response.find('{');
                    let json_end = response.rfind('}');
                    if let (Some(start), Some(end)) = (json_start, json_end) {
                        let json_str = &response[start..=end];
                        serde_json::from_str(json_str).map_err(|e| LlmError::ParseError {
                            message: format!("Failed to parse dependency analysis: {}", e),
                        })
                    } else {
                        let dependencies: Vec<DependencyInfo> = graph
                            .edges
                            .iter()
                            .filter(|e| e.from == service_name)
                            .map(|e| DependencyInfo {
                                service_name: e.to.clone(),
                                dependency_type: "required".to_string(),
                                impact_level: "medium".to_string(),
                                description: String::new(),
                            })
                            .collect();

                        let dependents: Vec<String> = graph
                            .edges
                            .iter()
                            .filter(|e| e.to == service_name)
                            .map(|e| e.from.clone())
                            .collect();

                        Ok(DependencyAnalysis {
                            service_name: service_name.to_string(),
                            dependencies,
                            dependents,
                            critical_path: vec![],
                            circular_risk: false,
                            deployment_order: vec![],
                            recommendations: vec![],
                        })
                    }
                }
            }
        }

        fn complete_prompt(&self, prompt: &str) -> Result<String, LlmError> {
            if self.config.api_key.is_empty() {
                return Err(LlmError::ConfigError {
                    message: "LLM API key not configured".to_string(),
                });
            }
            run_async(self.call_api_with_retry(prompt, 3))
        }
    };
}

impl LlmProvider for OpenAICompatibleProvider {
    impl_llm_provider_for_openai_compatible!();

    fn stream_response(
        &self,
        prompt: &str,
    ) -> Pin<Box<dyn Stream<Item = Result<String, LlmError>> + Send + '_>> {
        if self.config.api_key.is_empty() {
            return Box::pin(futures_util::stream::empty());
        }

        // Clone necessary data for the async task
        let client = self.client.clone();
        let api_url = self.api_url.clone();
        let api_key = self.config.api_key.clone();
        let model = self.config.model.clone();
        let prompt = prompt.to_string();

        // Create a channel to bridge sync and async
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        // Spawn async task to handle streaming
        tokio::spawn(async move {
            let body = serde_json::json!({
                "model": model,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are an expert DevOps engineer helping with deployment planning."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "temperature": 0.7,
                "max_tokens": 1000,
                "stream": true
            });

            let mut request = client
                .post(&api_url)
                .header("Content-Type", "application/json")
                .json(&body)
                .timeout(std::time::Duration::from_secs(60));

            if !api_key.is_empty() {
                request = request.header("Authorization", format!("Bearer {}", api_key));
            }

            match request.send().await {
                Ok(response) => {
                    if !response.status().is_success() {
                        let _ = tx.send(Err(LlmError::ApiError {
                            message: format!("API returned status: {}", response.status()),
                        }));
                        return;
                    }

                    let mut stream = response.bytes_stream();
                    let mut buffer = String::new();

                    use futures_util::StreamExt as _;
                    while let Some(item) = stream.next().await {
                        match item {
                            Ok(bytes) => {
                                let text = match String::from_utf8(bytes.to_vec()) {
                                    Ok(t) => t,
                                    Err(e) => {
                                        let _ = tx.send(Err(LlmError::ParseError {
                                            message: format!("Invalid UTF-8: {}", e),
                                        }));
                                        continue;
                                    }
                                };

                                buffer.push_str(&text);

                                // Process complete lines (SSE format: "data: {...}\n\n")
                                while let Some(newline_pos) = buffer.find("\n\n") {
                                    let line = buffer[..newline_pos].trim().to_string();
                                    buffer = buffer[newline_pos + 2..].to_string();

                                    if line.starts_with("data: ") {
                                        let json_str = &line[6..];

                                        // Check for [DONE] marker
                                        if json_str.trim() == "[DONE]" {
                                            return;
                                        }

                                        match serde_json::from_str::<serde_json::Value>(json_str) {
                                            Ok(json) => {
                                                if let Some(choices) =
                                                    json.get("choices").and_then(|c| c.as_array())
                                                {
                                                    if let Some(choice) = choices.first() {
                                                        if let Some(delta) = choice.get("delta") {
                                                            if let Some(content) = delta
                                                                .get("content")
                                                                .and_then(|c| c.as_str())
                                                            {
                                                                if !content.is_empty() {
                                                                    let _ = tx.send(Ok(
                                                                        content.to_string()
                                                                    ));
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            Err(_) => {
                                                // Skip invalid JSON lines (e.g., keep-alive messages)
                                                continue;
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                let _ = tx.send(Err(LlmError::NetworkError {
                                    message: format!("Stream error: {}", e),
                                }));
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(LlmError::NetworkError {
                        message: format!("Network error: {}", e),
                    }));
                }
            }
        });

        // Convert receiver to stream
        Box::pin(tokio_stream::wrappers::UnboundedReceiverStream::new(rx))
    }
}

// Gemini Provider
pub struct GeminiLlmProvider {
    config: LlmConfig,
    client: reqwest::Client,
}

impl GeminiLlmProvider {
    pub fn new(config: LlmConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    async fn call_api(&self, prompt: &str) -> Result<String, LlmError> {
        self.call_api_with_retry(prompt, 3).await
    }

    async fn call_api_with_retry(
        &self,
        prompt: &str,
        max_retries: u32,
    ) -> Result<String, LlmError> {
        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
            self.config.model, self.config.api_key
        );

        let body = serde_json::json!({
            "contents": [{
                "parts": [{
                    "text": format!("You are an expert DevOps engineer helping with deployment planning.\n\n{}", prompt)
                }]
            }]
        });

        let mut last_error = None;

        for attempt in 0..max_retries {
            let request = self
                .client
                .post(&url)
                .header("Content-Type", "application/json")
                .json(&body)
                .timeout(std::time::Duration::from_secs(30));

            match request.send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        match response.json::<serde_json::Value>().await {
                            Ok(json) => {
                                if let Some(content) =
                                    json["candidates"][0]["content"]["parts"][0]["text"].as_str()
                                {
                                    return Ok(content.to_string());
                                } else {
                                    last_error = Some(LlmError::ParseError {
                                        message: "Invalid response format".to_string(),
                                    });
                                }
                            }
                            Err(e) => {
                                last_error = Some(LlmError::ParseError {
                                    message: e.to_string(),
                                });
                            }
                        }
                    } else {
                        let status = response.status();
                        if status.is_client_error() {
                            return Err(LlmError::ApiError {
                                message: format!(
                                    "API returned status: {} (client error, not retrying)",
                                    status
                                ),
                            });
                        }
                        last_error = Some(LlmError::ApiError {
                            message: format!(
                                "API returned status: {} (attempt {}/{})",
                                status,
                                attempt + 1,
                                max_retries
                            ),
                        });
                    }
                }
                Err(e) => {
                    last_error = Some(LlmError::NetworkError {
                        message: format!(
                            "Network error (attempt {}/{}): {}",
                            attempt + 1,
                            max_retries,
                            e
                        ),
                    });
                }
            }

            if attempt < max_retries - 1 {
                let delay = std::time::Duration::from_millis(500 * (attempt + 1) as u64);
                tokio::time::sleep(delay).await;
            }
        }

        Err(last_error.unwrap())
    }
}

impl LlmProvider for GeminiLlmProvider {
    impl_llm_provider_for_openai_compatible!();
}

// Alibaba Qwen Provider
pub struct AlibabaQwenLlmProvider {
    config: LlmConfig,
    client: reqwest::Client,
}

impl AlibabaQwenLlmProvider {
    pub fn new(config: LlmConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    async fn call_api(&self, prompt: &str) -> Result<String, LlmError> {
        self.call_api_with_retry(prompt, 3).await
    }

    async fn call_api_with_retry(
        &self,
        prompt: &str,
        max_retries: u32,
    ) -> Result<String, LlmError> {
        let default_url =
            "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation"
                .to_string();
        let base_url = self.config.base_url.as_ref().unwrap_or(&default_url);

        let body = serde_json::json!({
            "model": self.config.model,
            "input": {
                "messages": [
                    {
                        "role": "system",
                        "content": "You are an expert DevOps engineer helping with deployment planning."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            },
            "parameters": {
                "temperature": 0.7,
                "max_tokens": 1000
            }
        });

        let mut last_error = None;

        for attempt in 0..max_retries {
            let request = self
                .client
                .post(base_url)
                .header("Authorization", format!("Bearer {}", self.config.api_key))
                .header("Content-Type", "application/json")
                .json(&body)
                .timeout(std::time::Duration::from_secs(30));

            match request.send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        match response.json::<serde_json::Value>().await {
                            Ok(json) => {
                                if let Some(content) =
                                    json["output"]["choices"][0]["message"]["content"].as_str()
                                {
                                    return Ok(content.to_string());
                                } else {
                                    last_error = Some(LlmError::ParseError {
                                        message: "Invalid response format".to_string(),
                                    });
                                }
                            }
                            Err(e) => {
                                last_error = Some(LlmError::ParseError {
                                    message: e.to_string(),
                                });
                            }
                        }
                    } else {
                        let status = response.status();
                        if status.is_client_error() {
                            return Err(LlmError::ApiError {
                                message: format!(
                                    "API returned status: {} (client error, not retrying)",
                                    status
                                ),
                            });
                        }
                        last_error = Some(LlmError::ApiError {
                            message: format!(
                                "API returned status: {} (attempt {}/{})",
                                status,
                                attempt + 1,
                                max_retries
                            ),
                        });
                    }
                }
                Err(e) => {
                    last_error = Some(LlmError::NetworkError {
                        message: format!(
                            "Network error (attempt {}/{}): {}",
                            attempt + 1,
                            max_retries,
                            e
                        ),
                    });
                }
            }

            if attempt < max_retries - 1 {
                let delay = std::time::Duration::from_millis(500 * (attempt + 1) as u64);
                tokio::time::sleep(delay).await;
            }
        }

        Err(last_error.unwrap())
    }
}

impl LlmProvider for AlibabaQwenLlmProvider {
    impl_llm_provider_for_openai_compatible!();
}

// Zhipu GLM Provider
pub struct ZhipuLlmProvider {
    config: LlmConfig,
    client: reqwest::Client,
}

impl ZhipuLlmProvider {
    pub fn new(config: LlmConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    async fn call_api(&self, prompt: &str) -> Result<String, LlmError> {
        self.call_api_with_retry(prompt, 3).await
    }

    async fn call_api_with_retry(
        &self,
        prompt: &str,
        max_retries: u32,
    ) -> Result<String, LlmError> {
        // Zhipu uses JWT token authentication
        // For simplicity, we'll use API key in Authorization header
        let url = format!("https://open.bigmodel.cn/api/paas/v4/chat/completions");

        let body = serde_json::json!({
            "model": self.config.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are an expert DevOps engineer helping with deployment planning."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.7,
            "max_tokens": 1000
        });

        let mut last_error = None;

        for attempt in 0..max_retries {
            let request = self
                .client
                .post(&url)
                .header("Authorization", format!("Bearer {}", self.config.api_key))
                .header("Content-Type", "application/json")
                .json(&body)
                .timeout(std::time::Duration::from_secs(30));

            match request.send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        match response.json::<serde_json::Value>().await {
                            Ok(json) => {
                                if let Some(content) =
                                    json["choices"][0]["message"]["content"].as_str()
                                {
                                    return Ok(content.to_string());
                                } else {
                                    last_error = Some(LlmError::ParseError {
                                        message: "Invalid response format".to_string(),
                                    });
                                }
                            }
                            Err(e) => {
                                last_error = Some(LlmError::ParseError {
                                    message: e.to_string(),
                                });
                            }
                        }
                    } else {
                        let status = response.status();
                        if status.is_client_error() {
                            return Err(LlmError::ApiError {
                                message: format!(
                                    "API returned status: {} (client error, not retrying)",
                                    status
                                ),
                            });
                        }
                        last_error = Some(LlmError::ApiError {
                            message: format!(
                                "API returned status: {} (attempt {}/{})",
                                status,
                                attempt + 1,
                                max_retries
                            ),
                        });
                    }
                }
                Err(e) => {
                    last_error = Some(LlmError::NetworkError {
                        message: format!(
                            "Network error (attempt {}/{}): {}",
                            attempt + 1,
                            max_retries,
                            e
                        ),
                    });
                }
            }

            if attempt < max_retries - 1 {
                let delay = std::time::Duration::from_millis(500 * (attempt + 1) as u64);
                tokio::time::sleep(delay).await;
            }
        }

        Err(last_error.unwrap())
    }
}

impl LlmProvider for ZhipuLlmProvider {
    impl_llm_provider_for_openai_compatible!();
}

pub fn create_llm_provider(config: LlmConfig) -> Result<Box<dyn LlmProvider>, LlmError> {
    match config.provider {
        LlmProviderType::OpenAI => Ok(Box::new(OpenAILlmProvider::new(config))),
        LlmProviderType::Ollama => Ok(Box::new(OllamaLlmProvider::new(config))),
        LlmProviderType::Claude => Ok(Box::new(ClaudeLlmProvider::new(config))),
        LlmProviderType::Gemini => Ok(Box::new(GeminiLlmProvider::new(config))),
        LlmProviderType::OpenRouter => {
            let api_url = config
                .base_url
                .clone()
                .unwrap_or_else(|| "https://openrouter.ai/api/v1/chat/completions".to_string());
            Ok(Box::new(OpenAICompatibleProvider::new(config, api_url)))
        }
        LlmProviderType::AlibabaQwen => Ok(Box::new(AlibabaQwenLlmProvider::new(config))),
        LlmProviderType::DeepSeek => {
            let api_url = config
                .base_url
                .clone()
                .unwrap_or_else(|| "https://api.deepseek.com/v1/chat/completions".to_string());
            Ok(Box::new(OpenAICompatibleProvider::new(config, api_url)))
        }
        LlmProviderType::Zhipu => Ok(Box::new(ZhipuLlmProvider::new(config))),
    }
}

// P0-2: 部署计划制定 - Prompt 构建和响应解析

/// 构建部署计划制定的 Prompt
pub fn build_deployment_plan_prompt(
    context: &DeploymentPlanContext,
) -> Result<String, LlmError> {
    let graph_json = serde_json::to_string_pretty(&context.dependency_graph)
        .map_err(|e| LlmError::ConfigError {
            message: format!("Failed to serialize dependency graph: {}", e),
        })?;

    let prompt = format!(r#"
# 角色定义
你是一位资深的 DevOps/SRE 工程师，负责制定可靠的部署计划。

# 任务目标
基于提供的环境扫描结果和依赖关系图，制定一个安全、可靠的部署计划。

# 输入信息

## 1. 项目信息
- 项目名称: {}
- 项目ID: {}
- 目标主机: {} ({})
- 环境类型: {}

## 2. 代码同步状态
- 本地代码路径: {}
- 远程代码路径: {}
- 同步状态: {}
- 代码一致性: {}
- 最后同步时间: {}

## 3. 服务依赖图
```json
{}
```

## 4. 远程环境状态
- Docker 版本: {}
- Docker Compose 版本: {}
- 运行中的容器数: {}
- 可用的镜像数: {}
- 系统资源: CPU {}%, Memory {}%, Disk {}%

# 输出要求

请以 JSON 格式输出部署计划，包含以下字段：

{{
  "deployment_plan": {{
    "steps": [
      {{
        "id": "step_1",
        "service_name": "database",
        "action": "deploy",
        "description": "部署数据库服务",
        "command": "docker-compose up -d database",
        "depends_on": [],
        "estimated_duration": "2分钟",
        "rollback_command": "docker-compose down database"
      }}
    ],
    "total_estimated_duration": "10分钟"
  }},
  "risk_assessment": {{
    "risk_level": "Medium",
    "concerns": [
      "数据库迁移可能导致数据丢失"
    ],
    "recommendations": [
      "建议先备份数据库"
    ]
  }},
  "dry_run_analysis": {{
    "simulated_steps": [],
    "potential_issues": [],
    "recommendations": []
  }},
  "validation_checklist": [
    "检查数据库备份是否完成",
    "验证网络连接是否正常"
  ]
}}

# 分析要求

1. **依赖关系分析**：识别服务之间的依赖关系，确定正确的部署顺序
2. **风险评估**：评估每个步骤的风险等级（Low/Medium/High/Critical）
3. **推演和测试**：模拟每个步骤的执行，预测可能的失败点
4. **优化建议**：建议并行执行的步骤、检查点、回滚策略

# 约束条件

1. 必须遵循服务依赖关系
2. 高风险操作必须标记为需要人工审批
3. 必须提供回滚方案
4. 必须考虑资源限制
5. 必须考虑最小化服务中断时间

# 输出格式

请严格按照 JSON 格式输出，确保所有字段都包含在内。
"#,
        context.project_name,
        context.project_id,
        context.host_id,
        context.host_address,
        context.environment,
        context.local_repo_path,
        context.remote_repo_path,
        context.sync_status,
        context.code_consistency_status,
        context.last_sync_time,
        graph_json,
        context.remote_state.docker_version,
        context.remote_state.compose_version,
        context.remote_state.running_containers_count,
        context.remote_state.available_images_count,
        format!("{:.1}", context.remote_state.cpu_usage),
        format!("{:.1}", context.remote_state.memory_usage),
        format!("{:.1}", context.remote_state.disk_usage),
    );

    Ok(prompt)
}

/// 从 LLM 响应中提取 JSON
fn extract_json_from_response(response: &str) -> String {
    // 尝试提取 ```json ... ``` 代码块
    if let Some(start) = response.find("```json") {
        if let Some(end) = response[start..].find("```") {
            return response[start + 7..start + end].trim().to_string();
        }
    }
    
    // 尝试提取 ``` ... ``` 代码块（可能是 markdown 代码块）
    if let Some(start) = response.find("```") {
        if let Some(end) = response[start + 3..].find("```") {
            let content = &response[start + 3..start + 3 + end];
            if content.trim().starts_with('{') {
                return content.trim().to_string();
            }
        }
    }
    
    // 尝试提取 {...} JSON 对象
    if let Some(start) = response.find('{') {
        if let Some(end) = response.rfind('}') {
            return response[start..=end].to_string();
        }
    }
    
    response.to_string()
}

/// 解析 LLM 返回的部署计划响应
pub fn parse_llm_plan_response(
    response: &str,
) -> Result<LLMDeploymentPlanResponse, LlmError> {
    let json_str = extract_json_from_response(response);
    
    let plan: LLMDeploymentPlanResponse = serde_json::from_str(&json_str)
        .map_err(|e| LlmError::ConfigError {
            message: format!("Failed to parse LLM response: {}. Response: {}", e, json_str),
        })?;
    
    // 验证计划
    validate_llm_plan(&plan)?;
    
    Ok(plan)
}

/// 验证 LLM 生成的部署计划
fn validate_llm_plan(plan: &LLMDeploymentPlanResponse) -> Result<(), LlmError> {
    // 检查步骤是否为空
    if plan.deployment_plan.steps.is_empty() {
        return Err(LlmError::ConfigError {
            message: "Deployment plan has no steps".to_string(),
        });
    }
    
    // 检查步骤 ID 是否唯一
    let mut step_ids = std::collections::HashSet::new();
    for step in &plan.deployment_plan.steps {
        if step_ids.contains(&step.id) {
            return Err(LlmError::ConfigError {
                message: format!("Duplicate step ID: {}", step.id),
            });
        }
        step_ids.insert(step.id.clone());
    }
    
    // 检查依赖关系是否有效
    for step in &plan.deployment_plan.steps {
        for dep in &step.depends_on {
            if !step_ids.contains(dep) {
                return Err(LlmError::ConfigError {
                    message: format!("Step {} depends on unknown step: {}", step.id, dep),
                });
            }
        }
    }
    
    Ok(())
}
