pub mod context_integration;
pub mod llm;

use agus_core_domain::{
    DeploymentAction, DeploymentPlan, DeploymentStep, PlanValidationError, ServiceDependencyGraph,
};
use serde::Serialize;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum PlanGenerationError {
    InvalidGraph { message: String },
    CycleDetected { message: String },
    InvalidPlan { message: String },
}

impl std::fmt::Display for PlanGenerationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanGenerationError::InvalidGraph { message } => {
                write!(f, "invalid service graph: {message}")
            }
            PlanGenerationError::CycleDetected { message } => {
                write!(f, "cycle detected: {message}")
            }
            PlanGenerationError::InvalidPlan { message } => write!(f, "invalid plan: {message}"),
        }
    }
}

impl std::error::Error for PlanGenerationError {}

impl From<PlanValidationError> for PlanGenerationError {
    fn from(err: PlanValidationError) -> Self {
        PlanGenerationError::InvalidPlan {
            message: err.to_string(),
        }
    }
}

pub fn generate_deployment_plan(
    graph: &ServiceDependencyGraph,
) -> Result<DeploymentPlan, PlanGenerationError> {
    generate_deployment_plan_with_llm(graph, None)
}

pub fn generate_deployment_plan_with_llm(
    graph: &ServiceDependencyGraph,
    llm_provider: Option<&dyn llm::LlmProvider>,
) -> Result<DeploymentPlan, PlanGenerationError> {
    let services = graph.nodes.iter().map(|service| service.name.as_str());
    let mut service_set: HashSet<&str> = HashSet::new();
    for name in services {
        service_set.insert(name);
    }

    let mut dependencies_by_service: HashMap<String, Vec<String>> = HashMap::new();
    for edge in &graph.edges {
        if !service_set.contains(edge.from.as_str()) {
            return Err(PlanGenerationError::InvalidGraph {
                message: format!("edge from unknown service {}", edge.from),
            });
        }
        if !service_set.contains(edge.to.as_str()) {
            return Err(PlanGenerationError::InvalidGraph {
                message: format!("edge to unknown service {}", edge.to),
            });
        }
        dependencies_by_service
            .entry(edge.from.clone())
            .or_default()
            .push(edge.to.clone());
    }

    // Use LLM to analyze services if available
    // Note: Analysis result is not currently used, but kept for future enhancements
    if let Some(llm) = llm_provider {
        if let Err(e) = llm.analyze_services(graph) {
            // Log error but continue without LLM analysis
            eprintln!("LLM analysis failed: {}", e);
        }
    }

    let order = topo_sort_services(graph)?;
    let mut steps = Vec::new();

    for service_name in order {
        let deploy_id = format!("deploy:{service_name}");
        let mut depends_on = dependencies_by_service
            .get(&service_name)
            .cloned()
            .unwrap_or_default();
        depends_on.sort();
        let deploy_depends_on = depends_on
            .into_iter()
            .map(|dependency| format!("deploy:{dependency}"))
            .collect();

        // Generate memo using LLM if available
        let memo = if let Some(ref llm) = llm_provider {
            match llm.generate_memo(&service_name, "DeployService") {
                Ok(memo_text) => Some(memo_text),
                Err(_) => None,
            }
        } else {
            None
        };

        // Assess risk using LLM if available
        let approval_required = if let Some(ref llm) = llm_provider {
            match llm.assess_risk(&service_name, "DeployService") {
                Ok(assessment) => {
                    assessment.risk_level == "High" || assessment.risk_level == "Critical"
                }
                Err(_) => false,
            }
        } else {
            false
        };

        steps.push(DeploymentStep {
            id: deploy_id.clone(),
            service_name: service_name.clone(),
            action: DeploymentAction::DeployService,
            depends_on: deploy_depends_on,
            approval_required,
            memo,
        });

        steps.push(DeploymentStep {
            id: format!("verify:{service_name}"),
            service_name,
            action: DeploymentAction::VerifyService,
            depends_on: vec![deploy_id],
            approval_required: false,
            memo: None,
        });
    }

    let plan = DeploymentPlan { steps };
    plan.validate()?;
    Ok(plan)
}

fn topo_sort_services(graph: &ServiceDependencyGraph) -> Result<Vec<String>, PlanGenerationError> {
    let mut indegree: HashMap<String, usize> = HashMap::new();
    let mut adjacency: HashMap<String, Vec<String>> = HashMap::new();

    for service in &graph.nodes {
        indegree.insert(service.name.clone(), 0);
        adjacency.insert(service.name.clone(), Vec::new());
    }

    for edge in &graph.edges {
        if let (Some(degree), Some(neighbors)) =
            (indegree.get_mut(&edge.from), adjacency.get_mut(&edge.to))
        {
            *degree += 1;
            neighbors.push(edge.from.clone());
        } else {
            return Err(PlanGenerationError::InvalidGraph {
                message: format!("edge references unknown service {}", edge.from),
            });
        }
    }

    let mut ready: Vec<String> = indegree
        .iter()
        .filter_map(|(name, degree)| {
            if *degree == 0 {
                Some(name.clone())
            } else {
                None
            }
        })
        .collect();
    ready.sort();

    let mut order = Vec::new();
    while !ready.is_empty() {
        let name = ready.remove(0);
        order.push(name.clone());
        if let Some(neighbors) = adjacency.get(&name) {
            for neighbor in neighbors {
                if let Some(degree) = indegree.get_mut(neighbor) {
                    *degree -= 1;
                    if *degree == 0 {
                        ready.push(neighbor.clone());
                        ready.sort();
                    }
                }
            }
        }
    }

    if order.len() != indegree.len() {
        let cycle_nodes: Vec<String> = indegree
            .iter()
            .filter_map(|(name, degree)| {
                if *degree > 0 {
                    Some(name.clone())
                } else {
                    None
                }
            })
            .collect();
        let message = if cycle_nodes.is_empty() {
            "cycle detected in service graph".to_string()
        } else {
            format!("cycle detected among services: {}", cycle_nodes.join(", "))
        };
        return Err(PlanGenerationError::CycleDetected { message });
    }

    Ok(order)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agus_core_domain::{Service, ServiceDependencyEdge, ServiceDependencyGraph, ServiceKind};

    fn service(name: &str) -> Service {
        Service {
            name: name.to_string(),
            kind: ServiceKind::ComposeService,
            exposed_ports: Vec::new(),
        }
    }

    #[test]
    fn generates_plan_for_simple_dag() {
        let graph = ServiceDependencyGraph {
            nodes: vec![service("db"), service("api")],
            edges: vec![ServiceDependencyEdge {
                from: "api".to_string(),
                to: "db".to_string(),
            }],
        };

        let plan = generate_deployment_plan(&graph).expect("generate plan");
        plan.validate().expect("validate plan");

        let deploy_db = plan
            .steps
            .iter()
            .find(|step| step.id == "deploy:db")
            .expect("deploy db");
        let deploy_api = plan
            .steps
            .iter()
            .find(|step| step.id == "deploy:api")
            .expect("deploy api");

        assert!(deploy_api.depends_on.contains(&deploy_db.id));
    }

    #[test]
    fn wires_verify_dependency() {
        let graph = ServiceDependencyGraph {
            nodes: vec![service("worker")],
            edges: Vec::new(),
        };

        let plan = generate_deployment_plan(&graph).expect("generate plan");
        let deploy = plan
            .steps
            .iter()
            .find(|step| step.id == "deploy:worker")
            .expect("deploy worker");
        let verify = plan
            .steps
            .iter()
            .find(|step| step.id == "verify:worker")
            .expect("verify worker");

        assert_eq!(verify.depends_on, vec![deploy.id.clone()]);
    }

    #[test]
    fn detects_cycles_in_plan_generation() {
        let graph = ServiceDependencyGraph {
            nodes: vec![service("api"), service("worker")],
            edges: vec![
                ServiceDependencyEdge {
                    from: "api".to_string(),
                    to: "worker".to_string(),
                },
                ServiceDependencyEdge {
                    from: "worker".to_string(),
                    to: "api".to_string(),
                },
            ],
        };

        let result = generate_deployment_plan(&graph);
        assert!(matches!(
            result,
            Err(PlanGenerationError::CycleDetected { .. })
        ));
    }
}
