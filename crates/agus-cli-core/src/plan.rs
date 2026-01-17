use std::path::Path;

use agus_core_domain::{DeploymentAction, DeploymentPlan};

use crate::CliError;

pub fn load_plan(path: impl AsRef<Path>) -> Result<DeploymentPlan, CliError> {
    let path = path.as_ref();
    let content = std::fs::read_to_string(path)?;
    let plan = serde_json::from_str(&content)?;
    Ok(plan)
}

pub fn save_plan(path: impl AsRef<Path>, plan: &DeploymentPlan) -> Result<(), CliError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(plan)?;
    std::fs::write(path, content)?;
    Ok(())
}

pub fn plan_to_dot(plan: &DeploymentPlan) -> String {
    let mut output = String::from("digraph plan {\n  node [shape=box];\n");
    for step in &plan.steps {
        let label = format!("{}\\n{}", step.id, action_label(&step.action));
        output.push_str(&format!(
            "  \"{}\" [label=\"{}\"];\n",
            escape_label(&step.id),
            escape_label(&label)
        ));
    }
    for step in &plan.steps {
        for dep in &step.depends_on {
            output.push_str(&format!(
                "  \"{}\" -> \"{}\";\n",
                escape_label(dep),
                escape_label(&step.id)
            ));
        }
    }
    output.push_str("}\n");
    output
}

pub fn plan_to_mermaid(plan: &DeploymentPlan) -> String {
    let mut output = String::from("graph TD\n");
    for step in &plan.steps {
        let label = format!("{}\\n{}", step.id, action_label(&step.action));
        output.push_str(&format!(
            "  {}[\"{}\"]\n",
            escape_mermaid_id(&step.id),
            escape_mermaid_label(&label)
        ));
    }
    for step in &plan.steps {
        for dep in &step.depends_on {
            output.push_str(&format!(
                "  {} --> {}\n",
                escape_mermaid_id(dep),
                escape_mermaid_id(&step.id)
            ));
        }
    }
    output
}

fn action_label(action: &DeploymentAction) -> String {
    format!("{:?}", action)
}

fn escape_label(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn escape_mermaid_label(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn escape_mermaid_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use agus_core_domain::{DeploymentAction, DeploymentStep};

    #[test]
    fn dot_contains_edges() {
        let plan = DeploymentPlan {
            steps: vec![
                DeploymentStep {
                    id: "step-1".to_string(),
                    service_name: "svc".to_string(),
                    action: DeploymentAction::DeployService,
                    depends_on: vec![],
                    approval_required: false,
                    memo: None,
                },
                DeploymentStep {
                    id: "step-2".to_string(),
                    service_name: "svc".to_string(),
                    action: DeploymentAction::VerifyService,
                    depends_on: vec!["step-1".to_string()],
                    approval_required: false,
                    memo: None,
                },
            ],
        };

        let dot = plan_to_dot(&plan);
        assert!(dot.contains("\"step-1\" -> \"step-2\""));
    }
}
