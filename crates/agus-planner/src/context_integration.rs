//! Integration helpers for context engine and LLM providers
//!
//! This module provides helper functions to enhance LLM prompts with enriched context

#[cfg(test)]
use agus_context_engine::ErrorContext;
use agus_context_engine::{
    ConfigChange, EnrichedContext, Event, HistoricalError, ServiceDependency,
};

/// Format historical errors for LLM prompt
pub fn format_historical_errors(errors: &[HistoricalError]) -> String {
    if errors.is_empty() {
        return "No historical errors found.".to_string();
    }

    let mut output = String::new();
    for (i, error) in errors.iter().enumerate() {
        output.push_str(&format!(
            "\n{}. [{}] {}",
            i + 1,
            error.timestamp.format("%Y-%m-%d %H:%M:%S"),
            error.message
        ));

        if let Some(resolution) = &error.resolution {
            output.push_str(&format!("\n   Resolution: {}", resolution));
        }

        if let Some(score) = error.similarity_score {
            output.push_str(&format!("\n   Similarity: {:.0}%", score * 100.0));
        }
    }

    output
}

/// Format concurrent events for LLM prompt
pub fn format_concurrent_events(events: &[Event]) -> String {
    if events.is_empty() {
        return "No concurrent events detected.".to_string();
    }

    let mut output = String::new();
    for (i, event) in events.iter().enumerate() {
        output.push_str(&format!(
            "\n{}. [{}] {:?}: {}",
            i + 1,
            event.timestamp.format("%Y-%m-%d %H:%M:%S"),
            event.event_type,
            event.description
        ));

        if let Some(service) = &event.service_name {
            output.push_str(&format!(" (Service: {})", service));
        }
    }

    output
}

/// Format configuration changes for LLM prompt
pub fn format_config_changes(changes: &[ConfigChange]) -> String {
    if changes.is_empty() {
        return "No recent configuration changes.".to_string();
    }

    let mut output = String::new();
    for (i, change) in changes.iter().enumerate() {
        output.push_str(&format!(
            "\n{}. [{}] {}: {}",
            i + 1,
            change.timestamp.format("%Y-%m-%d %H:%M:%S"),
            change.service_name,
            change.description
        ));

        if !change.changed_fields.is_empty() {
            output.push_str(&format!(
                "\n   Changed fields: {}",
                change.changed_fields.join(", ")
            ));
        }
    }

    output
}

/// Format dependency chain for LLM prompt
pub fn format_dependency_chain(dependencies: &[ServiceDependency]) -> String {
    if dependencies.is_empty() {
        return "No dependency information available.".to_string();
    }

    let mut output = String::new();
    for dep in dependencies {
        output.push_str(&format!("\nService: {}", dep.service_name));

        if !dep.upstream.is_empty() {
            output.push_str(&format!("\n  Depends on: {}", dep.upstream.join(", ")));
        }

        if !dep.downstream.is_empty() {
            output.push_str(&format!("\n  Required by: {}", dep.downstream.join(", ")));
        }
    }

    output
}

/// Build enriched prompt for error diagnosis
pub fn build_diagnosis_prompt(context: &EnrichedContext) -> String {
    format!(
        r#"You are Agus intelligent operations assistant. Please analyze the following error:

## Current Error
Service: {}
Message: {}
Severity: {:?}
Time: {}

## Historical Context
{}

## Concurrent Events
{}

## Recent Configuration Changes
{}

## Service Dependencies
{}

Please provide:
1. Root cause analysis (considering historical patterns)
2. Possible triggers (based on concurrent events)
3. Fix recommendations (prioritized)
4. Prevention measures
"#,
        context.current.service_name,
        context.current.message,
        context.current.severity,
        context.current.timestamp.format("%Y-%m-%d %H:%M:%S"),
        format_historical_errors(&context.historical_similar),
        format_concurrent_events(&context.concurrent_events),
        format_config_changes(&context.recent_config_changes),
        format_dependency_chain(&context.dependency_chain),
    )
}

/// Build enriched prompt for performance evaluation
pub fn build_performance_prompt(
    service_name: &str,
    metrics: &str,
    context: &EnrichedContext,
) -> String {
    format!(
        r#"You are Agus performance analysis assistant. Please analyze the following metrics:

## Service: {}

## Current Metrics
{}

## Recent Events
{}

## Recent Configuration Changes
{}

Please provide:
1. Performance bottleneck identification
2. Trend analysis
3. Optimization recommendations
4. Capacity planning suggestions
"#,
        service_name,
        metrics,
        format_concurrent_events(&context.concurrent_events),
        format_config_changes(&context.recent_config_changes),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use agus_context_engine::models::ErrorSeverity;
    use chrono::Utc;
    use std::collections::HashMap;

    #[test]
    fn test_format_historical_errors() {
        let errors = vec![HistoricalError {
            id: "err-1".to_string(),
            service_name: "web-api".to_string(),
            message: "Connection timeout".to_string(),
            timestamp: Utc::now(),
            resolution: Some("Restarted service".to_string()),
            resolution_time: Some(Utc::now()),
            similarity_score: Some(0.95),
        }];

        let formatted = format_historical_errors(&errors);
        assert!(formatted.contains("Connection timeout"));
        assert!(formatted.contains("Restarted service"));
        assert!(formatted.contains("95%"));
    }

    #[test]
    fn test_build_diagnosis_prompt() {
        let context = EnrichedContext {
            current: ErrorContext {
                service_name: "web-api".to_string(),
                message: "Database connection failed".to_string(),
                timestamp: Utc::now(),
                severity: ErrorSeverity::High,
                metadata: HashMap::new(),
            },
            historical_similar: vec![],
            concurrent_events: vec![],
            recent_config_changes: vec![],
            dependency_chain: vec![],
        };

        let prompt = build_diagnosis_prompt(&context);
        assert!(prompt.contains("Database connection failed"));
        assert!(prompt.contains("Root cause analysis"));
    }
}
