//! Enhanced LLM provider with embedding support
//!
//! Extends existing LLM providers to support embedding generation

use super::{LlmError, LlmProvider};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Extended LLM provider with embedding support
#[async_trait]
pub trait EmbeddingProvider: LlmProvider {
    /// Generate embedding for text
    async fn generate_embedding(&self, text: &str) -> Result<Vec<f32>, LlmError>;
    
    /// Generate embeddings for multiple texts (batch)
    async fn generate_embeddings_batch(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, LlmError> {
        let mut embeddings = Vec::new();
        for text in texts {
            let embedding = self.generate_embedding(text).await?;
            embeddings.push(embedding);
        }
        Ok(embeddings)
    }
}

#[derive(Debug, Serialize)]
struct OpenAIEmbeddingRequest {
    input: String,
    model: String,
}

#[derive(Debug, Deserialize)]
struct OpenAIEmbeddingResponse {
    data: Vec<OpenAIEmbeddingData>,
}

#[derive(Debug, Deserialize)]
struct OpenAIEmbeddingData {
    embedding: Vec<f32>,
}

/// OpenAI provider with embedding support
pub struct OpenAIEmbeddingProvider {
    api_key: String,
    client: reqwest::Client,
    embedding_model: String,
}

impl OpenAIEmbeddingProvider {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            client: reqwest::Client::new(),
            embedding_model: "text-embedding-3-small".to_string(),
        }
    }
}

#[async_trait]
impl EmbeddingProvider for OpenAIEmbeddingProvider {
    async fn generate_embedding(&self, text: &str) -> Result<Vec<f32>, LlmError> {
        let url = "https://api.openai.com/v1/embeddings";
        
        let request = OpenAIEmbeddingRequest {
            input: text.to_string(),
            model: self.embedding_model.clone(),
        };
        
        let response = self.client
            .post(url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| LlmError::ApiError {
                message: format!("Failed to call OpenAI embedding API: {}", e),
            })?;
        
        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(LlmError::ApiError {
                message: format!("OpenAI embedding API error {}: {}", status, error_text),
            });
        }
        
        let embedding_response: OpenAIEmbeddingResponse = response.json().await
            .map_err(|e| LlmError::ParseError {
                message: format!("Failed to parse OpenAI embedding response: {}", e),
            })?;
        
        embedding_response.data
            .first()
            .map(|d| d.embedding.clone())
            .ok_or_else(|| LlmError::ApiError {
                message: "No embedding returned from OpenAI".to_string(),
            })
    }
}

// Implement LlmProvider trait (placeholder - would use existing OpenAI provider logic)
#[async_trait]
impl LlmProvider for OpenAIEmbeddingProvider {
    async fn diagnose_error(&self, _context: &str) -> Result<String, LlmError> {
        // Would delegate to existing OpenAI provider
        Ok("Diagnosis not implemented in embedding provider".to_string())
    }
    
    async fn evaluate_performance(&self, _metrics: &str) -> Result<String, LlmError> {
        Ok("Performance evaluation not implemented in embedding provider".to_string())
    }
    
    async fn analyze_dependencies(&self, _graph: &str) -> Result<String, LlmError> {
        Ok("Dependency analysis not implemented in embedding provider".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    #[ignore] // Requires OpenAI API key
    async fn test_openai_embedding() {
        let api_key = std::env::var("OPENAI_API_KEY").unwrap();
        let provider = OpenAIEmbeddingProvider::new(api_key);
        
        let embedding = provider.generate_embedding("test message").await.unwrap();
        assert!(!embedding.is_empty());
        assert_eq!(embedding.len(), 1536); // text-embedding-3-small dimension
    }
}
