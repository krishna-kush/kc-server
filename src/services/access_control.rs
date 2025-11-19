/// Access control service - Handles access checks and execution logging
use crate::models::{Binary, Execution};
use crate::overload::network::{AccessCheckRequest, AccessCheckResponse};
use mongodb::Database;
use mongodb::bson::doc;

pub struct AccessControlService;

impl AccessControlService {
    /// Check if a binary should be allowed to execute
    pub async fn check_access(
        db: &Database,
        request: &AccessCheckRequest,
    ) -> Result<AccessCheckResponse, String> {
        // Find the binary
        let collection = db.collection::<Binary>("binaries");
        let binary = collection
            .find_one(doc! { "binary_id": &request.binary_id })
            .await
            .map_err(|e| format!("Database error: {}", e))?;
        
        let binary = match binary {
            Some(b) => b,
            None => {
                log::warn!("❌ Binary not found: {}", request.binary_id);
                return Ok(AccessCheckResponse {
                    allowed: false,
                    should_delete: true,
                    message: "Binary not registered".to_string(),
                });
            }
        };
        
        // Check policy
        let allowed = binary.check_policy();
        
        // Log execution
        let execution = Execution::new(
            binary.binary_id.clone(),
            binary.user_id.clone(),
            request.hostname.clone(),
            request.os_info.name.clone(),
            request.os_info.version.clone(),
            allowed,
        );
        
        let exec_collection = db.collection::<Execution>("executions");
        if let Err(e) = exec_collection.insert_one(&execution).await {
            log::error!("Failed to log execution: {}", e);
        }
        
        // Update binary statistics
        if allowed {
            Self::update_stats(db, &binary.binary_id).await;
        }
        
        // Prepare response
        let (message, should_delete) = if !allowed {
            if !binary.is_active {
                ("Binary has been deactivated".to_string(), true)
            } else {
                ("Access policy not satisfied".to_string(), false)
            }
        } else {
            ("Access granted".to_string(), false)
        };
        
        log::info!(
            "Access check: {} - {} (allowed: {})",
            request.binary_id,
            request.hostname,
            allowed
        );
        
        Ok(AccessCheckResponse {
            allowed,
            should_delete,
            message,
        })
    }
    
    /// Update binary statistics after successful execution
    async fn update_stats(db: &Database, binary_id: &str) {
        let collection = db.collection::<Binary>("binaries");
        
        let now = mongodb::bson::DateTime::now();
        let update = doc! {
            "$inc": { "stats.total_executions": 1 },
            "$set": { "stats.last_execution": now },
        };
        
        if let Err(e) = collection
            .update_one(doc! { "binary_id": binary_id }, update)
            .await
        {
            log::error!("Failed to update stats for {}: {}", binary_id, e);
        }
    }
    
    /// Get execution history for a binary
    pub async fn get_executions(
        db: &Database,
        binary_id: &str,
        limit: i64,
    ) -> Result<Vec<Execution>, String> {
        use futures::stream::StreamExt;
        
        let collection = db.collection::<Execution>("executions");
        
        let options = mongodb::options::FindOptions::builder()
            .sort(doc! { "timestamp": -1 })
            .limit(limit)
            .build();
        
        let mut cursor = collection
            .find(doc! { "binary_id": binary_id })
            .with_options(options)
            .await
            .map_err(|e| format!("Database error: {}", e))?;
        
        let mut executions = Vec::new();
        while let Some(result) = cursor.next().await {
            match result {
                Ok(execution) => executions.push(execution),
                Err(e) => log::error!("Error reading execution: {}", e),
            }
        }
        
        Ok(executions)
    }
}
