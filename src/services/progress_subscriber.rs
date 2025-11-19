use redis::AsyncCommands;
use mongodb::{Collection, Database, bson::doc};
use serde::{Deserialize, Serialize};
use crate::models::{MergeTask, Binary, AccessPolicy, BinaryStats};
use futures::StreamExt;
use chrono::Utc;

#[derive(Debug, Deserialize, Serialize)]
pub struct ProgressUpdate {
    pub percentage: u8,
    pub message: String,
    pub updated_at: i64,
    #[serde(default)]
    pub complete: bool,
    pub binary_id: Option<String>,
    pub download_url: Option<String>,
    pub error: Option<String>,
    pub wrapped_size: Option<u64>,
}

#[derive(Clone)]
pub struct ProgressSubscriber {
    redis_url: String,
    mongo_collection: Collection<MergeTask>,
    db: Database,
}

impl ProgressSubscriber {
    pub fn new(redis_url: String, mongo_collection: Collection<MergeTask>, db: Database) -> Self {
        Self { redis_url, mongo_collection, db }
    }

    pub async fn subscribe_to_task(&self, task_id: String) -> Result<(), Box<dyn std::error::Error>> {
        let client = redis::Client::open(self.redis_url.as_str())?;
        let mut pubsub = client.get_async_connection().await?.into_pubsub();
        
        let channel = format!("progress:{}", task_id);
        pubsub.subscribe(&channel).await?;
        
        let redis_url = self.redis_url.clone();
        let collection = self.mongo_collection.clone();
        let db = self.db.clone();
        let task_id_clone = task_id.clone();

        tokio::spawn(async move {
            let mut stream = pubsub.on_message();
            
            log::info!("📡 Subscribed to progress updates for task: {}", task_id_clone);
            
            while let Some(msg) = stream.next().await {
                let payload: String = match msg.get_payload() {
                    Ok(p) => p,
                    Err(e) => {
                        log::error!("Failed to get payload: {}", e);
                        continue;
                    }
                };
                
                if let Ok(update) = serde_json::from_str::<ProgressUpdate>(&payload) {
                    log::info!("📊 Progress update: {}% - {}", update.percentage, update.message);
                    
                    // Update MongoDB
                    let _ = collection.update_one(
                        doc! { "task_id": &task_id_clone },
                        doc! {
                            "$set": {
                                "progress_percentage": update.percentage as i32,
                                "progress_message": &update.message,
                                "updated_at": mongodb::bson::DateTime::now(),
                            }
                        },
                    ).await;
                    
                    // If complete, update final status
                    if update.complete {
                        let status = if update.error.is_some() { "failed" } else { "complete" };
                        log::info!("✅ Task {} completed with status: {}", task_id_clone, status);
                        
                        let _ = collection.update_one(
                            doc! { "task_id": &task_id_clone },
                            doc! {
                                "$set": {
                                    "status": status,
                                    "binary_id": &update.binary_id,
                                    "download_url": &update.download_url,
                                    "error": &update.error,
                                    "completed_at": update.complete.then(|| mongodb::bson::DateTime::now()),
                                }
                            },
                        ).await;
                        
                        // Create Binary document if merge was successful
                        if update.error.is_none() && update.binary_id.is_some() && update.download_url.is_some() {
                            if let Ok(task_doc) = collection.find_one(doc! { "task_id": &task_id_clone }).await {
                                if let Some(task) = task_doc {
                                    let binary_collection = db.collection::<Binary>("binaries");
                                    
                                    // Extract wrapped_size from update if available
                                    let wrapped_size = update.wrapped_size.unwrap_or(0);
                                    
                                    let binary = Binary {
                                        id: None,
                                        binary_id: task_id_clone.clone(), // Use task_id (with "bin_" prefix) instead of weaver's UUID
                                        user_id: task.user_id.clone(),
                                        original_name: task.base_binary_name.clone(),
                                        description: None,
                                        original_size: task.original_size,
                                        wrapped_size,
                                        file_path: update.download_url.clone().unwrap(),
                                        status: "ready".to_string(),
                                        is_active: true,
                                        access_policy: AccessPolicy::Always,
                                        grace_period: None,
                                        stats: BinaryStats::default(),
                                        architecture: None,
                                        created_at: Utc::now(),
                                        updated_at: Utc::now(),
                                    };
                                    
                                    match binary_collection.insert_one(&binary).await {
                                        Ok(_) => log::info!("✅ Created Binary document: {}", task_id_clone),
                                        Err(e) => log::error!("❌ Failed to create Binary document: {}", e),
                                    }
                                }
                            }
                        }
                        
                        // Give the SSE handler a moment to pick up the final message
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

                        log::info!("🔌 Unsubscribing from task: {}", task_id_clone);
                        break;
                    }
                }
            }
        });
        
        Ok(())
    }
}
