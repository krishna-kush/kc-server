use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};
use mongodb::bson::DateTime;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MergeTask {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub task_id: String,
    pub user_id: String,
    pub status: String, // "pending", "processing", "complete", "failed"
    pub binary_id: Option<String>,
    pub download_url: Option<String>,
    pub error: Option<String>,
    pub progress_percentage: u8,
    pub progress_message: String,
    pub base_binary_name: String,
    pub overload_binary_name: String,
    pub mode: String, // "before" or "after"
    pub original_size: u64,
    pub wrapped_size: Option<u64>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
    pub completed_at: Option<DateTime>,
}

impl MergeTask {
    pub fn new(task_id: String, user_id: String, base_name: String, overload_name: String, mode: String, original_size: u64) -> Self {
        Self {
            id: None,
            task_id,
            user_id,
            status: "pending".to_string(),
            binary_id: None,
            download_url: None,
            error: None,
            progress_percentage: 0,
            progress_message: "Queued".to_string(),
            base_binary_name: base_name,
            overload_binary_name: overload_name,
            mode,
            original_size,
            wrapped_size: None,
            created_at: DateTime::now(),
            updated_at: DateTime::now(),
            completed_at: None,
        }
    }
}
