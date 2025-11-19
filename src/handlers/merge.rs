use actix_web::{web, HttpResponse, Error};
use actix_multipart::Multipart;
use futures::StreamExt;
use uuid::Uuid;
use mongodb::Database;
use crate::models::MergeTask;
use crate::services::ProgressSubscriber;

pub async fn merge_binaries(
    mut payload: Multipart,
    db: web::Data<Database>,
    progress_subscriber: web::Data<ProgressSubscriber>,
) -> Result<HttpResponse, Error> {
    let mut base_binary: Option<Vec<u8>> = None;
    let mut overload_binary: Option<Vec<u8>> = None;
    let mut base_name = String::from("base.bin");
    let mut overload_name = String::from("overload.bin");
    let mut mode = String::from("before");
    
    // Parse multipart form data
    while let Some(item) = payload.next().await {
        let mut field = item?;
        let content_disposition = field.content_disposition();
        let field_name = content_disposition.get_name().unwrap_or("");
        
        match field_name {
            "base_binary" => {
                if let Some(filename) = content_disposition.get_filename() {
                    base_name = filename.to_string();
                }
                let mut data = Vec::new();
                while let Some(chunk) = field.next().await {
                    data.extend_from_slice(&chunk?);
                }
                base_binary = Some(data);
            }
            "overload_binary" => {
                if let Some(filename) = content_disposition.get_filename() {
                    overload_name = filename.to_string();
                }
                let mut data = Vec::new();
                while let Some(chunk) = field.next().await {
                    data.extend_from_slice(&chunk?);
                }
                overload_binary = Some(data);
            }
            "mode" => {
                let mut data = Vec::new();
                while let Some(chunk) = field.next().await {
                    data.extend_from_slice(&chunk?);
                }
                mode = String::from_utf8_lossy(&data).to_string();
            }
            _ => {}
        }
    }
    
    let base_data = base_binary.ok_or_else(|| {
        actix_web::error::ErrorBadRequest("Missing base_binary")
    })?;
    
    let overload_data = overload_binary.ok_or_else(|| {
        actix_web::error::ErrorBadRequest("Missing overload_binary")
    })?;
    
    let base_size = base_data.len() as u64;
    
    // Create task in MongoDB
    let task_id = Uuid::new_v4().to_string();
    let merge_task = MergeTask::new(
        task_id.clone(),
        "anonymous".to_string(), // TODO: Get from auth
        base_name.clone(),
        overload_name.clone(),
        mode.clone(),
        base_size,
    );
    
    let collection = db.collection::<MergeTask>("merge_tasks");
    collection.insert_one(merge_task).await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    
    log::info!("📝 Created merge task: {}", task_id);
    
    // Subscribe to progress updates
    progress_subscriber.subscribe_to_task(task_id.clone()).await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    
    // Forward to Weaver
    let weaver_url = std::env::var("WEAVER_URL")
        .unwrap_or_else(|_| "http://weaver:8080".to_string());
    
    let task_id_clone = task_id.clone();
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        
        let form = reqwest::multipart::Form::new()
            .part("base_binary", reqwest::multipart::Part::bytes(base_data)
                .file_name(base_name))
            .part("overload_binary", reqwest::multipart::Part::bytes(overload_data)
                .file_name(overload_name))
            .text("mode", mode)
            .text("task_id", task_id_clone.clone());
        
        log::info!("🚀 Forwarding merge request to Weaver: {}", task_id_clone);
        
        match client
            .post(format!("{}/merge", weaver_url))
            .multipart(form)
            .send()
            .await
        {
            Ok(resp) => {
                log::info!("✅ Weaver accepted task: {} (status: {})", task_id_clone, resp.status());
            }
            Err(e) => {
                log::error!("❌ Failed to forward to Weaver: {}", e);
            }
        }
    });
    
    // Return immediately
    Ok(HttpResponse::Accepted().json(serde_json::json!({
        "task_id": task_id,
        "progress_url": format!("/progress/{}", task_id),
        "progress_stream": format!("/progress/{}/stream", task_id),
        "message": "Merge request accepted. Use progress_url to poll or progress_stream for real-time updates."
    })))
}

pub async fn get_progress(
    task_id: web::Path<String>,
    db: web::Data<Database>,
) -> Result<HttpResponse, Error> {
    use mongodb::bson::Bson;
    
    let collection = db.collection::<mongodb::bson::Document>("merge_tasks");
    
    let doc = collection
        .find_one(mongodb::bson::doc! { "task_id": task_id.as_str() })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    
    match doc {
        Some(d) => {
            // Extract fields manually to handle DateTime conversion
            let task_id = d.get_str("task_id").unwrap_or("");
            let status = d.get_str("status").unwrap_or("unknown");
            let percentage = d.get_i32("progress_percentage").unwrap_or(0) as u8;
            let message = d.get_str("progress_message").unwrap_or("");
            let binary_id = d.get_str("binary_id").ok();
            let download_url = d.get_str("download_url").ok();
            let error = d.get_str("error").ok();
            
            // Build full download URL with external weaver URL if relative path
            let full_download_url = if let Some(url) = download_url {
                if url.starts_with("http") {
                    // Already absolute URL
                    Some(url.to_string())
                } else {
                    // Relative URL from weaver - use external-facing weaver URL
                    // WEAVER_EXTERNAL_URL for user-facing downloads (e.g., http://localhost:8081 or https://killcode.app/api/weaver)
                    // Falls back to WEAVER_URL if not set
                    let weaver_external = std::env::var("WEAVER_EXTERNAL_URL")
                        .or_else(|_| std::env::var("WEAVER_URL"))
                        .unwrap_or_else(|_| "http://localhost:8081".to_string());
                    Some(format!("{}{}", weaver_external, url))
                }
            } else {
                None
            };
            
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "task_id": task_id,
                "status": status,
                "percentage": percentage,
                "message": message,
                "binary_id": binary_id,
                "download_url": full_download_url,
                "error": error,
            })))
        },
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Task not found"
        }))),
    }
}
