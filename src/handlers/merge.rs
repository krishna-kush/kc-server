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
    user_id: web::ReqData<String>,
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
        let field_name = content_disposition.map_or("", |cd| cd.get_name().unwrap_or(""));
        
        match field_name {
            "base_binary" => {
                if let Some(filename) = content_disposition.and_then(|cd| cd.get_filename()) {
                    base_name = filename.to_string();
                }
                let mut data = Vec::new();
                while let Some(chunk) = field.next().await {
                    data.extend_from_slice(&chunk?);
                }
                base_binary = Some(data);
            }
            "overload_binary" => {
                if let Some(filename) = content_disposition.and_then(|cd| cd.get_filename()) {
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
        user_id.into_inner(),
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
    user_id: web::ReqData<String>,
) -> Result<HttpResponse, Error> {
    use mongodb::bson::Bson;
    
    let collection = db.collection::<mongodb::bson::Document>("merge_tasks");
    
    let doc = collection
        .find_one(mongodb::bson::doc! { "task_id": task_id.as_str(), "user_id": user_id.into_inner() })
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
            // Return local proxy URL
            let full_download_url = Some(format!("/merge/{}/download", task_id));
            
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "task_id": task_id,
                "status": status,
                "percentage": percentage,
                "message": message,
                "binary_id": binary_id,
                "download_url": format!("/merge/{}/download", task_id),
                "error": error,
            })))
        },
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Task not found"
        }))),
    }
}

pub async fn download_merged_binary(
    task_id: web::Path<String>,
    db: web::Data<Database>,
    user_id: web::ReqData<String>,
) -> Result<HttpResponse, Error> {
    let collection = db.collection::<mongodb::bson::Document>("merge_tasks");
    
    // Verify ownership and get binary_id/download_url
    let doc = collection
        .find_one(mongodb::bson::doc! { "task_id": task_id.as_str(), "user_id": user_id.into_inner() })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?
        .ok_or_else(|| actix_web::error::ErrorNotFound("Task not found"))?;
        
    let binary_id = doc.get_str("binary_id").ok();
    let download_url = doc.get_str("download_url").ok();
    
    if binary_id.is_none() && download_url.is_none() {
        return Ok(HttpResponse::NotFound().body("Binary not ready"));
    }
    
    // Construct Weaver URL
    // If we have binary_id, use /download/{id}
    // If we have download_url (relative), use that
    let weaver_url = std::env::var("WEAVER_URL")
        .unwrap_or_else(|_| "http://weaver:8080".to_string());
        
    let target_url = if let Some(bid) = binary_id {
        format!("{}/download/{}", weaver_url, bid)
    } else {
        format!("{}{}", weaver_url, download_url.unwrap())
    };
    
    // Proxy request to Weaver
    let client = reqwest::Client::new();
    let resp = client.get(&target_url)
        .send()
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to connect to weaver: {}", e)))?;
        
    if !resp.status().is_success() {
        return Ok(HttpResponse::build(actix_web::http::StatusCode::from_u16(resp.status().as_u16()).unwrap())
            .body("Failed to fetch binary from weaver"));
    }
    
    let content_type = resp.headers().get("content-type")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
        
    let content_disposition = resp.headers().get("content-disposition")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
        
    let mut builder = HttpResponse::Ok();
    builder.content_type(content_type);
    
    if let Some(cd) = content_disposition {
        builder.insert_header(("Content-Disposition", cd));
    }
    
    // Stream response
    let stream = resp.bytes_stream().map(|item| {
        item.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    });
    
    Ok(builder.streaming(stream))
}
