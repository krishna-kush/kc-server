/// Binary management handlers - Upload, check access, manage binaries
use actix_web::{web, HttpResponse, Error};
use actix_multipart::Multipart;
use futures::StreamExt;
use mongodb::Database;
use mongodb::bson::doc;
use uuid::Uuid;
use std::path::PathBuf;
use chrono::Utc;

use crate::models::{Binary, UpdateAccessRequest, BinaryDetailsResponse, License, MergeTask};
use crate::services::{BinaryPatcher, AccessControlService, ProgressSubscriber};
use crate::services::license_patcher;
use crate::overload::network::{AccessCheckRequest, AccessCheckResponse};
use crate::security::generate_shared_secret;
use crate::utils::get_overload_path;
use actix_web::HttpRequest;

/// Upload a binary (no license creation, no merge)
/// Just store the binary and return binary_id
pub async fn upload_binary(
    req: HttpRequest,
    mut payload: Multipart,
    db: web::Data<Database>,
    progress_subscriber: web::Data<ProgressSubscriber>,
) -> Result<HttpResponse, Error> {
    let mut binary_data: Option<Vec<u8>> = None;
    let mut filename = String::from("binary.bin");
    let mut user_id = String::from("anonymous"); // TODO: Get from auth middleware
    let mut description: Option<String> = None;
    
    // Parse multipart form data
    while let Some(item) = payload.next().await {
        let mut field = item?;
        let content_disposition = field.content_disposition();
        let field_name = content_disposition.get_name().unwrap_or("");
        
        match field_name {
            "binary" => {
                if let Some(fname) = content_disposition.get_filename() {
                    filename = fname.to_string();
                }
                let mut data = Vec::new();
                while let Some(chunk) = field.next().await {
                    data.extend_from_slice(&chunk?);
                }
                binary_data = Some(data);
            }
            "user_id" => {
                let mut data = Vec::new();
                while let Some(chunk) = field.next().await {
                    data.extend_from_slice(&chunk?);
                }
                user_id = String::from_utf8_lossy(&data).to_string();
            }
            "description" => {
                let mut data = Vec::new();
                while let Some(chunk) = field.next().await {
                    data.extend_from_slice(&chunk?);
                }
                let desc = String::from_utf8_lossy(&data).to_string();
                if !desc.is_empty() {
                    description = Some(desc);
                }
            }
            _ => {}
        }
    }
    
    let user_binary = binary_data.ok_or_else(|| {
        actix_web::error::ErrorBadRequest("Missing binary file")
    })?;
    
    let original_size = user_binary.len() as u64;
    
    // Generate unique binary ID
    let binary_id = format!("bin_{}", Uuid::new_v4().simple());
    
    log::info!("📦 Uploading binary: {} ({}) - {} bytes", filename, binary_id, original_size);
    
    // Prepare upload directory
    let upload_dir = PathBuf::from("/app/uploads");
    std::fs::create_dir_all(&upload_dir)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    
    // Detect binary architecture
    let arch = crate::utils::Architecture::detect_from_binary(&user_binary);
    log::info!("🔍 Detected architecture: {}", arch.as_str());
    
    // Save user binary
    let binary_path = upload_dir.join(format!("{}_original", binary_id));
    std::fs::write(&binary_path, &user_binary)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    
    // Create Binary record in database
    let binary_record = Binary {
        id: None,
        binary_id: binary_id.clone(),
        user_id: user_id.clone(),
        original_name: filename.clone(),
        description,
        original_size,
        wrapped_size: 0, // No wrapped binary yet
        file_path: binary_path.to_string_lossy().to_string(),
        status: "uploaded".to_string(),
        is_active: true,
        access_policy: crate::models::AccessPolicy::Always,
        grace_period: None,
        stats: crate::models::BinaryStats::default(),
        architecture: Some(arch.as_str().to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    
    let binary_collection = db.collection::<Binary>("binaries");
    binary_collection.insert_one(&binary_record).await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    
    log::info!("✅ Binary saved: {} - {}", binary_id, filename);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "binary_id": binary_id,
        "message": "Binary uploaded successfully. Create a license to use it.",
    })))
}

/// Response from Weaver merge endpoint
#[derive(Debug, serde::Deserialize)]
struct WeaverMergeResponse {
    success: bool,
    binary_id: String,
    size: u64,
    download_url: String,
    expires_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Merge binaries using Weaver service
async fn merge_with_weaver(
    weaver_url: &str,
    binary_id: &str,
    overload_path: &PathBuf,
    user_binary_path: &PathBuf,
) -> Result<Vec<u8>, String> {
    let client = reqwest::Client::new();
    
    let overload_bytes = std::fs::read(overload_path)
        .map_err(|e| format!("Failed to read overload: {}", e))?;
    
    let user_bytes = std::fs::read(user_binary_path)
        .map_err(|e| format!("Failed to read user binary: {}", e))?;
    
    let overload_size = overload_bytes.len();
    let user_size = user_bytes.len();
    
    log::info!("🔗 Calling Weaver to merge binary: {} (overload: {} bytes, base: {} bytes)", 
        binary_id, overload_size, user_size);
    
    // Match the format used by the working merge handler (exactly)
    let form = reqwest::multipart::Form::new()
        .part("base_binary", reqwest::multipart::Part::bytes(user_bytes)
            .file_name("base"))
        .part("overload_binary", reqwest::multipart::Part::bytes(overload_bytes)
            .file_name("overload"))
        .text("mode", "before")
        .text("task_id", binary_id.to_string());
        // Note: Not sending "sync" field - weaver defaults to async, but that's fine
    
    let response = client
        .post(format!("{}/merge", weaver_url))
        .multipart(form)
        .send()
        .await
        .map_err(|e| format!("Weaver request failed: {}", e))?;
    
    let status = response.status();
    if !status.is_success() {
        // Read error body before logging to ensure we capture it
        let error_body = response.text().await.unwrap_or_else(|_| "Unable to read error response".to_string());
        log::error!("❌ Weaver returned error {}: {}", status, error_body);
        eprintln!("Weaver error {}: {}", status, error_body); // Also print to stderr for immediate visibility
        return Err(format!("Weaver returned error {}: {}", status, error_body));
    }
    
    log::info!("✅ Weaver merge request accepted (status: {})", status);
    
    // Parse the merge response to get weaver's binary_id
    let merge_response: WeaverMergeResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse Weaver response: {}", e))?;
    
    if !merge_response.success {
        return Err(format!(
            "Weaver merge failed: {}",
            merge_response.error.unwrap_or_else(|| "Unknown error".to_string())
        ));
    }
    
    let weaver_binary_id = merge_response.binary_id;
    log::info!("✅ Weaver merge completed, binary_id: {}", weaver_binary_id);
    
    // Fetch merged artifact from Weaver download endpoint using weaver's binary_id
    let download_url = format!("{}/download/{}", weaver_url, weaver_binary_id);
    log::info!("⬇️  Fetching merged artifact from Weaver: {}", download_url);

    let dl_resp = reqwest::get(&download_url)
        .await
        .map_err(|e| format!("Weaver download request failed: {}", e))?;

    if !dl_resp.status().is_success() {
        return Err(format!(
            "Weaver download returned error: {}",
            dl_resp.status()
        ));
    }

    let bytes = dl_resp
        .bytes()
        .await
        .map_err(|e| format!("Failed to read Weaver download body: {}", e))?;

    if bytes.is_empty() {
        return Err("Downloaded merged artifact is empty".to_string());
    }

    log::info!("✅ Downloaded merged binary: {} bytes", bytes.len());
    Ok(bytes.to_vec())
}

/// Forward merge request to weaver without downloading (async mode)
async fn forward_merge_to_weaver(
    weaver_url: &str,
    task_id: &str,
    overload_path: &PathBuf,
    user_binary_path: &PathBuf,
    sync_mode: bool,
) -> Result<(), String> {
    let client = reqwest::Client::new();
    
    let overload_bytes = std::fs::read(overload_path)
        .map_err(|e| format!("Failed to read overload: {}", e))?;
    
    let user_bytes = std::fs::read(user_binary_path)
        .map_err(|e| format!("Failed to read user binary: {}", e))?;
    
    log::info!(
        "🔗 Forwarding merge request to Weaver (stop-on-exit): task_id={}, sync_mode={}",
        task_id,
        sync_mode
    );
    
    // Always use stop-on-exit endpoint (parent monitors base and kills overload when base exits)
    // The sync_mode parameter is no longer used in stop-on-exit - overload always does continuous checking
    // but the parent wrapper will kill it when base exits
    let form = reqwest::multipart::Form::new()
        .part("base_binary", reqwest::multipart::Part::bytes(user_bytes)
            .file_name("base"))
        .part("overload_binary", reqwest::multipart::Part::bytes(overload_bytes)
            .file_name("overload"))
        .text("task_id", task_id.to_string());
    
    let response = client
        .post(format!("{}/merge/stop-on-exit", weaver_url))
        .multipart(form)
        .send()
        .await
        .map_err(|e| format!("Weaver request failed: {}", e))?;
    
    let status = response.status();
    if !status.is_success() {
        let error_body = response.text().await.unwrap_or_else(|_| "Unable to read error".to_string());
        return Err(format!("Weaver returned error {}: {}", status, error_body));
    }
    
    log::info!("✅ Weaver accepted merge request: {}", task_id);
    Ok(())
}

/// V2: Forward merge request to weaver with advanced health monitoring
async fn forward_merge_to_weaver_v2(
    weaver_url: &str,
    task_id: &str,
    overload_path: &PathBuf,
    user_binary_path: &PathBuf,
    grace_period: i32,
    sync_mode: bool,
    network_failure_kill_count: u32,
) -> Result<String, String> {
    let client = reqwest::Client::new();
    
    let overload_bytes = std::fs::read(overload_path)
        .map_err(|e| format!("Failed to read overload: {}", e))?;
    
    let user_bytes = std::fs::read(user_binary_path)
        .map_err(|e| format!("Failed to read user binary: {}", e))?;
    
    log::info!(
        "🔗 Forwarding V2 merge request to Weaver: task_id={}, grace_period={}s, sync={}, failure_threshold={}",
        task_id,
        grace_period,
        sync_mode,
        network_failure_kill_count
    );
    
    // Use V2 endpoint with advanced features
    let form = reqwest::multipart::Form::new()
        .part("base_binary", reqwest::multipart::Part::bytes(user_bytes)
            .file_name("base"))
        .part("overload_binary", reqwest::multipart::Part::bytes(overload_bytes)
            .file_name("overload"))
        .text("task_id", task_id.to_string())
        .text("grace_period", grace_period.to_string())
        .text("sync_mode", sync_mode.to_string())
        .text("network_failure_kill_count", network_failure_kill_count.to_string());
    
    let response = client
        .post(format!("{}/merge/v2/stop-on-exit", weaver_url))
        .multipart(form)
        .send()
        .await
        .map_err(|e| format!("Weaver V2 request failed: {}", e))?;
    
    let status = response.status();
    if !status.is_success() {
        let error_body = response.text().await.unwrap_or_else(|_| "Unable to read error".to_string());
        return Err(format!("Weaver V2 returned error {}: {}", status, error_body));
    }
    
    // Parse response to get download URL
    let response_json: WeaverMergeResponse = response.json().await
        .map_err(|e| format!("Failed to parse weaver response: {}", e))?;
    
    if !response_json.success {
        return Err(response_json.error.unwrap_or_else(|| "Unknown error".to_string()));
    }
    
    log::info!("✅ Weaver V2 merge complete: {}", task_id);
    
    // Return full URL for download
    Ok(format!("{}{}", weaver_url, response_json.download_url))
}

/// Check access for a binary execution
pub async fn check_access(
    request: web::Json<AccessCheckRequest>,
    db: web::Data<Database>,
) -> Result<HttpResponse, Error> {
    match AccessControlService::check_access(&db, &request).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(e) => {
            log::error!("Access check error: {}", e);
            Ok(HttpResponse::Ok().json(AccessCheckResponse {
                allowed: false,
                should_delete: false,
                message: format!("Server error: {}", e),
            }))
        }
    }
}

/// Get binary details
pub async fn get_binary(
    binary_id: web::Path<String>,
    db: web::Data<Database>,
) -> Result<HttpResponse, Error> {
    let collection = db.collection::<Binary>("binaries");
    
    let binary = collection
        .find_one(doc! { "binary_id": binary_id.as_str() })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    
    match binary {
        Some(b) => {
            let response: BinaryDetailsResponse = b.into();
            Ok(HttpResponse::Ok().json(response))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Binary not found"
        }))),
    }
}

/// Update binary access settings
pub async fn update_binary(
    binary_id: web::Path<String>,
    update: web::Json<UpdateAccessRequest>,
    db: web::Data<Database>,
) -> Result<HttpResponse, Error> {
    let collection = db.collection::<Binary>("binaries");
    
    let now = mongodb::bson::DateTime::now();
    let mut update_doc = doc! {
        "$set": {
            "updated_at": now,
        }
    };
    
    if let Some(is_active) = update.is_active {
        update_doc.get_document_mut("$set").unwrap()
            .insert("is_active", is_active);
    }
    
    if let Some(ref policy) = update.access_policy {
        update_doc.get_document_mut("$set").unwrap()
            .insert("access_policy", mongodb::bson::to_bson(policy)
                .map_err(|e| actix_web::error::ErrorInternalServerError(e))?);
    }
    
    if let Some(grace_period) = update.grace_period {
        update_doc.get_document_mut("$set").unwrap()
            .insert("grace_period", mongodb::bson::to_bson(&grace_period)
                .map_err(|e| actix_web::error::ErrorInternalServerError(e))?);
    }
    
    let result = collection
        .update_one(doc! { "binary_id": binary_id.as_str() }, update_doc)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    
    if result.matched_count == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Binary not found"
        })));
    }
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Binary updated successfully"
    })))
}

/// Download wrapped binary
/// Download binary merged with license (on-demand merge)
/// GET /api/v1/binary/{binary_id}/download?license_id={license_id}
pub async fn download_binary(
    binary_id: web::Path<String>,
    query: web::Query<std::collections::HashMap<String, String>>,
    db: web::Data<Database>,
) -> Result<HttpResponse, Error> {
    // Get license_id from query params
    let license_id = query.get("license_id")
        .ok_or_else(|| actix_web::error::ErrorBadRequest("Missing license_id query parameter"))?;
    
    log::info!("Download request for binary {} with license {}", binary_id, license_id);
    
    // Load binary from database
    let binary_collection = db.collection::<Binary>("binaries");
    let binary = binary_collection
        .find_one(doc! { "binary_id": binary_id.as_str() })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?
        .ok_or_else(|| actix_web::error::ErrorNotFound("Binary not found"))?;
    
    // Load license from database
    let license_collection = db.collection::<License>("licenses");
    let license = license_collection
        .find_one(doc! { "license_id": license_id })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?
        .ok_or_else(|| actix_web::error::ErrorNotFound("License not found"))?;
    
    // Verify license belongs to this binary
    if license.binary_id != *binary_id {
        return Err(actix_web::error::ErrorBadRequest("License does not match binary"));
    }
    
    // Check if merged binary is cached
    let cache_path = PathBuf::from(format!("/app/uploads/{}_{}_merged", binary_id, license_id));
    
    if cache_path.exists() {
        log::info!("✅ Serving cached merged binary: {}", cache_path.display());
        let binary_bytes = std::fs::read(&cache_path)
            .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to read cached binary: {}", e)))?;
        
        return Ok(HttpResponse::Ok()
            .content_type("application/octet-stream")
            .insert_header((
                "Content-Disposition",
                format!("attachment; filename=\"{}\"", binary.original_name),
            ))
            .body(binary_bytes));
    }
    
    // Not cached, perform on-demand merge
    log::info!("🔨 Merging binary {} with license {} on-demand", binary_id, license_id);
    
    // Load original binary
    let original_binary_path = PathBuf::from(&binary.file_path);
    let user_binary = std::fs::read(&original_binary_path)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to read binary: {}", e)))?;
    
    // Get overload template for architecture
    let arch = crate::utils::Architecture::from_str(
        binary.architecture.as_deref().unwrap_or("x86_64")
    );
    let base_dir = std::path::Path::new("/app/overload_bins");
    let overload_template_path = crate::utils::get_latest_overload(base_dir, arch)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    
    // Create license config
    let server_url = std::env::var("SERVER_URL")
        .unwrap_or_else(|_| "http://localhost:8080".to_string());
    
    let license_config = serde_json::json!({
        "license_id": license.license_id,
        "server_url": server_url,
        "shared_secret": license.shared_secret,
        "check_interval_ms": license.check_interval_ms,
        "self_destruct": true,
        "kill_method": format!("{:?}", license.kill_method).to_lowercase(),
        "log_level": "info",
    });
    
    // Copy and patch overload
    let temp_overload_path = PathBuf::from(format!("/app/uploads/{}_{}_overload_temp", binary_id, license_id));
    std::fs::copy(&overload_template_path, &temp_overload_path)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    
    crate::services::license_patcher::patch_license_into_binary(
        temp_overload_path.to_str().unwrap(),
        &license_config.to_string(),
    ).map_err(|e| actix_web::error::ErrorInternalServerError(format!("License patching failed: {}", e)))?;
    
    let patched_overload = std::fs::read(&temp_overload_path)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    std::fs::remove_file(&temp_overload_path).ok();
    
    // Save temporarily for weaver
    let temp_user_binary_path = PathBuf::from(format!("/app/uploads/{}_{}_original_temp", binary_id, license_id));
    let temp_overload_final_path = PathBuf::from(format!("/app/uploads/{}_{}_overload_final", binary_id, license_id));
    
    std::fs::write(&temp_user_binary_path, &user_binary)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    std::fs::write(&temp_overload_final_path, &patched_overload)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    
    // Call weaver to merge
    let weaver_url = std::env::var("WEAVER_URL")
        .unwrap_or_else(|_| "http://weaver:8080".to_string());
    
    let merge_result = forward_merge_to_weaver_v2(
        &weaver_url,
        binary_id.as_str(),
        &temp_overload_final_path,
        &temp_user_binary_path,
        license.grace_period,
        license.sync_mode,
        license.network_failure_kill_count,
    ).await;
    
    // Cleanup temp files
    std::fs::remove_file(&temp_user_binary_path).ok();
    std::fs::remove_file(&temp_overload_final_path).ok();
    
    match merge_result {
        Ok(download_url) => {
            // Fetch merged binary from weaver
            let client = reqwest::Client::new();
            let response = client.get(&download_url).send().await
                .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to fetch merged binary: {}", e)))?;
            
            let binary_bytes = response.bytes().await
                .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to read binary: {}", e)))?;
            
            // Cache the merged binary
            std::fs::write(&cache_path, &binary_bytes).ok();
            
            log::info!("✅ Merged binary cached: {}", cache_path.display());
            
            Ok(HttpResponse::Ok()
                .content_type("application/octet-stream")
                .insert_header((
                    "Content-Disposition",
                    format!("attachment; filename=\"{}\"", binary.original_name),
                ))
                .body(binary_bytes.to_vec()))
        }
        Err(e) => {
            log::error!("❌ Failed to merge binary: {}", e);
            Err(actix_web::error::ErrorInternalServerError(format!("Merge failed: {}", e)))
        }
    }
}

/// Get execution history for a binary
pub async fn get_executions(
    binary_id: web::Path<String>,
    db: web::Data<Database>,
) -> Result<HttpResponse, Error> {
    let executions = AccessControlService::get_executions(&db, &binary_id, 100)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    
    Ok(HttpResponse::Ok().json(executions))
}

/// List all binaries for a user with search and pagination
#[derive(serde::Deserialize)]
pub struct ListBinariesQuery {
    search: Option<String>,
    page: Option<i64>,
    per_page: Option<i64>,
    status: Option<String>,
    sort_by: Option<String>,
    sort_order: Option<String>,
}

pub async fn list_binaries(
    db: web::Data<Database>,
    query: web::Query<ListBinariesQuery>,
    // TODO: Get user_id from auth middleware
) -> Result<HttpResponse, Error> {
    use futures::stream::StreamExt;
    
    let collection = db.collection::<Binary>("binaries");
    
    // Build filter
    let mut filter = doc! {};
    
    // Search by filename
    if let Some(search) = &query.search {
        if !search.is_empty() {
            filter.insert("original_name", doc! {
                "$regex": search,
                "$options": "i" // case-insensitive
            });
        }
    }
    
    // Filter by status
    if let Some(status) = &query.status {
        if !status.is_empty() {
            filter.insert("status", status);
        }
    }
    
    // Pagination
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(10).min(100).max(1);
    let skip = (page - 1) * per_page;
    
    // Get total count
    let total = collection.count_documents(filter.clone()).await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    
    // Build sort document
    let sort_field = query.sort_by.as_deref().unwrap_or("created_at");
    let sort_order = match query.sort_order.as_deref() {
        Some("asc") => 1,
        _ => -1, // Default to descending
    };
    
    // Map frontend field names to database field names
    let db_field = match sort_field {
        "name" => "original_name",
        "size" => "size",
        "created" => "created_at",
        "licenses" => "license_count", // Note: This is calculated, will need special handling
        _ => "created_at",
    };
    
    let sort_doc = doc! { db_field: sort_order };
    
    // Query with pagination
    let options = mongodb::options::FindOptions::builder()
        .sort(sort_doc)
        .skip(skip as u64)
        .limit(per_page)
        .build();
    
    let mut cursor = collection
        .find(filter)
        .with_options(options)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    
    let licenses_collection = db.collection::<License>("licenses");
    
    let mut binaries = Vec::new();
    while let Some(result) = cursor.next().await {
        match result {
            Ok(binary) => {
                // Count licenses for this binary
                let license_count = licenses_collection
                    .count_documents(doc! { "binary_id": &binary.binary_id })
                    .await
                    .unwrap_or(0);
                
                let mut response: BinaryDetailsResponse = binary.into();
                response.license_count = license_count;
                binaries.push(response);
            }
            Err(e) => log::error!("Error reading binary: {}", e),
        }
    }
    
    // Sort by licenses if requested (in-memory sort since it's a calculated field)
    if sort_field == "licenses" {
        binaries.sort_by(|a, b| {
            if sort_order == 1 {
                a.license_count.cmp(&b.license_count)
            } else {
                b.license_count.cmp(&a.license_count)
            }
        });
    }
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "binaries": binaries,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total as f64 / per_page as f64).ceil() as i64,
    })))
}

/// Delete a binary and its associated files
/// DELETE /binary/{id}
pub async fn delete_binary(
    binary_id: web::Path<String>,
    db: web::Data<Database>,
) -> Result<HttpResponse, Error> {
    let binary_id = binary_id.into_inner();
    
    log::info!("🗑️  Deleting binary: {}", binary_id);
    
    // Fetch binary to get file path
    let collection = db.collection::<Binary>("binaries");
    let binary = collection
        .find_one(doc! { "binary_id": &binary_id })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    
    if let Some(binary) = binary {
        // Delete file from disk if it exists
        if !binary.file_path.is_empty() {
            if let Err(e) = std::fs::remove_file(&binary.file_path) {
                log::warn!("Failed to delete binary file {}: {}", binary.file_path, e);
            } else {
                log::info!("✅ Deleted file: {}", binary.file_path);
            }
        }
        
        // Delete from database
        collection
            .delete_one(doc! { "binary_id": &binary_id })
            .await
            .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
        
        // Also delete associated licenses
        let license_collection = db.collection::<License>("licenses");
        let delete_result = license_collection
            .delete_many(doc! { "binary_id": &binary_id })
            .await
            .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
        
        log::info!("✅ Deleted binary {} and {} associated licenses", binary_id, delete_result.deleted_count);
        
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Binary deleted successfully",
            "binary_id": binary_id,
            "licenses_deleted": delete_result.deleted_count,
        })))
    } else {
        Err(actix_web::error::ErrorNotFound("Binary not found"))
    }
}
