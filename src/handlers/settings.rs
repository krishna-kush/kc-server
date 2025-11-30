use actix_web::{web, HttpResponse, Error};
use mongodb::Database;
use mongodb::bson::doc;
use futures::StreamExt;
use serde::{Deserialize, Serialize};

use crate::models::{User, Binary, License};
use crate::services::storage::{StorageService, StorageType};

#[derive(Debug, Serialize)]
pub struct StorageStats {
    pub storage_used: u64,
    pub storage_quota: u64,
    pub usage_percentage: f64,
    pub binaries_count: u64,
    pub licenses_count: u64,
    pub files: FileBreakdown,
}

#[derive(Debug, Serialize)]
pub struct FileBreakdown {
    pub original_binaries: u64,
    pub merged_binaries: u64,
}

#[derive(Debug, Serialize)]
pub struct CleanupRecommendations {
    pub licenses: Vec<StorageItem>,
    pub binaries: Vec<StorageItem>,
}

#[derive(Debug, Serialize)]
pub struct StorageItem {
    pub id: String,
    pub name: String,
    pub size: u64,
    pub last_active: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize)]
pub struct LicenseCleanupItem {
    pub license_id: String,
    pub binary_name: String,
    pub last_verified: Option<chrono::DateTime<chrono::Utc>>,
    pub size: u64,
}

#[derive(Debug, Serialize)]
pub struct BinaryCleanupItem {
    pub binary_id: String,
    pub name: String,
    pub size: u64,
}

/// Get storage statistics for the current user
/// GET /settings/storage
pub async fn get_storage_stats(
    db: web::Data<Database>,
    user_id: web::ReqData<String>,
) -> Result<HttpResponse, Error> {
    let user_id = user_id.into_inner();
    log::info!("Getting storage stats for user: {}", user_id);
    
    // Get user to check current storage usage
    let user = db
        .collection::<User>("users")
        .find_one(doc! { "_id": mongodb::bson::oid::ObjectId::parse_str(&user_id).unwrap() })
        .await
        .map_err(|e| {
            log::error!("Database error fetching user: {}", e);
            actix_web::error::ErrorInternalServerError(e)
        })?
        .ok_or_else(|| {
            log::error!("User not found: {}", user_id);
            actix_web::error::ErrorNotFound("User not found")
        })?;
        
    log::info!("User found, storage_used: {}", user.storage_used);

    let quota: u64 = std::env::var("FREE_STORAGE_QUOTA")
        .unwrap_or_else(|_| "5368709120".to_string())
        .parse()
        .unwrap_or(5368709120);
        
    log::info!("Quota: {}", quota);

    // Get counts
    let binaries_count = db
        .collection::<Binary>("binaries")
        .count_documents(doc! { "user_id": &user_id })
        .await
        .unwrap_or(0);
        
    let licenses_count = db
        .collection::<License>("licenses")
        .count_documents(doc! { "user_id": &user_id })
        .await
        .unwrap_or(0);

    log::info!("Counts - Binaries: {}, Licenses: {}", binaries_count, licenses_count);

    let original_size = user.storage_original.max(0) as u64;
    let merged_size = user.storage_merged.max(0) as u64;
    
    log::info!("Breakdown - Original: {}, Merged: {}", original_size, merged_size);

    let storage_used = user.storage_used.max(0) as u64;

    Ok(HttpResponse::Ok().json(StorageStats {
        storage_used,
        storage_quota: quota,
        usage_percentage: (storage_used as f64 / quota as f64) * 100.0,
        binaries_count,
        licenses_count,
        files: FileBreakdown {
            original_binaries: original_size,
            merged_binaries: merged_size,
        },
    }))
}

/// Delete all licenses for a user
/// DELETE /settings/delete-all-licenses
pub async fn delete_all_licenses(
    db: web::Data<Database>,
    user_id: web::ReqData<String>,
) -> Result<HttpResponse, Error> {
    let freed = delete_licenses_internal(&db, &user_id.into_inner()).await?;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "All licenses deleted successfully",
        "freed_bytes": freed,
    })))
}

/// Internal helper to delete licenses
async fn delete_licenses_internal(db: &Database, user_id: &str) -> Result<u64, Error> {
    let collection = db.collection::<License>("licenses");
    
    // Find all licenses for this user to get binary_ids
    let mut cursor = collection
        .find(doc! { "user_id": user_id })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
        
    let mut total_freed = 0;
    
    while let Some(license) = cursor.next().await {
        if let Ok(license) = license {
            // Delete merged binary file
            let merged_path = StorageService::get_merged_binary_path(user_id, &license.binary_id, &license.license_id);
            if let Ok(metadata) = tokio::fs::metadata(&merged_path).await {
                total_freed += metadata.len();
                let _ = tokio::fs::remove_file(merged_path).await;
            }
        }
    }
    
    // Delete all licenses
    collection
        .delete_many(doc! { "user_id": user_id })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
        
    // Update storage
    if total_freed > 0 {
        StorageService::update_storage_stats(db, user_id, total_freed, StorageType::Merged, false).await?;
    }
    
    Ok(total_freed)
}

/// Delete all binaries (and licenses) for a user
/// DELETE /settings/delete-all-binaries
pub async fn delete_all_binaries(
    db: web::Data<Database>,
    user_id: web::ReqData<String>,
) -> Result<HttpResponse, Error> {
    let user_id = user_id.into_inner();
    
    // 1. Delete all licenses first (and their merged files)
    let licenses_freed = delete_licenses_internal(&db, &user_id).await?;
    
    // 2. Delete all original binaries
    let collection = db.collection::<Binary>("binaries");
    let mut cursor = collection
        .find(doc! { "user_id": &user_id })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
        
    let mut binaries_freed = 0;
    
    while let Some(binary) = cursor.next().await {
        if let Ok(binary) = binary {
            // Use DB size for quota freeing
            binaries_freed += binary.original_size;

            // Delete original binary file
            let path = StorageService::get_original_binary_path(&user_id, &binary.binary_id);
            if path.exists() {
                let _ = tokio::fs::remove_file(path).await;
            }
            
            // Also delete overload template
            let overload_path = StorageService::get_overload_path(&user_id, &binary.binary_id);
            if let Ok(_) = tokio::fs::metadata(&overload_path).await {
                let _ = tokio::fs::remove_file(overload_path).await;
            }
        }
    }
    
    // Delete all binaries from DB
    collection
        .delete_many(doc! { "user_id": &user_id })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
        
    // Update storage for binaries
    if binaries_freed > 0 {
        StorageService::update_storage_stats(&db, &user_id, binaries_freed, StorageType::Original, false).await?;
    }
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "All binaries and licenses deleted successfully",
        "freed_bytes": licenses_freed + binaries_freed,
    })))
}

pub async fn get_cleanup_recommendations(
    db: web::Data<Database>,
    user_id: web::ReqData<String>,
) -> Result<HttpResponse, Error> {
    let user_id = user_id.into_inner();
    
    // Fetch all binaries
    let binary_collection = db.collection::<Binary>("binaries");
    let mut binary_cursor = binary_collection
        .find(doc! { "user_id": &user_id })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
        
    let mut all_binaries = Vec::new();
    while let Some(binary) = binary_cursor.next().await {
        if let Ok(binary) = binary {
            all_binaries.push(binary);
        }
    }

    // Fetch all licenses
    let license_collection = db.collection::<License>("licenses");
    let mut license_cursor = license_collection
        .find(doc! { "user_id": &user_id })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
        
    let mut all_licenses = Vec::new();
    while let Some(license) = license_cursor.next().await {
        if let Ok(license) = license {
            all_licenses.push(license);
        }
    }

    // Calculate last active date for binaries based on their licenses
    let mut binary_last_active: std::collections::HashMap<String, Option<chrono::DateTime<chrono::Utc>>> = std::collections::HashMap::new();
    
    for license in &all_licenses {
        if let Some(last_check) = license.last_check_at {
            let entry = binary_last_active.entry(license.binary_id.clone()).or_insert(None);
            match entry {
                Some(current_max) => {
                    if last_check > *current_max {
                        *entry = Some(last_check);
                    }
                }
                None => {
                    *entry = Some(last_check);
                }
            }
        }
    }

    // Build Binaries List
    let mut binaries = Vec::new();
    for binary in &all_binaries {
        let last_active = binary_last_active.get(&binary.binary_id).cloned().flatten();
        binaries.push(StorageItem {
            id: binary.binary_id.clone(),
            name: binary.original_name.clone(),
            size: binary.original_size,
            last_active,
        });
    }

    // Build Licenses List
    let mut licenses = Vec::new();
    for license in &all_licenses {
        // Get binary name
        let binary_name = all_binaries.iter()
            .find(|b| b.binary_id == license.binary_id)
            .map(|b| b.original_name.clone())
            .unwrap_or_else(|| "Unknown Binary".to_string());

        // Get merged size
        let merged_path = StorageService::get_merged_binary_path(&user_id, &license.binary_id, &license.license_id);
        let size = if let Ok(metadata) = tokio::fs::metadata(&merged_path).await {
            metadata.len()
        } else {
            0
        };

        if size > 0 {
            licenses.push(StorageItem {
                id: license.license_id.clone(),
                name: format!("{} (License)", binary_name),
                size,
                last_active: license.last_check_at,
            });
        }
    }

    Ok(HttpResponse::Ok().json(CleanupRecommendations {
        licenses,
        binaries,
    }))
}
