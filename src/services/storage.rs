use std::path::{Path, PathBuf};
use mongodb::Database;
use mongodb::bson::doc;
use actix_web::error::ErrorInternalServerError;

pub struct StorageService;

pub enum StorageType {
    Original,
    Merged,
}

impl StorageService {
    pub fn get_upload_root() -> String {
        std::env::var("UPLOAD_DIR").unwrap_or_else(|_| "/app/uploads".to_string())
    }

    /// Get the root directory for a user's uploads
    pub fn get_user_dir(user_id: &str) -> PathBuf {
        Path::new(&Self::get_upload_root()).join(user_id)
    }

    /// Get the directory for base binaries
    pub fn get_base_dir(user_id: &str) -> PathBuf {
        Self::get_user_dir(user_id).join("bin").join("base")
    }

    /// Get the directory for license (merged) binaries
    pub fn get_license_dir(user_id: &str) -> PathBuf {
        Self::get_user_dir(user_id).join("bin").join("license")
    }

    /// Get the full path for an original binary
    pub fn get_original_binary_path(user_id: &str, binary_id: &str) -> PathBuf {
        Self::get_base_dir(user_id).join(format!("{}_original", binary_id))
    }

    /// Get the full path for an overload template (stored alongside original)
    pub fn get_overload_path(user_id: &str, binary_id: &str) -> PathBuf {
        Self::get_base_dir(user_id).join(format!("{}_overload", binary_id))
    }

    /// Get the full path for a merged binary
    pub fn get_merged_binary_path(user_id: &str, binary_id: &str, license_id: &str) -> PathBuf {
        Self::get_license_dir(user_id).join(format!("{}_{}_merged", binary_id, license_id))
    }

    /// Ensure the directory structure exists for a file path
    pub async fn ensure_dir(path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        Ok(())
    }

    /// Update user storage statistics
    pub async fn update_storage_stats(
        db: &Database,
        user_id: &str,
        delta: u64,
        storage_type: StorageType,
        is_addition: bool,
    ) -> Result<(), actix_web::Error> {
        let delta_i64 = delta as i64;
        let change = if is_addition { delta_i64 } else { -delta_i64 };

        let update = match storage_type {
            StorageType::Original => doc! {
                "$inc": {
                    "storage_used": change,
                    "storage_original": change
                }
            },
            StorageType::Merged => doc! {
                "$inc": {
                    "storage_used": change,
                    "storage_merged": change
                }
            },
        };

        let oid = mongodb::bson::oid::ObjectId::parse_str(user_id)
            .map_err(|e| {
                log::error!("Invalid user_id format for storage update: {}", user_id);
                ErrorInternalServerError(format!("Invalid user_id: {}", e))
            })?;

        let result = db.collection::<crate::models::User>("users")
            .update_one(
                doc! { "_id": oid },
                update,
            )
            .await
            .map_err(|e| {
                log::error!("Database error updating storage stats: {}", e);
                ErrorInternalServerError(e)
            })?;

        if result.matched_count == 0 {
            log::warn!("User not found for storage update: {}", user_id);
        }

        Ok(())
    }
}
