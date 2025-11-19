/// Telemetry and monitoring endpoints for verification tracking
use actix_web::{web, HttpResponse, Error};
use mongodb::{bson::doc, Database};
use chrono::{Utc, Duration};

use crate::models::{
    VerificationAttempt, VerificationHistoryResponse, VerificationAttemptSummary,
    DashboardStats, LicenseActivity, License,
};

/// Get verification history for a specific license
/// GET /api/v1/telemetry/license/{license_id}/history
pub async fn get_license_history(
    license_id: web::Path<String>,
    query: web::Query<HistoryQuery>,
    db: web::Data<Database>,
) -> Result<HttpResponse, Error> {
    let limit = query.limit.unwrap_or(100).min(1000);
    let skip = query.skip.unwrap_or(0);
    
    let collection = db.collection::<VerificationAttempt>("verification_attempts");
    
    // Get total count
    let total_attempts = collection
        .count_documents(doc! { "license_id": license_id.as_str() })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))? as usize;
    
    // Get attempts with pagination
    let mut cursor = collection
        .find(doc! { "license_id": license_id.as_str() })
        .sort(doc! { "timestamp": -1 })
        .skip(skip)
        .limit(limit as i64)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    let mut attempts = Vec::new();
    while cursor.advance().await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))? {
        let attempt = cursor.deserialize_current()
            .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Deserialization error: {}", e)))?;
        attempts.push(VerificationAttemptSummary::from(attempt));
    }
    
    // Calculate statistics
    let successful_attempts = collection
        .count_documents(doc! { 
            "license_id": license_id.as_str(),
            "success": true
        })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))? as usize;
    
    let failed_attempts = total_attempts - successful_attempts;
    
    // Get last successful verification timestamp
    let last_verified_at = if let Ok(Some(last_attempt)) = collection
        .find_one(doc! { 
            "license_id": license_id.as_str(),
            "success": true
        })
        .sort(doc! { "timestamp": -1 })
        .await
    {
        Some(last_attempt.timestamp)
    } else {
        None
    };
    
    Ok(HttpResponse::Ok().json(VerificationHistoryResponse {
        license_id: license_id.to_string(),
        total_attempts,
        successful_attempts,
        failed_attempts,
        last_verified_at,
        attempts,
    }))
}

/// Get dashboard statistics
/// GET /api/v1/telemetry/dashboard
pub async fn get_dashboard_stats(
    db: web::Data<Database>,
) -> Result<HttpResponse, Error> {
    let license_collection = db.collection::<License>("licenses");
    let attempt_collection = db.collection::<VerificationAttempt>("verification_attempts");
    
    // License statistics
    let total_licenses = license_collection
        .count_documents(doc! {})
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    let active_licenses = license_collection
        .count_documents(doc! { "revoked": false })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    let revoked_licenses = license_collection
        .count_documents(doc! { "revoked": true })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    // Verification statistics
    let total_verifications = attempt_collection
        .count_documents(doc! {})
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    let successful_verifications = attempt_collection
        .count_documents(doc! { "success": true })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    let failed_verifications = total_verifications - successful_verifications;
    
    // Last 24 hours
    let yesterday = Utc::now() - Duration::hours(24);
    let verifications_last_24h = attempt_collection
        .count_documents(doc! {
            "timestamp": { "$gte": yesterday.to_rfc3339() }
        })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    // Most active licenses (top 10 by verification count)
    let pipeline = vec![
        doc! {
            "$group": {
                "_id": "$license_id",
                "binary_id": { "$first": "$binary_id" },
                "count": { "$sum": 1 },
                "last_verified": { "$max": "$timestamp" }
            }
        },
        doc! {
            "$sort": { "count": -1 }
        },
        doc! {
            "$limit": 10
        }
    ];
    
    let mut cursor = attempt_collection
        .aggregate(pipeline)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    let mut most_active_licenses = Vec::new();
    while cursor.advance().await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))? {
        let doc = cursor.current();
        
        let license_id = doc.get_str("_id").unwrap_or("").to_string();
        let binary_id = doc.get_str("binary_id").unwrap_or("").to_string();
        let count = doc.get_i64("count").unwrap_or(0);
        let last_verified_str = doc.get_str("last_verified").ok();
        
        let last_verified_at = last_verified_str
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));
        
        most_active_licenses.push(LicenseActivity {
            license_id,
            binary_id,
            verification_count: count,
            last_verified_at,
        });
    }
    
    Ok(HttpResponse::Ok().json(DashboardStats {
        total_licenses: total_licenses as i64,
        active_licenses: active_licenses as i64,
        revoked_licenses: revoked_licenses as i64,
        total_verifications: total_verifications as i64,
        successful_verifications: successful_verifications as i64,
        failed_verifications: failed_verifications as i64,
        verifications_last_24h: verifications_last_24h as i64,
        most_active_licenses,
    }))
}

/// Query parameters for history endpoint
#[derive(Debug, serde::Deserialize)]
pub struct HistoryQuery {
    pub limit: Option<u64>,
    pub skip: Option<u64>,
}

/// Get verification attempts for a specific binary with pagination
/// GET /api/v1/binary/{binary_id}/verification-attempts
pub async fn get_binary_verification_attempts(
    binary_id: web::Path<String>,
    query: web::Query<HistoryQuery>,
    db: web::Data<Database>,
) -> Result<HttpResponse, Error> {
    let limit = query.limit.unwrap_or(20).min(100);
    let skip = query.skip.unwrap_or(0);
    
    let collection = db.collection::<VerificationAttempt>("verification_attempts");
    
    // Get total count for this binary
    let total = collection
        .count_documents(doc! { "binary_id": binary_id.as_str() })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))? as i64;
    
    // Get attempts with pagination
    let mut cursor = collection
        .find(doc! { "binary_id": binary_id.as_str() })
        .sort(doc! { "timestamp": -1 })
        .skip(skip)
        .limit(limit as i64)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    let mut attempts = Vec::new();
    while cursor.advance().await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))? {
        let attempt = cursor.deserialize_current()
            .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Deserialization error: {}", e)))?;
        attempts.push(VerificationAttemptSummary::from(attempt));
    }
    
    let page = (skip / limit) + 1;
    let total_pages = (total as f64 / limit as f64).ceil() as i64;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "attempts": attempts,
        "pagination": {
            "total": total,
            "page": page,
            "per_page": limit,
            "total_pages": total_pages,
        }
    })))
}
