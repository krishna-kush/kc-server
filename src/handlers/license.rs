/// License management and verification endpoints
use actix_web::{web, HttpRequest, HttpResponse, Error};
use mongodb::{Database, bson::doc};
use validator::Validate;
use chrono::{Utc, Duration};
use uuid::Uuid;
use serde::Deserialize;

use crate::models::{
    License, CreateLicenseRequest, CreateLicenseResponse,
    UpdateLicenseRequest, LicenseDetailsResponse,
    VerifyRequest, VerifyResponse, VerificationAttempt,
    InstanceStatus, Binary, BinaryInstance, LicenseListItem,
};
use crate::security::{
    verify_signature, validate_timestamp, generate_shared_secret,
    construct_signature_data,
};

/// Create a new license for a binary
/// POST /api/v1/license/create
pub async fn create_license(
    req: web::Json<CreateLicenseRequest>,
    db: web::Data<Database>,
    user_id: web::ReqData<String>,
) -> Result<HttpResponse, Error> {
    // Validate request
    req.validate()
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Validation error: {}", e)))?;
    
    let uid = user_id.into_inner();
    
    // Generate unique license ID and shared secret
    let license_id = format!("lic_{}", Uuid::new_v4().simple());
    let shared_secret = generate_shared_secret();
    
    log::info!("Creating license {} for binary {}", license_id, req.binary_id);
    
    // Create license
    let mut license = License::new(
        license_id.clone(),
        req.binary_id.clone(),
        uid.clone(),
        shared_secret,
    );
    
    // Verify binary exists and belongs to user
    let binary_collection = db.collection::<crate::models::Binary>("binaries");
    let binary = binary_collection
        .find_one(doc! { "binary_id": &req.binary_id, "user_id": &uid })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?
        .ok_or_else(|| actix_web::error::ErrorNotFound("Binary not found"))?;
    
    // Set optional fields
    if let Some(license_type) = &req.license_type {
        license.license_type = license_type.clone();
    }
    
    if let Some(sync_mode) = req.sync_mode {
        license.sync_mode = sync_mode;
        // If sync mode, set check_interval_ms to 0
        if sync_mode {
            license.check_interval_ms = 0;
        }
    }
    
    if let Some(check_interval_ms) = req.check_interval_ms {
        license.check_interval_ms = check_interval_ms;
    }
    
    if let Some(max_execs) = req.max_executions {
        license.max_executions = Some(max_execs);
    }
    
    if let Some(expires_in) = req.expires_in_seconds {
        license.expires_at = Some(Utc::now() + Duration::seconds(expires_in));
    }
    
    if let Some(machines) = &req.allowed_machines {
        license.allowed_machines = machines.clone();
    }
    
    if let Some(grace_period) = req.grace_period {
        license.grace_period = grace_period;
    }
    
    if let Some(network_failure_kill_count) = req.network_failure_kill_count {
        license.network_failure_kill_count = network_failure_kill_count;
    }
    
    if let Some(ref kill_method) = req.kill_method {
        license.kill_method = kill_method.clone();
    }
    
    // Save to database
    let collection = db.collection::<License>("licenses");
    collection.insert_one(&license)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    log::info!("✅ License created: {} for binary {}", license_id, req.binary_id);
    
    // Return response (note: download will trigger merge)
    Ok(HttpResponse::Created().json(CreateLicenseResponse {
        license_id: license.license_id.clone(),
        binary_id: license.binary_id.clone(),
        created_at: license.created_at,
        expires_at: license.expires_at,
        max_executions: license.max_executions,
        download_url: format!("/api/v1/binary/{}/download?license_id={}", license.binary_id, license.license_id),
    }))
}

/// Verify license authorization (called by overload binary)
/// POST /api/v1/verify
/// 
/// Headers:
/// - X-License-ID: License identifier
/// - X-Timestamp: Unix timestamp
/// - X-Signature: HMAC-SHA256(license_id + timestamp, shared_secret)
pub async fn verify_license(
    req: HttpRequest,
    body: web::Json<VerifyRequest>,
    db: web::Data<Database>,
) -> Result<HttpResponse, Error> {
    // Extract headers
    let license_id = req.headers()
        .get("X-License-ID")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| actix_web::error::ErrorBadRequest("Missing X-License-ID header"))?;
    
    let timestamp_str = req.headers()
        .get("X-Timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| actix_web::error::ErrorBadRequest("Missing X-Timestamp header"))?;
    
    let timestamp: i64 = timestamp_str.parse()
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid timestamp format"))?;
    
    let signature = req.headers()
        .get("X-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| actix_web::error::ErrorBadRequest("Missing X-Signature header"))?;
    
    // Validate timestamp (prevent replay attacks)
    if !validate_timestamp(timestamp) {
        log::warn!("❌ Timestamp validation failed for license: {}", license_id);
        return Ok(HttpResponse::Unauthorized().json(VerifyResponse {
            authorized: false,
            message: "Request timestamp outside valid window".to_string(),
            expires_in: None,
            check_interval_ms: None,
            kill_method: None,
        }));
    }
    
    // Fetch license from database
    let collection = db.collection::<License>("licenses");
    let license = collection
        .find_one(doc! { "license_id": license_id })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?
        .ok_or_else(|| {
            log::warn!("❌ License not found: {}", license_id);
            actix_web::error::ErrorNotFound("License not found")
        })?;
    
    // Verify HMAC signature
    let signature_data = construct_signature_data(license_id, timestamp);
    if !verify_signature(&signature_data, &license.shared_secret, signature) {
        log::warn!("❌ Invalid signature for license: {}", license_id);
        
        // Increment failed attempts and check grace period
        let new_failed_attempts = license.failed_attempts + 1;
        collection.update_one(
            doc! { "license_id": license_id },
            doc! { 
                "$set": { 
                    "failed_attempts": new_failed_attempts,
                    "updated_at": Utc::now().to_rfc3339(),
                }
            },
        )
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
        
        log::info!(
            "⚠️  Failed attempts: {}/{} (grace_period) for license: {}",
            new_failed_attempts,
            license.grace_period,
            license_id
        );
        
        // If within grace period, return unauthorized but allow process to continue
        let should_kill = license.grace_period == 0 || new_failed_attempts > license.grace_period;
        let within_grace_period = !should_kill;
        
        // Log verification attempt
        let ip_address = req.peer_addr()
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        
        let attempt = VerificationAttempt::new(
            license_id.to_string(),
            license.binary_id.clone(),
            false,
            body.machine_fingerprint.clone(),
            ip_address,
            Some("Invalid signature".to_string()),
            new_failed_attempts,
            license.grace_period,
            within_grace_period,
        );
        
        let attempt_collection = db.collection::<VerificationAttempt>("verification_attempts");
        let _ = attempt_collection.insert_one(&attempt).await;
        
        return Ok(HttpResponse::Unauthorized().json(VerifyResponse {
            authorized: !should_kill,
            message: if should_kill {
                "Invalid signature - grace period exceeded".to_string()
            } else {
                format!("Invalid signature - {} attempts remaining", license.grace_period - new_failed_attempts + 1)
            },
            expires_in: None,
            check_interval_ms: None,
            kill_method: None,
        }));
    }
    
    // Check if license is valid
    if !license.is_valid() {
        let message = if license.revoked {
            "License has been revoked"
        } else {
            "License has expired"
        };
        
        log::info!("❌ License invalid: {} - {}", license_id, message);
        
        // Log verification attempt
        let ip_address = req.peer_addr()
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        
        let attempt = VerificationAttempt::new(
            license_id.to_string(),
            license.binary_id.clone(),
            false,
            body.machine_fingerprint.clone(),
            ip_address,
            Some(message.to_string()),
            license.failed_attempts,
            license.grace_period,
            false,
        );
        
        let attempt_collection = db.collection::<VerificationAttempt>("verification_attempts");
        let _ = attempt_collection.insert_one(&attempt).await;
        
        return Ok(HttpResponse::Ok().json(VerifyResponse {
            authorized: false,
            message: message.to_string(),
            expires_in: None,
            check_interval_ms: None,
            kill_method: None,
        }));
    }
    
    // Check execution limits
    if !license.can_execute() {
        log::info!("❌ Execution limit reached for license: {}", license_id);
        
        // Log verification attempt
        let ip_address = req.peer_addr()
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        
        let attempt = VerificationAttempt::new(
            license_id.to_string(),
            license.binary_id.clone(),
            false,
            body.machine_fingerprint.clone(),
            ip_address,
            Some("Execution limit reached".to_string()),
            license.failed_attempts,
            license.grace_period,
            false,
        );
        
        let attempt_collection = db.collection::<VerificationAttempt>("verification_attempts");
        let _ = attempt_collection.insert_one(&attempt).await;
        
        return Ok(HttpResponse::Ok().json(VerifyResponse {
            authorized: false,
            message: "Execution limit reached".to_string(),
            expires_in: None,
            check_interval_ms: None,
            kill_method: None,
        }));
    }
    
    // Check machine restrictions
    if !license.is_machine_allowed(&body.machine_fingerprint) {
        log::warn!(
            "❌ Machine not allowed for license {}: {}",
            license_id,
            body.machine_fingerprint
        );
        
        // Log verification attempt
        let ip_address = req.peer_addr()
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        
        let attempt = VerificationAttempt::new(
            license_id.to_string(),
            license.binary_id.clone(),
            false,
            body.machine_fingerprint.clone(),
            ip_address,
            Some("Machine not authorized".to_string()),
            license.failed_attempts,
            license.grace_period,
            false,
        );
        
        let attempt_collection = db.collection::<VerificationAttempt>("verification_attempts");
        let _ = attempt_collection.insert_one(&attempt).await;
        
        return Ok(HttpResponse::Ok().json(VerifyResponse {
            authorized: false,
            message: "Machine not authorized".to_string(),
            expires_in: None,
            check_interval_ms: None,
            kill_method: None,
        }));
    }
    
    // Get client IP address
    let ip_address = req.peer_addr()
        .map(|addr| addr.ip().to_string());
    
    // Check if this is the first check (startup) from X-First-Check header
    let is_first_check = req.headers()
        .get("X-First-Check")
        .and_then(|v| v.to_str().ok())
        .map(|s| s == "true")
        .unwrap_or(true);  // Default to true for backward compatibility
    
    // Record execution only on first check (startup), not on interval checks
    let mut updated_license = license.clone();
    if is_first_check {
        updated_license.record_execution(
            Some(body.machine_fingerprint.clone()),
            ip_address.clone(),
        );
        log::info!("📊 Recorded execution {} for license {}", updated_license.executions_used, license_id);
    } else {
        // Just update last check time and fingerprint without incrementing execution count
        updated_license.last_check_at = Some(Utc::now());
        updated_license.last_machine_fingerprint = Some(body.machine_fingerprint.clone());
        updated_license.last_check_ip = ip_address.clone();
        updated_license.updated_at = Utc::now();
        log::debug!("🔄 Interval check for license {} (execution not counted)", license_id);
    }
    
    // Update in database - use string format for dates to match serde serialization
    let last_check_str = updated_license.last_check_at
        .map(|dt| dt.to_rfc3339());
    
    collection.update_one(
        doc! { "license_id": license_id },
        doc! {
            "$set": {
                "executions_used": updated_license.executions_used,
                "last_check_at": last_check_str,
                "last_machine_fingerprint": updated_license.last_machine_fingerprint.clone(),
                "last_check_ip": updated_license.last_check_ip.clone(),
                "failed_attempts": 0,  // Reset on successful verification
                "updated_at": updated_license.updated_at.to_rfc3339(),
            }
        },
    )
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    log::info!(
        "✅ License verified: {} (executions: {}/{})",
        license_id,
        updated_license.executions_used,
        updated_license.max_executions.map(|m| m.to_string()).unwrap_or("unlimited".to_string())
    );
    
    // Log successful verification attempt
    let ip_address_str = updated_license.last_check_ip
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    
    let attempt = VerificationAttempt::new(
        license_id.to_string(),
        license.binary_id.clone(),
        true,
        body.machine_fingerprint.clone(),
        ip_address_str.clone(),
        None,
        0,  // Reset to 0 on success
        license.grace_period,
        false,  // N/A for successful attempts
    );
    
    let attempt_collection = db.collection::<VerificationAttempt>("verification_attempts");
    let _ = attempt_collection.insert_one(&attempt).await;
    
    // Track binary instance (unique computer using this license)
    let instance_collection = db.collection::<crate::models::BinaryInstance>("binary_instances");
    
    // Try to find existing instance
    let existing_instance = instance_collection
        .find_one(doc! {
            "license_id": license_id,
            "machine_fingerprint": &body.machine_fingerprint
        })
        .await
        .ok()
        .flatten();
    
    if let Some(mut instance) = existing_instance {
        // Update existing instance
        instance.update_check_in(Some(ip_address_str.clone()));
        
        let _ = instance_collection.update_one(
            doc! {
                "license_id": license_id,
                "machine_fingerprint": &body.machine_fingerprint
            },
            doc! {
                "$set": {
                    "last_seen": instance.last_seen.to_rfc3339(),
                    "is_active": true,
                    "total_checks": instance.total_checks as i64,
                    "last_ip": ip_address_str.clone(),
                }
            },
        ).await;
        
        log::debug!("🔄 Updated binary instance for license {} (total_checks: {})", license_id, instance.total_checks);
    } else {
        // Create new instance
        let new_instance = crate::models::BinaryInstance::new(
            license_id.to_string(),
            license.binary_id.clone(),
            body.machine_fingerprint.clone(),
            Some(ip_address_str.clone()),
        );
        
        let _ = instance_collection.insert_one(&new_instance).await;
        
        log::info!("✨ New binary instance created for license {} on machine {}", license_id, body.machine_fingerprint);
    }
    
    // Return updated settings for patchable licenses
    let kill_method_str = match updated_license.kill_method {
        crate::models::KillMethod::Stop => "stop",
        crate::models::KillMethod::Delete => "delete",
        crate::models::KillMethod::Shred => "shred",
    };
    
    Ok(HttpResponse::Ok().json(VerifyResponse {
        authorized: true,
        message: "License valid".to_string(),
        expires_in: updated_license.expires_in_seconds(),
        check_interval_ms: Some(updated_license.check_interval_ms),
        kill_method: Some(kill_method_str.to_string()),
    }))
}

/// Get license details
/// GET /api/v1/license/{license_id}
pub async fn get_license(
    license_id: web::Path<String>,
    db: web::Data<Database>,
    user_id: web::ReqData<String>,
) -> Result<HttpResponse, Error> {
    let collection = db.collection::<License>("licenses");
    let license = collection
        .find_one(doc! { "license_id": license_id.as_str(), "user_id": user_id.into_inner() })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?
        .ok_or_else(|| actix_web::error::ErrorNotFound("License not found"))?;
    
    Ok(HttpResponse::Ok().json(LicenseDetailsResponse::from(license)))
}

/// Get license stats with instances and verification attempts
/// GET /api/v1/license/{license_id}/stats
pub async fn get_license_stats(
    license_id: web::Path<String>,
    db: web::Data<Database>,
    user_id: web::ReqData<String>,
) -> Result<HttpResponse, Error> {
    // Get license
    let license_collection = db.collection::<License>("licenses");
    let license = license_collection
        .find_one(doc! { "license_id": license_id.as_str(), "user_id": user_id.into_inner() })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?
        .ok_or_else(|| actix_web::error::ErrorNotFound("License not found"))?;
    
    // Get all binary instances for this license
    let instance_collection = db.collection::<crate::models::BinaryInstance>("binary_instances");
    let mut instances_cursor = instance_collection
        .find(doc! { "license_id": license_id.as_str() })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    use futures::stream::StreamExt;
    let mut instances = Vec::new();
    let mut active_count = 0u64;
    let mut unknown_count = 0u64;
    
    while let Some(result) = instances_cursor.next().await {
        if let Ok(instance) = result {
            let summary = crate::models::BinaryInstanceSummary::from_instance(
                instance,
                Some(license.check_interval_ms),
                license.sync_mode,
            );
            
            match summary.status {
                InstanceStatus::Active => active_count += 1,
                InstanceStatus::Unknown => unknown_count += 1,
                _ => {},
            }
            
            instances.push(summary);
        }
    }
    
    let unique_computers = instances.len() as u64;
    let inactive_count = unique_computers - active_count - unknown_count;
    
    // Get recent verification attempts (last 100)
    let attempt_collection = db.collection::<crate::models::VerificationAttempt>("verification_attempts");
    let mut attempts_cursor = attempt_collection
        .find(doc! { "license_id": license_id.as_str() })
        .sort(doc! { "timestamp": -1 })
        .limit(100)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    let mut recent_verifications = Vec::new();
    while let Some(result) = attempts_cursor.next().await {
        if let Ok(attempt) = result {
            recent_verifications.push(crate::models::VerificationAttemptSummary::from(attempt));
        }
    }
    
    Ok(HttpResponse::Ok().json(crate::models::LicenseStatsResponse {
        license: crate::models::LicenseDetailsResponse::from(license),
        unique_computers,
        active_computers: active_count,
        inactive_computers: inactive_count,
        unknown_computers: unknown_count,
        instances,
        recent_verifications,
    }))
}

/// Update license
/// PATCH /api/v1/license/{license_id}
pub async fn update_license(
    license_id: web::Path<String>,
    req: web::Json<UpdateLicenseRequest>,
    db: web::Data<Database>,
    user_id: web::ReqData<String>,
) -> Result<HttpResponse, Error> {
    
    req.validate()
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Validation error: {}", e)))?;
    
    let collection = db.collection::<License>("licenses");
    
    // Build update document - use string format for dates to match serde serialization
    let now = Utc::now().to_rfc3339();
    let mut update_doc = doc! {
        "$set": {
            "updated_at": now,
        }
    };
    
    if let Some(max_execs) = req.max_executions {
        update_doc.get_document_mut("$set")
            .unwrap()
            .insert("max_executions", max_execs);
    }
    
    if let Some(expires_in) = req.expires_in_seconds {
        let expires_at = Utc::now() + Duration::seconds(expires_in);
        let expires_str = expires_at.to_rfc3339();
        update_doc.get_document_mut("$set")
            .unwrap()
            .insert("expires_at", expires_str);
    }
    
    if let Some(machines) = &req.allowed_machines {
        update_doc.get_document_mut("$set")
            .unwrap()
            .insert("allowed_machines", machines);
    }
    
    if let Some(revoked) = req.revoked {
        update_doc.get_document_mut("$set")
            .unwrap()
            .insert("revoked", revoked);
    }
    
    if let Some(check_interval_ms) = req.check_interval_ms {
        update_doc.get_document_mut("$set")
            .unwrap()
            .insert("check_interval_ms", check_interval_ms as i64);
    }
    
    if let Some(kill_method) = &req.kill_method {
        // Serialize KillMethod to lowercase string for BSON
        let kill_method_str = match kill_method {
            crate::models::KillMethod::Stop => "stop",
            crate::models::KillMethod::Delete => "delete",
            crate::models::KillMethod::Shred => "shred",
        };
        update_doc.get_document_mut("$set")
            .unwrap()
            .insert("kill_method", kill_method_str);
    }
    
    // Update license
    let result = collection.update_one(
        doc! { "license_id": license_id.as_str(), "user_id": user_id.into_inner() },
        update_doc,
    )
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    if result.matched_count == 0 {
        return Err(actix_web::error::ErrorNotFound("License not found"));
    }
    
    log::info!("✅ License updated: {}", license_id);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "License updated successfully",
        "license_id": license_id.as_str(),
    })))
}

/// Delete (revoke) license
/// DELETE /api/v1/license/{license_id}
pub async fn delete_license(
    license_id: web::Path<String>,
    db: web::Data<Database>,
    user_id: web::ReqData<String>,
) -> Result<HttpResponse, Error> {
    
    let collection = db.collection::<License>("licenses");
    
    // Actually delete the license from the database
    let result = collection.delete_one(
        doc! { "license_id": license_id.as_str(), "user_id": user_id.into_inner() },
    )
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    if result.deleted_count == 0 {
        return Err(actix_web::error::ErrorNotFound("License not found"));
    }
    
    log::info!("✅ License deleted: {}", license_id);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "License deleted successfully",
        "license_id": license_id.as_str(),
    })))
}

/// Revoke a license immediately
/// POST /api/v1/license/{license_id}/revoke
pub async fn revoke_license(
    license_id: web::Path<String>,
    db: web::Data<Database>,
    user_id: web::ReqData<String>,
) -> Result<HttpResponse, Error> {
    let uid = user_id.into_inner();
    let collection = db.collection::<License>("licenses");
    
    // Check if license exists
    let license = collection
        .find_one(doc! { "license_id": license_id.as_str(), "user_id": &uid })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?
        .ok_or_else(|| actix_web::error::ErrorNotFound("License not found"))?;
    
    if license.revoked {
        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "License already revoked",
            "license_id": license_id.as_str(),
            "revoked": true,
        })));
    }
    
    // Revoke the license
    let now = Utc::now().to_rfc3339();
    collection.update_one(
        doc! { "license_id": license_id.as_str(), "user_id": &uid },
        doc! {
            "$set": {
                "revoked": true,
                "updated_at": &now,
            }
        },
    )
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    log::info!("⛔ License revoked: {}", license_id);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "License revoked successfully",
        "license_id": license_id.as_str(),
        "revoked": true,
        "revoked_at": now,
    })))
}

/// Get analytics for a specific binary
/// GET /api/v1/binary/{binary_id}/analytics
pub async fn get_binary_analytics(
    binary_id: web::Path<String>,
    db: web::Data<Database>,
    user_id: web::ReqData<String>,
) -> Result<HttpResponse, Error> {
    // Verify binary ownership
    let binary_collection = db.collection::<crate::models::Binary>("binaries");
    let exists = binary_collection
        .count_documents(doc! { "binary_id": binary_id.as_str(), "user_id": user_id.into_inner() })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))? > 0;
        
    if !exists {
        return Err(actix_web::error::ErrorNotFound("Binary not found"));
    }
    
    let license_collection = db.collection::<License>("licenses");
    let attempt_collection = db.collection::<VerificationAttempt>("verification_attempts");
    
    // Get license statistics for this binary
    let total_licenses = license_collection
        .count_documents(doc! { "binary_id": binary_id.as_str() })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    let active_licenses = license_collection
        .count_documents(doc! { 
            "binary_id": binary_id.as_str(),
            "revoked": false
        })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    let revoked_licenses = total_licenses - active_licenses;
    
    // Get verification statistics for this binary
    let total_verifications = attempt_collection
        .count_documents(doc! { "binary_id": binary_id.as_str() })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    let successful_verifications = attempt_collection
        .count_documents(doc! { 
            "binary_id": binary_id.as_str(),
            "success": true
        })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    let failed_verifications = total_verifications - successful_verifications;
    
    // Get unique machines that verified
    let pipeline = vec![
        doc! {
            "$match": {
                "binary_id": binary_id.as_str(),
            }
        },
        doc! {
            "$group": {
                "_id": "$machine_fingerprint",
                "count": { "$sum": 1 },
                "last_verified": { "$max": "$timestamp" }
            }
        },
        doc! {
            "$sort": { "count": -1 }
        }
    ];
    
    let mut cursor = attempt_collection
        .aggregate(pipeline)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    let mut machine_stats = Vec::new();
    use futures::stream::StreamExt;
    
    while let Some(result) = cursor.next().await {
        match result {
            Ok(doc) => {
                let machine_fingerprint = doc.get_str("_id").unwrap_or("unknown").to_string();
                let count = doc.get_i64("count").unwrap_or(0);
                let last_verified_str = doc.get_str("last_verified").ok();
                let last_verified = last_verified_str
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| dt.with_timezone(&Utc));
                
                machine_stats.push(serde_json::json!({
                    "machine_fingerprint": machine_fingerprint,
                    "verification_count": count,
                    "last_verified_at": last_verified,
                }));
            }
            Err(e) => log::error!("Error reading machine stat: {}", e),
        }
    }
    
    let unique_machines = machine_stats.len() as i64;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "binary_id": binary_id.as_str(),
        "licenses": {
            "total": total_licenses,
            "active": active_licenses,
            "revoked": revoked_licenses,
        },
        "verifications": {
            "total": total_verifications,
            "successful": successful_verifications,
            "failed": failed_verifications,
            "success_rate": if total_verifications > 0 {
                (successful_verifications as f64 / total_verifications as f64 * 100.0).round() / 100.0
            } else {
                0.0
            },
        },
        "machines": {
            "unique_count": unique_machines,
            "top_machines": machine_stats,
        }
    })))
}

/// List all licenses for a binary
/// GET /api/v1/binary/{binary_id}/licenses
pub async fn list_licenses_for_binary(
    binary_id: web::Path<String>,
    db: web::Data<Database>,
    user_id: web::ReqData<String>,
) -> Result<HttpResponse, Error> {
    // Verify binary ownership
    let binary_collection = db.collection::<crate::models::Binary>("binaries");
    let exists = binary_collection
        .count_documents(doc! { "binary_id": binary_id.as_str(), "user_id": user_id.into_inner() })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))? > 0;
        
    if !exists {
        return Err(actix_web::error::ErrorNotFound("Binary not found"));
    }
    
    let collection = db.collection::<License>("licenses");
    let mut cursor = collection
        .find(doc! { "binary_id": binary_id.as_str() })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    let mut licenses = Vec::new();
    use futures::stream::StreamExt;
    
    while let Some(result) = cursor.next().await {
        match result {
            Ok(license) => licenses.push(LicenseDetailsResponse::from(license)),
            Err(e) => log::error!("Error reading license: {}", e),
        }
    }
    
    Ok(HttpResponse::Ok().json(licenses))
}

#[derive(Debug, Deserialize)]
pub struct ListLicensesQuery {
    search: Option<String>,
    page: Option<i64>,
    per_page: Option<i64>,
    sort_by: Option<String>,
    sort_order: Option<String>,
}

/// GET /api/v1/licenses - List all licenses with pagination and sorting
pub async fn list_all_licenses(
    query: web::Query<ListLicensesQuery>,
    db: web::Data<Database>,
    user_id: web::ReqData<String>,
) -> Result<HttpResponse, Error> {
    use futures::stream::StreamExt;
    
    let licenses_collection = db.collection::<License>("licenses");
    let binaries_collection = db.collection::<Binary>("binaries");
    let instances_collection = db.collection::<BinaryInstance>("binary_instances");
    let attempts_collection = db.collection::<VerificationAttempt>("verification_attempts");
    
    // Build filter
    let mut filter = doc! { "user_id": user_id.into_inner() };
    
    // Search by license_id
    if let Some(search) = &query.search {
        if !search.is_empty() {
            filter.insert("license_id", doc! {
                "$regex": search,
                "$options": "i"
            });
        }
    }
    
    // Pagination
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(10).min(100).max(1);
    let skip = (page - 1) * per_page;
    
    // Get total count
    let total = licenses_collection.count_documents(filter.clone()).await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    
    // Build sort document
    let sort_field = query.sort_by.as_deref().unwrap_or("created_at");
    let sort_order = match query.sort_order.as_deref() {
        Some("asc") => 1,
        _ => -1,
    };
    
    let db_field = match sort_field {
        "binary" | "binary_name" => "binary_id",
        "type" => "license_type",
        "created" => "created_at",
        "expires" => "expires_at",
        "executions" => "executions_used",
        "computers" => "unique_computers", // Will sort in-memory
        "verifications" => "verification_count", // Will sort in-memory
        _ => "created_at",
    };
    
    let sort_doc = doc! { db_field: sort_order };
    
    let options = mongodb::options::FindOptions::builder()
        .sort(sort_doc)
        .skip(skip as u64)
        .limit(per_page)
        .build();
    
    let mut cursor = licenses_collection
        .find(filter)
        .with_options(options)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    
    let mut licenses = Vec::new();
    
    while let Some(result) = cursor.next().await {
        match result {
            Ok(license) => {
                // Get binary name
                let binary = binaries_collection
                    .find_one(doc! { "binary_id": &license.binary_id })
                    .await
                    .ok()
                    .flatten();
                
                let binary_name = binary.map(|b| b.original_name).unwrap_or_else(|| "Unknown".to_string());
                
                // Count unique computers (instances)
                let unique_computers = instances_collection
                    .count_documents(doc! { "license_id": &license.license_id })
                    .await
                    .unwrap_or(0);
                
                // Count verification attempts
                let verification_count = attempts_collection
                    .count_documents(doc! { "license_id": &license.license_id })
                    .await
                    .unwrap_or(0);
                
                licenses.push(crate::models::LicenseListItem {
                    license_id: license.license_id,
                    binary_id: license.binary_id,
                    binary_name,
                    license_type: license.license_type,
                    sync_mode: license.sync_mode,
                    created_at: license.created_at,
                    expires_at: license.expires_at,
                    max_executions: license.max_executions,
                    executions_used: license.executions_used,
                    revoked: license.revoked,
                    unique_computers,
                    verification_count,
                });
            }
            Err(e) => log::error!("Error reading license: {}", e),
        }
    }
    
    // Sort by calculated fields if needed
    if sort_field == "computers" || sort_field == "verifications" {
        licenses.sort_by(|a, b| {
            let cmp = if sort_field == "computers" {
                a.unique_computers.cmp(&b.unique_computers)
            } else {
                a.verification_count.cmp(&b.verification_count)
            };
            if sort_order == 1 { cmp } else { cmp.reverse() }
        });
    }
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "licenses": licenses,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total as f64 / per_page as f64).ceil() as i64,
    })))
}
