use actix_web::{web, HttpResponse, Responder};
use mongodb::{bson::{doc, oid::ObjectId}, Database};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::models::{User, AuthProvider};
use crate::services::OtpService;
use crate::utils::Claims;

// ========== Request/Response Types ==========

#[derive(Debug, Serialize)]
pub struct SecuritySettingsResponse {
    pub two_factor_enabled: bool,
    pub has_password: bool,
    pub auth_provider: AuthProvider,
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct Toggle2FARequest {
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Validate)]
pub struct AddPasswordRequest {
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub new_password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ResetPasswordRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct VerifyResetOtpRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(equal = 6, message = "OTP must be 6 digits"))]
    pub otp: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub new_password: String,
}

// ========== Handlers ==========

/// Get security settings for the current user
pub async fn get_security_settings(
    db: web::Data<Database>,
    claims: web::ReqData<Claims>,
) -> impl Responder {
    let claims = claims.into_inner();
    let collection = db.collection::<User>("users");

    let user_id = match ObjectId::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid user ID"
            }));
        }
    };

    match collection.find_one(doc! { "_id": &user_id }).await {
        Ok(Some(user)) => HttpResponse::Ok().json(SecuritySettingsResponse {
            two_factor_enabled: user.two_factor_enabled,
            has_password: user.has_password,
            auth_provider: user.auth_provider,
            email: user.email,
        }),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "User not found"
        })),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Database error"
        })),
    }
}

/// Toggle 2FA for the current user
pub async fn toggle_2fa(
    db: web::Data<Database>,
    claims: web::ReqData<Claims>,
    req: web::Json<Toggle2FARequest>,
) -> impl Responder {
    let claims = claims.into_inner();
    let collection = db.collection::<User>("users");

    let user_id = match ObjectId::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid user ID"
            }));
        }
    };

    // Get user to check if they have a password (2FA requires password login)
    let user = match collection.find_one(doc! { "_id": &user_id }).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "User not found"
            }));
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error"
            }));
        }
    };

    // 2FA only makes sense if user has password login enabled
    if req.enabled && !user.has_password {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Please add a password first before enabling 2FA"
        }));
    }

    match collection
        .update_one(
            doc! { "_id": &user_id },
            doc! {
                "$set": {
                    "two_factor_enabled": req.enabled,
                    "updated_at": mongodb::bson::DateTime::now()
                }
            },
        )
        .await
    {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "two_factor_enabled": req.enabled,
            "message": if req.enabled { "2FA enabled successfully" } else { "2FA disabled successfully" }
        })),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to update 2FA settings"
        })),
    }
}

/// Add password for OAuth-only users
pub async fn add_password(
    db: web::Data<Database>,
    claims: web::ReqData<Claims>,
    req: web::Json<AddPasswordRequest>,
) -> impl Responder {
    if let Err(errors) = req.validate() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Validation failed",
            "details": errors.to_string()
        }));
    }

    let claims = claims.into_inner();
    let collection = db.collection::<User>("users");

    let user_id = match ObjectId::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid user ID"
            }));
        }
    };

    // Get user to check if they already have a password
    let user = match collection.find_one(doc! { "_id": &user_id }).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "User not found"
            }));
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error"
            }));
        }
    };

    if user.has_password {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "User already has a password. Use change password instead."
        }));
    }

    let password_hash = match bcrypt::hash(&req.password, bcrypt::DEFAULT_COST) {
        Ok(hash) => hash,
        Err(_) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to hash password"
            }));
        }
    };

    // Update auth_provider to Both if it was Google-only
    let new_provider = match user.auth_provider {
        AuthProvider::Google => "both",
        _ => "both",
    };

    match collection
        .update_one(
            doc! { "_id": &user_id },
            doc! {
                "$set": {
                    "password_hash": password_hash,
                    "has_password": true,
                    "auth_provider": new_provider,
                    "updated_at": mongodb::bson::DateTime::now()
                }
            },
        )
        .await
    {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "Password added successfully"
        })),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to add password"
        })),
    }
}

/// Change password for users who have a password
pub async fn change_password(
    db: web::Data<Database>,
    claims: web::ReqData<Claims>,
    req: web::Json<ChangePasswordRequest>,
) -> impl Responder {
    if let Err(errors) = req.validate() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Validation failed",
            "details": errors.to_string()
        }));
    }

    let claims = claims.into_inner();
    let collection = db.collection::<User>("users");

    let user_id = match ObjectId::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid user ID"
            }));
        }
    };

    // Get user
    let user = match collection.find_one(doc! { "_id": &user_id }).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "User not found"
            }));
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error"
            }));
        }
    };

    if !user.has_password {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "User doesn't have a password. Use add password instead."
        }));
    }

    // Verify current password
    match bcrypt::verify(&req.current_password, &user.password_hash) {
        Ok(true) => {}
        Ok(false) => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Current password is incorrect"
            }));
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Password verification failed"
            }));
        }
    }

    let password_hash = match bcrypt::hash(&req.new_password, bcrypt::DEFAULT_COST) {
        Ok(hash) => hash,
        Err(_) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to hash password"
            }));
        }
    };

    match collection
        .update_one(
            doc! { "_id": &user_id },
            doc! {
                "$set": {
                    "password_hash": password_hash,
                    "updated_at": mongodb::bson::DateTime::now()
                }
            },
        )
        .await
    {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "Password changed successfully"
        })),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to change password"
        })),
    }
}

/// Request password reset OTP (public endpoint)
pub async fn request_password_reset(
    db: web::Data<Database>,
    req: web::Json<ResetPasswordRequest>,
) -> impl Responder {
    if let Err(errors) = req.validate() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Validation failed",
            "details": errors.to_string()
        }));
    }

    let collection = db.collection::<User>("users");
    let email = req.email.to_lowercase().trim().to_string();

    // Check if user exists and has password
    match collection.find_one(doc! { "email": &email }).await {
        Ok(Some(user)) => {
            if !user.has_password {
                // Don't reveal that user doesn't have password, just say email sent
                return HttpResponse::Ok().json(serde_json::json!({
                    "success": true,
                    "message": "If an account exists with this email, a reset code has been sent"
                }));
            }
        }
        Ok(None) => {
            // Don't reveal that user doesn't exist
            return HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "If an account exists with this email, a reset code has been sent"
            }));
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error"
            }));
        }
    }

    // Send OTP for password reset
    let otp_service = OtpService::new();
    match otp_service.send_otp(&email).await {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "If an account exists with this email, a reset code has been sent"
        })),
        Err(e) => {
            log::error!("Failed to send password reset OTP: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to send reset code"
            }))
        }
    }
}

/// Verify OTP and reset password (public endpoint)
pub async fn verify_reset_otp(
    db: web::Data<Database>,
    req: web::Json<VerifyResetOtpRequest>,
) -> impl Responder {
    if let Err(errors) = req.validate() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Validation failed",
            "details": errors.to_string()
        }));
    }

    let email = req.email.to_lowercase().trim().to_string();

    // Verify OTP
    let otp_service = OtpService::new();
    match otp_service.verify_otp(&email, &req.otp).await {
        Ok(true) => {}
        Ok(false) => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid or expired verification code"
            }));
        }
        Err(e) => {
            log::error!("OTP verification error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Verification failed"
            }));
        }
    }

    let collection = db.collection::<User>("users");

    // Get user
    let user = match collection.find_one(doc! { "email": &email }).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "User not found"
            }));
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error"
            }));
        }
    };

    let password_hash = match bcrypt::hash(&req.new_password, bcrypt::DEFAULT_COST) {
        Ok(hash) => hash,
        Err(_) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to hash password"
            }));
        }
    };

    // Update auth_provider to include password if it was Google-only
    let new_provider = match user.auth_provider {
        AuthProvider::Google => "both",
        AuthProvider::Password => "password",
        AuthProvider::Both => "both",
    };

    match collection
        .update_one(
            doc! { "email": &email },
            doc! {
                "$set": {
                    "password_hash": password_hash,
                    "has_password": true,
                    "auth_provider": new_provider,
                    "updated_at": mongodb::bson::DateTime::now()
                }
            },
        )
        .await
    {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "Password reset successfully"
        })),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to reset password"
        })),
    }
}
