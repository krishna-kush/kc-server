use actix_web::{web, HttpResponse, Responder};
use mongodb::{bson::doc, Database};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::models::{User, UserResponse, AuthProvider};
use crate::services::OtpService;
use crate::utils::create_token;

// ========== Request/Response Types ==========

/// Check email request
#[derive(Debug, Deserialize, Validate)]
pub struct CheckEmailRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct CheckEmailResponse {
    pub exists: bool,
    pub email: String,
}

/// Login request (for existing users)
#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(min = 6, message = "Password must be at least 6 characters"))]
    pub password: String,
}

/// Request OTP for signup
#[derive(Debug, Deserialize, Validate)]
pub struct RequestOtpRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct RequestOtpResponse {
    pub success: bool,
    pub message: String,
}

/// Verify OTP and complete signup
#[derive(Debug, Deserialize, Validate)]
pub struct VerifyOtpAndSignupRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(equal = 6, message = "OTP must be 6 digits"))]
    pub otp: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,
}

/// Verify 2FA OTP request
#[derive(Debug, Deserialize, Validate)]
pub struct Verify2FARequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(equal = 6, message = "OTP must be 6 digits"))]
    pub otp: String,
}

/// Auth response
#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserResponse,
    pub is_new_user: bool,
}

// ========== Handlers ==========

/// Check if email exists (Step 1 of auth flow)
pub async fn check_email(
    db: web::Data<Database>,
    req: web::Json<CheckEmailRequest>,
) -> impl Responder {
    if let Err(errors) = req.validate() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Validation failed",
            "details": errors.to_string()
        }));
    }

    let collection = db.collection::<mongodb::bson::Document>("users");
    let email = req.email.to_lowercase().trim().to_string();

    // Just check if a document exists with this email, don't deserialize the whole User
    match collection.find_one(doc! { "email": &email }).await {
        Ok(Some(_)) => HttpResponse::Ok().json(CheckEmailResponse {
            exists: true,
            email,
        }),
        Ok(None) => HttpResponse::Ok().json(CheckEmailResponse {
            exists: false,
            email,
        }),
        Err(e) => {
            log::error!("Database error in check_email: {:?}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error"
            }))
        }
    }
}

/// Login endpoint for existing users
pub async fn login(
    db: web::Data<Database>,
    req: web::Json<LoginRequest>,
) -> impl Responder {
    if let Err(errors) = req.validate() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Validation failed",
            "details": errors.to_string()
        }));
    }

    let collection = db.collection::<User>("users");
    let email = req.email.to_lowercase().trim().to_string();

    match collection.find_one(doc! { "email": &email }).await {
        Ok(Some(user)) => {
            // Check if user has a password set
            if !user.has_password {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "This account doesn't have a password. Please use Google sign-in or reset your password."
                }));
            }
            
            match bcrypt::verify(&req.password, &user.password_hash) {
                Ok(valid) => {
                    if valid {
                        // Check if 2FA is enabled
                        if user.two_factor_enabled {
                            // Send OTP for 2FA (using 2FA-specific template)
                            let otp_service = crate::services::OtpService::new();
                            match otp_service.send_2fa_otp(&email).await {
                                Ok(()) => {
                                    return HttpResponse::Ok().json(serde_json::json!({
                                        "requires_2fa": true,
                                        "email": email,
                                        "message": "2FA code sent to your email"
                                    }));
                                }
                                Err(e) => {
                                    log::error!("Failed to send 2FA OTP: {}", e);
                                    return HttpResponse::InternalServerError().json(serde_json::json!({
                                        "error": "Failed to send verification code"
                                    }));
                                }
                            }
                        }
                        
                        let user_id = user.id.as_ref().unwrap().to_hex();
                        match create_token(&user_id, &user.email) {
                            Ok(token) => HttpResponse::Ok().json(AuthResponse {
                                token,
                                user: user.into(),
                                is_new_user: false,
                            }),
                            Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
                                "error": "Failed to create token"
                            })),
                        }
                    } else {
                        HttpResponse::Unauthorized().json(serde_json::json!({
                            "error": "Invalid password"
                        }))
                    }
                }
                Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Password verification failed"
                })),
            }
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "User not found"
        })),
        Err(e) => {
            log::error!("Database error in login: {:?}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error"
            }))
        }
    }
}

/// Request OTP for new user signup
pub async fn request_otp(
    db: web::Data<Database>,
    req: web::Json<RequestOtpRequest>,
) -> impl Responder {
    if let Err(errors) = req.validate() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Validation failed",
            "details": errors.to_string()
        }));
    }

    let collection = db.collection::<User>("users");
    let email = req.email.to_lowercase().trim().to_string();

    // Check if user already exists
    match collection.find_one(doc! { "email": &email }).await {
        Ok(Some(_)) => {
            return HttpResponse::Conflict().json(serde_json::json!({
                "error": "User already exists. Please login instead."
            }));
        }
        Ok(None) => {}
        Err(_) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error"
            }));
        }
    }

    // Send OTP
    let otp_service = OtpService::new();
    match otp_service.send_otp(&email).await {
        Ok(()) => HttpResponse::Ok().json(RequestOtpResponse {
            success: true,
            message: "Verification code sent to your email".to_string(),
        }),
        Err(e) => {
            log::error!("Failed to send OTP: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to send verification code"
            }))
        }
    }
}

/// Verify OTP and create account
pub async fn verify_otp_and_signup(
    db: web::Data<Database>,
    req: web::Json<VerifyOtpAndSignupRequest>,
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

    // Create user
    let collection = db.collection::<User>("users");
    
    // Double-check user doesn't exist
    if let Ok(Some(_)) = collection.find_one(doc! { "email": &email }).await {
        return HttpResponse::Conflict().json(serde_json::json!({
            "error": "User already exists"
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

    let now = chrono::Utc::now();
    let new_user = User {
        id: None,
        email: email.clone(),
        password_hash,
        created_at: now,
        updated_at: now,
        storage_used: 0,
        storage_original: 0,
        storage_merged: 0,
        two_factor_enabled: false,
        has_password: true,
        auth_provider: AuthProvider::Password,
        profile_picture: None,
    };

    match collection.insert_one(&new_user).await {
        Ok(result) => {
            let user_id = result.inserted_id.as_object_id().unwrap().to_hex();
            match create_token(&user_id, &email) {
                Ok(token) => {
                    let user_response = UserResponse {
                        id: user_id,
                        email: email.clone(),
                        created_at: now,
                        two_factor_enabled: false,
                        has_password: true,
                        auth_provider: AuthProvider::Password,
                        profile_picture: None,
                    };
                    
                    // Send welcome email (async, don't wait)
                    let mailer_url = std::env::var("MAILER_URL")
                        .unwrap_or_else(|_| "http://mailer:8082".to_string());
                    let welcome_email = email.clone();
                    tokio::spawn(async move {
                        let client = reqwest::Client::new();
                        let _ = client
                            .post(format!("{}/send", mailer_url))
                            .json(&serde_json::json!({
                                "to": welcome_email,
                                "subject": "Welcome to KillCode!",
                                "template": "welcome",
                                "data": {
                                    "email": welcome_email
                                }
                            }))
                            .send()
                            .await;
                    });
                    
                    HttpResponse::Created().json(AuthResponse {
                        token,
                        user: user_response,
                        is_new_user: true,
                    })
                }
                Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to create token"
                })),
            }
        }
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to create user"
        })),
    }
}

/// Legacy auth endpoint (kept for backwards compatibility during transition)
/// This will be deprecated - use /auth/login and /auth/signup instead
#[derive(Debug, Deserialize, Validate)]
pub struct LegacyAuthRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(min = 6, message = "Password must be at least 6 characters"))]
    pub password: String,
}

pub async fn auth(
    db: web::Data<Database>,
    auth_req: web::Json<LegacyAuthRequest>,
) -> impl Responder {
    // Validate request
    if let Err(errors) = auth_req.validate() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Validation failed",
            "details": errors.to_string()
        }));
    }

    let collection = db.collection::<User>("users");
    let email = auth_req.email.to_lowercase().trim().to_string();

    // Check if user exists
    match collection.find_one(doc! { "email": &email }).await {
        Ok(Some(user)) => {
            // User exists - LOGIN
            match bcrypt::verify(&auth_req.password, &user.password_hash) {
                Ok(valid) => {
                    if valid {
                        // Password is correct
                        let user_id = user.id.as_ref().unwrap().to_hex();
                        match create_token(&user_id, &user.email) {
                            Ok(token) => HttpResponse::Ok().json(AuthResponse {
                                token,
                                user: user.into(),
                                is_new_user: false,
                            }),
                            Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
                                "error": "Failed to create token"
                            })),
                        }
                    } else {
                        // Invalid password
                        HttpResponse::Unauthorized().json(serde_json::json!({
                            "error": "Invalid password"
                        }))
                    }
                }
                Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Password verification failed"
                })),
            }
        }
        Ok(None) => {
            // User doesn't exist - SIGNUP
            match bcrypt::hash(&auth_req.password, bcrypt::DEFAULT_COST) {
                Ok(password_hash) => {
                    let now = chrono::Utc::now();
                    let new_user = User {
                        id: None,
                        email: email.clone(),
                        password_hash,
                        created_at: now,
                        updated_at: now,
                        storage_used: 0,
                        storage_original: 0,
                        storage_merged: 0,
                        two_factor_enabled: false,
                        has_password: true,
                        auth_provider: AuthProvider::Password,
                        profile_picture: None,
                    };

                    match collection.insert_one(&new_user).await {
                        Ok(result) => {
                            let user_id = result.inserted_id.as_object_id().unwrap().to_hex();
                            match create_token(&user_id, &email) {
                                Ok(token) => {
                                    let user_response = UserResponse {
                                        id: user_id,
                                        email: email.clone(),
                                        created_at: now,
                                        two_factor_enabled: false,
                                        has_password: true,
                                        auth_provider: AuthProvider::Password,
                                        profile_picture: None,
                                    };
                                    HttpResponse::Created().json(AuthResponse {
                                        token,
                                        user: user_response,
                                        is_new_user: true,
                                    })
                                }
                                Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
                                    "error": "Failed to create token"
                                })),
                            }
                        }
                        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
                            "error": "Failed to create user"
                        })),
                    }
                }
                Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to hash password"
                })),
            }
        }
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Database error"
        })),
    }
}

pub async fn verify(claims: web::ReqData<crate::utils::Claims>) -> impl Responder {
    let claims = claims.into_inner();
    HttpResponse::Ok().json(serde_json::json!({
        "user_id": claims.sub,
        "email": claims.email,
    }))
}

/// Verify 2FA OTP and complete login
pub async fn verify_2fa(
    db: web::Data<Database>,
    req: web::Json<Verify2FARequest>,
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
            log::error!("2FA OTP verification error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Verification failed"
            }));
        }
    }

    let collection = db.collection::<User>("users");
    
    // Get user
    match collection.find_one(doc! { "email": &email }).await {
        Ok(Some(user)) => {
            let user_id = user.id.as_ref().unwrap().to_hex();
            match create_token(&user_id, &user.email) {
                Ok(token) => HttpResponse::Ok().json(AuthResponse {
                    token,
                    user: user.into(),
                    is_new_user: false,
                }),
                Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to create token"
                })),
            }
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "User not found"
        })),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Database error"
        })),
    }
}
