use actix_web::{web, HttpResponse, Responder};
use mongodb::{bson::doc, Database};
use serde::{Deserialize, Serialize};

use crate::models::{User, UserResponse, AuthProvider};
use crate::utils::create_token;

// ========== Google OAuth Types ==========

#[derive(Debug, Deserialize)]
pub struct GoogleAuthRequest {
    pub code: String,
    pub redirect_uri: String,
}

#[derive(Debug, Serialize)]
struct GoogleTokenRequest {
    code: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    grant_type: String,
}

#[derive(Debug, Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
    #[allow(dead_code)]
    expires_in: u64,
    #[allow(dead_code)]
    token_type: String,
    #[serde(default)]
    id_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GoogleUserInfo {
    #[allow(dead_code)]
    id: String,
    email: String,
    #[allow(dead_code)]
    verified_email: Option<bool>,
    #[allow(dead_code)]
    name: Option<String>,
    #[allow(dead_code)]
    picture: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GoogleAuthResponse {
    pub token: String,
    pub user: UserResponse,
    pub is_new_user: bool,
}

#[derive(Debug, Serialize)]
pub struct GoogleConfigResponse {
    pub client_id: String,
    pub scopes: Vec<String>,
}

// ========== Handlers ==========

/// Get Google OAuth configuration (client ID for frontend)
pub async fn get_google_config() -> impl Responder {
    let client_id = std::env::var("GOOGLE_CLIENT_ID").unwrap_or_default();
    
    if client_id.is_empty() {
        return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Google OAuth not configured"
        }));
    }

    HttpResponse::Ok().json(GoogleConfigResponse {
        client_id,
        scopes: vec![
            "openid".to_string(),
            "email".to_string(),
            "profile".to_string(),
        ],
    })
}

/// Handle Google OAuth callback
pub async fn google_callback(
    db: web::Data<Database>,
    req: web::Json<GoogleAuthRequest>,
) -> impl Responder {
    let client_id = match std::env::var("GOOGLE_CLIENT_ID") {
        Ok(id) if !id.is_empty() => id,
        _ => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Google OAuth not configured"
            }));
        }
    };

    let client_secret = match std::env::var("GOOGLE_CLIENT_SECRET") {
        Ok(secret) if !secret.is_empty() => secret,
        _ => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Google OAuth not configured"
            }));
        }
    };

    // Exchange authorization code for access token
    let token_request = GoogleTokenRequest {
        code: req.code.clone(),
        client_id,
        client_secret,
        redirect_uri: req.redirect_uri.clone(),
        grant_type: "authorization_code".to_string(),
    };

    let client = reqwest::Client::new();
    
    let token_response = match client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", &token_request.code),
            ("client_id", &token_request.client_id),
            ("client_secret", &token_request.client_secret),
            ("redirect_uri", &token_request.redirect_uri),
            ("grant_type", &token_request.grant_type),
        ])
        .send()
        .await
    {
        Ok(resp) => {
            if !resp.status().is_success() {
                let error_text = resp.text().await.unwrap_or_default();
                log::error!("Google token exchange failed: {}", error_text);
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Failed to exchange authorization code"
                }));
            }
            match resp.json::<GoogleTokenResponse>().await {
                Ok(token) => token,
                Err(e) => {
                    log::error!("Failed to parse Google token response: {}", e);
                    return HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": "Failed to parse Google response"
                    }));
                }
            }
        }
        Err(e) => {
            log::error!("Failed to exchange Google auth code: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to connect to Google"
            }));
        }
    };

    // Get user info from Google
    let user_info = match client
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(&token_response.access_token)
        .send()
        .await
    {
        Ok(resp) => {
            if !resp.status().is_success() {
                let error_text = resp.text().await.unwrap_or_default();
                log::error!("Google userinfo request failed: {}", error_text);
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Failed to get user info from Google"
                }));
            }
            match resp.json::<GoogleUserInfo>().await {
                Ok(info) => info,
                Err(e) => {
                    log::error!("Failed to parse Google user info: {}", e);
                    return HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": "Failed to parse Google user info"
                    }));
                }
            }
        }
        Err(e) => {
            log::error!("Failed to get Google user info: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to connect to Google"
            }));
        }
    };

    let email = user_info.email.to_lowercase().trim().to_string();
    let collection = db.collection::<User>("users");

    // Check if user exists
    match collection.find_one(doc! { "email": &email }).await {
        Ok(Some(mut user)) => {
            // User exists - login and upgrade auth_provider if needed
            let user_id = user.id.as_ref().unwrap().to_hex();
            
            // If user was password-only, upgrade to Both
            // Also update profile picture if available
            let mut update_doc = doc! { "updated_at": mongodb::bson::DateTime::now() };
            
            if user.auth_provider == AuthProvider::Password {
                update_doc.insert("auth_provider", "both");
                user.auth_provider = AuthProvider::Both;
            }
            
            // Update profile picture from Google if available
            if let Some(ref picture) = user_info.picture {
                update_doc.insert("profile_picture", picture);
                user.profile_picture = Some(picture.clone());
            }
            
            let _ = collection.update_one(
                doc! { "_id": user.id.as_ref().unwrap() },
                doc! { "$set": update_doc }
            ).await;
            
            match create_token(&user_id, &user.email) {
                Ok(token) => HttpResponse::Ok().json(GoogleAuthResponse {
                    token,
                    user: user.into(),
                    is_new_user: false,
                }),
                Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to create token"
                })),
            }
        }
        Ok(None) => {
            // User doesn't exist - create new account
            // Generate a random password hash for OAuth users (they won't use it)
            let random_password: String = uuid::Uuid::new_v4().to_string();
            let password_hash = match bcrypt::hash(&random_password, bcrypt::DEFAULT_COST) {
                Ok(hash) => hash,
                Err(_) => {
                    return HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": "Failed to create account"
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
                has_password: false,  // OAuth-only user doesn't have a password
                auth_provider: AuthProvider::Google,
                profile_picture: user_info.picture.clone(),
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
                                has_password: false,
                                auth_provider: AuthProvider::Google,
                                profile_picture: user_info.picture.clone(),
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

                            HttpResponse::Created().json(GoogleAuthResponse {
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
            "error": "Database error"
        })),
    }
}
