use actix_web::{web, HttpResponse, Responder};
use mongodb::{bson::doc, Database};
use validator::Validate;

use crate::models::{AuthRequest, AuthResponse, User, UserResponse};
use crate::utils::create_token;

pub async fn auth(
    db: web::Data<Database>,
    auth_req: web::Json<AuthRequest>,
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
