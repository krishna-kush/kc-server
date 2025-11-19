use actix_web::{web, HttpResponse, Responder};
use mongodb::{bson::doc, Database};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::models::User;

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

pub async fn check_email(
    db: web::Data<Database>,
    req: web::Json<CheckEmailRequest>,
) -> impl Responder {
    // Validate request
    if let Err(errors) = req.validate() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Validation failed",
            "details": errors.to_string()
        }));
    }

    let collection = db.collection::<User>("users");
    let email = req.email.to_lowercase().trim().to_string();

    // Check if user exists
    match collection.find_one(doc! { "email": &email }).await {
        Ok(Some(_)) => {
            // User exists
            HttpResponse::Ok().json(CheckEmailResponse {
                exists: true,
                email,
            })
        }
        Ok(None) => {
            // User doesn't exist
            HttpResponse::Ok().json(CheckEmailResponse {
                exists: false,
                email,
            })
        }
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Database error"
        })),
    }
}
