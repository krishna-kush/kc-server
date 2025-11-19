/// Public statistics endpoints (no auth required)
use actix_web::{web, HttpResponse, Error};
use mongodb::{bson::doc, Database};
use serde::Serialize;

use crate::models::VerificationAttempt;

#[derive(Debug, Serialize)]
pub struct VerificationStatsResponse {
    pub total_verifications: i64,
}

/// Get public statistics about total verifications
/// GET /api/v1/stats/verifications
pub async fn get_verification_stats(
    db: web::Data<Database>,
) -> Result<HttpResponse, Error> {
    let collection = db.collection::<VerificationAttempt>("verification_attempts");
    
    let total = collection
        .count_documents(doc! {})
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    Ok(HttpResponse::Ok().json(VerificationStatsResponse {
        total_verifications: total as i64,
    }))
}
