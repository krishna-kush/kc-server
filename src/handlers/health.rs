use actix_web::{HttpResponse, Result};
use serde_json::json;

/// Health check endpoint
pub async fn health() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(json!({
        "status": "healthy",
        "service": "killcode-server",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}
