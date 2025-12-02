use actix_web::{web, HttpResponse, Error};
use actix_web::http::header;
use futures::stream::{Stream, StreamExt};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::mpsc;
use mongodb::Database;

/// SSE stream for progress updates
pub struct ProgressStream {
    rx: mpsc::Receiver<String>,
}

impl Stream for ProgressStream {
    type Item = Result<web::Bytes, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(msg)) => {
                let data = format!("data: {}\n\n", msg);
                Poll::Ready(Some(Ok(web::Bytes::from(data))))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// SSE endpoint for progress updates
/// GET /api/progress/{task_id}/stream
pub async fn progress_stream(
    task_id: web::Path<String>,
    db: web::Data<mongodb::Database>,
    user_id: web::ReqData<String>,
) -> Result<HttpResponse, Error> {
    // Verify task ownership
    let collection = db.collection::<mongodb::bson::Document>("merge_tasks");
    let exists = collection
        .count_documents(mongodb::bson::doc! { 
            "task_id": task_id.as_str(),
            "user_id": user_id.into_inner()
        })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))? > 0;

    if !exists {
        return Err(actix_web::error::ErrorNotFound("Task not found"));
    }

    let redis_url = std::env::var("REDIS_URL")
        .unwrap_or_else(|_| "redis://redis:6379".to_string());
    
    let (tx, rx) = mpsc::channel::<String>(100);
    let task_id_clone = task_id.to_string();
    
    tokio::spawn(async move {
        let client = match redis::Client::open(redis_url.as_str()) {
            Ok(c) => c,
            Err(e) => {
                log::error!("Failed to create Redis client: {}", e);
                return;
            }
        };
        
        let mut pubsub = match client.get_async_pubsub().await {
            Ok(ps) => ps,
            Err(e) => {
                log::error!("Failed to get Redis pubsub connection: {}", e);
                return;
            }
        };
        
        let channel = format!("progress:{}", task_id_clone);
        if let Err(e) = pubsub.subscribe(&channel).await {
            log::error!("Failed to subscribe to channel {}: {}", channel, e);
            return;
        }
        
        log::info!("📡 SSE: Subscribed to {}", channel);
        
        let mut stream = pubsub.on_message();
        while let Some(msg) = stream.next().await {
            let payload: String = msg.get_payload().unwrap_or_default();
            
            // Send to SSE stream
            if tx.send(payload.clone()).await.is_err() {
                log::info!("SSE client disconnected for task {}", task_id_clone);
                break;
            }
            
            // Check if complete
            if let Ok(update) = serde_json::from_str::<serde_json::Value>(&payload) {
                if update.get("complete").and_then(|v| v.as_bool()).unwrap_or(false) {
                    log::info!("Task {} complete, closing SSE stream", task_id_clone);
                    break;
                }
            }
        }
    });
    
    // Return SSE response
    Ok(HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, "text/event-stream"))
        .insert_header((header::CACHE_CONTROL, "no-cache"))
        .insert_header((header::CONNECTION, "keep-alive"))
        .streaming(ProgressStream { rx }))
}
