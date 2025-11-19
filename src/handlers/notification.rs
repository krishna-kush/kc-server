use actix_web::{web, HttpResponse, Error};
use mongodb::{Database, bson::{doc, oid::ObjectId}};
use crate::models::{
    Notification, CreateNotificationRequest, UpdateNotificationRequest, NotificationType,
};
use chrono::Utc;

/// Get all notifications for the authenticated user
/// GET /api/v1/notifications
pub async fn get_notifications(
    db: web::Data<Database>,
    user_id: web::ReqData<String>,
) -> Result<HttpResponse, Error> {
    let collection = db.collection::<Notification>("notifications");
    let uid = user_id.into_inner();
    
    let mut cursor = collection
        .find(doc! { "user_id": &uid })
        .sort(doc! { "timestamp": -1 })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    let mut notifications = Vec::new();
    while cursor.advance().await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))? {
        let notification = cursor.deserialize_current()
            .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Deserialization error: {}", e)))?;
        
        notifications.push(crate::models::NotificationResponse::from(notification));
    }
    
    Ok(HttpResponse::Ok().json(notifications))
}

/// Create a new notification
/// POST /api/v1/notifications
pub async fn create_notification(
    db: web::Data<Database>,
    user_id: web::ReqData<String>,
    request: web::Json<CreateNotificationRequest>,
) -> Result<HttpResponse, Error> {
    let collection = db.collection::<Notification>("notifications");
    let uid = user_id.into_inner();
    
    let notification = Notification {
        id: None,
        user_id: uid.clone(),
        title: request.title.clone(),
        message: request.message.clone(),
        notification_type: request.notification_type.clone(),
        percentage: request.percentage,
        timestamp: Utc::now(),
        read: false,
    };
    
    let result = collection
        .insert_one(&notification)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    let notification_id = result.inserted_id.as_object_id()
        .ok_or_else(|| actix_web::error::ErrorInternalServerError("Failed to get notification ID"))?;
    
    let mut created_notification = notification;
    created_notification.id = Some(notification_id);
    
    Ok(HttpResponse::Created().json(crate::models::NotificationResponse::from(created_notification)))
}

/// Update a notification
/// PATCH /api/v1/notifications/{id}
pub async fn update_notification(
    db: web::Data<Database>,
    user_id: web::ReqData<String>,
    notification_id: web::Path<String>,
    request: web::Json<UpdateNotificationRequest>,
) -> Result<HttpResponse, Error> {
    let collection = db.collection::<Notification>("notifications");
    let uid = user_id.into_inner();
    
    let object_id = ObjectId::parse_str(notification_id.as_str())
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid notification ID"))?;
    
    let mut update_doc = doc! {};
    
    if let Some(title) = &request.title {
        update_doc.insert("title", title);
    }
    if let Some(message) = &request.message {
        update_doc.insert("message", message);
    }
    if let Some(notification_type) = &request.notification_type {
        update_doc.insert("type", mongodb::bson::to_bson(notification_type)
            .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Serialization error: {}", e)))?);
    }
    if let Some(percentage) = request.percentage {
        update_doc.insert("percentage", percentage);
    }
    if let Some(read) = request.read {
        update_doc.insert("read", read);
    }
    
    if update_doc.is_empty() {
        return Err(actix_web::error::ErrorBadRequest("No fields to update"));
    }
    
    let result = collection
        .update_one(
            doc! { "_id": object_id, "user_id": &uid },
            doc! { "$set": update_doc }
        )
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    if result.matched_count == 0 {
        return Err(actix_web::error::ErrorNotFound("Notification not found"));
    }
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Notification updated successfully"
    })))
}

/// Mark notification as read
/// POST /api/v1/notifications/{id}/read
pub async fn mark_as_read(
    db: web::Data<Database>,
    user_id: web::ReqData<String>,
    notification_id: web::Path<String>,
) -> Result<HttpResponse, Error> {
    let collection = db.collection::<Notification>("notifications");
    let uid = user_id.into_inner();
    
    let object_id = ObjectId::parse_str(notification_id.as_str())
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid notification ID"))?;
    
    let result = collection
        .update_one(
            doc! { "_id": object_id, "user_id": &uid },
            doc! { "$set": { "read": true } }
        )
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    if result.matched_count == 0 {
        return Err(actix_web::error::ErrorNotFound("Notification not found"));
    }
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Notification marked as read"
    })))
}

/// Mark all notifications as read
/// POST /api/v1/notifications/read-all
pub async fn mark_all_as_read(
    db: web::Data<Database>,
    user_id: web::ReqData<String>,
) -> Result<HttpResponse, Error> {
    let collection = db.collection::<Notification>("notifications");
    let uid = user_id.into_inner();
    
    collection
        .update_many(
            doc! { "user_id": &uid, "read": false },
            doc! { "$set": { "read": true } }
        )
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "All notifications marked as read"
    })))
}

/// Delete a notification
/// DELETE /api/v1/notifications/{id}
pub async fn delete_notification(
    db: web::Data<Database>,
    user_id: web::ReqData<String>,
    notification_id: web::Path<String>,
) -> Result<HttpResponse, Error> {
    let collection = db.collection::<Notification>("notifications");
    let uid = user_id.into_inner();
    
    let object_id = ObjectId::parse_str(notification_id.as_str())
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid notification ID"))?;
    
    let result = collection
        .delete_one(doc! { "_id": object_id, "user_id": &uid })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    if result.deleted_count == 0 {
        return Err(actix_web::error::ErrorNotFound("Notification not found"));
    }
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Notification deleted successfully"
    })))
}

/// Delete all notifications
/// DELETE /api/v1/notifications
pub async fn clear_all_notifications(
    db: web::Data<Database>,
    user_id: web::ReqData<String>,
) -> Result<HttpResponse, Error> {
    let collection = db.collection::<Notification>("notifications");
    let uid = user_id.into_inner();
    
    collection
        .delete_many(doc! { "user_id": &uid })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "All notifications cleared"
    })))
}
