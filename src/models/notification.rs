use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use mongodb::bson::oid::ObjectId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub user_id: String,
    pub title: String,
    pub message: String,
    #[serde(rename = "type")]
    pub notification_type: NotificationType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percentage: Option<i32>,
    pub timestamp: DateTime<Utc>,
    pub read: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationResponse {
    pub id: String,
    pub user_id: String,
    pub title: String,
    pub message: String,
    #[serde(rename = "type")]
    pub notification_type: NotificationType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percentage: Option<i32>,
    pub timestamp: DateTime<Utc>,
    pub read: bool,
}

impl From<Notification> for NotificationResponse {
    fn from(notif: Notification) -> Self {
        NotificationResponse {
            id: notif.id.map(|oid| oid.to_hex()).unwrap_or_default(),
            user_id: notif.user_id,
            title: notif.title,
            message: notif.message,
            notification_type: notif.notification_type,
            percentage: notif.percentage,
            timestamp: notif.timestamp,
            read: notif.read,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NotificationType {
    Info,
    Success,
    Error,
    Warning,
    Progress,
}

#[derive(Debug, Deserialize)]
pub struct CreateNotificationRequest {
    pub title: String,
    pub message: String,
    #[serde(rename = "type")]
    pub notification_type: NotificationType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percentage: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateNotificationRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub notification_type: Option<NotificationType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percentage: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read: Option<bool>,
}
