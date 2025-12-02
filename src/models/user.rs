use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use validator::Validate;

/// Custom deserializer that handles both BSON DateTime and ISO 8601 string formats
mod flexible_datetime {
    use chrono::{DateTime, Utc};
    use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(date: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize as BSON DateTime
        let bson_dt = bson::DateTime::from_chrono(*date);
        Serialize::serialize(&bson_dt, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        // Try to deserialize as different types
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum DateTimeFormat {
            BsonDateTime(bson::DateTime),
            String(String),
            // Handle extended JSON format: { "$date": { "$numberLong": "..." } }
            ExtendedJson { #[serde(rename = "$date")] date: ExtendedDateInner },
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum ExtendedDateInner {
            NumberLong { #[serde(rename = "$numberLong")] number_long: String },
            IsoString(String),
        }

        match DateTimeFormat::deserialize(deserializer)? {
            DateTimeFormat::BsonDateTime(dt) => Ok(dt.to_chrono()),
            DateTimeFormat::String(s) => {
                // Try parsing as ISO 8601 / RFC 3339
                DateTime::parse_from_rfc3339(&s)
                    .map(|dt| dt.with_timezone(&Utc))
                    .or_else(|_| {
                        // Try parsing as a more flexible format
                        s.parse::<DateTime<Utc>>()
                    })
                    .map_err(|e| D::Error::custom(format!("Failed to parse datetime string '{}': {}", s, e)))
            }
            DateTimeFormat::ExtendedJson { date } => {
                match date {
                    ExtendedDateInner::NumberLong { number_long } => {
                        let millis: i64 = number_long.parse()
                            .map_err(|e| D::Error::custom(format!("Failed to parse numberLong: {}", e)))?;
                        Ok(bson::DateTime::from_millis(millis).to_chrono())
                    }
                    ExtendedDateInner::IsoString(s) => {
                        DateTime::parse_from_rfc3339(&s)
                            .map(|dt| dt.with_timezone(&Utc))
                            .map_err(|e| D::Error::custom(format!("Failed to parse datetime: {}", e)))
                    }
                }
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuthProvider {
    #[default]
    Password,
    Google,
    Both,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub email: String,
    #[serde(default)]
    pub password_hash: String,
    #[serde(with = "flexible_datetime")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(with = "flexible_datetime")]
    pub updated_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub storage_used: i64,
    #[serde(default)]
    pub storage_original: i64,
    #[serde(default)]
    pub storage_merged: i64,
    /// Whether 2FA is enabled for this user
    #[serde(default)]
    pub two_factor_enabled: bool,
    /// Whether user has a password set (false for OAuth-only users)
    #[serde(default = "default_has_password")]
    pub has_password: bool,
    /// Authentication provider(s) used by this user
    #[serde(default)]
    pub auth_provider: AuthProvider,
    /// Profile picture URL (from OAuth provider like Google)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_picture: Option<String>,
}

fn default_has_password() -> bool {
    true
}

#[derive(Debug, Deserialize, Validate)]
pub struct AuthRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(min = 6, message = "Password must be at least 6 characters"))]
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserResponse,
    pub is_new_user: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub two_factor_enabled: bool,
    #[serde(default = "default_has_password")]
    pub has_password: bool,
    #[serde(default)]
    pub auth_provider: AuthProvider,
    /// Profile picture URL (from OAuth provider like Google)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_picture: Option<String>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        UserResponse {
            id: user.id.unwrap().to_hex(),
            email: user.email,
            created_at: user.created_at,
            two_factor_enabled: user.two_factor_enabled,
            has_password: user.has_password,
            auth_provider: user.auth_provider,
            profile_picture: user.profile_picture,
        }
    }
}
