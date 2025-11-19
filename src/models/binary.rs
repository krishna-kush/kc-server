/// Database models for binary management and access control
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use mongodb::bson::oid::ObjectId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Binary {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    
    /// Unique binary identifier (e.g., "bin_abc123")
    pub binary_id: String,
    
    /// User who owns this binary
    pub user_id: String,
    
    /// Original filename
    pub original_name: String,
    
    /// Optional description
    pub description: Option<String>,
    
    /// Original file size in bytes
    pub original_size: u64,
    
    /// Wrapped (merged) file size in bytes
    pub wrapped_size: u64,
    
    /// Path to stored wrapped binary
    pub file_path: String,
    
    /// Current processing status: e.g., "processing", "ready", "failed"
    pub status: String,
    
    /// Whether binary is currently active (access allowed)
    pub is_active: bool,
    
    /// Access control policy
    pub access_policy: AccessPolicy,
    
    /// Grace period for offline mode (seconds)
    /// 0 = no grace period (fail immediately if server unreachable)
    /// None = infinite grace (always allow offline)
    pub grace_period: Option<u32>,
    
    /// Statistics
    pub stats: BinaryStats,
    
    /// Binary architecture (x86_64, aarch64, etc.)
    pub architecture: Option<String>,
    
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AccessPolicy {
    /// Always allow access (while is_active = true)
    Always,
    
    /// Allow until expiration date
    TimeLimited {
        expires_at: DateTime<Utc>,
    },
    
    /// Allow up to N executions
    CountLimited {
        max_executions: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BinaryStats {
    /// Total number of executions
    #[serde(default)]
    pub total_executions: u64,
    
    /// Number of unique hostnames
    #[serde(default)]
    pub unique_hosts: u64,
    
    /// Last execution timestamp
    #[serde(default)]
    pub last_execution: Option<DateTime<Utc>>,
}

impl Binary {
    pub fn new(
        binary_id: String,
        user_id: String,
        original_name: String,
        original_size: u64,
        file_path: String,
    ) -> Self {
        Self {
            id: None,
            binary_id,
            user_id,
            original_name,
            description: None,
            original_size,
            wrapped_size: 0, // Will be updated after merge
            file_path,
            status: "ready".to_string(),
            is_active: true,
            access_policy: AccessPolicy::Always,
            grace_period: Some(0), // Default: no grace period (strict online check)
            stats: BinaryStats::default(),
            architecture: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
    
    /// Check if access should be granted based on policy
    pub fn check_policy(&self) -> bool {
        if !self.is_active {
            return false;
        }
        
        match &self.access_policy {
            AccessPolicy::Always => true,
            AccessPolicy::TimeLimited { expires_at } => Utc::now() < *expires_at,
            AccessPolicy::CountLimited { max_executions } => {
                self.stats.total_executions < (*max_executions as u64)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Execution {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    
    /// Binary ID that was executed
    pub binary_id: String,
    
    /// User ID who owns the binary
    pub user_id: String,
    
    /// Hashed hostname (for privacy)
    pub hostname_hash: String,
    
    /// OS information
    pub os_name: String,
    pub os_version: String,
    
    /// Whether access was granted
    pub allowed: bool,
    
    /// Timestamp of execution
    pub timestamp: DateTime<Utc>,
}

impl Execution {
    pub fn new(
        binary_id: String,
        user_id: String,
        hostname: String,
        os_name: String,
        os_version: String,
        allowed: bool,
    ) -> Self {
        Self {
            id: None,
            binary_id,
            user_id,
            hostname_hash: Self::hash_hostname(&hostname),
            os_name,
            os_version,
            allowed,
            timestamp: Utc::now(),
        }
    }
    
    /// Hash hostname for privacy (SHA256)
    fn hash_hostname(hostname: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(hostname.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

/// Request payload for uploading a binary
#[derive(Debug, Deserialize)]
pub struct UploadBinaryRequest {
    pub user_id: String,
    // File will come from multipart form data
}

/// Response after uploading a binary
#[derive(Debug, Serialize)]
pub struct UploadBinaryResponse {
    pub binary_id: String,
    pub message: String,
    pub download_url: String,
}

/// Request to update binary access
#[derive(Debug, Deserialize)]
pub struct UpdateAccessRequest {
    pub is_active: Option<bool>,
    pub access_policy: Option<AccessPolicy>,
    /// Grace period in seconds
    /// 0 = no grace (strict online check)
    /// Some(seconds) = allow offline execution for N seconds
    /// None = infinite grace (always allow offline)
    pub grace_period: Option<Option<u32>>,
}

/// Response for binary details
#[derive(Debug, Serialize)]
pub struct BinaryDetailsResponse {
    pub binary_id: String,
    pub original_name: String,
    pub original_size: u64,
    pub wrapped_size: u64,
    pub status: String,
    pub is_active: bool,
    pub access_policy: AccessPolicy,
    pub grace_period: Option<u32>,
    pub stats: BinaryStats,
    pub license_count: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Binary> for BinaryDetailsResponse {
    fn from(binary: Binary) -> Self {
        Self {
            binary_id: binary.binary_id,
            original_name: binary.original_name,
            original_size: binary.original_size,
            wrapped_size: binary.wrapped_size,
            status: binary.status,
            is_active: binary.is_active,
            access_policy: binary.access_policy,
            grace_period: binary.grace_period,
            stats: binary.stats,
            license_count: 0, // Will be set by handler
            created_at: binary.created_at,
            updated_at: binary.updated_at,
        }
    }
}
