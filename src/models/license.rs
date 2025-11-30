/// License management model for binary access control
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};
use mongodb::bson::oid::ObjectId;
use validator::Validate;

/// Method to use when killing parent binary on unauthorized access
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum KillMethod {
    /// Only stop the process (SIGTERM then SIGKILL)
    Stop,
    /// Stop the process and delete the binary file
    Delete,
    /// Stop the process and securely shred the binary file (3-pass overwrite)
    Shred,
}

impl Default for KillMethod {
    fn default() -> Self {
        Self::Shred
    }
}

/// Type of license determining mutability of settings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LicenseType {
    /// Read-only license: all settings are immutable, cannot be edited
    ReadOnly,
    /// Patchable license: dynamic options can be updated via license management
    Patchable,
}

impl Default for LicenseType {
    fn default() -> Self {
        Self::Patchable
    }
}

/// License entity stored in MongoDB
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    
    /// Unique license identifier (UUID format, same as embedded in overload binary)
    pub license_id: String,
    
    /// Links to the binary this license protects
    pub binary_id: String,
    
    /// User who owns this license
    pub user_id: String,
    
    /// Type of license: readonly (immutable) or patchable (can update dynamic options)
    #[serde(default)]
    pub license_type: LicenseType,
    
    /// Shared secret for HMAC validation (stored in database, never exposed to client)
    pub shared_secret: String,
    
    /// License creation timestamp
    pub created_at: DateTime<Utc>,
    
    /// License expiration timestamp (None = never expires)
    pub expires_at: Option<DateTime<Utc>>,
    
    /// Maximum number of executions allowed (None = unlimited)
    pub max_executions: Option<i64>,
    
    /// Number of times binary has been executed
    pub executions_used: i64,
    
    /// Whether license has been revoked
    pub revoked: bool,
    
    /// Allowed machine fingerprints (empty = any machine)
    pub allowed_machines: Vec<String>,
    
    /// Last successful verification timestamp
    pub last_check_at: Option<DateTime<Utc>>,
    
    /// Last machine fingerprint that checked in
    pub last_machine_fingerprint: Option<String>,
    
    /// Last IP address that checked in
    pub last_check_ip: Option<String>,
    
    /// Grace period: max consecutive failed verifications before killing process (0 = no tolerance)
    #[serde(default)]
    pub grace_period: i32,
    
    /// Count of consecutive failed verification attempts (resets on success)
    #[serde(default)]
    pub failed_attempts: i32,
    
    /// Sync mode: true = check once and exit, false = continuous checking loop
    #[serde(default)]
    pub sync_mode: bool,
    
    /// Check interval in milliseconds (0 for sync mode, >0 for async mode)
    #[serde(default)]
    pub check_interval_ms: u64,
    
    /// Network failure threshold: how many consecutive network failures before killing
    #[serde(default = "default_network_failure_kill_count")]
    pub network_failure_kill_count: u32,
    
    /// Method to use when killing parent binary on unauthorized access
    #[serde(default)]
    pub kill_method: KillMethod,
    
    /// Last timestamp when license was updated
    pub updated_at: DateTime<Utc>,
}

fn default_network_failure_kill_count() -> u32 {
    5
}

impl License {
    /// Create a new license with default values
    pub fn new(
        license_id: String,
        binary_id: String,
        user_id: String,
        shared_secret: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: None,
            license_id,
            binary_id,
            user_id,
            license_type: LicenseType::default(),
            shared_secret,
            created_at: now,
            expires_at: None,
            max_executions: None,
            executions_used: 0,
            revoked: false,
            allowed_machines: Vec::new(),
            last_check_at: None,
            last_machine_fingerprint: None,
            last_check_ip: None,
            grace_period: 0,
            failed_attempts: 0,
            sync_mode: false,
            check_interval_ms: 60000,
            network_failure_kill_count: 5,
            kill_method: KillMethod::default(),
            updated_at: now,
        }
    }
    
    /// Check if license is currently valid (not considering execution limits)
    pub fn is_valid(&self) -> bool {
        // Check if revoked
        if self.revoked {
            return false;
        }
        
        // Check expiration
        if let Some(expires_at) = self.expires_at {
            if Utc::now() > expires_at {
                return false;
            }
        }
        
        true
    }
    
    /// Check if license allows execution (considering all limits)
    pub fn can_execute(&self) -> bool {
        if !self.is_valid() {
            return false;
        }
        
        // Check execution limit
        if let Some(max_executions) = self.max_executions {
            if self.executions_used >= max_executions {
                return false;
            }
        }
        
        true
    }
    
    /// Check if a machine fingerprint is allowed
    pub fn is_machine_allowed(&self, fingerprint: &str) -> bool {
        // If no machines specified, allow all
        if self.allowed_machines.is_empty() {
            return true;
        }
        
        // Check if fingerprint is in allowed list
        self.allowed_machines.iter().any(|m| m == fingerprint)
    }
    
    /// Record a successful execution
    pub fn record_execution(
        &mut self,
        machine_fingerprint: Option<String>,
        ip_address: Option<String>,
    ) {
        self.executions_used += 1;
        self.last_check_at = Some(Utc::now());
        self.last_machine_fingerprint = machine_fingerprint;
        self.last_check_ip = ip_address;
        self.updated_at = Utc::now();
    }
    
    /// Get time until expiration in seconds (None if no expiration)
    pub fn expires_in_seconds(&self) -> Option<i64> {
        self.expires_at.map(|expires_at| {
            let duration = expires_at.signed_duration_since(Utc::now());
            duration.num_seconds().max(0)
        })
    }
}

/// Request to create a new license
#[derive(Debug, Deserialize, Validate)]
pub struct CreateLicenseRequest {
    /// Binary ID this license is for
    #[validate(length(min = 1))]
    pub binary_id: String,
    
    /// Type of license (readonly = immutable, patchable = can update dynamic options)
    pub license_type: Option<LicenseType>,
    
    /// Sync mode: true = synchronous (check once), false = async (continuous checking)
    pub sync_mode: Option<bool>,
    
    /// Check interval in milliseconds (only for async mode)
    #[validate(range(min = 1000))]
    pub check_interval_ms: Option<u64>,
    
    /// Maximum executions allowed (None = unlimited)
    #[validate(range(min = 1))]
    pub max_executions: Option<i64>,
    
    /// Expiration time in seconds from now (None = never expires)
    #[validate(range(min = 60))]
    pub expires_in_seconds: Option<i64>,
    
    /// Allowed machine fingerprints (empty = any machine)
    pub allowed_machines: Option<Vec<String>>,
    
    /// Grace period in seconds: how long binary can run offline without verification
    #[validate(range(min = 0, max = 86400))]
    pub grace_period: Option<i32>,
    
    /// Network failure threshold: how many consecutive network failures before killing
    #[validate(range(min = 1, max = 50))]
    pub network_failure_kill_count: Option<u32>,
    
    /// Method to use when killing parent binary on unauthorized access
    pub kill_method: Option<KillMethod>,
}

/// Response when creating a license
#[derive(Debug, Serialize)]
pub struct CreateLicenseResponse {
    pub license_id: String,
    pub binary_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub max_executions: Option<i64>,
    pub download_url: String,
}

/// Request to update a license
#[derive(Debug, Deserialize, Validate)]
pub struct UpdateLicenseRequest {
    /// Update maximum executions
    #[validate(range(min = 1))]
    pub max_executions: Option<i64>,
    
    /// Update expiration (seconds from now)
    #[validate(range(min = 60))]
    pub expires_in_seconds: Option<i64>,
    
    /// Update allowed machines
    pub allowed_machines: Option<Vec<String>>,
    
    /// Update check interval in milliseconds (patchable setting in overload)
    #[validate(range(min = 1000))]
    pub check_interval_ms: Option<u64>,
    
    /// Update kill method (patchable setting in overload)
    pub kill_method: Option<KillMethod>,
    
    /// Revoke the license
    pub revoked: Option<bool>,
}

/// License details response (for dashboard)
#[derive(Debug, Serialize)]
pub struct LicenseDetailsResponse {
    pub license_id: String,
    pub binary_id: String,
    pub license_type: LicenseType,
    pub sync_mode: bool,
    pub check_interval_ms: u64,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub expires_in_seconds: Option<i64>,
    pub max_executions: Option<i64>,
    pub executions_used: i64,
    pub revoked: bool,
    pub allowed_machines: Vec<String>,
    pub last_check_at: Option<DateTime<Utc>>,
    pub last_machine_fingerprint: Option<String>,
    pub grace_period: i32,
    pub network_failure_kill_count: u32,
    pub failed_attempts: i32,
    pub kill_method: KillMethod,
}

impl From<License> for LicenseDetailsResponse {
    fn from(license: License) -> Self {
        let expires_in_seconds = license.expires_in_seconds();
        Self {
            license_id: license.license_id,
            binary_id: license.binary_id,
            license_type: license.license_type,
            sync_mode: license.sync_mode,
            check_interval_ms: license.check_interval_ms,
            created_at: license.created_at,
            expires_at: license.expires_at,
            expires_in_seconds,
            max_executions: license.max_executions,
            executions_used: license.executions_used,
            revoked: license.revoked,
            allowed_machines: license.allowed_machines,
            last_check_at: license.last_check_at,
            last_machine_fingerprint: license.last_machine_fingerprint,
            grace_period: license.grace_period,
            network_failure_kill_count: license.network_failure_kill_count,
            failed_attempts: license.failed_attempts,
            kill_method: license.kill_method,
        }
    }
}

/// Verification request from overload binary (via HMAC headers)
#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub license_id: String,
    pub machine_fingerprint: String,
    pub timestamp: i64,
}

/// Verification response to overload binary
#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub authorized: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<i64>,
    /// Updated settings for patchable licenses (overload should use these)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_interval_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kill_method: Option<String>,
}

/// License stats response with instances and verification attempts
#[derive(Debug, Serialize)]
pub struct LicenseStatsResponse {
    pub license: LicenseDetailsResponse,
    pub unique_computers: u64,
    pub active_computers: u64,
    pub inactive_computers: u64,
    pub unknown_computers: u64,
    pub instances: Vec<crate::models::BinaryInstanceSummary>,
    pub recent_verifications: Vec<crate::models::VerificationAttemptSummary>,
}

/// License list item with binary info for /licenses page
#[derive(Debug, Serialize)]
pub struct LicenseListItem {
    pub license_id: String,
    pub binary_id: String,
    pub binary_name: String,
    pub license_type: LicenseType,
    pub sync_mode: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub max_executions: Option<i64>,
    pub executions_used: i64,
    pub revoked: bool,
    pub unique_computers: u64,
    pub verification_count: u64,
    pub size: Option<u64>,
}
