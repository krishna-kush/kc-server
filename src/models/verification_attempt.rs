/// Verification attempt tracking for telemetry and monitoring
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use mongodb::bson::oid::ObjectId;

/// Verification attempt record stored in MongoDB
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationAttempt {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    
    /// License ID that was verified
    pub license_id: String,
    
    /// Binary ID associated with this license
    pub binary_id: String,
    
    /// Timestamp of the verification attempt
    pub timestamp: DateTime<Utc>,
    
    /// Whether verification was successful
    pub success: bool,
    
    /// Machine fingerprint from the request
    pub machine_fingerprint: String,
    
    /// IP address from the request
    pub ip_address: String,
    
    /// Error message if verification failed
    pub error_message: Option<String>,
    
    /// Number of consecutive failed attempts at this point
    pub failed_attempts: i32,
    
    /// Grace period setting at this point
    pub grace_period: i32,
    
    /// Whether this attempt was within grace period
    pub within_grace_period: bool,
}

impl VerificationAttempt {
    /// Create a new verification attempt record
    pub fn new(
        license_id: String,
        binary_id: String,
        success: bool,
        machine_fingerprint: String,
        ip_address: String,
        error_message: Option<String>,
        failed_attempts: i32,
        grace_period: i32,
        within_grace_period: bool,
    ) -> Self {
        Self {
            id: None,
            license_id,
            binary_id,
            timestamp: Utc::now(),
            success,
            machine_fingerprint,
            ip_address,
            error_message,
            failed_attempts,
            grace_period,
            within_grace_period,
        }
    }
}

/// Response for license verification history
#[derive(Debug, Serialize)]
pub struct VerificationHistoryResponse {
    pub license_id: String,
    pub total_attempts: usize,
    pub successful_attempts: usize,
    pub failed_attempts: usize,
    pub last_verified_at: Option<DateTime<Utc>>,
    pub attempts: Vec<VerificationAttemptSummary>,
}

/// Summary of a verification attempt for API response
#[derive(Debug, Serialize)]
pub struct VerificationAttemptSummary {
    pub license_id: String,
    pub timestamp: DateTime<Utc>,
    pub success: bool,
    pub machine_fingerprint: String,
    pub ip_address: String,
    pub error_message: Option<String>,
    pub failed_attempts: i32,
    pub within_grace_period: bool,
}

impl From<VerificationAttempt> for VerificationAttemptSummary {
    fn from(attempt: VerificationAttempt) -> Self {
        Self {
            license_id: attempt.license_id,
            timestamp: attempt.timestamp,
            success: attempt.success,
            machine_fingerprint: attempt.machine_fingerprint,
            ip_address: attempt.ip_address,
            error_message: attempt.error_message,
            failed_attempts: attempt.failed_attempts,
            within_grace_period: attempt.within_grace_period,
        }
    }
}

/// Dashboard statistics response
#[derive(Debug, Serialize)]
pub struct DashboardStats {
    pub total_licenses: i64,
    pub active_licenses: i64,
    pub revoked_licenses: i64,
    pub total_verifications: i64,
    pub successful_verifications: i64,
    pub failed_verifications: i64,
    pub verifications_last_24h: i64,
    pub most_active_licenses: Vec<LicenseActivity>,
}

/// License activity summary for dashboard
#[derive(Debug, Serialize)]
pub struct LicenseActivity {
    pub license_id: String,
    pub binary_id: String,
    pub verification_count: i64,
    pub last_verified_at: Option<DateTime<Utc>>,
}
