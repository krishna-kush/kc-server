/// Binary instance tracking - tracks unique computers using each license
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use mongodb::bson::oid::ObjectId;

/// Represents a unique instance of a binary running on a specific machine
/// Uniqueness: (license_id + machine_fingerprint) = one instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryInstance {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    
    /// License this instance is using
    pub license_id: String,
    
    /// Binary being executed
    pub binary_id: String,
    
    /// Unique machine identifier (fingerprint)
    pub machine_fingerprint: String,
    
    /// When this instance was first seen
    pub first_seen: DateTime<Utc>,
    
    /// Last time this instance checked in
    pub last_seen: DateTime<Utc>,
    
    /// Whether this instance is currently active (checked in recently)
    pub is_active: bool,
    
    /// Total number of verification checks from this instance
    pub total_checks: u64,
    
    /// Last IP address this instance checked in from
    pub last_ip: Option<String>,
}

impl BinaryInstance {
    pub fn new(
        license_id: String,
        binary_id: String,
        machine_fingerprint: String,
        ip_address: Option<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: None,
            license_id,
            binary_id,
            machine_fingerprint,
            first_seen: now,
            last_seen: now,
            is_active: true,
            total_checks: 1,
            last_ip: ip_address,
        }
    }
    
    /// Update instance on new check-in
    pub fn update_check_in(&mut self, ip_address: Option<String>) {
        self.last_seen = Utc::now();
        self.is_active = true;
        self.total_checks += 1;
        if ip_address.is_some() {
            self.last_ip = ip_address;
        }
    }
    
    /// Mark instance as inactive if not seen for more than threshold
    pub fn check_activity(&mut self, inactive_threshold_seconds: i64) {
        let now = Utc::now();
        let elapsed = now.signed_duration_since(self.last_seen).num_seconds();
        if elapsed > inactive_threshold_seconds {
            self.is_active = false;
        }
    }
}

/// Status of a binary instance
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InstanceStatus {
    Active,
    Inactive,
    Unknown,
}

/// Summary response for binary instance
#[derive(Debug, Serialize)]
pub struct BinaryInstanceSummary {
    pub machine_fingerprint: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub status: InstanceStatus,
    pub total_checks: u64,
    pub last_ip: Option<String>,
}

impl BinaryInstanceSummary {
    /// Create summary with calculated status based on check_interval
    pub fn from_instance(instance: BinaryInstance, check_interval_ms: Option<u64>, sync_mode: bool) -> Self {
        let status = Self::calculate_status(&instance, check_interval_ms, sync_mode);
        Self {
            machine_fingerprint: instance.machine_fingerprint,
            first_seen: instance.first_seen,
            last_seen: instance.last_seen,
            status,
            total_checks: instance.total_checks,
            last_ip: instance.last_ip,
        }
    }

    fn calculate_status(instance: &BinaryInstance, check_interval_ms: Option<u64>, sync_mode: bool) -> InstanceStatus {
        // Sync mode (single verification) - we can't determine if still active
        if sync_mode {
            return InstanceStatus::Unknown;
        }

        // Async mode - check if last_seen is within expected interval
        if let Some(interval_ms) = check_interval_ms {
            let now = Utc::now();
            let elapsed = now.signed_duration_since(instance.last_seen);
            let elapsed_ms = elapsed.num_milliseconds() as u64;
            
            // Allow 2x interval + 30 seconds for network delays
            let threshold_ms = (interval_ms * 2) + 30000;
            
            if elapsed_ms <= threshold_ms {
                InstanceStatus::Active
            } else {
                InstanceStatus::Inactive
            }
        } else {
            // No interval set, can't determine
            InstanceStatus::Unknown
        }
    }
}
