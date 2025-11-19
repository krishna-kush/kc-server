/// HMAC-based authentication for license verification
/// Prevents unauthorized access and replay attacks

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Maximum allowed time difference for timestamp validation (seconds)
/// Prevents replay attacks
pub const TIMESTAMP_TOLERANCE: i64 = 300; // 5 minutes

/// Generate HMAC-SHA256 signature
/// 
/// # Arguments
/// * `data` - Data to sign (typically: license_id + timestamp)
/// * `secret` - Shared secret key
/// 
/// # Returns
/// Hex-encoded signature string
pub fn create_signature(data: &str, secret: &str) -> Result<String, String> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| format!("Invalid secret key: {}", e))?;
    
    mac.update(data.as_bytes());
    
    let result = mac.finalize();
    Ok(hex::encode(result.into_bytes()))
}

/// Verify HMAC-SHA256 signature in constant time
/// 
/// # Arguments
/// * `data` - Data that was signed
/// * `secret` - Shared secret key
/// * `signature` - Provided signature to verify
/// 
/// # Returns
/// true if signature is valid, false otherwise
pub fn verify_signature(data: &str, secret: &str, signature: &str) -> bool {
    // Generate expected signature
    let expected = match create_signature(data, secret) {
        Ok(sig) => sig,
        Err(e) => {
            log::error!("Failed to create signature: {}", e);
            return false;
        }
    };
    
    // Constant-time comparison to prevent timing attacks
    let signature_bytes = signature.as_bytes();
    let expected_bytes = expected.as_bytes();
    
    // Ensure same length to avoid early return
    if signature_bytes.len() != expected_bytes.len() {
        return false;
    }
    
    signature_bytes.ct_eq(expected_bytes).into()
}

/// Validate timestamp to prevent replay attacks
/// 
/// # Arguments
/// * `timestamp` - Unix timestamp from request
/// 
/// # Returns
/// true if timestamp is within acceptable window
pub fn validate_timestamp(timestamp: i64) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    
    let diff = (now - timestamp).abs();
    
    if diff > TIMESTAMP_TOLERANCE {
        log::warn!(
            "Timestamp validation failed: diff={} seconds (tolerance={} seconds)",
            diff,
            TIMESTAMP_TOLERANCE
        );
        return false;
    }
    
    true
}

/// Generate a cryptographically secure random secret
/// 
/// # Returns
/// 64-character hex string (32 bytes of entropy)
pub fn generate_shared_secret() -> String {
    use rand::Rng;
    
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    
    hex::encode(bytes)
}

/// Construct signature data string from license_id and timestamp
/// This is the format expected for HMAC signing
pub fn construct_signature_data(license_id: &str, timestamp: i64) -> String {
    format!("{}{}", license_id, timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_signature_generation() {
        let data = "test_license_id1234567890";
        let secret = "test_secret_key";
        
        let sig1 = create_signature(data, secret).unwrap();
        let sig2 = create_signature(data, secret).unwrap();
        
        // Same input should produce same signature
        assert_eq!(sig1, sig2);
        assert_eq!(sig1.len(), 64); // SHA256 = 32 bytes = 64 hex chars
    }
    
    #[test]
    fn test_signature_verification_success() {
        let data = "license_12345_1700000000";
        let secret = "super_secret_key_12345";
        
        let signature = create_signature(data, secret).unwrap();
        assert!(verify_signature(data, secret, &signature));
    }
    
    #[test]
    fn test_signature_verification_failure() {
        let data = "license_12345_1700000000";
        let secret = "super_secret_key_12345";
        let wrong_secret = "wrong_secret";
        
        let signature = create_signature(data, secret).unwrap();
        assert!(!verify_signature(data, wrong_secret, &signature));
    }
    
    #[test]
    fn test_signature_verification_tampered_data() {
        let data = "license_12345_1700000000";
        let tampered_data = "license_99999_1700000000";
        let secret = "super_secret_key_12345";
        
        let signature = create_signature(data, secret).unwrap();
        assert!(!verify_signature(tampered_data, secret, &signature));
    }
    
    #[test]
    fn test_timestamp_validation_current() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        assert!(validate_timestamp(now));
    }
    
    #[test]
    fn test_timestamp_validation_within_tolerance() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        // 4 minutes ago (within 5 minute tolerance)
        assert!(validate_timestamp(now - 240));
        
        // 4 minutes in future
        assert!(validate_timestamp(now + 240));
    }
    
    #[test]
    fn test_timestamp_validation_outside_tolerance() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        // 10 minutes ago (outside 5 minute tolerance)
        assert!(!validate_timestamp(now - 600));
        
        // 10 minutes in future
        assert!(!validate_timestamp(now + 600));
    }
    
    #[test]
    fn test_generate_shared_secret() {
        let secret1 = generate_shared_secret();
        let secret2 = generate_shared_secret();
        
        // Should be 64 hex characters (32 bytes)
        assert_eq!(secret1.len(), 64);
        assert_eq!(secret2.len(), 64);
        
        // Should be different (extremely unlikely to collide)
        assert_ne!(secret1, secret2);
        
        // Should be valid hex
        assert!(hex::decode(&secret1).is_ok());
        assert!(hex::decode(&secret2).is_ok());
    }
    
    #[test]
    fn test_construct_signature_data() {
        let license_id = "bin_abc123";
        let timestamp = 1700000000i64;
        
        let data = construct_signature_data(license_id, timestamp);
        assert_eq!(data, "bin_abc1231700000000");
    }
}
