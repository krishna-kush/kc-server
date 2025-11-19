/// License signing using HMAC-SHA256
use hmac::{Hmac, Mac};
use sha2::Sha256;
use base64::{Engine as _, engine::general_purpose};

type HmacSha256 = Hmac<Sha256>;

/// Sign license JSON data
pub fn sign_license(data: &str, key: &[u8]) -> Result<String, String> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| format!("Invalid key: {}", e))?;
    
    mac.update(data.as_bytes());
    let signature = mac.finalize().into_bytes();
    
    Ok(general_purpose::STANDARD.encode(&signature))
}

/// Verify license signature
pub fn verify_license_signature(data: &str, signature: &str, key: &[u8]) -> Result<bool, String> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| format!("Invalid key: {}", e))?;
    
    mac.update(data.as_bytes());
    
    let signature_bytes = general_purpose::STANDARD
        .decode(signature)
        .map_err(|e| format!("Base64 decode failed: {}", e))?;
    
    Ok(mac.verify_slice(&signature_bytes).is_ok())
}

/// Create a signed license package (data + signature as JSON)
pub fn create_signed_package(license_json: &str, signing_key: &[u8]) -> Result<String, String> {
    let signature = sign_license(license_json, signing_key)?;
    
    let package = serde_json::json!({
        "data": license_json,
        "signature": signature,
        "algorithm": "HMAC-SHA256"
    });
    
    serde_json::to_string(&package)
        .map_err(|e| format!("JSON serialization failed: {}", e))
}

/// Verify and extract license from signed package
pub fn verify_signed_package(package_json: &str, signing_key: &[u8]) -> Result<String, String> {
    let package: serde_json::Value = serde_json::from_str(package_json)
        .map_err(|e| format!("JSON parsing failed: {}", e))?;
    
    let data = package["data"]
        .as_str()
        .ok_or_else(|| "Missing 'data' field".to_string())?;
    
    let signature = package["signature"]
        .as_str()
        .ok_or_else(|| "Missing 'signature' field".to_string())?;
    
    let algorithm = package["algorithm"]
        .as_str()
        .unwrap_or("HMAC-SHA256");
    
    if algorithm != "HMAC-SHA256" {
        return Err(format!("Unsupported algorithm: {}", algorithm));
    }
    
    if !verify_license_signature(data, signature, signing_key)? {
        return Err("Signature verification failed".to_string());
    }
    
    Ok(data.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let key = b"test_signing_key_32_bytes_long!!";
        let data = r#"{"license_id":"test123"}"#;
        
        let signature = sign_license(data, key).unwrap();
        let valid = verify_license_signature(data, &signature, key).unwrap();
        
        assert!(valid);
    }

    #[test]
    fn test_wrong_signature_fails() {
        let key = b"test_signing_key_32_bytes_long!!";
        let data = r#"{"license_id":"test123"}"#;
        
        let signature = sign_license(data, key).unwrap();
        let tampered_data = r#"{"license_id":"hacked"}"#;
        let valid = verify_license_signature(tampered_data, &signature, key).unwrap();
        
        assert!(!valid);
    }

    #[test]
    fn test_signed_package() {
        let key = b"test_signing_key_32_bytes_long!!";
        let license_json = r#"{"license_id":"test123","server_url":"http://localhost"}"#;
        
        let package = create_signed_package(license_json, key).unwrap();
        let extracted = verify_signed_package(&package, key).unwrap();
        
        assert_eq!(license_json, extracted);
    }

    #[test]
    fn test_tampered_package_fails() {
        let key = b"test_signing_key_32_bytes_long!!";
        let license_json = r#"{"license_id":"test123"}"#;
        
        let mut package = create_signed_package(license_json, key).unwrap();
        // Tamper with the package
        package = package.replace("test123", "hacked");
        
        let result = verify_signed_package(&package, key);
        assert!(result.is_err());
    }
}
