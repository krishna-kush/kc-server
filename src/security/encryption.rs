/// License encryption using AES-256-GCM
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{Engine as _, engine::general_purpose};
use rand::RngCore;

/// Encrypt license JSON data
pub fn encrypt_license(plaintext: &str, key: &[u8; 32]) -> Result<String, String> {
    let cipher = Aes256Gcm::new(key.into());
    
    // Generate random nonce (96 bits for GCM)
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;
    
    // Combine nonce + ciphertext and encode as base64
    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&ciphertext);
    
    Ok(general_purpose::STANDARD.encode(&combined))
}

/// Decrypt license data
pub fn decrypt_license(encrypted: &str, key: &[u8; 32]) -> Result<String, String> {
    let cipher = Aes256Gcm::new(key.into());
    
    // Decode from base64
    let combined = general_purpose::STANDARD
        .decode(encrypted)
        .map_err(|e| format!("Base64 decode failed: {}", e))?;
    
    if combined.len() < 12 {
        return Err("Invalid encrypted data: too short".to_string());
    }
    
    // Split nonce and ciphertext
    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    // Decrypt
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))?;
    
    String::from_utf8(plaintext)
        .map_err(|e| format!("UTF-8 decode failed: {}", e))
}

/// Generate a new 256-bit encryption key
pub fn generate_encryption_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Encode key as base64 for storage/transmission
pub fn encode_key(key: &[u8; 32]) -> String {
    general_purpose::STANDARD.encode(key)
}

/// Decode key from base64
pub fn decode_key(encoded: &str) -> Result<[u8; 32], String> {
    let bytes = general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("Base64 decode failed: {}", e))?;
    
    if bytes.len() != 32 {
        return Err(format!("Invalid key length: expected 32, got {}", bytes.len()));
    }
    
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = generate_encryption_key();
        let plaintext = r#"{"license_id":"test123","server_url":"http://localhost"}"#;
        
        let encrypted = encrypt_license(plaintext, &key).unwrap();
        let decrypted = decrypt_license(&encrypted, &key).unwrap();
        
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_key_encoding() {
        let key = generate_encryption_key();
        let encoded = encode_key(&key);
        let decoded = decode_key(&encoded).unwrap();
        
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = generate_encryption_key();
        let key2 = generate_encryption_key();
        let plaintext = "secret data";
        
        let encrypted = encrypt_license(plaintext, &key1).unwrap();
        let result = decrypt_license(&encrypted, &key2);
        
        assert!(result.is_err());
    }
}
