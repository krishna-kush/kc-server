/// Embedded configuration structure for overload binary
/// This struct is injected at a known offset in the compiled binary

/// Magic header to identify config location in binary
pub const MAGIC_HEADER: &[u8; 18] = b"KILLCODE_CONFIG_V1";

/// Fixed offset where config is embedded (must match binary layout)
pub const CONFIG_OFFSET: usize = 0x2000; // 8KB offset

/// Size of the entire config block
pub const CONFIG_SIZE: usize = 512;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct EmbeddedConfig {
    /// Magic header for verification
    pub magic: [u8; 18],
    
    /// Unique binary identifier (UUID format)
    pub binary_id: [u8; 64],
    
    /// Server URL (null-terminated)
    pub server_url: [u8; 256],
    
    /// Shared secret for HMAC authentication (64 hex characters = 32 bytes)
    pub shared_secret: [u8; 64],
    
    /// Grace period for offline mode (seconds)
    /// 0 = no grace (fail immediately if server unreachable)
    /// u32::MAX = infinite grace (always allow offline)
    pub grace_period: u32,
    
    /// Reserved for future use
    pub reserved: [u8; 72],
    
    /// SHA256 checksum of all above fields
    pub checksum: [u8; 32],
}

impl EmbeddedConfig {
    /// Create a new config with default values (placeholder)
    pub fn new_placeholder() -> Self {
        let mut config = Self {
            magic: *MAGIC_HEADER,
            binary_id: [0u8; 64],
            server_url: [0u8; 256],
            shared_secret: [0u8; 64],
            grace_period: 0, // Default: no grace period (strict online check)
            reserved: [0u8; 72],
            checksum: [0u8; 32],
        };
        
        // Write placeholder text
        let placeholder_id = b"PLACEHOLDER_BINARY_ID_WILL_BE_REPLACED_AT_RUNTIME_BY_SERVER";
        config.binary_id[..placeholder_id.len()].copy_from_slice(placeholder_id);
        
        let placeholder_url = b"PLACEHOLDER_SERVER_URL_WILL_BE_REPLACED";
        config.server_url[..placeholder_url.len()].copy_from_slice(placeholder_url);
        
        let placeholder_secret = b"PLACEHOLDER_SHARED_SECRET_WILL_BE_REPLACED_BY_SERVER_AT_RUNTIME";
        config.shared_secret[..placeholder_secret.len().min(64)].copy_from_slice(&placeholder_secret[..placeholder_secret.len().min(64)]);
        
        config
    }
    
    /// Create a config with actual values
    pub fn new(binary_id: &str, server_url: &str, shared_secret: &str, grace_period: u32) -> Self {
        let mut config = Self {
            magic: *MAGIC_HEADER,
            binary_id: [0u8; 64],
            server_url: [0u8; 256],
            shared_secret: [0u8; 64],
            grace_period,
            reserved: [0u8; 72],
            checksum: [0u8; 32],
        };
        
        // Copy binary ID (null-terminated)
        let id_bytes = binary_id.as_bytes();
        let len = id_bytes.len().min(63);
        config.binary_id[..len].copy_from_slice(&id_bytes[..len]);
        
        // Copy server URL (null-terminated)
        let url_bytes = server_url.as_bytes();
        let len = url_bytes.len().min(255);
        config.server_url[..len].copy_from_slice(&url_bytes[..len]);
        
        // Copy shared secret (null-terminated)
        let secret_bytes = shared_secret.as_bytes();
        let len = secret_bytes.len().min(63);
        config.shared_secret[..len].copy_from_slice(&secret_bytes[..len]);
        
        // Calculate checksum (excluding checksum field itself)
        config.checksum = config.calculate_checksum();
        
        config
    }
    
    /// Calculate SHA256 checksum of config (excluding checksum field)
    fn calculate_checksum(&self) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(&self.magic);
        hasher.update(&self.binary_id);
        hasher.update(&self.server_url);
        hasher.update(&self.shared_secret);
        hasher.update(&self.grace_period.to_le_bytes());
        hasher.update(&self.reserved);
        
        let result = hasher.finalize();
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&result);
        checksum
    }
    
    /// Verify the checksum is valid
    pub fn verify_checksum(&self) -> bool {
        let calculated = self.calculate_checksum();
        calculated == self.checksum
    }
    
    /// Get binary ID as string
    pub fn get_binary_id(&self) -> String {
        let null_pos = self.binary_id.iter().position(|&c| c == 0).unwrap_or(64);
        String::from_utf8_lossy(&self.binary_id[..null_pos]).to_string()
    }
    
    /// Get server URL as string
    pub fn get_server_url(&self) -> String {
        let null_pos = self.server_url.iter().position(|&c| c == 0).unwrap_or(256);
        String::from_utf8_lossy(&self.server_url[..null_pos]).to_string()
    }
    
    /// Get shared secret as string
    pub fn get_shared_secret(&self) -> String {
        let null_pos = self.shared_secret.iter().position(|&c| c == 0).unwrap_or(64);
        String::from_utf8_lossy(&self.shared_secret[..null_pos]).to_string()
    }
    
    /// Convert to bytes for embedding
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(CONFIG_SIZE);
        bytes.extend_from_slice(&self.magic);
        bytes.extend_from_slice(&self.binary_id);
        bytes.extend_from_slice(&self.server_url);
        bytes.extend_from_slice(&self.shared_secret);
        bytes.extend_from_slice(&self.grace_period.to_le_bytes());
        bytes.extend_from_slice(&self.reserved);
        bytes.extend_from_slice(&self.checksum);
        
        // Pad to CONFIG_SIZE
        bytes.resize(CONFIG_SIZE, 0);
        bytes
    }
    
    /// Parse from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < CONFIG_SIZE {
            return Err("Invalid config size".to_string());
        }
        
        let mut magic = [0u8; 18];
        let mut binary_id = [0u8; 64];
        let mut server_url = [0u8; 256];
        let mut shared_secret = [0u8; 64];
        let mut reserved = [0u8; 72];
        let mut checksum = [0u8; 32];
        
        let mut offset = 0;
        magic.copy_from_slice(&bytes[offset..offset + 18]);
        offset += 18;
        
        binary_id.copy_from_slice(&bytes[offset..offset + 64]);
        offset += 64;
        
        server_url.copy_from_slice(&bytes[offset..offset + 256]);
        offset += 256;
        
        shared_secret.copy_from_slice(&bytes[offset..offset + 64]);
        offset += 64;
        
        let grace_period = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        offset += 4;
        
        reserved.copy_from_slice(&bytes[offset..offset + 72]);
        offset += 72;
        
        checksum.copy_from_slice(&bytes[offset..offset + 32]);
        
        let config = Self {
            magic,
            binary_id,
            server_url,
            shared_secret,
            grace_period,
            reserved,
            checksum,
        };
        
        // Verify magic header
        if config.magic != *MAGIC_HEADER {
            return Err("Invalid magic header".to_string());
        }
        
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_config_roundtrip() {
        let config = EmbeddedConfig::new("bin_test123", "http://localhost:8080", "test_secret_key", 3600);
        let bytes = config.to_bytes();
        let parsed = EmbeddedConfig::from_bytes(&bytes).unwrap();
        
        assert_eq!(parsed.get_binary_id(), "bin_test123");
        assert_eq!(parsed.get_server_url(), "http://localhost:8080");
        assert_eq!(parsed.grace_period, 3600);
        assert!(parsed.verify_checksum());
    }
    
    #[test]
    fn test_placeholder_config() {
        let config = EmbeddedConfig::new_placeholder();
        assert_eq!(config.magic, *MAGIC_HEADER);
        assert!(config.get_binary_id().contains("PLACEHOLDER"));
    }
}
