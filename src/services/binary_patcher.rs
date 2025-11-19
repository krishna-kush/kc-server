/// Binary patching service - Injects unique ID into overload template
use crate::overload::{EmbeddedConfig, CONFIG_OFFSET, CONFIG_SIZE};
use std::path::Path;

pub struct BinaryPatcher;

impl BinaryPatcher {
    /// Patch the overload template with unique configuration
    pub fn patch_overload(
        template_path: &Path,
        binary_id: &str,
        server_url: &str,
        shared_secret: &str,
        grace_period: u32,
    ) -> Result<Vec<u8>, String> {
        // Read the template binary
        let template_bytes = std::fs::read(template_path)
            .map_err(|e| format!("Failed to read template: {}", e))?;
        
        if template_bytes.len() < CONFIG_OFFSET + CONFIG_SIZE {
            return Err(format!(
                "Template binary too small: {} bytes (need at least {})",
                template_bytes.len(),
                CONFIG_OFFSET + CONFIG_SIZE
            ));
        }
        
        // Create configuration
        let config = EmbeddedConfig::new(binary_id, server_url, shared_secret, grace_period);
        let config_bytes = config.to_bytes();
        
        // Patch the binary
        let mut patched = template_bytes.clone();
        patched[CONFIG_OFFSET..CONFIG_OFFSET + CONFIG_SIZE]
            .copy_from_slice(&config_bytes);
        
        log::info!(
            "✅ Patched overload template: {} bytes, ID: {}",
            patched.len(),
            binary_id
        );
        
        Ok(patched)
    }
    
    /// Verify that a binary has been properly patched
    pub fn verify_patch(binary_bytes: &[u8]) -> Result<EmbeddedConfig, String> {
        if binary_bytes.len() < CONFIG_OFFSET + CONFIG_SIZE {
            return Err("Binary too small".to_string());
        }
        
        let config_bytes = &binary_bytes[CONFIG_OFFSET..CONFIG_OFFSET + CONFIG_SIZE];
        let config = EmbeddedConfig::from_bytes(config_bytes)?;
        
        if !config.verify_checksum() {
            return Err("Config checksum verification failed".to_string());
        }
        
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overload::EmbeddedConfig;
    
    #[test]
    fn test_patch_verification() {
        // Create a mock template (large enough to hold config)
        let mut template = vec![0u8; CONFIG_OFFSET + CONFIG_SIZE + 1000];
        
        // Write placeholder config
        let placeholder = EmbeddedConfig::new_placeholder();
        let placeholder_bytes = placeholder.to_bytes();
        template[CONFIG_OFFSET..CONFIG_OFFSET + CONFIG_SIZE]
            .copy_from_slice(&placeholder_bytes);
        
        // Save to temp file
        let temp_path = std::env::temp_dir().join("test_template");
        std::fs::write(&temp_path, &template).unwrap();
        
        // Patch it
        let patched = BinaryPatcher::patch_overload(
            &temp_path,
            "bin_test123",
            "http://localhost:8080",
            3600,
        ).unwrap();
        
        // Verify the patch
        let config = BinaryPatcher::verify_patch(&patched).unwrap();
        assert_eq!(config.get_binary_id(), "bin_test123");
        assert_eq!(config.get_server_url(), "http://localhost:8080");
        assert_eq!(config.grace_period, 3600);
        
        // Cleanup
        std::fs::remove_file(temp_path).ok();
    }
}
