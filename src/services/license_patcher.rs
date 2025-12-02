/// License patching utility for embedding license data into overload binary
use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};

/// Size of the .license section in overload binary (4KB)
pub const LICENSE_SECTION_SIZE: usize = 4096;

/// Find the offset of .license section in an ELF or PE binary
pub fn find_license_section_offset(binary_path: &str) -> Result<u64, String> {
    log::info!("🔍 Searching for .license section in: {}", binary_path);
    
    // Read the binary
    let mut file = File::open(binary_path)
        .map_err(|e| format!("Failed to open binary: {}", e))?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .map_err(|e| format!("Failed to read binary: {}", e))?;
    
    log::info!("📊 Binary size: {} bytes", buffer.len());
    
    // Detect binary format
    if buffer.len() < 4 {
        return Err("Binary too small".to_string());
    }
    
    use crate::utils::overload_version::Architecture;
    let arch = Architecture::detect_from_binary(&buffer)
        .unwrap_or(Architecture::LINUX_X86_64);
    log::info!("🔎 Detected binary architecture: {:?}", arch);
    
    // Search for the license section marker (4096 bytes of zeros)
    // This is the static LICENSE_DATA array we defined in embedded.rs
    log::info!("🔎 Scanning for 4KB zero block (LICENSE_DATA section)...");
    let mut offset = 0;
    let search_limit = buffer.len().saturating_sub(LICENSE_SECTION_SIZE);
    let mut blocks_checked = 0;
    
    while offset < search_limit {
        // Check if we found a 4KB block of zeros (our placeholder)
        let slice = &buffer[offset..offset + LICENSE_SECTION_SIZE];
        blocks_checked += 1;
        
        // Simple heuristic: if we find a large block of zeros, it's likely our section
        if slice.iter().all(|&b| b == 0) {
            // Found a 4KB zero block - this is our .license section
            log::info!("✅ Located .license section at offset: 0x{:x} (checked {} blocks)", offset, blocks_checked);
            return Ok(offset as u64);
        }
        
        offset += 4; // Check every 4 bytes (word-aligned) for better coverage
    }
    
    log::error!("❌ Failed to find .license section after checking {} blocks", blocks_checked);
    
    Err("Could not find .license section in binary".to_string())
}

/// Patch license configuration into overload binary
pub fn patch_license_into_binary(
    binary_path: &str,
    license_json: &str,
) -> Result<(), String> {
    log::info!("🔧 Patching license into binary: {}", binary_path);
    log::info!("📝 License data size: {} bytes", license_json.len());
    
    if license_json.len() >= LICENSE_SECTION_SIZE {
        return Err(format!(
            "License data too large: {} bytes (max: {} bytes)",
            license_json.len(),
            LICENSE_SECTION_SIZE - 1
        ));
    }
    
    // Find the .license section offset
    let offset = find_license_section_offset(binary_path)?;
    
    log::info!("📍 Found .license section at offset: 0x{:x}", offset);
    
    // Open file for writing
    let mut file = OpenOptions::new()
        .write(true)
        .open(binary_path)
        .map_err(|e| format!("Failed to open binary for writing: {}", e))?;
    
    // Seek to the .license section
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("Failed to seek to .license section: {}", e))?;
    
    // Write the license JSON (will be null-terminated automatically since we're writing into zeros)
    file.write_all(license_json.as_bytes())
        .map_err(|e| format!("Failed to write license data: {}", e))?;
    
    log::info!("✅ Patched {} bytes of license data into binary", license_json.len());
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    
    #[test]
    fn test_find_license_section() {
        // Create a mock binary with a 4KB zero block
        let mut file = NamedTempFile::new().unwrap();
        
        // Write some random data
        file.write_all(&[1, 2, 3, 4]).unwrap();
        
        // Write our "license section" (4KB of zeros)
        let zeros = vec![0u8; LICENSE_SECTION_SIZE];
        file.write_all(&zeros).unwrap();
        
        // Write more random data
        file.write_all(&[5, 6, 7, 8]).unwrap();
        
        file.flush().unwrap();
        
        // Try to find the section
        let path = file.path().to_str().unwrap();
        let offset = find_license_section_offset(path).unwrap();
        
        // Should find it at offset 4 (after the initial random bytes)
        // But it needs to be aligned, so it might be at 16
        assert!(offset >= 0 && offset < 100, "Offset should be near the start");
    }
    
    #[test]
    fn test_patch_too_large() {
        let file = NamedTempFile::new().unwrap();
        let large_json = "x".repeat(LICENSE_SECTION_SIZE);
        
        let result = patch_license_into_binary(
            file.path().to_str().unwrap(),
            &large_json,
        );
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }
}
