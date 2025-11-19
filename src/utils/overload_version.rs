/// Overload binary version management
/// Handles selection of versioned overload binaries from /app/overload_bins/{version}/{arch}/

use semver::Version;
use std::fs;
use std::path::{Path, PathBuf};

/// Supported architectures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    // Linux
    LinuxX8664,
    LinuxX86,
    LinuxAarch64,
    LinuxArmv7,
    
    // Windows
    WindowsX8664,
    WindowsX86,
    
    // macOS
    MacOSX8664,
    MacOSArm64,
}

impl Architecture {
    /// Get directory name for this architecture
    pub fn as_str(&self) -> &'static str {
        match self {
            // Linux
            Architecture::LinuxX8664 => "linux-x86_64",
            Architecture::LinuxX86 => "linux-x86",
            Architecture::LinuxAarch64 => "linux-arm64",
            Architecture::LinuxArmv7 => "linux-armv7",
            
            // Windows
            Architecture::WindowsX8664 => "windows-x86_64",
            Architecture::WindowsX86 => "windows-x86",
            
            // macOS
            Architecture::MacOSX8664 => "macos-x86_64",
            Architecture::MacOSArm64 => "macos-arm64",
        }
    }

    /// Detect architecture from binary data (supports ELF, PE, Mach-O)
    pub fn detect_from_binary(data: &[u8]) -> Self {
        if data.len() < 64 {
            return Architecture::LinuxX8664; // Default
        }
        
        // Check ELF magic (Linux)
        if &data[0..4] == b"\x7fELF" {
            // ELF class: 1=32-bit, 2=64-bit (offset 4)
            let class = data[4];
            // ELF machine type is at offset 18 (2 bytes, little-endian)
            let machine = u16::from_le_bytes([data[18], data[19]]);
            
            return match (machine, class) {
                (0x3E, 2) => Architecture::LinuxX8664,    // x86-64
                (0x03, 1) => Architecture::LinuxX86,      // x86 32-bit
                (0xB7, 2) => Architecture::LinuxAarch64,  // AArch64
                (0x28, 1) => Architecture::LinuxArmv7,    // ARM 32-bit
                _ => Architecture::LinuxX8664,            // Unknown ELF, default
            };
        }
        
        // Check PE magic (Windows)
        if &data[0..2] == b"MZ" {
            // DOS header, find PE header offset at 0x3C (4 bytes)
            if data.len() < 0x40 {
                return Architecture::WindowsX8664; // Default for Windows
            }
            
            let pe_offset = u32::from_le_bytes([
                data[0x3C], data[0x3D], data[0x3E], data[0x3F]
            ]) as usize;
            
            if pe_offset + 6 > data.len() {
                return Architecture::WindowsX8664;
            }
            
            // Check PE signature
            if &data[pe_offset..pe_offset+4] == b"PE\0\0" {
                // Machine type at PE offset + 4 (2 bytes)
                let machine = u16::from_le_bytes([
                    data[pe_offset + 4],
                    data[pe_offset + 5]
                ]);
                
                return match machine {
                    0x8664 => Architecture::WindowsX8664,  // x86-64
                    0x014C => Architecture::WindowsX86,    // x86 32-bit
                    _ => Architecture::WindowsX8664,       // Unknown PE, default
                };
            }
        }
        
        // Check Mach-O magic (macOS)
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        match magic {
            0xFEEDFACF => {
                // Mach-O 64-bit, CPU type at offset 4
                let cpu_type = i32::from_le_bytes([data[4], data[5], data[6], data[7]]);
                match cpu_type {
                    0x01000007 => Architecture::MacOSX8664,  // x86-64
                    0x0100000C => Architecture::MacOSArm64,  // ARM64
                    _ => Architecture::MacOSX8664,
                }
            }
            0xFEEDFACE => {
                // Mach-O 32-bit (Intel)
                Architecture::MacOSX8664
            }
            0xCAFEBABE | 0xBEBAFECA => {
                // Universal binary, assume ARM64 for modern macs
                Architecture::MacOSArm64
            }
            _ => Architecture::LinuxX8664, // Unknown format, default
        }
    }
    
    /// Detect architecture from current system
    pub fn detect() -> Self {
        // Default to x86_64 for system detection
        Architecture::LinuxX8664
    }
    
    /// Parse architecture from string
    pub fn from_str(s: &str) -> Self {
        match s {
            "linux-x86_64" | "x86_64" => Architecture::LinuxX8664,
            "linux-x86" | "x86" => Architecture::LinuxX86,
            "linux-arm64" | "aarch64" => Architecture::LinuxAarch64,
            "linux-armv7" | "armv7" => Architecture::LinuxArmv7,
            "windows-x86_64" => Architecture::WindowsX8664,
            "windows-x86" => Architecture::WindowsX86,
            "macos-x86_64" => Architecture::MacOSX8664,
            "macos-arm64" => Architecture::MacOSArm64,
            _ => Architecture::LinuxX8664, // Default
        }
    }
}

/// Find the latest version of overload for the given architecture
/// 
/// # Arguments
/// * `base_dir` - Base directory containing versioned builds (e.g., "/app/overload_bins")
/// * `arch` - Target architecture
/// 
/// # Returns
/// Path to the latest overload binary, or error if none found
pub fn get_latest_overload(base_dir: &Path, arch: Architecture) -> Result<PathBuf, String> {
    // List all version directories
    let entries = fs::read_dir(base_dir)
        .map_err(|e| format!("Failed to read overload_bins directory: {}", e))?;

    let mut versions: Vec<(Version, PathBuf)> = Vec::new();

    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
        let path = entry.path();

        // Skip if not a directory
        if !path.is_dir() {
            continue;
        }

        // Parse version from directory name
        if let Some(version_str) = path.file_name().and_then(|n| n.to_str()) {
            if let Ok(version) = Version::parse(version_str) {
                // Check if overload binary exists for this version and architecture
                let overload_path = path.join(arch.as_str()).join("overload");
                if overload_path.exists() && overload_path.is_file() {
                    versions.push((version, overload_path));
                }
            }
        }
    }

    // Sort by version (newest first)
    versions.sort_by(|a, b| b.0.cmp(&a.0));

    // Return the latest version
    versions
        .first()
        .map(|(version, path)| {
            eprintln!("ℹ️  Selected overload version {} for {}", version, arch.as_str());
            path.clone()
        })
        .ok_or_else(|| {
            format!(
                "No overload binary found for architecture {} in {}",
                arch.as_str(),
                base_dir.display()
            )
        })
}

/// Get path to overload binary for the current system architecture
pub fn get_overload_path() -> Result<PathBuf, String> {
    let base_dir = Path::new("/app/overload_bins");
    let arch = Architecture::detect();
    get_latest_overload(base_dir, arch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_version_selection() {
        // Create temporary directory structure
        let temp_dir = TempDir::new().unwrap();
        let base = temp_dir.path();

        // Create multiple versions
        let versions = ["1.0.0", "1.2.0", "1.1.5", "2.0.0-beta.1", "0.9.0"];
        for version in &versions {
            let version_dir = base.join(version).join("linux-x86_64");
            fs::create_dir_all(&version_dir).unwrap();
            fs::write(version_dir.join("overload"), b"fake binary").unwrap();
        }

        // Should select 1.2.0 (highest stable version)
        let result = get_latest_overload(base, Architecture::LinuxX8664).unwrap();
        assert!(result.to_str().unwrap().contains("1.2.0"));
    }

    #[test]
    fn test_architecture_strings() {
        assert_eq!(Architecture::LinuxX8664.as_str(), "linux-x86_64");
        assert_eq!(Architecture::LinuxAarch64.as_str(), "linux-aarch64");
        assert_eq!(Architecture::LinuxArm.as_str(), "linux-arm");
    }
}
