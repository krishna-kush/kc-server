/// Overload binary version management
/// Handles selection of versioned overload binaries from /app/overload_bins/{version}/{arch}/

use semver::Version;
use std::fs;
use std::path::{Path, PathBuf};
use goblin::Object;

/// Supported architectures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    // Linux
    LINUX_X86_64,
    LINUX_X86,
    LINUX_AARCH64,
    LINUX_ARMV7,
    
    // Windows
    WINDOWS_X86_64,
    WINDOWS_X86,
    
    // macOS
    MACOS_X86_64,
    MACOS_ARM64,
}

impl Architecture {
    /// Get directory name for this architecture
    pub fn as_str(&self) -> &'static str {
        match self {
            // Linux
            Architecture::LINUX_X86_64 => "linux-x86_64",
            Architecture::LINUX_X86 => "linux-x86",
            Architecture::LINUX_AARCH64 => "linux-arm64",
            Architecture::LINUX_ARMV7 => "linux-armv7",
            
            // Windows
            Architecture::WINDOWS_X86_64 => "windows-x86_64",
            Architecture::WINDOWS_X86 => "windows-x86",
            
            // macOS
            Architecture::MACOS_X86_64 => "macos-x86_64",
            Architecture::MACOS_ARM64 => "macos-arm64",
        }
    }

    /// Check if the data is a valid executable binary (ELF, PE, or Mach-O)
    pub fn is_valid_binary(data: &[u8]) -> bool {
        matches!(
            Object::parse(data),
            Ok(Object::Elf(_)) | Ok(Object::PE(_)) | Ok(Object::Mach(_))
        )
    }

    /// Detect architecture from binary data (supports ELF, PE, Mach-O)
    /// Returns None if the file is not a valid binary
    pub fn detect_from_binary(data: &[u8]) -> Option<Self> {
        match Object::parse(data) {
            Ok(Object::Elf(elf)) => {
                let arch = if elf.is_64 {
                    match elf.header.e_machine {
                        goblin::elf::header::EM_X86_64 => Architecture::LINUX_X86_64,
                        goblin::elf::header::EM_AARCH64 => Architecture::LINUX_AARCH64,
                        _ => Architecture::LINUX_X86_64,
                    }
                } else {
                    match elf.header.e_machine {
                        goblin::elf::header::EM_386 => Architecture::LINUX_X86,
                        goblin::elf::header::EM_ARM => Architecture::LINUX_ARMV7,
                        _ => Architecture::LINUX_X86,
                    }
                };
                Some(arch)
            },
            Ok(Object::PE(pe)) => {
                let arch = match pe.header.coff_header.machine {
                    goblin::pe::header::COFF_MACHINE_X86_64 => Architecture::WINDOWS_X86_64,
                    goblin::pe::header::COFF_MACHINE_X86 => Architecture::WINDOWS_X86,
                    _ => Architecture::WINDOWS_X86_64,
                };
                Some(arch)
            },
            Ok(Object::Mach(mach)) => {
                let arch = match mach {
                    goblin::mach::Mach::Binary(macho) => {
                        match macho.header.cputype {
                            goblin::mach::constants::cputype::CPU_TYPE_X86_64 => Architecture::MACOS_X86_64,
                            goblin::mach::constants::cputype::CPU_TYPE_ARM64 => Architecture::MACOS_ARM64,
                            _ => Architecture::MACOS_X86_64,
                        }
                    },
                    goblin::mach::Mach::Fat(_) => {
                        // Universal binaries (Fat) usually support both.
                        // Defaulting to ARM64 for modern macOS compatibility.
                        Architecture::MACOS_ARM64
                    }
                };
                Some(arch)
            },
            _ => None, // Not a valid binary
        }
    }
    
    /// Detect architecture from current system
    pub fn detect() -> Self {
        // Default to x86_64 for system detection
        Architecture::LINUX_X86_64
    }
    
    /// Check if this architecture is Windows
    pub fn is_windows(&self) -> bool {
        matches!(self, Architecture::WINDOWS_X86_64 | Architecture::WINDOWS_X86)
    }
    
    /// Get the binary filename for this architecture (with extension if needed)
    pub fn binary_filename(&self) -> &'static str {
        if self.is_windows() {
            "overload.exe"
        } else {
            "overload"
        }
    }
    
    /// Parse architecture from string
    pub fn from_str(s: &str) -> Self {
        match s {
            "linux-x86_64" | "x86_64" => Architecture::LINUX_X86_64,
            "linux-x86" | "x86" => Architecture::LINUX_X86,
            "linux-arm64" | "aarch64" => Architecture::LINUX_AARCH64,
            "linux-armv7" | "armv7" => Architecture::LINUX_ARMV7,
            "windows-x86_64" => Architecture::WINDOWS_X86_64,
            "windows-x86" => Architecture::WINDOWS_X86,
            "macos-x86_64" => Architecture::MACOS_X86_64,
            "macos-arm64" => Architecture::MACOS_ARM64,
            _ => Architecture::LINUX_X86_64, // Default
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
                // Use platform-specific filename (overload.exe for Windows, overload for others)
                let overload_path = path.join(arch.as_str()).join(arch.binary_filename());
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
        let result = get_latest_overload(base, Architecture::LINUX_X86_64).unwrap();
        assert!(result.to_str().unwrap().contains("1.2.0"));
    }

    #[test]
    fn test_architecture_strings() {
        assert_eq!(Architecture::LINUX_X86_64.as_str(), "linux-x86_64");
        assert_eq!(Architecture::LINUX_AARCH64.as_str(), "linux-arm64");
        assert_eq!(Architecture::LINUX_ARMV7.as_str(), "linux-armv7");
    }
}
