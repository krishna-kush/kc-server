/// Network communication for access control checks
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessCheckRequest {
    pub binary_id: String,
    pub hostname: String,
    pub os_info: OsInfo,
    pub timestamp: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OsInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessCheckResponse {
    pub allowed: bool,
    pub should_delete: bool,
    pub message: String,
}

impl OsInfo {
    /// Get current OS information
    pub fn current() -> Self {
        #[cfg(target_os = "linux")]
        {
            Self {
                name: "Linux".to_string(),
                version: Self::get_linux_version(),
            }
        }
        
        #[cfg(target_os = "windows")]
        {
            Self {
                name: "Windows".to_string(),
                version: "Unknown".to_string(),
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            Self {
                name: "macOS".to_string(),
                version: "Unknown".to_string(),
            }
        }
    }
    
    #[cfg(target_os = "linux")]
    fn get_linux_version() -> String {
        std::fs::read_to_string("/proc/version")
            .ok()
            .and_then(|v| {
                v.split_whitespace()
                    .nth(2)
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "Unknown".to_string())
    }
}

impl AccessCheckRequest {
    /// Create a new access check request
    pub fn new(binary_id: String) -> Self {
        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown".to_string());
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        Self {
            binary_id,
            hostname,
            os_info: OsInfo::current(),
            timestamp,
        }
    }
}

/// Perform access check with retry logic
pub fn check_access(
    server_url: &str,
    binary_id: &str,
) -> Result<AccessCheckResponse, String> {
    let request = AccessCheckRequest::new(binary_id.to_string());
    
    // Retry logic: 3 attempts with exponential backoff
    for attempt in 1..=3 {
        match send_request(server_url, &request) {
            Ok(response) => return Ok(response),
            Err(e) => {
                if attempt < 3 {
                    let delay = std::time::Duration::from_secs(2_u64.pow(attempt - 1));
                    std::thread::sleep(delay);
                    eprintln!("Retry {}/3 after error: {}", attempt, e);
                } else {
                    return Err(format!("Failed after 3 attempts: {}", e));
                }
            }
        }
    }
    
    Err("Unreachable".to_string())
}

/// Send HTTP POST request to check access
fn send_request(
    server_url: &str,
    request: &AccessCheckRequest,
) -> Result<AccessCheckResponse, String> {
    let url = format!("{}/binary/check-access", server_url);
    
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to create client: {}", e))?;
    
    let response = client
        .post(&url)
        .json(request)
        .send()
        .map_err(|e| format!("Request failed: {}", e))?;
    
    if !response.status().is_success() {
        return Err(format!("Server returned error: {}", response.status()));
    }
    
    response
        .json::<AccessCheckResponse>()
        .map_err(|e| format!("Failed to parse response: {}", e))
}
