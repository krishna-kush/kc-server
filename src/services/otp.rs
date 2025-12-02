/// OTP (One-Time Password) service for email verification
use redis::AsyncCommands;
use rand::Rng;
use std::env;

const OTP_PREFIX: &str = "otp:";
const OTP_TTL_SECONDS: i64 = 600; // 10 minutes

pub struct OtpService {
    redis_url: String,
    mailer_url: String,
}

impl OtpService {
    pub fn new() -> Self {
        Self {
            redis_url: env::var("REDIS_URL").unwrap_or_else(|_| "redis://redis:6379".to_string()),
            mailer_url: env::var("MAILER_URL").unwrap_or_else(|_| "http://mailer:8082".to_string()),
        }
    }

    /// Generate a 6-digit OTP
    fn generate_otp() -> String {
        let mut rng = rand::rng();
        let otp: u32 = rng.random_range(100000..1000000);
        otp.to_string()
    }

    /// Store OTP in Redis and send via email (for signup)
    pub async fn send_otp(&self, email: &str) -> Result<(), String> {
        let otp = Self::generate_otp();
        
        // Store in Redis
        let client = redis::Client::open(self.redis_url.as_str())
            .map_err(|e| format!("Redis connection error: {}", e))?;
        let mut conn = client.get_multiplexed_async_connection()
            .await
            .map_err(|e| format!("Redis connection error: {}", e))?;
        
        let key = format!("{}{}", OTP_PREFIX, email.to_lowercase());
        let _: () = conn.set_ex(&key, &otp, OTP_TTL_SECONDS as u64)
            .await
            .map_err(|e| format!("Redis error: {}", e))?;
        
        log::info!("📧 Sending signup OTP to {}", email);
        
        // Send via mailer service
        let client = reqwest::Client::new();
        let response = client
            .post(format!("{}/send/otp", self.mailer_url))
            .json(&serde_json::json!({
                "email": email,
                "otp": otp
            }))
            .send()
            .await
            .map_err(|e| format!("Mailer request error: {}", e))?;
        
        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(format!("Mailer error: {}", error_text));
        }
        
        log::info!("✅ Signup OTP queued for {}", email);
        Ok(())
    }

    /// Store OTP in Redis and send via email (for 2FA login)
    pub async fn send_2fa_otp(&self, email: &str) -> Result<(), String> {
        let otp = Self::generate_otp();
        
        // Store in Redis
        let client = redis::Client::open(self.redis_url.as_str())
            .map_err(|e| format!("Redis connection error: {}", e))?;
        let mut conn = client.get_multiplexed_async_connection()
            .await
            .map_err(|e| format!("Redis connection error: {}", e))?;
        
        let key = format!("{}{}", OTP_PREFIX, email.to_lowercase());
        let _: () = conn.set_ex(&key, &otp, OTP_TTL_SECONDS as u64)
            .await
            .map_err(|e| format!("Redis error: {}", e))?;
        
        log::info!("📧 Sending 2FA OTP to {}", email);
        
        // Send via mailer service (using 2FA specific endpoint)
        let client = reqwest::Client::new();
        let response = client
            .post(format!("{}/send/otp-2fa", self.mailer_url))
            .json(&serde_json::json!({
                "email": email,
                "otp": otp
            }))
            .send()
            .await
            .map_err(|e| format!("Mailer request error: {}", e))?;
        
        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(format!("Mailer error: {}", error_text));
        }
        
        log::info!("✅ 2FA OTP queued for {}", email);
        Ok(())
    }

    /// Verify OTP
    pub async fn verify_otp(&self, email: &str, otp: &str) -> Result<bool, String> {
        let client = redis::Client::open(self.redis_url.as_str())
            .map_err(|e| format!("Redis connection error: {}", e))?;
        let mut conn = client.get_multiplexed_async_connection()
            .await
            .map_err(|e| format!("Redis connection error: {}", e))?;
        
        let key = format!("{}{}", OTP_PREFIX, email.to_lowercase());
        let stored_otp: Option<String> = conn.get(&key)
            .await
            .map_err(|e| format!("Redis error: {}", e))?;
        
        match stored_otp {
            Some(stored) => {
                if stored == otp {
                    // Delete OTP after successful verification
                    let _: () = conn.del(&key)
                        .await
                        .map_err(|e| format!("Redis error: {}", e))?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            None => Ok(false), // OTP expired or doesn't exist
        }
    }

    /// Delete OTP (for cleanup)
    pub async fn delete_otp(&self, email: &str) -> Result<(), String> {
        let client = redis::Client::open(self.redis_url.as_str())
            .map_err(|e| format!("Redis connection error: {}", e))?;
        let mut conn = client.get_multiplexed_async_connection()
            .await
            .map_err(|e| format!("Redis connection error: {}", e))?;
        
        let key = format!("{}{}", OTP_PREFIX, email.to_lowercase());
        let _: () = conn.del(&key)
            .await
            .map_err(|e| format!("Redis error: {}", e))?;
        
        Ok(())
    }
}

impl Default for OtpService {
    fn default() -> Self {
        Self::new()
    }
}
