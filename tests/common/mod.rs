// Common test utilities for server integration tests

use std::env;

/// Get MongoDB URL from environment or use default
/// Uses MONGODB_URI from .env or constructs from MONGODB_PORT
pub fn get_mongodb_url() -> String {
    env::var("MONGODB_URI").unwrap_or_else(|_| {
        let port = env::var("MONGODB_PORT").unwrap_or_else(|_| "27017".to_string());
        format!("mongodb://mongodb:{}", port)
    })
}

/// Get Redis URL from environment or use default
/// Uses REDIS_URL from .env or constructs from REDIS_PORT
pub fn get_redis_url() -> String {
    env::var("REDIS_URL").unwrap_or_else(|_| {
        let port = env::var("REDIS_PORT").unwrap_or_else(|_| "6379".to_string());
        format!("redis://redis:{}", port)
    })
}

/// Get Weaver URL from environment or use default
/// Uses WEAVER_URL from .env or constructs from WEAVER_PORT_EXTERNAL
pub fn get_weaver_url() -> String {
    env::var("WEAVER_URL").unwrap_or_else(|_| {
        let port = env::var("WEAVER_PORT_EXTERNAL").unwrap_or_else(|_| "8081".to_string());
        format!("http://weaver:{}", port)
    })
}

/// Get Server URL from environment or use default
/// Uses SERVER_URL from .env or constructs from SERVER_PORT_EXTERNAL
pub fn get_server_url() -> String {
    env::var("SERVER_URL").unwrap_or_else(|_| {
        let port = env::var("SERVER_PORT_EXTERNAL").unwrap_or_else(|_| "8080".to_string());
        format!("http://server:{}", port)
    })
}

/// Check if we're running in Docker
pub fn is_docker_environment() -> bool {
    std::path::Path::new("/.dockerenv").exists()
}
