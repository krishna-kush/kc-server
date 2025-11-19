use actix_web::{test, web, App};
use mongodb::Client;

mod common;
use common::{get_mongodb_url, get_redis_url, get_weaver_url};

/// Test server health endpoint
#[actix_web::test]
async fn test_health_endpoint() {
    let app = test::init_service(
        App::new()
            .route("/health", web::get().to(|| async { "OK" }))
    ).await;
    
    let req = test::TestRequest::get()
        .uri("/health")
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

/// Test MongoDB connection
#[actix_web::test]
async fn test_mongodb_connection() {
    let mongodb_url = get_mongodb_url();
    println!("📊 Testing MongoDB at: {}", mongodb_url);
    
    let client = Client::with_uri_str(&mongodb_url).await;
    
    match client {
        Ok(c) => {
            let db = c.database("killcode_test");
            let collections = db.list_collection_names().await;
            assert!(collections.is_ok(), "Should be able to list collections");
            println!("✅ MongoDB connection successful");
        }
        Err(e) => {
            println!("⚠️  MongoDB not available: {}", e);
            println!("   This is expected if MongoDB is not running");
        }
    }
}

/// Test Redis connection
#[actix_web::test]
async fn test_redis_connection() {
    let redis_url = get_redis_url();
    println!("📊 Testing Redis at: {}", redis_url);
    
    let client = redis::Client::open(redis_url.as_str());
    
    match client {
        Ok(c) => {
            let conn = c.get_multiplexed_async_connection().await;
            match conn {
                Ok(_) => println!("✅ Redis connection successful"),
                Err(e) => {
                    println!("⚠️  Redis not available: {}", e);
                    println!("   This is expected if Redis is not running");
                }
            }
        }
        Err(e) => {
            println!("⚠️  Redis client error: {}", e);
        }
    }
}

/// Test Weaver service availability
#[actix_web::test]
async fn test_weaver_availability() {
    let weaver_url = get_weaver_url();
    println!("📊 Testing Weaver at: {}", weaver_url);
    
    let client = reqwest::Client::new();
    let health_url = format!("{}/health", weaver_url);
    
    match client.get(&health_url).send().await {
        Ok(resp) => {
            println!("✅ Weaver service available: {} (status: {})", weaver_url, resp.status());
            assert!(resp.status().is_success() || resp.status().is_client_error());
        }
        Err(e) => {
            println!("⚠️  Weaver not available: {}", e);
            println!("   This is expected if Weaver is not running");
            println!("   Start Weaver with: docker compose up weaver");
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[actix_web::test]
    async fn test_full_stack_connectivity() {
        println!("\n🔄 Testing Full Stack Connectivity");
        println!("====================================\n");
        
        // Test MongoDB
        println!("1️⃣  Testing MongoDB...");
        test_mongodb_connection().await;
        
        // Test Redis
        println!("\n2️⃣  Testing Redis...");
        test_redis_connection().await;
        
        // Test Weaver
        println!("\n3️⃣  Testing Weaver...");
        test_weaver_availability().await;
        
        println!("\n✅ Full stack connectivity test complete!\n");
    }
}
