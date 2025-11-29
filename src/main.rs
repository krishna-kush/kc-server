// Import from library crate
use server::{db, handlers, middleware, models, services};

use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use dotenv::dotenv;
use std::env;
use services::ProgressSubscriber;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    let host = env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("SERVER_PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .unwrap_or(8080);

    // Initialize database
    let db = db::init_db()
        .await
        .expect("Failed to initialize database");

    // Redis URL for progress tracking
    let redis_url = env::var("REDIS_URL")
        .unwrap_or_else(|_| "redis://redis:6379".to_string());

    // Initialize Progress Subscriber
    let progress_subscriber = ProgressSubscriber::new(
        redis_url.clone(),
        db.collection("merge_tasks"),
        db.clone(),
    );

    log::info!("🚀 Starting server at {}:{}", host, port);
    log::info!("📡 Redis URL: {}", redis_url);

    // Get CORS allowed origins from environment
    let cors_origins = env::var("CORS_ALLOWED_ORIGINS")
        .unwrap_or_else(|_| "http://localhost:5173".to_string());
    let origins: Vec<String> = cors_origins
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    
    log::info!("🔒 CORS allowed origins: {:?}", origins);

    HttpServer::new(move || {
        let mut cors = Cors::default()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);
        
        // Add each allowed origin
        for origin in &origins {
            cors = cors.allowed_origin(origin);
        }
        
        // Add credentials support
        cors = cors.supports_credentials();

        App::new()
            .wrap(cors)
            .wrap(actix_web::middleware::Logger::default())
            .app_data(web::Data::new(db.clone()))
            .app_data(web::Data::new(progress_subscriber.clone()))
            .route("/health", web::get().to(handlers::health))
            .route("/check-email", web::post().to(handlers::check_email))
            .route("/auth", web::post().to(handlers::auth))
            // Binary management routes (protected - require authentication)
            .service(
                web::scope("/binary")
                    .wrap(middleware::AuthMiddleware)
                    .route("/upload", web::post().to(handlers::upload_binary))
                    .route("/check-access", web::post().to(handlers::check_access))
                    .route("/{id}", web::get().to(handlers::get_binary))
                    .route("/{id}", web::patch().to(handlers::update_binary))
                    .route("/{id}", web::delete().to(handlers::delete_binary))
                    .route("/{id}/download", web::get().to(handlers::download_binary))
                    .route("/{id}/executions", web::get().to(handlers::get_executions))
                    .route("/{binary_id}/verification-attempts", web::get().to(handlers::get_binary_verification_attempts))
                    .route("/{binary_id}/licenses", web::get().to(handlers::list_licenses_for_binary))
            )
            .service(
                web::scope("/binaries")
                    .wrap(middleware::AuthMiddleware)
                    .route("", web::get().to(handlers::list_binaries))
            )
            // License management routes (protected - require authentication)
            .service(
                web::scope("/license")
                    .wrap(middleware::AuthMiddleware)
                    .route("/create", web::post().to(handlers::create_license))
                    .route("/{license_id}", web::get().to(handlers::get_license))
                    .route("/{license_id}/stats", web::get().to(handlers::get_license_stats))
                    .route("/{license_id}", web::patch().to(handlers::update_license))
                    .route("/{license_id}", web::delete().to(handlers::delete_license))
                    .route("/{license_id}/revoke", web::post().to(handlers::revoke_license))
            )
            .service(
                web::scope("/licenses")
                    .wrap(middleware::AuthMiddleware)
                    .route("", web::get().to(handlers::list_all_licenses))
            )
            // Verify endpoint - Public (required for binary execution)
            .route("/verify", web::post().to(handlers::verify_license))
            // Legacy API v1 endpoints for binary compatibility
            .service(
                web::scope("/api/v1")
                    .route("/verify", web::post().to(handlers::verify_license))
            )
            // Telemetry endpoints (protected)
            .service(
                web::scope("/telemetry")
                    .wrap(middleware::AuthMiddleware)
                    .route("/license/{license_id}/history", web::get().to(handlers::get_license_history))
                    .route("/dashboard", web::get().to(handlers::get_dashboard_stats))
            )
            // Analytics endpoints (protected)
            .service(
                web::scope("/analytics")
                    .wrap(middleware::AuthMiddleware)
                    .route("", web::get().to(handlers::get_analytics))
            )
            // Public stats endpoints (no auth required)
            .route("/stats/verifications", web::get().to(handlers::get_verification_stats))
            // Merge and progress endpoints (protected)
            .service(
                web::scope("/progress")
                    .wrap(middleware::AuthMiddleware)
                    .route("/{task_id}", web::get().to(handlers::get_progress))
                    .route("/{task_id}/stream", web::get().to(handlers::progress_stream))
            )
            .service(
                web::scope("/merge")
                    .wrap(middleware::AuthMiddleware)
                    .route("", web::post().to(handlers::merge_binaries))
                    .route("/{task_id}/download", web::get().to(handlers::download_merged_binary))
            )
            // Notification routes (protected)
            .service(
                web::scope("/notifications")
                    .wrap(middleware::AuthMiddleware)
                    .route("", web::get().to(handlers::get_notifications))
                    .route("", web::post().to(handlers::create_notification))
                    .route("", web::delete().to(handlers::clear_all_notifications))
                    .route("/read-all", web::post().to(handlers::mark_all_as_read))
                    .route("/{id}", web::patch().to(handlers::update_notification))
                    .route("/{id}/read", web::post().to(handlers::mark_as_read))
                    .route("/{id}", web::delete().to(handlers::delete_notification))
            )
            .service(
                web::scope("/protected")
                    .wrap(middleware::AuthMiddleware)
                    .route("/verify", web::get().to(handlers::verify)),
            )
    })
    .bind((host.as_str(), port))?
    .run()
    .await
}
