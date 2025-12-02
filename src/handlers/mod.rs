pub mod auth;
mod health;
mod merge;
mod sse;
mod binary;
pub mod license;
pub mod telemetry;
pub mod notification;
pub mod analytics;
pub mod stats;
pub mod settings;
pub mod google_oauth;
pub mod security;

pub use auth::{auth, verify, login, request_otp, verify_otp_and_signup, verify_2fa};
pub use notification::{
    get_notifications, create_notification, update_notification,
    mark_as_read, mark_all_as_read, delete_notification, clear_all_notifications,
};
pub use health::health;
pub use merge::{merge_binaries, get_progress};
pub use sse::progress_stream;
pub use auth::check_email;
pub use binary::{
    upload_binary, check_access, get_binary, update_binary,
    download_binary, get_executions, list_binaries, delete_binary,
};
pub use license::{
    create_license, verify_license, get_license, get_license_stats,
    update_license, delete_license, list_licenses_for_binary, list_all_licenses,
    revoke_license, get_binary_analytics,
};
pub use telemetry::{get_license_history, get_dashboard_stats, get_binary_verification_attempts};
pub use stats::get_verification_stats;
pub use analytics::get_analytics;
pub use merge::*;
pub use health::*;
pub use sse::*;
pub use settings::{
    get_storage_stats, delete_all_licenses, delete_all_binaries, get_cleanup_recommendations,
};
pub use google_oauth::{get_google_config, google_callback};
pub use security::{
    get_security_settings, toggle_2fa, add_password, change_password,
    request_password_reset, verify_reset_otp,
};
