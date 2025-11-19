pub mod auth;
mod health;
mod merge;
mod sse;
mod check_email;
mod binary;
pub mod license;
pub mod telemetry;
pub mod notification;
pub mod stats;
pub mod analytics;

pub use auth::{auth, verify};
pub use notification::{
    get_notifications, create_notification, update_notification,
    mark_as_read, mark_all_as_read, delete_notification, clear_all_notifications,
};
pub use health::health;
pub use merge::{merge_binaries, get_progress};
pub use sse::progress_stream;
pub use check_email::check_email;
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
