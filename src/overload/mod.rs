/// Overload binary components
/// Shared modules used by both the overload binary and the server
pub mod config;
pub mod network;

pub use config::{EmbeddedConfig, CONFIG_OFFSET, CONFIG_SIZE, MAGIC_HEADER};
pub use network::{AccessCheckRequest, AccessCheckResponse, OsInfo};
