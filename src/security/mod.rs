/// Security module for authentication and cryptography
pub mod hmac;
pub mod encryption;
pub mod signing;

pub use hmac::{
    create_signature,
    verify_signature,
    validate_timestamp,
    generate_shared_secret,
    construct_signature_data,
    TIMESTAMP_TOLERANCE,
};
pub use encryption::{
    encrypt_license, decrypt_license,
    generate_encryption_key, encode_key, decode_key,
};
pub use signing::{
    sign_license, verify_license_signature,
    create_signed_package, verify_signed_package,
};
