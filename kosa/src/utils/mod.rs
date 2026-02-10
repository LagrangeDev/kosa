pub mod binary;
pub mod compress;
pub mod crypto;
pub mod marker;

use base64::{Engine, prelude::BASE64_STANDARD};

pub fn random_hex_string(num_bytes: usize) -> String {
    let mut raw_bytes = vec![0u8; num_bytes];
    rand::fill(raw_bytes.as_mut_slice());

    raw_bytes
        .iter()
        .fold(String::with_capacity(num_bytes * 2), |mut acc, b| {
            acc.push_str(&format!("{:02x}", b));
            acc
        })
}

pub fn base64_encode(input: &[u8]) -> String {
    BASE64_STANDARD.encode(input)
}

pub fn base64_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    BASE64_STANDARD.decode(input)
}
