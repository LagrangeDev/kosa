use byteorder::{BigEndian, ByteOrder};
use bytes::Bytes;
use thiserror::Error;

const ROUNDS: usize = 16;
const DELTA: u32 = 0x9e3779b9;
const SUM: u32 = DELTA.wrapping_mul(16);

pub type Key = [u8; 16];

#[derive(Debug, Error)]
pub enum TeaError {
    #[error("destination buffer too small: need {needed}, got {actual}")]
    DestinationTooSmall { needed: usize, actual: usize },

    #[error("invalid ciphertext length: {len}")]
    InvalidCiphertextLength { len: usize },

    #[error("invalid ciphertext")]
    InvalidCiphertext,
}

pub fn get_cipher_length(plain_len: usize) -> usize {
    10 - ((plain_len + 1) & 7) + plain_len + 7
}

pub fn get_plain_length(cipher_len: usize) -> usize {
    cipher_len - ((cipher_len & 7) + 3) - 7
}

pub fn encrypt<R: AsRef<[u8]>>(data: R, key: &[u8; 16]) -> Bytes {
    let mut dst = vec![0u8; get_cipher_length(data.as_ref().len())];
    encrypt_to(data, &mut dst, key).unwrap();
    dst.into()
}

pub fn decrypt<R: AsRef<[u8]>>(data: R, key: &[u8; 16]) -> Bytes {
    let mut dst = vec![0u8; data.as_ref().len()];
    decrypt_to(data, &mut dst, key).unwrap();
    dst[((dst[0] as usize & 7) + 3)..dst.len() - 7]
        .to_vec()
        .into()
}

pub fn encrypt_to<R: AsRef<[u8]>, W: AsMut<[u8]>>(
    src: R,
    mut dst: W,
    key: &[u8; 16],
) -> Result<usize, TeaError> {
    let src = src.as_ref();
    let dst = dst.as_mut();

    let fill = 10 - ((src.len() + 1) & 7);
    let length = fill + src.len() + 7;
    if dst.len() < length {
        return Err(TeaError::DestinationTooSmall {
            needed: length,
            actual: dst.len(),
        });
    }

    let mut keys = [0u32; 4];
    BigEndian::read_u32_into(key.as_ref(), &mut keys);
    let [k0, k1, k2, k3] = keys;

    rand::fill(&mut dst[..fill]);
    dst[0] = (fill - 3) as u8 | 0xf8;
    dst[fill..fill + src.len()].copy_from_slice(src);

    let (mut plain_xor, mut prev_xor) = (0u64, 0u64);

    for i in (0..length).step_by(8) {
        let plain = BigEndian::read_u64(&dst[i..i + 8]) ^ plain_xor;
        let mut v0 = plain.wrapping_shr(32) as u32;
        let mut v1 = plain as u32;
        let mut sum = 0u32;
        for _ in 0..ROUNDS {
            sum = sum.wrapping_add(DELTA);
            v0 = v0.wrapping_add(
                v1.wrapping_add(sum)
                    ^ v1.wrapping_shl(4).wrapping_add(k0)
                    ^ v1.wrapping_shr(5).wrapping_add(k1),
            );
            v1 = v1.wrapping_add(
                v0.wrapping_add(sum)
                    ^ v0.wrapping_shl(4).wrapping_add(k2)
                    ^ v0.wrapping_shr(5).wrapping_add(k3),
            );
        }
        plain_xor = ((v0 as u64) << 32 | v1 as u64) ^ prev_xor;
        prev_xor = plain;
        BigEndian::write_u64(&mut dst[i..i + 8], plain_xor);
    }
    Ok(length)
}

pub fn decrypt_to<R: AsRef<[u8]>, W: AsMut<[u8]>>(
    src: R,
    mut dst: W,
    key: &[u8; 16],
) -> Result<usize, TeaError> {
    let src = src.as_ref();
    let dst = dst.as_mut();

    if src.len() < 16 || (src.len() & 7) != 0 {
        return Err(TeaError::InvalidCiphertextLength { len: src.len() });
    }
    if dst.as_mut().len() < src.len() {
        return Err(TeaError::DestinationTooSmall {
            needed: src.len(),
            actual: dst.as_mut().len(),
        });
    }

    let mut keys = [0u32; 4];
    BigEndian::read_u32_into(key.as_ref(), &mut keys);
    let [k0, k1, k2, k3] = keys;

    let fill = (src[0] as usize & 7) + 3;
    if src.len() < fill + 7 {
        return Err(TeaError::InvalidCiphertext);
    }
    let (mut plain_xor, mut prev_xor) = (0u64, 0u64);

    for i in (0..src.len()).step_by(8) {
        let plain = BigEndian::read_u64(&src[i..i + 8]);
        plain_xor ^= plain;
        let mut v0 = plain_xor.wrapping_shr(32) as u32;
        let mut v1 = plain_xor as u32;

        let mut sum = SUM;
        for _ in 0..ROUNDS {
            v1 = v1.wrapping_sub(
                v0.wrapping_add(sum)
                    ^ v0.wrapping_shl(4).wrapping_add(k2)
                    ^ v0.wrapping_shr(5).wrapping_add(k3),
            );
            v0 = v0.wrapping_sub(
                v1.wrapping_add(sum)
                    ^ v1.wrapping_shl(4).wrapping_add(k0)
                    ^ v1.wrapping_shr(5).wrapping_add(k1),
            );
            sum = sum.wrapping_sub(DELTA);
        }
        plain_xor = (v0 as u64) << 32 | v1 as u64;
        BigEndian::write_u64(&mut dst[i..i + 8], plain_xor ^ prev_xor);
        prev_xor = plain;
    }

    Ok((src.len() - fill) - 7)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt() {
        let data = "hello world";
        let key = "cf285a5bc8c477f70b53a9800bff86d5";
        let key: [u8; 16] = hex::decode(key).unwrap().as_slice().try_into().unwrap();
        let ciphertext = encrypt(data, &key);
        let decrypted = decrypt(ciphertext, &key);
        assert_eq!(data, str::from_utf8(&decrypted).unwrap());
    }

    #[test]
    fn test_decrypt() {
        let key = "cf285a5bc8c477f70b53a9800bff86d5";
        let encrypted = "17fe7c282b8e5b92729399f8a1cdecb5f51d99d99dddc1dd";
        let key: [u8; 16] = hex::decode(key).unwrap().as_slice().try_into().unwrap();
        let encrypted = hex::decode(encrypted).unwrap();
        let data = "this is a test";
        let decrypted = decrypt(&encrypted, &key);
        assert_eq!(data, str::from_utf8(&decrypted).unwrap());
    }
}
