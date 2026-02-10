use aes::cipher::block_padding::{Pkcs7, UnpadError};
use aes_gcm::{
    Aes128Gcm, Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use bytes::{Bytes, BytesMut};
use cbc::cipher::{
    BlockDecryptMut, BlockEncryptMut, InvalidLength as CipherInvalidLength, KeyIvInit,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AesError {
    #[error("wrong key size: {0}")]
    WrongKeySize(usize),

    #[error("wrong iv size: {0}")]
    WrongIvSize(usize),

    #[error("ciphertext too short: {0}")]
    CiphertextTooShort(usize),

    #[error("aes-gcm error")]
    Gcm(#[from] aes_gcm::Error),

    #[error("cipher invalid length")]
    CipherInvalidLength(#[from] CipherInvalidLength),

    #[error("cbc unpad error")]
    CbcUnpad(#[from] UnpadError),
}

pub fn aes_gcm_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Bytes, AesError> {
    match key.len() {
        16 => _aes_gcm_encrypt(
            Aes128Gcm::new_from_slice(key).map_err(|_| AesError::WrongKeySize(key.len()))?,
            plaintext,
        ),
        32 => _aes_gcm_encrypt(
            Aes256Gcm::new_from_slice(key).map_err(|_| AesError::WrongKeySize(key.len()))?,
            plaintext,
        ),
        _ => Err(AesError::WrongKeySize(key.len())),
    }
}

fn _aes_gcm_encrypt<C>(ciper: C, plaintext: &[u8]) -> Result<Bytes, AesError>
where
    C: Aead,
{
    let nonce = C::generate_nonce(&mut OsRng);
    let ciphertext = ciper.encrypt(&nonce, plaintext)?;
    let mut result = BytesMut::with_capacity(nonce.len() + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(ciphertext.as_slice());
    Ok(Bytes::from(result))
}

pub fn aes_gcm_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Bytes, AesError> {
    match key.len() {
        16 => _aes_gcm_decrypt(
            Aes128Gcm::new_from_slice(key).map_err(|_| AesError::WrongKeySize(key.len()))?,
            ciphertext,
        ),
        32 => _aes_gcm_decrypt(
            Aes256Gcm::new_from_slice(key).map_err(|_| AesError::WrongKeySize(key.len()))?,
            ciphertext,
        ),
        _ => Err(AesError::WrongKeySize(key.len())),
    }
}

fn _aes_gcm_decrypt<C>(ciper: C, ciphertext: &[u8]) -> Result<Bytes, AesError>
where
    C: Aead,
{
    if ciphertext.len() < 12 + 16 {
        return Err(AesError::CiphertextTooShort(ciphertext.len()));
    };

    let nonce = Nonce::<C::NonceSize>::from_slice(&ciphertext[..12]);
    let ciphertext = &ciphertext[12..];
    let plaintext = ciper.decrypt(nonce, ciphertext)?;
    Ok(Bytes::from(plaintext))
}

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Bytes, AesError> {
    if iv.len() != 16 {
        return Err(AesError::WrongIvSize(iv.len()));
    }

    match key.len() {
        16 => _aes_cbc_encrypt(Aes128CbcEnc::new_from_slices(key, iv)?, plaintext),
        32 => _aes_cbc_encrypt(Aes256CbcEnc::new_from_slices(key, iv)?, plaintext),
        _ => Err(AesError::WrongKeySize(key.len())),
    }
}

fn _aes_cbc_encrypt<C>(ciper: C, plaintext: &[u8]) -> Result<Bytes, AesError>
where
    C: BlockEncryptMut,
{
    let cipertext = ciper.encrypt_padded_vec_mut::<Pkcs7>(plaintext);
    Ok(Bytes::from(cipertext))
}

pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Bytes, AesError> {
    if iv.len() != 16 {
        return Err(AesError::WrongIvSize(iv.len()));
    }

    match key.len() {
        16 => _aes_cbc_decrypt(Aes128CbcDec::new_from_slices(key, iv)?, ciphertext),
        32 => _aes_cbc_decrypt(Aes256CbcDec::new_from_slices(key, iv)?, ciphertext),
        _ => Err(AesError::WrongKeySize(key.len())),
    }
}

fn _aes_cbc_decrypt<C>(ciper: C, cipertext: &[u8]) -> Result<Bytes, AesError>
where
    C: BlockDecryptMut,
{
    let plaintext = ciper.decrypt_padded_vec_mut::<Pkcs7>(cipertext)?;
    Ok(Bytes::from(plaintext))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_aes_gcm() {
        let plaintext = b"hello world";
        let key = b"1234567812345678";
        let ciphertext = aes_gcm_encrypt(key, plaintext.as_slice()).unwrap();
        let plaintext_ = aes_gcm_decrypt(key, ciphertext.as_ref()).unwrap();
        assert_eq!(plaintext, plaintext_.as_ref());
    }

    #[test]
    fn test_aes_gcm_decrypt() {
        let ciphertext = hex::decode(
            "44764a596129fb1e3e8ce6be7dee545175579fc3064ca7cb41f258010398601f7ea6e2199be6bc",
        )
        .unwrap();
        let key = b"1234567812345678";
        let plaintext = aes_gcm_decrypt(key, ciphertext.as_slice()).unwrap();
        assert_eq!(plaintext.as_ref(), b"hello world");
    }

    #[test]
    fn test_aes_cbc_encrypt() {
        let plaintext = b"hello world";
        let key = b"1234567812345678";
        let iv = b"1234567812345678";
        let ciphertext = aes_cbc_encrypt(key, iv, plaintext).unwrap();
        assert_eq!(hex::encode(ciphertext), "6b64a9337ee7bd562d067547a275fceb");
    }

    #[test]
    fn test_aes_cbc_decrypt() {
        let ciphertext = hex::decode("1f18af426983fa1852e56a1d9e20164a").unwrap();
        let key = b"8765432187654321";
        let iv = b"1234567812345678";
        let plaintext = aes_cbc_decrypt(key, iv, ciphertext.as_slice()).unwrap();
        assert_eq!(plaintext.as_ref(), b"hello world");
    }
}
