use md5::{Digest, Md5};
use p256::{
    PublicKey, SecretKey,
    ecdh::{SharedSecret, diffie_hellman},
    elliptic_curve,
};
use thiserror::Error;

const SERVER_PUBLIC_KEY_BYTES: [u8; 65] = [
    0x04, // uncompress tag
    0xEB, 0xCA, 0x94, 0xD7, 0x33, 0xE3, 0x99, 0xB2, 0xDB, 0x96, 0xEA, 0xCD, 0xD3, 0xF6, 0x9A, 0x8B,
    0xB0, 0xF7, 0x42, 0x24, 0xE2, 0xB4, 0x4E, 0x33, 0x57, 0x81, 0x22, 0x11, 0xD2, 0xE6, 0x2E, 0xFB,
    0xC9, 0x1B, 0xB5, 0x53, 0x09, 0x8E, 0x25, 0xE3, 0x3A, 0x79, 0x9A, 0xDC, 0x7F, 0x76, 0xFE, 0xB2,
    0x08, 0xDA, 0x7C, 0x65, 0x22, 0xCD, 0xB0, 0x71, 0x9A, 0x30, 0x51, 0x80, 0xCC, 0x54, 0xA8, 0x2E,
];

#[derive(Debug, Error)]
pub enum EcdhError {
    #[error("invalid server public key")]
    ServerPublicKey(#[source] elliptic_curve::Error),

    #[error("invalid peer public key")]
    PeerPublicKey(#[source] elliptic_curve::Error),
}

#[derive(Debug)]
pub struct EcdhClient {
    private_key: SecretKey,
    public_key: PublicKey,
    shared_secret: SharedSecret,
}

impl Default for EcdhClient {
    fn default() -> Self {
        let private_key = SecretKey::generate();
        let public_key = PublicKey::from_secret_scalar(&private_key.to_nonzero_scalar());
        let server_pub_key = PublicKey::from_sec1_bytes(&SERVER_PUBLIC_KEY_BYTES)
            .map_err(EcdhError::ServerPublicKey)
            .unwrap();
        let shared_secret =
            diffie_hellman(private_key.to_nonzero_scalar(), server_pub_key.as_affine());

        Self {
            private_key,
            public_key,
            shared_secret,
        }
    }
}

impl EcdhClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn compute_shared_secret(&self, peer_public_key: &[u8]) -> Result<Vec<u8>, EcdhError> {
        let peer_pub_key =
            PublicKey::from_sec1_bytes(peer_public_key).map_err(EcdhError::PeerPublicKey)?;
        let shared_secret = diffie_hellman(
            self.private_key.to_nonzero_scalar(),
            peer_pub_key.as_affine(),
        );

        let raw_share = shared_secret.raw_secret_bytes();
        Ok(raw_share.to_vec())
    }

    pub fn compute_shared_secret_hash(
        &self,
        peer_public_key: &[u8],
    ) -> Result<[u8; 16], EcdhError> {
        let peer_pub_key =
            PublicKey::from_sec1_bytes(peer_public_key).map_err(EcdhError::PeerPublicKey)?;
        let shared_secret = diffie_hellman(
            self.private_key.to_nonzero_scalar(),
            peer_pub_key.as_affine(),
        );

        let raw_share = shared_secret.raw_secret_bytes();

        let input_slice = &raw_share.as_slice()[..16];
        Ok(*Md5::digest(input_slice).as_ref())
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_sec1_bytes().to_vec()
    }

    pub fn share_key(&self) -> Vec<u8> {
        self.shared_secret.raw_secret_bytes().to_vec()
    }

    pub fn share_key_hash(&self) -> [u8; 16] {
        let raw_share = self.shared_secret.raw_secret_bytes();
        let input_slice = &raw_share.as_slice()[..16];
        *Md5::digest(input_slice).as_ref()
    }
}
