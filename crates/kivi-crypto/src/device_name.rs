//! Имя устройства, зашифрованное ключом аккаунта (messenger-protocol,
//! README, «Имя устройства»). Сервер хранит и отдаёт только шифротекст;
//! прочитать имя могут устройства, у которых есть ключ идентичности аккаунта.
//!
//! - `key = HKDF-SHA256(IKM = приватный ключ идентичности, salt пустой,
//!   info = "KiVi device name v1", L = 32)`;
//! - `encrypted = nonce (12 байт) ‖ AES-256-GCM(key, nonce, имя в UTF-8)`.

use aes_gcm::aead::Aead as _;
use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce};
use hkdf::Hkdf;
use libsignal_protocol::PrivateKey;
use rand::RngCore as _;
use sha2::Sha256;

use crate::error::CryptoError;

const INFO: &[u8] = b"KiVi device name v1";
const NONCE_LEN: usize = 12;
/// Длина имени в символах (Unicode code points).
pub const MAX_DEVICE_NAME_CHARS: usize = 64;

pub(crate) fn encrypt(identity: &PrivateKey, name: &str) -> Result<Vec<u8>, CryptoError> {
    let chars = name.chars().count();
    if chars == 0 || chars > MAX_DEVICE_NAME_CHARS {
        return Err(CryptoError::Malformed(format!(
            "device name must be 1..={MAX_DEVICE_NAME_CHARS} characters, got {chars}"
        )));
    }
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    let ciphertext = cipher(identity)
        .encrypt(&Nonce::from(nonce), name.as_bytes())
        .map_err(|_| CryptoError::Protocol("device name encryption failed".to_owned()))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub(crate) fn decrypt(identity: &PrivateKey, encrypted: &[u8]) -> Result<String, CryptoError> {
    if encrypted.len() <= NONCE_LEN {
        return Err(CryptoError::Malformed(
            "encrypted device name is too short".to_owned(),
        ));
    }
    let (nonce, ciphertext) = encrypted.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("split at NONCE_LEN");
    let plaintext = cipher(identity)
        .decrypt(&Nonce::from(nonce), ciphertext)
        .map_err(|_| CryptoError::Malformed("device name does not decrypt".to_owned()))?;
    String::from_utf8(plaintext)
        .map_err(|_| CryptoError::Malformed("device name is not UTF-8".to_owned()))
}

fn cipher(identity: &PrivateKey) -> Aes256Gcm {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, &identity.serialize())
        .expand(INFO, &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Aes256Gcm::new_from_slice(&key).expect("AES-256 key is 32 bytes")
}
