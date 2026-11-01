//! Привязка нового устройства к аккаунту (ADR-0012 в Messenger-KiVi;
//! messenger-protocol, README, «Привязка устройства»).
//!
//! Новое устройство создаёт временную пару X25519 и показывает публичный
//! ключ в QR-коде. Основное устройство шифрует на него `ProvisionMessage`
//! (ключевую пару идентичности и данные аккаунта):
//!
//! - `shared = X25519(e_private, qr_public)`;
//! - `key = HKDF-SHA256(IKM = shared, salt = e_public ‖ qr_public,
//!   info = "KiVi provisioning v1", L = 32)`;
//! - `ciphertext = AES-256-GCM(key, nonce, plaintext)`, nonce 12 случайных
//!   байт, без дополнительных данных.
//!
//! Сервер пересылает только шифротекст: `qr_public` попадает к основному
//! устройству через QR, мимо сервера.

use aes_gcm::aead::Aead as _;
use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce};
use hkdf::Hkdf;
use libsignal_protocol::{KeyPair, PrivateKey, PublicKey, SignalProtocolError};
use rand::RngCore as _;
use sha2::Sha256;

use crate::error::CryptoError;

const INFO: &[u8] = b"KiVi provisioning v1";
const NONCE_LEN: usize = 12;

/// Временная пара X25519 нового устройства. Живёт, пока показан QR-код.
#[derive(Clone)]
pub struct ProvisioningKeyPair {
    /// Публичный ключ для QR: формат libsignal, `0x05` + 32 байта.
    pub public_key: Vec<u8>,
    /// Приватный ключ: 32 байта. Не покидает новое устройство.
    pub private_key: Vec<u8>,
}

/// Зашифрованный `ProvisionMessage` — поля `kivi.devices.v1.ProvisionEnvelope`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionCiphertext {
    /// Временный публичный ключ основного устройства, `0x05` + 32 байта.
    pub public_key: Vec<u8>,
    pub nonce: Vec<u8>,
    /// Шифротекст с тегом GCM (16 байт в конце).
    pub ciphertext: Vec<u8>,
}

/// Новая временная пара для QR-кода.
pub fn generate_provisioning_key_pair() -> ProvisioningKeyPair {
    let pair = KeyPair::generate(&mut rand::rng());
    ProvisioningKeyPair {
        public_key: pair.public_key.serialize().into_vec(),
        private_key: pair.private_key.serialize().to_vec(),
    }
}

/// Основное устройство: зашифровать `ProvisionMessage` на ключ из QR-кода.
pub fn encrypt_provision(
    qr_public: &[u8],
    plaintext: &[u8],
) -> Result<ProvisionCiphertext, CryptoError> {
    let qr_public = public_key(qr_public)?;
    let mut rng = rand::rng();
    let ephemeral = KeyPair::generate(&mut rng);
    let shared = ephemeral
        .private_key
        .calculate_agreement(&qr_public)
        .map_err(SignalProtocolError::from)?;
    let key = derive_key(&shared, &ephemeral.public_key, &qr_public);
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let ciphertext = cipher(&key)
        .encrypt(&Nonce::from(nonce), plaintext)
        .map_err(|_| CryptoError::Protocol("provision encryption failed".to_owned()))?;
    Ok(ProvisionCiphertext {
        public_key: ephemeral.public_key.serialize().into_vec(),
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

/// Новое устройство: расшифровать конверт своим временным приватным ключом.
/// Подменённый или повреждённый конверт — [`CryptoError::Malformed`].
pub fn decrypt_provision(
    qr_private: &[u8],
    envelope: &ProvisionCiphertext,
) -> Result<Vec<u8>, CryptoError> {
    let qr_private = PrivateKey::deserialize(qr_private)
        .map_err(|_| CryptoError::Malformed("provisioning private key".to_owned()))?;
    let qr_public = qr_private
        .public_key()
        .map_err(|_| CryptoError::Malformed("provisioning private key".to_owned()))?;
    let sender_public = public_key(&envelope.public_key)?;
    let nonce: [u8; NONCE_LEN] = envelope
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Malformed(format!("nonce must be {NONCE_LEN} bytes")))?;
    let shared = qr_private
        .calculate_agreement(&sender_public)
        .map_err(SignalProtocolError::from)?;
    let key = derive_key(&shared, &sender_public, &qr_public);
    cipher(&key)
        .decrypt(&Nonce::from(nonce), envelope.ciphertext.as_slice())
        .map_err(|_| CryptoError::Malformed("provision envelope does not decrypt".to_owned()))
}

/// `HKDF-SHA256(IKM = shared, salt = sender_public ‖ qr_public, info)`.
fn derive_key(shared: &[u8], sender_public: &PublicKey, qr_public: &PublicKey) -> [u8; 32] {
    let mut salt = sender_public.serialize().into_vec();
    salt.extend_from_slice(&qr_public.serialize());
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&salt), shared)
        .expand(INFO, &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

fn cipher(key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new_from_slice(key).expect("AES-256 key is 32 bytes")
}

fn public_key(bytes: &[u8]) -> Result<PublicKey, CryptoError> {
    PublicKey::deserialize(bytes)
        .map_err(|_| CryptoError::Malformed("X25519 public key (0x05 + 32 bytes)".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let qr = generate_provisioning_key_pair();
        assert_eq!(qr.public_key.len(), 33);
        assert_eq!(qr.private_key.len(), 32);
        let envelope = encrypt_provision(&qr.public_key, b"provision message").unwrap();
        assert_eq!(envelope.public_key.len(), 33);
        assert_eq!(envelope.nonce.len(), 12);
        assert_eq!(
            decrypt_provision(&qr.private_key, &envelope).unwrap(),
            b"provision message"
        );
    }

    #[test]
    fn other_key_or_tampering_fails() {
        let qr = generate_provisioning_key_pair();
        let envelope = encrypt_provision(&qr.public_key, b"secret").unwrap();

        let stranger = generate_provisioning_key_pair();
        assert!(matches!(
            decrypt_provision(&stranger.private_key, &envelope),
            Err(CryptoError::Malformed(_))
        ));

        let mut tampered = envelope.clone();
        tampered.ciphertext[0] ^= 1;
        assert!(decrypt_provision(&qr.private_key, &tampered).is_err());

        // Подмена ключа отправителя меняет и общий секрет, и salt.
        let mut swapped = envelope.clone();
        swapped.public_key = stranger.public_key.clone();
        assert!(decrypt_provision(&qr.private_key, &swapped).is_err());

        let mut short = envelope;
        short.nonce.pop();
        assert!(decrypt_provision(&qr.private_key, &short).is_err());
        assert!(encrypt_provision(&[5u8; 10], b"x").is_err());
    }
}
