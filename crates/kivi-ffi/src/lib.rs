//! FFI-биндинги ядра KiVi Messenger для Android (Kotlin) и iOS (Swift).
//!
//! Биндинги генерируются UniFFI из собранной библиотеки:
//! `cargo run -p uniffi-bindgen -- generate --library <libkivi_ffi> --language kotlin --out-dir out`.
//!
//! Слой тонкий: типы повторяют `kivi-crypto`, вся логика — там.

use std::sync::{Arc, Mutex, MutexGuard};

use kivi_crypto as crypto;

uniffi::setup_scaffolding!();

/// Ошибки ядра. На Kotlin/Swift приходят как исключения с текстом.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum KiviError {
    #[error("invalid account id: {0}")]
    InvalidAccountId(String),
    #[error("invalid device id: {0}")]
    InvalidDeviceId(u32),
    #[error("malformed input: {0}")]
    Malformed(String),
    #[error("no session with {0}")]
    NoSession(String),
    #[error("untrusted identity for {0}")]
    UntrustedIdentity(String),
    #[error("protocol error: {0}")]
    Protocol(String),
}

impl From<crypto::CryptoError> for KiviError {
    fn from(err: crypto::CryptoError) -> Self {
        match err {
            crypto::CryptoError::InvalidAccountId(v) => Self::InvalidAccountId(v),
            crypto::CryptoError::InvalidDeviceId(v) => Self::InvalidDeviceId(v),
            crypto::CryptoError::Malformed(v) => Self::Malformed(v),
            crypto::CryptoError::NoSession(v) => Self::NoSession(v),
            crypto::CryptoError::UntrustedIdentity(v) => Self::UntrustedIdentity(v),
            crypto::CryptoError::Protocol(v) => Self::Protocol(v),
        }
    }
}

#[derive(uniffi::Record)]
pub struct PreKey {
    pub key_id: u32,
    pub public_key: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct SignedKey {
    pub key_id: u32,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct DeviceKeys {
    pub identity_public_key: Vec<u8>,
    pub registration_id: u32,
    pub signed_pre_key: SignedKey,
    pub last_resort_kyber_pre_key: SignedKey,
}

#[derive(uniffi::Record)]
pub struct RemoteDeviceBundle {
    pub device_id: u32,
    pub registration_id: u32,
    pub identity_public_key: Vec<u8>,
    pub signed_pre_key: SignedKey,
    pub pre_key: Option<PreKey>,
    pub kyber_pre_key: SignedKey,
}

#[derive(uniffi::Enum)]
pub enum EnvelopeKind {
    Ciphertext,
    PreKeyMessage,
}

#[derive(uniffi::Record)]
pub struct OutgoingCiphertext {
    pub kind: EnvelopeKind,
    pub content: Vec<u8>,
}

/// Устройство текущего пользователя: ключи и сессии с собеседниками.
/// Потокобезопасно: вызовы сериализуются внутренней блокировкой.
#[derive(uniffi::Object)]
pub struct KiviDevice {
    inner: Mutex<crypto::LocalDevice>,
}

#[uniffi::export]
impl KiviDevice {
    /// Создаёт устройство с новыми ключами.
    #[uniffi::constructor]
    pub fn new(account_id: String, device_id: u32) -> Result<Arc<Self>, KiviError> {
        Ok(Arc::new(Self {
            inner: Mutex::new(crypto::LocalDevice::new(&account_id, device_id)?),
        }))
    }

    /// Ключи для регистрации устройства на сервере.
    pub fn device_keys(&self) -> DeviceKeys {
        self.lock().device_keys().clone().into()
    }

    pub fn generate_pre_keys(&self, count: u32) -> Result<Vec<PreKey>, KiviError> {
        Ok(self
            .lock()
            .generate_pre_keys(count)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub fn generate_kyber_pre_keys(&self, count: u32) -> Result<Vec<SignedKey>, KiviError> {
        Ok(self
            .lock()
            .generate_kyber_pre_keys(count)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub fn process_bundle(
        &self,
        remote_account_id: String,
        bundle: RemoteDeviceBundle,
    ) -> Result<(), KiviError> {
        Ok(self
            .lock()
            .process_bundle(&remote_account_id, &bundle.into())?)
    }

    pub fn has_session(
        &self,
        remote_account_id: String,
        remote_device_id: u32,
    ) -> Result<bool, KiviError> {
        Ok(self
            .lock()
            .has_session(&remote_account_id, remote_device_id)?)
    }

    pub fn encrypt(
        &self,
        remote_account_id: String,
        remote_device_id: u32,
        plaintext: Vec<u8>,
    ) -> Result<OutgoingCiphertext, KiviError> {
        Ok(self
            .lock()
            .encrypt(&remote_account_id, remote_device_id, &plaintext)?
            .into())
    }

    pub fn decrypt(
        &self,
        sender_account_id: String,
        sender_device_id: u32,
        kind: EnvelopeKind,
        content: Vec<u8>,
    ) -> Result<Vec<u8>, KiviError> {
        Ok(self
            .lock()
            .decrypt(&sender_account_id, sender_device_id, kind.into(), &content)?)
    }
}

impl KiviDevice {
    fn lock(&self) -> MutexGuard<'_, crypto::LocalDevice> {
        // Паника внутри ядра не должна навсегда блокировать устройство:
        // состояние libsignal-хранилищ остаётся согласованным между вызовами.
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl From<crypto::PreKey> for PreKey {
    fn from(k: crypto::PreKey) -> Self {
        Self {
            key_id: k.key_id,
            public_key: k.public_key,
        }
    }
}

impl From<PreKey> for crypto::PreKey {
    fn from(k: PreKey) -> Self {
        Self {
            key_id: k.key_id,
            public_key: k.public_key,
        }
    }
}

impl From<crypto::SignedKey> for SignedKey {
    fn from(k: crypto::SignedKey) -> Self {
        Self {
            key_id: k.key_id,
            public_key: k.public_key,
            signature: k.signature,
        }
    }
}

impl From<SignedKey> for crypto::SignedKey {
    fn from(k: SignedKey) -> Self {
        Self {
            key_id: k.key_id,
            public_key: k.public_key,
            signature: k.signature,
        }
    }
}

impl From<crypto::DeviceKeys> for DeviceKeys {
    fn from(k: crypto::DeviceKeys) -> Self {
        Self {
            identity_public_key: k.identity_public_key,
            registration_id: k.registration_id,
            signed_pre_key: k.signed_pre_key.into(),
            last_resort_kyber_pre_key: k.last_resort_kyber_pre_key.into(),
        }
    }
}

impl From<RemoteDeviceBundle> for crypto::RemoteDeviceBundle {
    fn from(b: RemoteDeviceBundle) -> Self {
        Self {
            device_id: b.device_id,
            registration_id: b.registration_id,
            identity_public_key: b.identity_public_key,
            signed_pre_key: b.signed_pre_key.into(),
            pre_key: b.pre_key.map(Into::into),
            kyber_pre_key: b.kyber_pre_key.into(),
        }
    }
}

impl From<EnvelopeKind> for crypto::EnvelopeKind {
    fn from(k: EnvelopeKind) -> Self {
        match k {
            EnvelopeKind::Ciphertext => Self::Ciphertext,
            EnvelopeKind::PreKeyMessage => Self::PreKeyMessage,
        }
    }
}

impl From<crypto::EnvelopeKind> for EnvelopeKind {
    fn from(k: crypto::EnvelopeKind) -> Self {
        match k {
            crypto::EnvelopeKind::Ciphertext => Self::Ciphertext,
            crypto::EnvelopeKind::PreKeyMessage => Self::PreKeyMessage,
        }
    }
}

impl From<crypto::OutgoingCiphertext> for OutgoingCiphertext {
    fn from(c: crypto::OutgoingCiphertext) -> Self {
        Self {
            kind: c.kind.into(),
            content: c.content,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "7f1c2e4a-9b3d-4c5e-8f6a-1b2c3d4e5f60";
    const BOB: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";

    #[test]
    fn round_trip_through_ffi_types() {
        let alice = KiviDevice::new(ALICE.into(), 1).unwrap();
        let bob = KiviDevice::new(BOB.into(), 1).unwrap();

        let keys = bob.device_keys();
        let bundle = RemoteDeviceBundle {
            device_id: 1,
            registration_id: keys.registration_id,
            identity_public_key: keys.identity_public_key,
            signed_pre_key: keys.signed_pre_key,
            pre_key: bob.generate_pre_keys(1).unwrap().pop(),
            kyber_pre_key: bob.generate_kyber_pre_keys(1).unwrap().remove(0),
        };
        alice.process_bundle(BOB.into(), bundle).unwrap();

        let message = alice.encrypt(BOB.into(), 1, b"hello".to_vec()).unwrap();
        assert!(matches!(message.kind, EnvelopeKind::PreKeyMessage));
        let plaintext = bob
            .decrypt(ALICE.into(), 1, message.kind, message.content)
            .unwrap();
        assert_eq!(plaintext, b"hello");
    }

    #[test]
    fn errors_are_mapped() {
        assert!(matches!(
            KiviDevice::new("bad".into(), 1),
            Err(KiviError::InvalidAccountId(_))
        ));
    }
}
