//! FFI-биндинги ядра KiVi Messenger для Android (Kotlin) и iOS (Swift).
//!
//! Биндинги генерируются UniFFI из собранной библиотеки:
//! `cargo run -p uniffi-bindgen -- generate --library <libkivi_ffi> --language kotlin --out-dir out`.
//!
//! Слой тонкий: типы повторяют `kivi-crypto`, вся логика — там.
//!
//! Состояние ядра хранится в БД платформы: Kotlin/Swift реализуют
//! [`KiviStore`] (ADR-0004 в Messenger-KiVi).

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
    #[error("device already exists in storage")]
    AlreadyExists,
    #[error("device is not registered yet")]
    NotRegistered,
    #[error("storage error: {0}")]
    Storage(String),
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
            crypto::CryptoError::AlreadyExists => Self::AlreadyExists,
            crypto::CryptoError::NotRegistered => Self::NotRegistered,
            crypto::CryptoError::Storage(v) => Self::Storage(v),
            crypto::CryptoError::Protocol(v) => Self::Protocol(v),
        }
    }
}

/// Вид записи хранилища (см. `kivi_crypto::RecordKind`).
#[derive(uniffi::Enum, Clone, Copy)]
pub enum RecordKind {
    /// Свой аккаунт: ключ идентичности, registration ID, счётчики.
    /// Содержит приватный ключ — платформа дополнительно шифрует запись
    /// аппаратным ключом (Keystore / Secure Enclave).
    LocalAccount,
    Session,
    RemoteIdentity,
    PreKey,
    SignedPreKey,
    KyberPreKey,
    KyberBaseKeySeen,
}

/// Ошибка хранилища, которую возвращает реализация [`KiviStore`].
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum KiviStoreError {
    // Поле не называется `message`: в Kotlin оно конфликтует с Throwable.message.
    #[error("{reason}")]
    Failed { reason: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for KiviStoreError {
    fn from(err: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Failed { reason: err.reason }
    }
}

/// Хранилище «ключ → значение», реализуемое платформой поверх своей
/// зашифрованной БД (Room + SQLCipher, GRDB + SQLCipher).
///
/// Методы вызываются синхронно в потоке, который вызвал метод
/// [`KiviDevice`]. Поэтому, например, `decrypt` и сохранение сообщения можно
/// выполнить в одной транзакции БД и отправить ACK после её фиксации.
#[uniffi::export(with_foreign)]
pub trait KiviStore: Send + Sync {
    fn load(&self, kind: RecordKind, key: String) -> Result<Option<Vec<u8>>, KiviStoreError>;
    fn store(&self, kind: RecordKind, key: String, value: Vec<u8>) -> Result<(), KiviStoreError>;
    fn remove(&self, kind: RecordKind, key: String) -> Result<(), KiviStoreError>;
}

/// Адаптер хранилища платформы к `kivi_crypto::Storage`.
struct ForeignStorage(Arc<dyn KiviStore>);

impl crypto::Storage for ForeignStorage {
    fn load(
        &self,
        kind: crypto::RecordKind,
        key: &str,
    ) -> Result<Option<Vec<u8>>, crypto::StorageError> {
        self.0.load(kind.into(), key.to_owned()).map_err(Into::into)
    }

    fn store(
        &self,
        kind: crypto::RecordKind,
        key: &str,
        value: &[u8],
    ) -> Result<(), crypto::StorageError> {
        self.0
            .store(kind.into(), key.to_owned(), value.to_vec())
            .map_err(Into::into)
    }

    fn remove(&self, kind: crypto::RecordKind, key: &str) -> Result<(), crypto::StorageError> {
        self.0
            .remove(kind.into(), key.to_owned())
            .map_err(Into::into)
    }
}

impl From<KiviStoreError> for crypto::StorageError {
    fn from(err: KiviStoreError) -> Self {
        Self(err.to_string())
    }
}

impl From<crypto::RecordKind> for RecordKind {
    fn from(kind: crypto::RecordKind) -> Self {
        match kind {
            crypto::RecordKind::LocalAccount => Self::LocalAccount,
            crypto::RecordKind::Session => Self::Session,
            crypto::RecordKind::RemoteIdentity => Self::RemoteIdentity,
            crypto::RecordKind::PreKey => Self::PreKey,
            crypto::RecordKind::SignedPreKey => Self::SignedPreKey,
            crypto::RecordKind::KyberPreKey => Self::KyberPreKey,
            crypto::RecordKind::KyberBaseKeySeen => Self::KyberBaseKeySeen,
        }
    }
}

/// Открывает устройство, ранее созданное в этом хранилище.
/// `null`/`nil` — устройства нет, нужно пройти регистрацию.
#[uniffi::export]
pub fn open_device(store: Arc<dyn KiviStore>) -> Result<Option<Arc<KiviDevice>>, KiviError> {
    Ok(
        crypto::LocalDevice::open(Arc::new(ForeignStorage(store)))?.map(|device| {
            Arc::new(KiviDevice {
                inner: Mutex::new(device),
            })
        }),
    )
}

/// Адрес устройства: UUID аккаунта и номер устройства.
#[derive(uniffi::Record, Debug, PartialEq, Eq)]
pub struct DeviceAddress {
    pub account_id: String,
    pub device_id: u32,
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
    /// Создаёт устройство с новыми ключами и сохраняет их в хранилище.
    /// Вызывается один раз — при регистрации. При следующих запусках
    /// устройство открывается через [`open_device`].
    #[uniffi::constructor]
    pub fn create(
        store: Arc<dyn KiviStore>,
        account_id: String,
        device_id: u32,
    ) -> Result<Arc<Self>, KiviError> {
        let storage = Arc::new(ForeignStorage(store));
        Ok(Arc::new(Self {
            inner: Mutex::new(crypto::LocalDevice::create(
                storage,
                &account_id,
                device_id,
            )?),
        }))
    }

    /// Создаёт устройство с новыми ключами, но без адреса — первый шаг
    /// регистрации: `deviceKeys()` уходят в `RegisterRequest`, адрес из
    /// `RegisterResponse` задаётся через [`KiviDevice::set_address`].
    #[uniffi::constructor]
    pub fn generate(store: Arc<dyn KiviStore>) -> Result<Arc<Self>, KiviError> {
        let storage = Arc::new(ForeignStorage(store));
        Ok(Arc::new(Self {
            inner: Mutex::new(crypto::LocalDevice::generate(storage)?),
        }))
    }

    /// Задаёт адрес, выданный сервером при регистрации.
    pub fn set_address(&self, account_id: String, device_id: u32) -> Result<(), KiviError> {
        Ok(self.lock().set_address(&account_id, device_id)?)
    }

    /// Адрес устройства; `null`/`nil` — регистрация не завершена.
    pub fn address(&self) -> Option<DeviceAddress> {
        self.lock()
            .address()
            .map(|(account_id, device_id)| DeviceAddress {
                account_id,
                device_id,
            })
    }

    /// Ключи для регистрации устройства на сервере.
    pub fn device_keys(&self) -> Result<DeviceKeys, KiviError> {
        Ok(self.lock().device_keys()?.into())
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

    /// Registration ID собеседника из сессии, для `destination_registration_id`.
    pub fn remote_registration_id(
        &self,
        remote_account_id: String,
        remote_device_id: u32,
    ) -> Result<Option<u32>, KiviError> {
        Ok(self
            .lock()
            .remote_registration_id(&remote_account_id, remote_device_id)?)
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

    /// Sealed sender: шифрование без раскрытия отправителя серверу.
    /// `sender_certificate` — от `CertificateService.GetSenderCertificate`.
    pub fn sealed_sender_encrypt(
        &self,
        remote_account_id: String,
        remote_device_id: u32,
        sender_certificate: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, KiviError> {
        Ok(self.lock().sealed_sender_encrypt(
            &remote_account_id,
            remote_device_id,
            &sender_certificate,
            &plaintext,
        )?)
    }

    /// Sealed sender: расшифровка и проверка сертификата отправителя по
    /// trust root на момент `timestamp_ms` (время приёма сервером).
    pub fn sealed_sender_decrypt(
        &self,
        ciphertext: Vec<u8>,
        trust_root: Vec<u8>,
        timestamp_ms: u64,
    ) -> Result<SealedSenderMessage, KiviError> {
        Ok(self
            .lock()
            .sealed_sender_decrypt(&ciphertext, &trust_root, timestamp_ms)?
            .into())
    }
}

/// Новый profile key: 32 случайных байта.
#[uniffi::export]
pub fn generate_profile_key() -> Vec<u8> {
    crypto::generate_profile_key()
}

/// Unidentified access key (16 байт), выведенный из profile key.
#[uniffi::export]
pub fn unidentified_access_key(profile_key: Vec<u8>) -> Result<Vec<u8>, KiviError> {
    Ok(crypto::unidentified_access_key(&profile_key)?)
}

/// Сообщение sealed sender: отправитель — из проверенного сертификата.
#[derive(uniffi::Record, Debug, PartialEq, Eq)]
pub struct SealedSenderMessage {
    pub sender_account_id: String,
    pub sender_device_id: u32,
    pub plaintext: Vec<u8>,
}

impl From<crypto::SealedSenderMessage> for SealedSenderMessage {
    fn from(m: crypto::SealedSenderMessage) -> Self {
        Self {
            sender_account_id: m.sender_account_id,
            sender_device_id: m.sender_device_id,
            plaintext: m.plaintext,
        }
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
    use std::collections::HashMap;

    use super::*;

    /// Хранилище «со стороны платформы»: проверяет путь через foreign trait.
    #[derive(Default)]
    struct TestStore(Mutex<HashMap<(u8, String), Vec<u8>>>);

    impl KiviStore for TestStore {
        fn load(&self, kind: RecordKind, key: String) -> Result<Option<Vec<u8>>, KiviStoreError> {
            Ok(self.0.lock().unwrap().get(&(kind as u8, key)).cloned())
        }

        fn store(
            &self,
            kind: RecordKind,
            key: String,
            value: Vec<u8>,
        ) -> Result<(), KiviStoreError> {
            self.0.lock().unwrap().insert((kind as u8, key), value);
            Ok(())
        }

        fn remove(&self, kind: RecordKind, key: String) -> Result<(), KiviStoreError> {
            self.0.lock().unwrap().remove(&(kind as u8, key));
            Ok(())
        }
    }

    /// Хранилище, у которого закрыта БД.
    struct FailingStore;

    fn closed() -> KiviStoreError {
        KiviStoreError::Failed {
            reason: "db closed".into(),
        }
    }

    impl KiviStore for FailingStore {
        fn load(&self, _: RecordKind, _: String) -> Result<Option<Vec<u8>>, KiviStoreError> {
            Err(closed())
        }

        fn store(&self, _: RecordKind, _: String, _: Vec<u8>) -> Result<(), KiviStoreError> {
            Err(closed())
        }

        fn remove(&self, _: RecordKind, _: String) -> Result<(), KiviStoreError> {
            Err(closed())
        }
    }

    const ALICE: &str = "7f1c2e4a-9b3d-4c5e-8f6a-1b2c3d4e5f60";
    const BOB: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";

    fn device(account_id: &str) -> (Arc<TestStore>, Arc<KiviDevice>) {
        let store = Arc::new(TestStore::default());
        let device = KiviDevice::create(store.clone(), account_id.into(), 1).unwrap();
        (store, device)
    }

    #[test]
    fn round_trip_through_ffi_types_and_restart() {
        let (_, alice) = device(ALICE);
        let (bob_store, bob) = device(BOB);

        let keys = bob.device_keys().unwrap();
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

        // Перезапуск: устройство Боба открывается из того же хранилища.
        drop(bob);
        let bob = open_device(bob_store).unwrap().expect("device exists");
        assert!(bob.has_session(ALICE.into(), 1).unwrap());
        // Сессия, полученная входящим сообщением, знает registration ID собеседника.
        assert_eq!(
            bob.remote_registration_id(ALICE.into(), 1).unwrap(),
            Some(alice.device_keys().unwrap().registration_id)
        );
        assert_eq!(bob.remote_registration_id(ALICE.into(), 2).unwrap(), None);
    }

    #[test]
    fn two_phase_registration_through_ffi() {
        let store = Arc::new(TestStore::default());
        let device = KiviDevice::generate(store.clone()).unwrap();
        assert!(device.address().is_none());
        assert!(device.device_keys().is_ok());
        assert!(matches!(
            device.encrypt(BOB.into(), 1, b"x".to_vec()),
            Err(KiviError::NotRegistered)
        ));
        device.set_address(ALICE.into(), 1).unwrap();
        drop(device);
        let device = open_device(store).unwrap().expect("device exists");
        assert_eq!(
            device.address(),
            Some(DeviceAddress {
                account_id: ALICE.into(),
                device_id: 1
            })
        );
    }

    #[test]
    fn open_device_on_empty_store_returns_none() {
        assert!(
            open_device(Arc::new(TestStore::default()))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn store_errors_are_reported() {
        let result = KiviDevice::create(Arc::new(FailingStore), ALICE.into(), 1);
        assert!(matches!(result, Err(KiviError::Storage(msg)) if msg.contains("db closed")));
    }

    #[test]
    fn errors_are_mapped() {
        let result = KiviDevice::create(Arc::new(TestStore::default()), "bad".into(), 1);
        assert!(matches!(result, Err(KiviError::InvalidAccountId(_))));
    }
}
