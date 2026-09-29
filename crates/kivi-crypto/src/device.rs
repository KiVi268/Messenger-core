use std::future::Future;
use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::FutureExt as _;
use libsignal_protocol::{
    CiphertextMessage, CiphertextMessageType, DeviceId, GenericSignedPreKey as _, IdentityKey,
    IdentityKeyPair, IdentityKeyStore as _, InMemSignalProtocolStore, KeyPair, KyberPreKeyRecord,
    KyberPreKeyStore as _, PreKeyBundle, PreKeyRecord, PreKeySignalMessage, PreKeyStore as _,
    ProtocolAddress, PublicKey, SessionStore as _, SignalMessage, SignalProtocolError,
    SignedPreKeyRecord, SignedPreKeyStore as _, Timestamp, kem, message_decrypt, message_encrypt,
    process_prekey_bundle,
};
use rand::Rng as _;

use crate::error::CryptoError;
use crate::types::{
    DeviceKeys, EnvelopeKind, OutgoingCiphertext, PreKey, RemoteDeviceBundle, SignedKey,
};

/// Registration ID в libsignal занимает 14 бит.
const REGISTRATION_ID_MAX: u32 = 0x3FFF;
/// ID подписанного EC-ключа и Kyber-ключа «последней надежды».
const SIGNED_PRE_KEY_ID: u32 = 1;
const LAST_RESORT_KYBER_PRE_KEY_ID: u32 = 1;
const KYBER_KEY_TYPE: kem::KeyType = kem::KeyType::Kyber1024;

/// Устройство текущего пользователя: его ключи и сессии с собеседниками.
pub struct LocalDevice {
    address: ProtocolAddress,
    store: InMemSignalProtocolStore,
    device_keys: DeviceKeys,
    next_pre_key_id: u32,
    next_kyber_pre_key_id: u32,
}

impl LocalDevice {
    /// Создаёт устройство с новыми ключами: ключ идентичности, registration
    /// ID, подписанный EC-ключ и Kyber-ключ «последней надежды».
    ///
    /// `account_id` — UUID аккаунта, `device_id` — номер устройства
    /// (основное — 1).
    pub fn new(account_id: &str, device_id: u32) -> Result<Self, CryptoError> {
        let address = protocol_address(account_id, device_id)?;
        let mut rng = rand::rng();

        let identity = IdentityKeyPair::generate(&mut rng);
        let registration_id = rng.random_range(1..=REGISTRATION_ID_MAX);
        let mut store = InMemSignalProtocolStore::new(identity, registration_id)?;
        let now = now_timestamp();

        let signed_pair = KeyPair::generate(&mut rng);
        let signed_signature = identity
            .private_key()
            .calculate_signature(&signed_pair.public_key.serialize(), &mut rng)
            .map_err(SignalProtocolError::from)?;
        let signed_record = SignedPreKeyRecord::new(
            SIGNED_PRE_KEY_ID.into(),
            now,
            &signed_pair,
            &signed_signature,
        );
        run(store.save_signed_pre_key(SIGNED_PRE_KEY_ID.into(), &signed_record))?;

        let kyber_record = KyberPreKeyRecord::generate(
            KYBER_KEY_TYPE,
            LAST_RESORT_KYBER_PRE_KEY_ID.into(),
            identity.private_key(),
        )?;
        run(store.save_kyber_pre_key(LAST_RESORT_KYBER_PRE_KEY_ID.into(), &kyber_record))?;

        let device_keys = DeviceKeys {
            identity_public_key: identity.identity_key().serialize().into_vec(),
            registration_id,
            signed_pre_key: SignedKey {
                key_id: SIGNED_PRE_KEY_ID,
                public_key: signed_pair.public_key.serialize().into_vec(),
                signature: signed_signature.into_vec(),
            },
            last_resort_kyber_pre_key: SignedKey {
                key_id: LAST_RESORT_KYBER_PRE_KEY_ID,
                public_key: kyber_record.public_key()?.serialize().into_vec(),
                signature: kyber_record.signature()?,
            },
        };

        Ok(Self {
            address,
            store,
            device_keys,
            next_pre_key_id: 1,
            next_kyber_pre_key_id: LAST_RESORT_KYBER_PRE_KEY_ID + 1,
        })
    }

    /// Ключи для регистрации устройства на сервере.
    pub fn device_keys(&self) -> &DeviceKeys {
        &self.device_keys
    }

    /// Генерирует одноразовые EC-ключи и сохраняет их приватные части.
    /// Публичные части отправляются на сервер (`UploadPreKeys.pre_keys`).
    pub fn generate_pre_keys(&mut self, count: u32) -> Result<Vec<PreKey>, CryptoError> {
        let mut rng = rand::rng();
        let mut keys = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let id = self.next_pre_key_id;
            self.next_pre_key_id += 1;
            let pair = KeyPair::generate(&mut rng);
            run(self
                .store
                .save_pre_key(id.into(), &PreKeyRecord::new(id.into(), &pair)))?;
            keys.push(PreKey {
                key_id: id,
                public_key: pair.public_key.serialize().into_vec(),
            });
        }
        Ok(keys)
    }

    /// Генерирует одноразовые Kyber-ключи и сохраняет их приватные части.
    /// Публичные части отправляются на сервер (`UploadPreKeys.kyber_pre_keys`).
    pub fn generate_kyber_pre_keys(&mut self, count: u32) -> Result<Vec<SignedKey>, CryptoError> {
        let mut keys = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let id = self.next_kyber_pre_key_id;
            self.next_kyber_pre_key_id += 1;
            let identity = run(self.store.identity_store.get_identity_key_pair())?;
            let record =
                KyberPreKeyRecord::generate(KYBER_KEY_TYPE, id.into(), identity.private_key())?;
            run(self.store.save_kyber_pre_key(id.into(), &record))?;
            keys.push(SignedKey {
                key_id: id,
                public_key: record.public_key()?.serialize().into_vec(),
                signature: record.signature()?,
            });
        }
        Ok(keys)
    }

    /// Устанавливает сессию с устройством собеседника по его ключам с сервера.
    pub fn process_bundle(
        &mut self,
        remote_account_id: &str,
        bundle: &RemoteDeviceBundle,
    ) -> Result<(), CryptoError> {
        let remote = protocol_address(remote_account_id, bundle.device_id)?;
        let pre_key = bundle
            .pre_key
            .as_ref()
            .map(|k| Ok::<_, CryptoError>((k.key_id.into(), parse_public_key(&k.public_key)?)))
            .transpose()?;
        let libsignal_bundle = PreKeyBundle::new(
            bundle.registration_id,
            device_id(bundle.device_id)?,
            pre_key,
            bundle.signed_pre_key.key_id.into(),
            parse_public_key(&bundle.signed_pre_key.public_key)?,
            bundle.signed_pre_key.signature.clone(),
            bundle.kyber_pre_key.key_id.into(),
            kem::PublicKey::deserialize(&bundle.kyber_pre_key.public_key)?,
            bundle.kyber_pre_key.signature.clone(),
            IdentityKey::decode(&bundle.identity_public_key)?,
        )?;
        let mut rng = rand::rng();
        run(process_prekey_bundle(
            &remote,
            &self.address,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            &libsignal_bundle,
            SystemTime::now(),
            &mut rng,
        ))
    }

    /// Есть ли сессия с устройством собеседника.
    pub fn has_session(
        &self,
        remote_account_id: &str,
        remote_device_id: u32,
    ) -> Result<bool, CryptoError> {
        let remote = protocol_address(remote_account_id, remote_device_id)?;
        Ok(run(self.store.load_session(&remote))?.is_some())
    }

    /// Шифрует сообщение для одного устройства собеседника. Сессия должна
    /// быть установлена (`process_bundle`) или получена входящим сообщением.
    pub fn encrypt(
        &mut self,
        remote_account_id: &str,
        remote_device_id: u32,
        plaintext: &[u8],
    ) -> Result<OutgoingCiphertext, CryptoError> {
        let remote = protocol_address(remote_account_id, remote_device_id)?;
        let mut rng = rand::rng();
        let message = run(message_encrypt(
            plaintext,
            &remote,
            &self.address,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            SystemTime::now(),
            &mut rng,
        ))?;
        let kind = match message.message_type() {
            CiphertextMessageType::Whisper => EnvelopeKind::Ciphertext,
            CiphertextMessageType::PreKey => EnvelopeKind::PreKeyMessage,
            other => {
                return Err(CryptoError::Protocol(format!(
                    "unexpected message type {other:?}"
                )));
            }
        };
        Ok(OutgoingCiphertext {
            kind,
            content: message.serialize().to_vec(),
        })
    }

    /// Расшифровывает входящее сообщение. Для `PreKeyMessage` сессия
    /// устанавливается автоматически, использованный одноразовый ключ
    /// удаляется.
    pub fn decrypt(
        &mut self,
        sender_account_id: &str,
        sender_device_id: u32,
        kind: EnvelopeKind,
        content: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let sender = protocol_address(sender_account_id, sender_device_id)?;
        let message = match kind {
            EnvelopeKind::Ciphertext => {
                CiphertextMessage::SignalMessage(SignalMessage::try_from(content)?)
            }
            EnvelopeKind::PreKeyMessage => {
                CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(content)?)
            }
        };
        let mut rng = rand::rng();
        run(message_decrypt(
            &message,
            &sender,
            &self.address,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            &mut self.store.pre_key_store,
            &self.store.signed_pre_key_store,
            &mut self.store.kyber_pre_key_store,
            &mut rng,
        ))
    }
}

fn protocol_address(account_id: &str, device: u32) -> Result<ProtocolAddress, CryptoError> {
    let uuid = uuid::Uuid::parse_str(account_id)
        .map_err(|_| CryptoError::InvalidAccountId(account_id.to_owned()))?;
    Ok(ProtocolAddress::new(uuid.to_string(), device_id(device)?))
}

fn device_id(device: u32) -> Result<DeviceId, CryptoError> {
    u8::try_from(device)
        .ok()
        .and_then(|d| DeviceId::new(d).ok())
        .ok_or(CryptoError::InvalidDeviceId(device))
}

fn parse_public_key(bytes: &[u8]) -> Result<PublicKey, CryptoError> {
    PublicKey::deserialize(bytes).map_err(|e| CryptoError::Malformed(e.to_string()))
}

fn now_timestamp() -> Timestamp {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default();
    Timestamp::from_epoch_millis(u64::try_from(millis).unwrap_or(u64::MAX))
}

/// Хранилища в памяти никогда не ждут ввода-вывода, поэтому async-API
/// libsignal завершается сразу. Когда появится постоянное хранилище, эту
/// функцию заменит нормальный executor.
fn run<T, E: Into<CryptoError>>(
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, CryptoError> {
    future
        .now_or_never()
        .expect("in-memory libsignal stores complete synchronously")
        .map_err(Into::into)
}
