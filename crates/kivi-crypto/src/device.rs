use std::future::Future;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::FutureExt as _;
use libsignal_protocol::{
    CiphertextMessage, CiphertextMessageType, DeviceId, Fingerprint, GenericSignedPreKey as _,
    IdentityKey, IdentityKeyPair, IdentityKeyStore as _, KeyPair, KyberPreKeyRecord,
    KyberPreKeyStore as _, PreKeyBundle, PreKeyRecord, PreKeySignalMessage, PreKeyStore as _,
    ProtocolAddress, PublicKey, ScannableFingerprint, SenderCertificate, SessionRecord,
    SessionStore as _, SessionUsabilityRequirements, SignalMessage, SignalProtocolError,
    SignedPreKeyRecord, SignedPreKeyStore as _, Timestamp, kem, message_decrypt, message_encrypt,
    process_prekey_bundle,
};
use rand::Rng as _;

use crate::error::CryptoError;
use crate::protocol_store::{LAST_RESORT_KYBER_PRE_KEY_ID, ProtocolStore, session_key};
use crate::storage::{RecordKind, Storage};
use crate::types::{
    DeviceKeys, EnvelopeKind, IdentityStatus, OutgoingCiphertext, PreKey, RemoteDeviceBundle,
    SafetyNumber, SealedSenderMessage, SignedKey,
};

/// Registration ID в libsignal занимает 14 бит.
const REGISTRATION_ID_MAX: u32 = 0x3FFF;
/// ID подписанного EC-ключа.
const SIGNED_PRE_KEY_ID: u32 = 1;
const KYBER_KEY_TYPE: kem::KeyType = kem::KeyType::Kyber1024;
/// Параметры номера безопасности — как у Signal: версия 2 (идентификатор —
/// 16 байт UUID аккаунта), 5200 итераций SHA-512.
const FINGERPRINT_VERSION: u32 = 2;
const FINGERPRINT_ITERATIONS: u32 = 5200;

/// Ключи записей вида [`RecordKind::LocalAccount`].
mod account {
    pub const IDENTITY_KEY_PAIR: &str = "identity_key_pair";
    pub const REGISTRATION_ID: &str = "registration_id";
    pub const ACCOUNT_ID: &str = "account_id";
    pub const DEVICE_ID: &str = "device_id";
    pub const NEXT_PRE_KEY_ID: &str = "next_pre_key_id";
    pub const NEXT_KYBER_PRE_KEY_ID: &str = "next_kyber_pre_key_id";
}

/// Устройство текущего пользователя: его ключи и сессии с собеседниками.
///
/// Всё состояние хранится в [`Storage`] платформы и переживает перезапуск
/// приложения: при следующем запуске устройство открывается через
/// [`LocalDevice::open`].
///
/// Регистрация идёт в два шага: ключи нужны серверу для регистрации, а
/// адрес (UUID аккаунта и номер устройства) сервер выдаёт в ответ.
/// 1. [`LocalDevice::generate`] — ключи без адреса, [`LocalDevice::device_keys`]
///    уходят в `RegisterRequest`;
/// 2. [`LocalDevice::set_address`] — адрес из `RegisterResponse`.
///
/// До второго шага сессии и шифрование недоступны ([`CryptoError::NotRegistered`]).
pub struct LocalDevice {
    storage: Arc<dyn Storage>,
    address: Option<ProtocolAddress>,
    identity: IdentityKeyPair,
    registration_id: u32,
}

impl LocalDevice {
    /// Создаёт устройство с известным адресом: [`LocalDevice::generate`] +
    /// [`LocalDevice::set_address`].
    pub fn create(
        storage: Arc<dyn Storage>,
        account_id: &str,
        device_id: u32,
    ) -> Result<Self, CryptoError> {
        // Адрес проверяется до генерации ключей, чтобы не оставить в хранилище
        // устройство без адреса из-за опечатки в аргументах.
        protocol_address(account_id, device_id)?;
        let mut device = Self::generate(storage)?;
        device.set_address(account_id, device_id)?;
        Ok(device)
    }

    /// Создаёт устройство с новыми ключами и сохраняет их: ключ идентичности,
    /// registration ID, подписанный EC-ключ и Kyber-ключ «последней надежды».
    /// Адрес задаётся после регистрации через [`LocalDevice::set_address`].
    ///
    /// Если в хранилище уже есть устройство, возвращает
    /// [`CryptoError::AlreadyExists`].
    pub fn generate(storage: Arc<dyn Storage>) -> Result<Self, CryptoError> {
        if storage
            .load(RecordKind::LocalAccount, account::IDENTITY_KEY_PAIR)?
            .is_some()
        {
            return Err(CryptoError::AlreadyExists);
        }

        let mut rng = rand::rng();
        let identity = IdentityKeyPair::generate(&mut rng);
        let registration_id = rng.random_range(1..=REGISTRATION_ID_MAX);
        let device = Self {
            storage,
            address: None,
            identity,
            registration_id,
        };

        let signed_pair = KeyPair::generate(&mut rng);
        let signed_signature = identity
            .private_key()
            .calculate_signature(&signed_pair.public_key.serialize(), &mut rng)
            .map_err(SignalProtocolError::from)?;
        let signed_record = SignedPreKeyRecord::new(
            SIGNED_PRE_KEY_ID.into(),
            now_timestamp(),
            &signed_pair,
            &signed_signature,
        );
        run(device
            .protocol_store()
            .save_signed_pre_key(SIGNED_PRE_KEY_ID.into(), &signed_record))?;

        let kyber_record = KyberPreKeyRecord::generate(
            KYBER_KEY_TYPE,
            LAST_RESORT_KYBER_PRE_KEY_ID.into(),
            identity.private_key(),
        )?;
        run(device
            .protocol_store()
            .save_kyber_pre_key(LAST_RESORT_KYBER_PRE_KEY_ID.into(), &kyber_record))?;

        // Ключ идентичности записывается последним: его наличие означает,
        // что устройство создано полностью.
        let s = &device.storage;
        s.store(
            RecordKind::LocalAccount,
            account::REGISTRATION_ID,
            &registration_id.to_be_bytes(),
        )?;
        s.store(
            RecordKind::LocalAccount,
            account::NEXT_PRE_KEY_ID,
            &1u32.to_be_bytes(),
        )?;
        s.store(
            RecordKind::LocalAccount,
            account::NEXT_KYBER_PRE_KEY_ID,
            &(LAST_RESORT_KYBER_PRE_KEY_ID + 1).to_be_bytes(),
        )?;
        s.store(
            RecordKind::LocalAccount,
            account::IDENTITY_KEY_PAIR,
            &identity.serialize(),
        )?;
        Ok(device)
    }

    /// Задаёт адрес устройства, выданный сервером при регистрации
    /// (`RegisterResponse.account_id`, `device_id`). Повторный вызов (например,
    /// после перерегистрации) заменяет адрес.
    pub fn set_address(&mut self, account_id: &str, device_id: u32) -> Result<(), CryptoError> {
        let address = protocol_address(account_id, device_id)?;
        self.storage.store(
            RecordKind::LocalAccount,
            account::ACCOUNT_ID,
            address.name().as_bytes(),
        )?;
        self.storage.store(
            RecordKind::LocalAccount,
            account::DEVICE_ID,
            &device_id.to_be_bytes(),
        )?;
        self.address = Some(address);
        Ok(())
    }

    /// Адрес устройства: UUID аккаунта и номер устройства. `None` — устройство
    /// ещё не зарегистрировано.
    pub fn address(&self) -> Option<(String, u32)> {
        self.address
            .as_ref()
            .map(|a| (a.name().to_owned(), u32::from(a.device_id())))
    }

    /// Открывает ранее созданное устройство. `None` — устройства в хранилище нет.
    pub fn open(storage: Arc<dyn Storage>) -> Result<Option<Self>, CryptoError> {
        let Some(identity) = storage.load(RecordKind::LocalAccount, account::IDENTITY_KEY_PAIR)?
        else {
            return Ok(None);
        };
        let identity = IdentityKeyPair::try_from(identity.as_slice())?;
        let registration_id = read_u32(&*storage, account::REGISTRATION_ID)?;
        // Адреса нет, если приложение закрыли между генерацией ключей и
        // ответом сервера на регистрацию.
        let address = match storage.load(RecordKind::LocalAccount, account::ACCOUNT_ID)? {
            None => None,
            Some(account_id) => {
                let account_id = String::from_utf8(account_id).map_err(|_| {
                    CryptoError::Malformed("stored account id is not UTF-8".to_owned())
                })?;
                let device_id = read_u32(&*storage, account::DEVICE_ID)?;
                Some(protocol_address(&account_id, device_id)?)
            }
        };
        Ok(Some(Self {
            address,
            storage,
            identity,
            registration_id,
        }))
    }

    /// Ключи для регистрации устройства на сервере.
    pub fn device_keys(&self) -> Result<DeviceKeys, CryptoError> {
        let store = self.protocol_store();
        let signed = run(store.get_signed_pre_key(SIGNED_PRE_KEY_ID.into()))?;
        let kyber = run(store.get_kyber_pre_key(LAST_RESORT_KYBER_PRE_KEY_ID.into()))?;
        Ok(DeviceKeys {
            identity_public_key: self.identity.identity_key().serialize().into_vec(),
            registration_id: self.registration_id,
            signed_pre_key: SignedKey {
                key_id: SIGNED_PRE_KEY_ID,
                public_key: signed.public_key()?.serialize().into_vec(),
                signature: signed.signature()?,
            },
            last_resort_kyber_pre_key: SignedKey {
                key_id: LAST_RESORT_KYBER_PRE_KEY_ID,
                public_key: kyber.public_key()?.serialize().into_vec(),
                signature: kyber.signature()?,
            },
        })
    }

    /// Генерирует одноразовые EC-ключи и сохраняет их приватные части.
    /// Публичные части отправляются на сервер (`UploadPreKeys.pre_keys`).
    pub fn generate_pre_keys(&self, count: u32) -> Result<Vec<PreKey>, CryptoError> {
        let mut rng = rand::rng();
        let first = self.reserve_ids(account::NEXT_PRE_KEY_ID, count)?;
        let mut store = self.protocol_store();
        (first..first + count)
            .map(|id| {
                let pair = KeyPair::generate(&mut rng);
                run(store.save_pre_key(id.into(), &PreKeyRecord::new(id.into(), &pair)))?;
                Ok(PreKey {
                    key_id: id,
                    public_key: pair.public_key.serialize().into_vec(),
                })
            })
            .collect()
    }

    /// Генерирует одноразовые Kyber-ключи и сохраняет их приватные части.
    /// Публичные части отправляются на сервер (`UploadPreKeys.kyber_pre_keys`).
    pub fn generate_kyber_pre_keys(&self, count: u32) -> Result<Vec<SignedKey>, CryptoError> {
        let first = self.reserve_ids(account::NEXT_KYBER_PRE_KEY_ID, count)?;
        let mut store = self.protocol_store();
        (first..first + count)
            .map(|id| {
                let record = KyberPreKeyRecord::generate(
                    KYBER_KEY_TYPE,
                    id.into(),
                    self.identity.private_key(),
                )?;
                run(store.save_kyber_pre_key(id.into(), &record))?;
                Ok(SignedKey {
                    key_id: id,
                    public_key: record.public_key()?.serialize().into_vec(),
                    signature: record.signature()?,
                })
            })
            .collect()
    }

    /// Устанавливает сессию с устройством собеседника по его ключам с сервера.
    pub fn process_bundle(
        &self,
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
        match run(process_prekey_bundle(
            &remote,
            self.local_address()?,
            &mut self.protocol_store(),
            &mut self.protocol_store(),
            &libsignal_bundle,
            SystemTime::now(),
            &mut rng,
        )) {
            Err(CryptoError::UntrustedIdentity(address)) => {
                // Ключ собеседника сменился. Запоминаем новый, чтобы показать
                // пользователю номер безопасности, — но только если ключи
                // устройства им действительно подписаны.
                let identity = IdentityKey::decode(&bundle.identity_public_key)?;
                if !identity.public_key().verify_signature(
                    &bundle.signed_pre_key.public_key,
                    &bundle.signed_pre_key.signature,
                ) {
                    return Err(CryptoError::Protocol(
                        "signed pre-key signature is invalid".to_owned(),
                    ));
                }
                run(self.protocol_store().save_identity(&remote, &identity))?;
                Err(CryptoError::UntrustedIdentity(address))
            }
            result => result,
        }
    }

    /// Есть ли сессия с устройством собеседника. Сессия со старым ключом
    /// собеседника (до смены ключа) не считается: её нужно установить заново.
    pub fn has_session(
        &self,
        remote_account_id: &str,
        remote_device_id: u32,
    ) -> Result<bool, CryptoError> {
        let remote = protocol_address(remote_account_id, remote_device_id)?;
        Ok(self.current_session(&remote)?.is_some())
    }

    /// Registration ID устройства собеседника из установленной сессии.
    /// Нужен в `OutgoingMessage.destination_registration_id`: по нему сервер
    /// узнаёт, что собеседник перерегистрировался (stale). `None` — сессии нет.
    pub fn remote_registration_id(
        &self,
        remote_account_id: &str,
        remote_device_id: u32,
    ) -> Result<Option<u32>, CryptoError> {
        let remote = protocol_address(remote_account_id, remote_device_id)?;
        match self.current_session(&remote)? {
            Some(record)
                if record.has_usable_sender_chain(
                    SystemTime::now(),
                    SessionUsabilityRequirements::NotStale,
                )? =>
            {
                Ok(Some(record.remote_registration_id()?))
            }
            _ => Ok(None),
        }
    }

    /// Шифрует сообщение для одного устройства собеседника. Сессия должна
    /// быть установлена (`process_bundle`) или получена входящим сообщением.
    pub fn encrypt(
        &self,
        remote_account_id: &str,
        remote_device_id: u32,
        plaintext: &[u8],
    ) -> Result<OutgoingCiphertext, CryptoError> {
        let remote = protocol_address(remote_account_id, remote_device_id)?;
        self.current_session(&remote)?;
        let mut rng = rand::rng();
        let message = run(message_encrypt(
            plaintext,
            &remote,
            self.local_address()?,
            &mut self.protocol_store(),
            &mut self.protocol_store(),
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
    ///
    /// Все изменения состояния записываются в [`Storage`] синхронно, в потоке
    /// вызова. Платформа выполняет `decrypt` и сохранение сообщения в одной
    /// транзакции своей БД и отправляет ACK только после её фиксации.
    pub fn decrypt(
        &self,
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
            self.local_address()?,
            &mut self.protocol_store(),
            &mut self.protocol_store(),
            &mut self.protocol_store(),
            &self.protocol_store(),
            &mut self.protocol_store(),
            &mut rng,
        ))
    }

    /// Шифрует сообщение через sealed sender: сервер не узнаёт отправителя.
    /// Сессия с устройством должна быть установлена, как для [`Self::encrypt`].
    /// `sender_certificate` — `SenderCertificate` этого устройства от сервера.
    pub fn sealed_sender_encrypt(
        &self,
        remote_account_id: &str,
        remote_device_id: u32,
        sender_certificate: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let local = self.local_address()?;
        let remote = protocol_address(remote_account_id, remote_device_id)?;
        self.current_session(&remote)?;
        let certificate = SenderCertificate::deserialize(sender_certificate)
            .map_err(|e| CryptoError::Malformed(e.to_string()))?;
        // Сертификат чужого устройства дал бы получателю неверный адрес для ответа.
        if certificate.sender_uuid()? != local.name()
            || certificate.sender_device_id()? != local.device_id()
        {
            return Err(CryptoError::Malformed(
                "sender certificate is issued for another device".to_owned(),
            ));
        }
        let mut rng = rand::rng();
        run(libsignal_protocol::sealed_sender_encrypt(
            &remote,
            &certificate,
            plaintext,
            &mut self.protocol_store(),
            &mut self.protocol_store(),
            SystemTime::now(),
            &mut rng,
        ))
    }

    /// Расшифровывает сообщение sealed sender. Проверяет сертификат
    /// отправителя по `trust_root` (публичный ключ, 33 байта) на момент
    /// `timestamp_ms` — время приёма сообщения сервером.
    pub fn sealed_sender_decrypt(
        &self,
        ciphertext: &[u8],
        trust_root: &[u8],
        timestamp_ms: u64,
    ) -> Result<SealedSenderMessage, CryptoError> {
        let local = self.local_address()?;
        let trust_root = parse_public_key(trust_root)?;
        let result = run(libsignal_protocol::sealed_sender_decrypt(
            ciphertext,
            &trust_root,
            Timestamp::from_epoch_millis(timestamp_ms),
            None,
            local.name().to_owned(),
            local.device_id(),
            &mut self.protocol_store(),
            &mut self.protocol_store(),
            &mut self.protocol_store(),
            &self.protocol_store(),
            &mut self.protocol_store(),
        ))?;
        Ok(SealedSenderMessage {
            sender_account_id: result.sender_uuid,
            sender_device_id: result.device_id.into(),
            plaintext: result.message,
        })
    }

    /// Состояние ключа идентичности собеседника.
    pub fn identity_status(&self, remote_account_id: &str) -> Result<IdentityStatus, CryptoError> {
        let name = account_name(remote_account_id)?;
        let Some(current) = self.remote_identity(&name)? else {
            return Ok(IdentityStatus::Unknown);
        };
        let store = self.protocol_store();
        if store.trusted_identity(&name)?.is_some_and(|t| t != current) {
            return Ok(IdentityStatus::Changed);
        }
        let verified = self
            .storage
            .load(RecordKind::VerifiedIdentity, &name)?
            .map(|b| IdentityKey::decode(&b))
            .transpose()?;
        Ok(if verified == Some(current) {
            IdentityStatus::Verified
        } else {
            IdentityStatus::Trusted
        })
    }

    /// Принимает текущий ключ собеседника после смены: отправка ему снова
    /// разрешена. Отметка «проверено» к новому ключу не переносится.
    pub fn trust_identity(&self, remote_account_id: &str) -> Result<(), CryptoError> {
        let name = account_name(remote_account_id)?;
        let current = self
            .remote_identity(&name)?
            .ok_or_else(|| CryptoError::NoSession(name.clone()))?;
        self.storage
            .store(RecordKind::TrustedIdentity, &name, &current.serialize())?;
        Ok(())
    }

    /// Отмечает текущий ключ собеседника проверенным (номер безопасности
    /// сверен) или снимает отметку. Проверенный ключ заодно принимается.
    pub fn set_verified(&self, remote_account_id: &str, verified: bool) -> Result<(), CryptoError> {
        let name = account_name(remote_account_id)?;
        if !verified {
            self.storage.remove(RecordKind::VerifiedIdentity, &name)?;
            return Ok(());
        }
        let current = self
            .remote_identity(&name)?
            .ok_or_else(|| CryptoError::NoSession(name.clone()))?;
        self.storage
            .store(RecordKind::TrustedIdentity, &name, &current.serialize())?;
        self.storage
            .store(RecordKind::VerifiedIdentity, &name, &current.serialize())?;
        Ok(())
    }

    /// Номер безопасности для текущего ключа собеседника. `None` — ключ
    /// собеседника ещё неизвестен.
    pub fn safety_number(
        &self,
        remote_account_id: &str,
    ) -> Result<Option<SafetyNumber>, CryptoError> {
        let name = account_name(remote_account_id)?;
        let Some(remote_key) = self.remote_identity(&name)? else {
            return Ok(None);
        };
        let fingerprint = self.fingerprint(&name, &remote_key)?;
        Ok(Some(SafetyNumber {
            digits: fingerprint.display_string().map_err(fingerprint_error)?,
            scannable: fingerprint
                .scannable
                .serialize()
                .map_err(fingerprint_error)?,
        }))
    }

    /// Сравнивает QR-код с экрана собеседника (`SafetyNumber::scannable`) со
    /// своим номером безопасности. `false` — ключи не совпадают (подмена или
    /// один из собеседников видит устаревший ключ).
    pub fn compare_safety_number(
        &self,
        remote_account_id: &str,
        scanned: &[u8],
    ) -> Result<bool, CryptoError> {
        let name = account_name(remote_account_id)?;
        let remote_key = self
            .remote_identity(&name)?
            .ok_or_else(|| CryptoError::NoSession(name.clone()))?;
        let ours: ScannableFingerprint = self.fingerprint(&name, &remote_key)?.scannable;
        match ours.compare(scanned) {
            Ok(same) => Ok(same),
            Err(libsignal_protocol::FingerprintError::VersionMismatch { .. }) => Ok(false),
            Err(e) => Err(CryptoError::Malformed(e.to_string())),
        }
    }

    fn fingerprint(
        &self,
        remote_name: &str,
        remote_key: &IdentityKey,
    ) -> Result<Fingerprint, CryptoError> {
        let local = self.local_address()?;
        Fingerprint::new(
            FINGERPRINT_VERSION,
            FINGERPRINT_ITERATIONS,
            uuid_bytes(local.name())?.as_slice(),
            self.identity.identity_key(),
            uuid_bytes(remote_name)?.as_slice(),
            remote_key,
        )
        .map_err(fingerprint_error)
    }

    fn remote_identity(&self, name: &str) -> Result<Option<IdentityKey>, CryptoError> {
        Ok(self
            .storage
            .load(RecordKind::RemoteIdentity, name)?
            .map(|b| IdentityKey::decode(&b))
            .transpose()?)
    }

    /// Сессия с устройством, если она с текущим ключом собеседника. Сессия со
    /// старым ключом (собеседник сменил ключ) удаляется: шифровать в ней
    /// бессмысленно, клиент установит новую по ключам с сервера.
    fn current_session(
        &self,
        remote: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, CryptoError> {
        let Some(session) = run(self.protocol_store().load_session(remote))? else {
            return Ok(None);
        };
        let current = self.remote_identity(remote.name())?;
        let session_key_bytes = session.remote_identity_key_bytes()?;
        if let Some(current) = current
            && session_key_bytes.as_deref() != Some(&*current.serialize())
        {
            self.storage
                .remove(RecordKind::Session, &session_key(remote))?;
            return Ok(None);
        }
        Ok(Some(session))
    }

    fn local_address(&self) -> Result<&ProtocolAddress, CryptoError> {
        self.address.as_ref().ok_or(CryptoError::NotRegistered)
    }

    fn protocol_store(&self) -> ProtocolStore<'_> {
        ProtocolStore {
            storage: &*self.storage,
            identity: self.identity,
            registration_id: self.registration_id,
        }
    }

    /// Резервирует `count` последовательных ID из счётчика и сохраняет новый
    /// счётчик до генерации ключей: ID не переиспользуются даже при сбое.
    fn reserve_ids(&self, counter: &str, count: u32) -> Result<u32, CryptoError> {
        let first = read_u32(&*self.storage, counter)?;
        let next = first
            .checked_add(count)
            .ok_or_else(|| CryptoError::Protocol("key id space exhausted".to_owned()))?;
        self.storage
            .store(RecordKind::LocalAccount, counter, &next.to_be_bytes())?;
        Ok(first)
    }
}

fn required(storage: &dyn Storage, key: &str) -> Result<Vec<u8>, CryptoError> {
    storage
        .load(RecordKind::LocalAccount, key)?
        .ok_or_else(|| CryptoError::Malformed(format!("stored account is missing {key}")))
}

fn read_u32(storage: &dyn Storage, key: &str) -> Result<u32, CryptoError> {
    let bytes = required(storage, key)?;
    let bytes: [u8; 4] = bytes
        .try_into()
        .map_err(|_| CryptoError::Malformed(format!("stored {key} is not u32")))?;
    Ok(u32::from_be_bytes(bytes))
}

fn protocol_address(account_id: &str, device: u32) -> Result<ProtocolAddress, CryptoError> {
    let uuid = uuid::Uuid::parse_str(account_id)
        .map_err(|_| CryptoError::InvalidAccountId(account_id.to_owned()))?;
    Ok(ProtocolAddress::new(uuid.to_string(), device_id(device)?))
}

fn account_name(account_id: &str) -> Result<String, CryptoError> {
    uuid::Uuid::parse_str(account_id)
        .map(|uuid| uuid.to_string())
        .map_err(|_| CryptoError::InvalidAccountId(account_id.to_owned()))
}

fn uuid_bytes(account_id: &str) -> Result<[u8; 16], CryptoError> {
    uuid::Uuid::parse_str(account_id)
        .map(|uuid| *uuid.as_bytes())
        .map_err(|_| CryptoError::InvalidAccountId(account_id.to_owned()))
}

fn fingerprint_error(err: libsignal_protocol::FingerprintError) -> CryptoError {
    CryptoError::Protocol(err.to_string())
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

/// Хранилище платформы синхронное, поэтому async-API libsignal поверх него
/// завершается сразу, без executor'а.
fn run<T, E: Into<CryptoError>>(
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, CryptoError> {
    future
        .now_or_never()
        .expect("storage callbacks are synchronous")
        .map_err(Into::into)
}
