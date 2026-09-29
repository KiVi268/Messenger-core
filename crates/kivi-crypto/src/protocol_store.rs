//! Реализация хранилищ libsignal поверх [`Storage`] платформы.

use async_trait::async_trait;
use libsignal_protocol::{
    CiphertextMessageType, Direction, GenericSignedPreKey as _, IdentityChange, IdentityKey,
    IdentityKeyPair, IdentityKeyStore, KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore,
    PreKeyId, PreKeyRecord, PreKeyStore, ProtocolAddress, PublicKey, SessionRecord, SessionStore,
    SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
};

use crate::storage::{RecordKind, Storage, StorageError};

type Result<T> = std::result::Result<T, SignalProtocolError>;

/// ID Kyber-ключа «последней надежды»: его нельзя удалять после
/// использования, вместо этого запоминаются использованные base key.
pub(crate) const LAST_RESORT_KYBER_PRE_KEY_ID: u32 = 1;

/// Адаптер: все пять хранилищ libsignal поверх одного [`Storage`].
///
/// Не хранит собственного состояния, кроме своего ключа идентичности,
/// поэтому для одного вызова libsignal можно создать несколько экземпляров
/// (libsignal принимает хранилища отдельными `&mut`-аргументами).
pub(crate) struct ProtocolStore<'a> {
    pub(crate) storage: &'a dyn Storage,
    pub(crate) identity: IdentityKeyPair,
    pub(crate) registration_id: u32,
}

impl ProtocolStore<'_> {
    /// Принятый пользователем ключ собеседника; для записей, сохранённых до
    /// появления [`RecordKind::TrustedIdentity`], — последний известный.
    pub(crate) fn trusted_identity(&self, account_id: &str) -> Result<Option<IdentityKey>> {
        let bytes = match self.load("trusted_identity", RecordKind::TrustedIdentity, account_id)? {
            Some(bytes) => Some(bytes),
            None => self.load("trusted_identity", RecordKind::RemoteIdentity, account_id)?,
        };
        bytes.map(|b| IdentityKey::decode(&b)).transpose()
    }

    fn load(&self, method: &'static str, kind: RecordKind, key: &str) -> Result<Option<Vec<u8>>> {
        self.storage.load(kind, key).map_err(callback_error(method))
    }

    fn store(&self, method: &'static str, kind: RecordKind, key: &str, value: &[u8]) -> Result<()> {
        self.storage
            .store(kind, key, value)
            .map_err(callback_error(method))
    }

    fn remove(&self, method: &'static str, kind: RecordKind, key: &str) -> Result<()> {
        self.storage
            .remove(kind, key)
            .map_err(callback_error(method))
    }
}

fn callback_error(method: &'static str) -> impl FnOnce(StorageError) -> SignalProtocolError {
    SignalProtocolError::for_application_callback(method)
}

/// Ключ сессии: `<account_id>.<device_id>`.
pub(crate) fn session_key(address: &ProtocolAddress) -> String {
    format!("{}.{}", address.name(), u32::from(address.device_id()))
}

#[async_trait(?Send)]
impl IdentityKeyStore for ProtocolStore<'_> {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair> {
        Ok(self.identity)
    }

    async fn get_local_registration_id(&self) -> Result<u32> {
        Ok(self.registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange> {
        // Ключ идентичности общий на аккаунт (ADR-0003) — храним по account_id.
        let existing = self.get_identity(address).await?;
        if self
            .load("save_identity", RecordKind::TrustedIdentity, address.name())?
            .is_none()
        {
            // Trust on first use. Для записей, сохранённых до появления
            // TrustedIdentity, принятым считается прежний ключ.
            let trusted = existing.unwrap_or(*identity);
            self.store(
                "save_identity",
                RecordKind::TrustedIdentity,
                address.name(),
                &trusted.serialize(),
            )?;
        }
        self.store(
            "save_identity",
            RecordKind::RemoteIdentity,
            address.name(),
            &identity.serialize(),
        )?;
        Ok(IdentityChange::from_changed(
            existing.is_some_and(|known| known != *identity),
        ))
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> Result<bool> {
        Ok(match direction {
            // Приём не блокируется: иначе сообщения собеседника, сменившего
            // ключ (переустановка), отбрасывались бы до подтверждения. Новый
            // ключ сохраняется, и отправка ему ждёт подтверждения пользователя.
            Direction::Receiving => true,
            Direction::Sending => match self.trusted_identity(address.name())? {
                None => true,
                Some(trusted) => trusted == *identity,
            },
        })
    }

    async fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>> {
        self.load("get_identity", RecordKind::RemoteIdentity, address.name())?
            .map(|bytes| IdentityKey::decode(&bytes))
            .transpose()
    }
}

#[async_trait(?Send)]
impl SessionStore for ProtocolStore<'_> {
    async fn load_session(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>> {
        self.load("load_session", RecordKind::Session, &session_key(address))?
            .map(|bytes| SessionRecord::deserialize(&bytes))
            .transpose()
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<()> {
        self.store(
            "store_session",
            RecordKind::Session,
            &session_key(address),
            &record.serialize()?,
        )
    }
}

#[async_trait(?Send)]
impl PreKeyStore for ProtocolStore<'_> {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord> {
        let key = u32::from(prekey_id).to_string();
        let bytes = self
            .load("get_pre_key", RecordKind::PreKey, &key)?
            .ok_or(SignalProtocolError::InvalidPreKeyId)?;
        PreKeyRecord::deserialize(&bytes)
    }

    async fn save_pre_key(&mut self, prekey_id: PreKeyId, record: &PreKeyRecord) -> Result<()> {
        let key = u32::from(prekey_id).to_string();
        self.store(
            "save_pre_key",
            RecordKind::PreKey,
            &key,
            &record.serialize()?,
        )
    }

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<()> {
        let key = u32::from(prekey_id).to_string();
        self.remove("remove_pre_key", RecordKind::PreKey, &key)
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for ProtocolStore<'_> {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord> {
        let key = u32::from(signed_prekey_id).to_string();
        let bytes = self
            .load("get_signed_pre_key", RecordKind::SignedPreKey, &key)?
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)?;
        SignedPreKeyRecord::deserialize(&bytes)
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<()> {
        let key = u32::from(signed_prekey_id).to_string();
        self.store(
            "save_signed_pre_key",
            RecordKind::SignedPreKey,
            &key,
            &record.serialize()?,
        )
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for ProtocolStore<'_> {
    async fn get_kyber_pre_key(&self, kyber_prekey_id: KyberPreKeyId) -> Result<KyberPreKeyRecord> {
        let key = u32::from(kyber_prekey_id).to_string();
        let bytes = self
            .load("get_kyber_pre_key", RecordKind::KyberPreKey, &key)?
            .ok_or(SignalProtocolError::InvalidKyberPreKeyId)?;
        KyberPreKeyRecord::deserialize(&bytes)
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<()> {
        let key = u32::from(kyber_prekey_id).to_string();
        self.store(
            "save_kyber_pre_key",
            RecordKind::KyberPreKey,
            &key,
            &record.serialize()?,
        )
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        ec_prekey_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) -> Result<()> {
        let id = u32::from(kyber_prekey_id);
        if id != LAST_RESORT_KYBER_PRE_KEY_ID {
            // Одноразовый ключ удаляется сразу после использования.
            return self.remove(
                "mark_kyber_pre_key_used",
                RecordKind::KyberPreKey,
                &id.to_string(),
            );
        }
        // Ключ «последней надежды» остаётся, но одна и та же пара
        // (подписанный ключ, base key) не должна приниматься дважды.
        let seen_key = format!(
            "{id}:{}:{}",
            u32::from(ec_prekey_id),
            to_hex(&base_key.serialize())
        );
        if self
            .load(
                "mark_kyber_pre_key_used",
                RecordKind::KyberBaseKeySeen,
                &seen_key,
            )?
            .is_some()
        {
            return Err(SignalProtocolError::InvalidMessage(
                CiphertextMessageType::PreKey,
                "reused base key".to_owned(),
            ));
        }
        self.store(
            "mark_kyber_pre_key_used",
            RecordKind::KyberBaseKeySeen,
            &seen_key,
            &[],
        )
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
