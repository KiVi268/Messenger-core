//! Типы, которыми ядро обменивается с клиентом. Поля совпадают с
//! сообщениями `messenger-protocol`.

/// Одноразовый EC pre-key (`kivi.keys.v1.PreKey`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreKey {
    pub key_id: u32,
    /// Публичный ключ в формате libsignal: 0x05 + 32 байта.
    pub public_key: Vec<u8>,
}

/// Подписанный ключ (`kivi.keys.v1.SignedPreKey` / `KyberPreKey`).
/// Подпись — ключом идентичности устройства.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedKey {
    pub key_id: u32,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Ключи, публикуемые при регистрации устройства (`kivi.keys.v1.DeviceKeys`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceKeys {
    pub identity_public_key: Vec<u8>,
    pub registration_id: u32,
    pub signed_pre_key: SignedKey,
    pub last_resort_kyber_pre_key: SignedKey,
}

/// Ключи устройства собеседника, полученные с сервера
/// (`kivi.keys.v1.DevicePreKeyBundle`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteDeviceBundle {
    pub device_id: u32,
    pub registration_id: u32,
    pub identity_public_key: Vec<u8>,
    pub signed_pre_key: SignedKey,
    /// Может отсутствовать, если одноразовые ключи закончились.
    pub pre_key: Option<PreKey>,
    pub kyber_pre_key: SignedKey,
}

/// Тип шифротекста (`kivi.messaging.v1.EnvelopeType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeKind {
    /// Сообщение в установленной сессии (`ENVELOPE_TYPE_CIPHERTEXT`).
    Ciphertext,
    /// Первое сообщение сессии (`ENVELOPE_TYPE_PREKEY_MESSAGE`).
    PreKeyMessage,
}

/// Зашифрованное сообщение для одного устройства получателя
/// (`kivi.messaging.v1.OutgoingMessage` без адресных полей).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutgoingCiphertext {
    pub kind: EnvelopeKind,
    pub content: Vec<u8>,
}
