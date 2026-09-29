use libsignal_protocol::SignalProtocolError;

use crate::storage::StorageError;

/// Ошибки E2EE-ядра.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// Идентификатор аккаунта не является UUID.
    #[error("invalid account id: {0}")]
    InvalidAccountId(String),

    /// Номер устройства вне диапазона, поддерживаемого libsignal (1..=127).
    #[error("invalid device id: {0}")]
    InvalidDeviceId(u32),

    /// Входные данные (ключи, шифротекст) не разбираются.
    #[error("malformed input: {0}")]
    Malformed(String),

    /// Нет сессии с устройством: сначала нужно установить её по ключам
    /// собеседника.
    #[error("no session with {0}")]
    NoSession(String),

    /// Ключ идентичности собеседника изменился и не подтверждён.
    #[error("untrusted identity for {0}")]
    UntrustedIdentity(String),

    /// Устройство уже создано в этом хранилище.
    #[error("device already exists in storage")]
    AlreadyExists,

    /// Ошибка хранилища платформы.
    #[error("storage error: {0}")]
    Storage(String),

    /// Прочие ошибки протокола (подписи, повреждённые сообщения и т. д.).
    #[error("protocol error: {0}")]
    Protocol(String),
}

impl From<StorageError> for CryptoError {
    fn from(err: StorageError) -> Self {
        Self::Storage(err.0)
    }
}

impl From<SignalProtocolError> for CryptoError {
    fn from(err: SignalProtocolError) -> Self {
        match err {
            SignalProtocolError::SessionNotFound(e) => Self::NoSession(e.to_string()),
            SignalProtocolError::ApplicationCallbackError(_, ref source) => {
                let source: &(dyn std::error::Error + 'static) = &**source;
                match source.downcast_ref::<StorageError>() {
                    Some(storage) => Self::Storage(storage.0.clone()),
                    None => Self::Protocol(err.to_string()),
                }
            }
            SignalProtocolError::UntrustedIdentity(addr) => {
                Self::UntrustedIdentity(addr.to_string())
            }
            SignalProtocolError::InvalidProtobufEncoding
            | SignalProtocolError::InvalidMessage(..)
            | SignalProtocolError::CiphertextMessageTooShort(_) => Self::Malformed(err.to_string()),
            other => Self::Protocol(other.to_string()),
        }
    }
}
