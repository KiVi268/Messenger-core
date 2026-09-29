use libsignal_protocol::SignalProtocolError;

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

    /// Прочие ошибки протокола (подписи, повреждённые сообщения и т. д.).
    #[error("protocol error: {0}")]
    Protocol(String),
}

impl From<SignalProtocolError> for CryptoError {
    fn from(err: SignalProtocolError) -> Self {
        match err {
            SignalProtocolError::SessionNotFound(e) => Self::NoSession(e.to_string()),
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
