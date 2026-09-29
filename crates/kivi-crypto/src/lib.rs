//! E2EE-ядро KiVi Messenger поверх libsignal.
//!
//! Крейт скрывает детали libsignal за небольшим API, которое нужно клиентам:
//! сгенерировать ключи устройства, установить сессию по ключам собеседника,
//! зашифровать и расшифровать сообщение.
//!
//! Типы соответствуют контракту `messenger-protocol` (`kivi.keys.v1`,
//! `kivi.messaging.v1`): клиент перекладывает поля один в один.
//!
//! Состояние (ключи, сессии) пока хранится в памяти. Как его сохранять
//! между запусками — отдельное решение (см. README, «Открытые вопросы»).

#![forbid(unsafe_code)]

mod device;
mod error;
mod types;

pub use device::LocalDevice;
pub use error::CryptoError;
pub use types::{
    DeviceKeys, EnvelopeKind, OutgoingCiphertext, PreKey, RemoteDeviceBundle, SignedKey,
};
