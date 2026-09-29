//! E2EE-ядро KiVi Messenger поверх libsignal.
//!
//! Крейт скрывает детали libsignal за небольшим API, которое нужно клиентам:
//! сгенерировать ключи устройства, установить сессию по ключам собеседника,
//! зашифровать и расшифровать сообщение.
//!
//! Типы соответствуют контракту `messenger-protocol` (`kivi.keys.v1`,
//! `kivi.messaging.v1`): клиент перекладывает поля один в один.
//!
//! Состояние (ключи, сессии) хранится в БД платформы через [`Storage`]
//! (ADR-0004 в Messenger-KiVi).

#![forbid(unsafe_code)]

mod device;
mod error;
mod profile;
mod protocol_store;
mod storage;
mod types;

pub use device::LocalDevice;
pub use error::CryptoError;
pub use profile::{
    PROFILE_KEY_LEN, UNIDENTIFIED_ACCESS_KEY_LEN, generate_profile_key, unidentified_access_key,
};
pub use storage::{MemoryStorage, RecordKind, Storage, StorageError};
pub use types::{
    DeviceKeys, EnvelopeKind, OutgoingCiphertext, PreKey, RemoteDeviceBundle, SealedSenderMessage,
    SignedKey,
};
