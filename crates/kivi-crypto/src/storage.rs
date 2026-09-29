//! Хранилище состояния ядра (ADR-0004 в Messenger-KiVi).
//!
//! Ядро не владеет базой данных: платформа реализует [`Storage`] поверх своей
//! зашифрованной БД (Room + SQLCipher на Android, GRDB + SQLCipher на iOS),
//! а ядро строит на нём хранилища libsignal.
//!
//! Все вызовы синхронные и выполняются в потоке, который вызвал метод ядра.
//! Благодаря этому платформа может выполнить, например, `decrypt` и запись
//! расшифрованного сообщения в одной транзакции своей БД — и только после
//! фиксации транзакции отправить серверу ACK (PRD §7.6.1).

use std::collections::HashMap;
use std::sync::Mutex;

/// Вид записи. Платформа может хранить все виды в одной таблице
/// `(kind, key) → value` или разнести по таблицам.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecordKind {
    /// Данные своего аккаунта и устройства: ключ идентичности, registration
    /// ID, адрес, счётчики ID ключей. Ключ идентичности приватный — платформа
    /// дополнительно шифрует эту запись аппаратным ключом (PRD §7.3).
    LocalAccount,
    /// Сессия с устройством собеседника. Ключ: `<account_id>.<device_id>`.
    Session,
    /// Ключ идентичности собеседника (общий на аккаунт, ADR-0003).
    /// Ключ: `<account_id>`.
    RemoteIdentity,
    /// Одноразовый EC-ключ. Ключ: ID ключа.
    PreKey,
    /// Подписанный EC-ключ. Ключ: ID ключа.
    SignedPreKey,
    /// Kyber-ключ (одноразовый или «последней надежды»). Ключ: ID ключа.
    KyberPreKey,
    /// Отметки об использовании Kyber-ключа «последней надежды» — защита от
    /// повторного использования. Значение пустое.
    KyberBaseKeySeen,
}

/// Ошибка хранилища платформы.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("storage error: {0}")]
pub struct StorageError(pub String);

/// Хранилище «ключ → значение», реализуемое платформой.
pub trait Storage: Send + Sync {
    fn load(&self, kind: RecordKind, key: &str) -> Result<Option<Vec<u8>>, StorageError>;
    fn store(&self, kind: RecordKind, key: &str, value: &[u8]) -> Result<(), StorageError>;
    fn remove(&self, kind: RecordKind, key: &str) -> Result<(), StorageError>;
}

/// Хранилище в памяти — для тестов и прототипов. Состояние теряется при
/// завершении процесса.
#[derive(Default)]
pub struct MemoryStorage {
    records: Mutex<HashMap<(RecordKind, String), Vec<u8>>>,
}

impl MemoryStorage {
    /// Количество записей данного вида.
    pub fn count(&self, kind: RecordKind) -> usize {
        self.records().keys().filter(|(k, _)| *k == kind).count()
    }

    fn records(&self) -> std::sync::MutexGuard<'_, HashMap<(RecordKind, String), Vec<u8>>> {
        self.records
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Storage for MemoryStorage {
    fn load(&self, kind: RecordKind, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.records().get(&(kind, key.to_owned())).cloned())
    }

    fn store(&self, kind: RecordKind, key: &str, value: &[u8]) -> Result<(), StorageError> {
        self.records()
            .insert((kind, key.to_owned()), value.to_vec());
        Ok(())
    }

    fn remove(&self, kind: RecordKind, key: &str) -> Result<(), StorageError> {
        self.records().remove(&(kind, key.to_owned()));
        Ok(())
    }
}
