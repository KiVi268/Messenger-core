//! Хранение состояния в хранилище платформы (ADR-0004 в Messenger-KiVi).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use kivi_crypto::{
    CryptoError, LocalDevice, MemoryStorage, RecordKind, RemoteDeviceBundle, Storage, StorageError,
};

const ALICE: &str = "7f1c2e4a-9b3d-4c5e-8f6a-1b2c3d4e5f60";
const BOB: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";

fn bundle_of(device: &LocalDevice, with_one_time_keys: bool) -> RemoteDeviceBundle {
    let keys = device.device_keys().unwrap();
    RemoteDeviceBundle {
        device_id: 1,
        registration_id: keys.registration_id,
        identity_public_key: keys.identity_public_key,
        signed_pre_key: keys.signed_pre_key,
        pre_key: with_one_time_keys.then(|| device.generate_pre_keys(1).unwrap().remove(0)),
        kyber_pre_key: if with_one_time_keys {
            device.generate_kyber_pre_keys(1).unwrap().remove(0)
        } else {
            keys.last_resort_kyber_pre_key
        },
    }
}

#[test]
fn state_survives_restart() {
    let alice_storage = Arc::new(MemoryStorage::default());
    let bob_storage = Arc::new(MemoryStorage::default());
    let alice = LocalDevice::create(alice_storage.clone(), ALICE, 1).unwrap();
    let bob = LocalDevice::create(bob_storage.clone(), BOB, 1).unwrap();
    let bob_keys = bob.device_keys().unwrap();

    alice.process_bundle(BOB, &bundle_of(&bob, true)).unwrap();
    let first = alice.encrypt(BOB, 1, b"before restart").unwrap();
    bob.decrypt(ALICE, 1, first.kind, &first.content).unwrap();

    // «Перезапуск приложения»: объекты уничтожены, хранилища остались.
    drop(alice);
    drop(bob);
    let alice = LocalDevice::open(alice_storage).unwrap().unwrap();
    let bob = LocalDevice::open(bob_storage).unwrap().unwrap();

    assert_eq!(bob.device_keys().unwrap(), bob_keys);
    assert!(alice.has_session(BOB, 1).unwrap());
    let reply = bob.encrypt(ALICE, 1, b"after restart").unwrap();
    assert_eq!(
        alice.decrypt(BOB, 1, reply.kind, &reply.content).unwrap(),
        b"after restart"
    );
}

#[test]
fn open_empty_storage_returns_none() {
    assert!(
        LocalDevice::open(Arc::new(MemoryStorage::default()))
            .unwrap()
            .is_none()
    );
}

#[test]
fn create_twice_in_same_storage_fails() {
    let storage = Arc::new(MemoryStorage::default());
    LocalDevice::create(storage.clone(), ALICE, 1).unwrap();
    assert!(matches!(
        LocalDevice::create(storage, ALICE, 1),
        Err(CryptoError::AlreadyExists)
    ));
}

#[test]
fn key_ids_continue_after_restart() {
    let storage = Arc::new(MemoryStorage::default());
    let device = LocalDevice::create(storage.clone(), BOB, 1).unwrap();
    device.generate_pre_keys(3).unwrap();
    drop(device);

    let device = LocalDevice::open(storage).unwrap().unwrap();
    let ids: Vec<u32> = device
        .generate_pre_keys(2)
        .unwrap()
        .iter()
        .map(|k| k.key_id)
        .collect();
    assert_eq!(ids, vec![4, 5]);
}

#[test]
fn used_one_time_keys_are_deleted() {
    let bob_storage = Arc::new(MemoryStorage::default());
    let alice = LocalDevice::create(Arc::new(MemoryStorage::default()), ALICE, 1).unwrap();
    let bob = LocalDevice::create(bob_storage.clone(), BOB, 1).unwrap();

    alice.process_bundle(BOB, &bundle_of(&bob, true)).unwrap();
    assert_eq!(bob_storage.count(RecordKind::PreKey), 1);
    // Kyber-ключ «последней надежды» + одноразовый.
    assert_eq!(bob_storage.count(RecordKind::KyberPreKey), 2);

    let message = alice.encrypt(BOB, 1, b"hi").unwrap();
    bob.decrypt(ALICE, 1, message.kind, &message.content)
        .unwrap();

    assert_eq!(bob_storage.count(RecordKind::PreKey), 0);
    assert_eq!(bob_storage.count(RecordKind::KyberPreKey), 1);
    assert_eq!(bob_storage.count(RecordKind::Session), 1);
    assert_eq!(bob_storage.count(RecordKind::RemoteIdentity), 1);
}

#[test]
fn last_resort_kyber_key_is_kept_and_reuse_is_rejected() {
    let bob_storage = Arc::new(MemoryStorage::default());
    let alice = LocalDevice::create(Arc::new(MemoryStorage::default()), ALICE, 1).unwrap();
    let bob = LocalDevice::create(bob_storage.clone(), BOB, 1).unwrap();

    alice.process_bundle(BOB, &bundle_of(&bob, false)).unwrap();
    let message = alice.encrypt(BOB, 1, b"hi").unwrap();

    bob.decrypt(ALICE, 1, message.kind, &message.content)
        .unwrap();
    assert_eq!(bob_storage.count(RecordKind::KyberPreKey), 1);
    assert_eq!(bob_storage.count(RecordKind::KyberBaseKeySeen), 1);

    // Сессия потеряна (например, сброшена), а атакующий повторяет то же
    // первое сообщение: ключ «последней надежды» не должен принять его снова.
    bob_storage
        .remove(RecordKind::Session, &format!("{ALICE}.1"))
        .unwrap();
    assert!(
        bob.decrypt(ALICE, 1, message.kind, &message.content)
            .is_err()
    );
}

#[test]
fn changed_identity_is_not_trusted() {
    let alice = LocalDevice::create(Arc::new(MemoryStorage::default()), ALICE, 1).unwrap();
    let bob = LocalDevice::create(Arc::new(MemoryStorage::default()), BOB, 1).unwrap();
    alice.process_bundle(BOB, &bundle_of(&bob, true)).unwrap();

    // Боб переустановил приложение: новый ключ идентичности под тем же аккаунтом.
    let new_bob = LocalDevice::create(Arc::new(MemoryStorage::default()), BOB, 1).unwrap();
    assert!(matches!(
        alice.process_bundle(BOB, &bundle_of(&new_bob, true)),
        Err(CryptoError::UntrustedIdentity(_))
    ));
}

/// Хранилище, которое можно «сломать» посреди работы.
#[derive(Default)]
struct FlakyStorage {
    inner: MemoryStorage,
    broken: AtomicBool,
}

impl Storage for FlakyStorage {
    fn load(&self, kind: RecordKind, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        self.check()?;
        self.inner.load(kind, key)
    }

    fn store(&self, kind: RecordKind, key: &str, value: &[u8]) -> Result<(), StorageError> {
        self.check()?;
        self.inner.store(kind, key, value)
    }

    fn remove(&self, kind: RecordKind, key: &str) -> Result<(), StorageError> {
        self.check()?;
        self.inner.remove(kind, key)
    }
}

impl FlakyStorage {
    fn check(&self) -> Result<(), StorageError> {
        if self.broken.load(Ordering::SeqCst) {
            Err(StorageError("disk full".to_owned()))
        } else {
            Ok(())
        }
    }
}

#[test]
fn storage_errors_reach_the_caller() {
    let alice_storage = Arc::new(FlakyStorage::default());
    let alice = LocalDevice::create(alice_storage.clone(), ALICE, 1).unwrap();
    let bob = LocalDevice::create(Arc::new(MemoryStorage::default()), BOB, 1).unwrap();
    let bundle = bundle_of(&bob, true);

    alice_storage.broken.store(true, Ordering::SeqCst);
    let err = alice.process_bundle(BOB, &bundle).unwrap_err();
    assert!(
        matches!(&err, CryptoError::Storage(msg) if msg == "disk full"),
        "{err:?}"
    );
    assert!(matches!(
        alice.generate_pre_keys(1),
        Err(CryptoError::Storage(_))
    ));
}
