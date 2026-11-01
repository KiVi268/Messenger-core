//! Привязка второго устройства (ADR-0012): ключ идентичности передаётся с
//! основного устройства по QR, у нового устройства свои ключи и сессии.

use std::sync::Arc;

use kivi_crypto::{
    CryptoError, DeviceKeys, IdentityStatus, LocalDevice, MemoryStorage, RemoteDeviceBundle,
    decrypt_provision, encrypt_provision, generate_provisioning_key_pair,
};

const ALICE: &str = "7f1c2e4a-9b3d-4c5e-8f6a-1b2c3d4e5f60";
const BOB: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";

fn bundle(device_id: u32, keys: DeviceKeys) -> RemoteDeviceBundle {
    RemoteDeviceBundle {
        device_id,
        registration_id: keys.registration_id,
        identity_public_key: keys.identity_public_key,
        signed_pre_key: keys.signed_pre_key,
        pre_key: None,
        kyber_pre_key: keys.last_resort_kyber_pre_key,
    }
}

/// Основное устройство Алисы передаёт ключ идентичности новому через
/// зашифрованный конверт и возвращает привязанное устройство.
fn link(primary: &LocalDevice) -> LocalDevice {
    // Новое устройство: временная пара для QR.
    let qr = generate_provisioning_key_pair();

    // Основное: ключевая пара идентичности внутри ProvisionMessage (здесь —
    // просто склеенные байты: protobuf собирает платформа).
    let (public, private) = primary.identity_key_pair();
    let mut message = public.clone();
    message.extend_from_slice(&private);
    let envelope = encrypt_provision(&qr.public_key, &message).unwrap();

    // Новое: расшифровывает и создаёт устройство с ключом аккаунта.
    let received = decrypt_provision(&qr.private_key, &envelope).unwrap();
    let (public, private) = received.split_at(33);
    let mut linked =
        LocalDevice::generate_with_identity(Arc::new(MemoryStorage::default()), public, private)
            .unwrap();
    linked.set_address(ALICE, 2).unwrap();
    linked
}

#[test]
fn linked_device_shares_identity_but_has_own_keys() {
    let primary = LocalDevice::create(Arc::new(MemoryStorage::default()), ALICE, 1).unwrap();
    let linked = link(&primary);

    let primary_keys = primary.device_keys().unwrap();
    let linked_keys = linked.device_keys().unwrap();
    assert_eq!(
        primary_keys.identity_public_key,
        linked_keys.identity_public_key
    );
    assert_eq!(primary.identity_key_pair(), linked.identity_key_pair());
    // Свои подписанные ключи, подписанные общим ключом идентичности.
    assert_ne!(
        primary_keys.signed_pre_key.public_key,
        linked_keys.signed_pre_key.public_key
    );
}

#[test]
fn contact_writes_to_both_devices_without_identity_warning() {
    let primary = LocalDevice::create(Arc::new(MemoryStorage::default()), ALICE, 1).unwrap();
    let linked = link(&primary);
    let bob = LocalDevice::create(Arc::new(MemoryStorage::default()), BOB, 1).unwrap();

    // Боб знает Алису по основному устройству.
    bob.process_bundle(ALICE, &bundle(1, primary.device_keys().unwrap()))
        .unwrap();
    assert_eq!(bob.identity_status(ALICE).unwrap(), IdentityStatus::Trusted);
    let safety_before = bob.safety_number(ALICE).unwrap();

    // Второе устройство Алисы появилось: тот же ключ — ни предупреждения,
    // ни нового номера безопасности.
    bob.process_bundle(ALICE, &bundle(2, linked.device_keys().unwrap()))
        .unwrap();
    assert_eq!(bob.identity_status(ALICE).unwrap(), IdentityStatus::Trusted);
    assert_eq!(bob.safety_number(ALICE).unwrap(), safety_before);

    for (device, device_id) in [(&primary, 1), (&linked, 2)] {
        let message = bob.encrypt(ALICE, device_id, b"hi Alice").unwrap();
        assert_eq!(
            device
                .decrypt(BOB, 1, message.kind, &message.content)
                .unwrap(),
            b"hi Alice"
        );
    }

    // Второе устройство тоже пишет Бобу.
    linked
        .process_bundle(BOB, &bundle(1, bob.device_keys().unwrap()))
        .unwrap();
    let reply = linked.encrypt(BOB, 1, b"from tablet").unwrap();
    assert_eq!(
        bob.decrypt(ALICE, 2, reply.kind, &reply.content).unwrap(),
        b"from tablet"
    );
}

#[test]
fn own_devices_can_sync_with_each_other() {
    let primary = LocalDevice::create(Arc::new(MemoryStorage::default()), ALICE, 1).unwrap();
    let linked = link(&primary);

    // SyncMessage: основное шифрует для второго устройства своего аккаунта.
    primary
        .process_bundle(ALICE, &bundle(2, linked.device_keys().unwrap()))
        .unwrap();
    let sync = primary.encrypt(ALICE, 2, b"sent transcript").unwrap();
    assert_eq!(
        linked.decrypt(ALICE, 1, sync.kind, &sync.content).unwrap(),
        b"sent transcript"
    );
}

#[test]
fn device_name_is_readable_on_every_device_of_the_account() {
    let primary = LocalDevice::create(Arc::new(MemoryStorage::default()), ALICE, 1).unwrap();
    let linked = link(&primary);
    let stranger = LocalDevice::create(Arc::new(MemoryStorage::default()), BOB, 1).unwrap();

    let encrypted = linked.encrypt_device_name("Galaxy Tab S9").unwrap();
    assert_eq!(
        primary.decrypt_device_name(&encrypted).unwrap(),
        "Galaxy Tab S9"
    );
    assert!(matches!(
        stranger.decrypt_device_name(&encrypted),
        Err(CryptoError::Malformed(_))
    ));
    // Одинаковые имена шифруются по-разному (случайный nonce).
    assert_ne!(
        encrypted,
        linked.encrypt_device_name("Galaxy Tab S9").unwrap()
    );

    assert!(primary.encrypt_device_name("").is_err());
    assert!(primary.encrypt_device_name(&"ж".repeat(65)).is_err());
    assert_eq!(
        primary
            .decrypt_device_name(&primary.encrypt_device_name(&"ж".repeat(64)).unwrap())
            .unwrap()
            .chars()
            .count(),
        64
    );
    assert!(primary.decrypt_device_name(&[0u8; 12]).is_err());
}

#[test]
fn identity_must_be_a_pair_and_storage_empty() {
    let primary = LocalDevice::create(Arc::new(MemoryStorage::default()), ALICE, 1).unwrap();
    let other = LocalDevice::create(Arc::new(MemoryStorage::default()), BOB, 1).unwrap();
    let (public, _) = primary.identity_key_pair();
    let (_, foreign_private) = other.identity_key_pair();

    assert!(matches!(
        LocalDevice::generate_with_identity(
            Arc::new(MemoryStorage::default()),
            &public,
            &foreign_private
        ),
        Err(CryptoError::Malformed(_))
    ));
    assert!(matches!(
        LocalDevice::generate_with_identity(
            Arc::new(MemoryStorage::default()),
            &[1, 2, 3],
            &foreign_private
        ),
        Err(CryptoError::Malformed(_))
    ));

    let (public, private) = primary.identity_key_pair();
    let storage = Arc::new(MemoryStorage::default());
    LocalDevice::generate(storage.clone()).unwrap();
    assert!(matches!(
        LocalDevice::generate_with_identity(storage, &public, &private),
        Err(CryptoError::AlreadyExists)
    ));
}

#[test]
fn linked_device_survives_restart() {
    let primary = LocalDevice::create(Arc::new(MemoryStorage::default()), ALICE, 1).unwrap();
    let (public, private) = primary.identity_key_pair();
    let storage = Arc::new(MemoryStorage::default());
    let mut linked =
        LocalDevice::generate_with_identity(storage.clone(), &public, &private).unwrap();
    linked.set_address(ALICE, 2).unwrap();
    let keys = linked.device_keys().unwrap();
    drop(linked);

    let reopened = LocalDevice::open(storage).unwrap().unwrap();
    assert_eq!(reopened.address(), Some((ALICE.to_owned(), 2)));
    assert_eq!(reopened.device_keys().unwrap(), keys);
    assert_eq!(reopened.identity_key_pair(), primary.identity_key_pair());
}
