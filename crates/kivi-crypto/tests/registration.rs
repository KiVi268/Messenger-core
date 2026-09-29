//! Двухшаговая регистрация: ключи нужны серверу до того, как он выдаст адрес.

use std::sync::Arc;

use kivi_crypto::{CryptoError, LocalDevice, MemoryStorage, RemoteDeviceBundle};

const ALICE: &str = "7f1c2e4a-9b3d-4c5e-8f6a-1b2c3d4e5f60";
const BOB: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";

#[test]
fn keys_are_available_before_address_and_messaging_after() {
    let storage = Arc::new(MemoryStorage::default());
    let mut alice = LocalDevice::generate(storage).unwrap();
    assert_eq!(alice.address(), None);

    // Ключи для RegisterRequest доступны сразу.
    let keys = alice.device_keys().unwrap();
    assert_eq!(keys.identity_public_key.len(), 33);

    // До ответа сервера шифровать нельзя.
    assert!(matches!(
        alice.encrypt(BOB, 1, b"too early"),
        Err(CryptoError::NotRegistered)
    ));

    // Сервер выдал адрес — устройство работает как обычно.
    alice.set_address(ALICE, 1).unwrap();
    assert_eq!(alice.address(), Some((ALICE.to_owned(), 1)));

    let bob = LocalDevice::create(Arc::new(MemoryStorage::default()), BOB, 1).unwrap();
    let bob_keys = bob.device_keys().unwrap();
    alice
        .process_bundle(
            BOB,
            &RemoteDeviceBundle {
                device_id: 1,
                registration_id: bob_keys.registration_id,
                identity_public_key: bob_keys.identity_public_key,
                signed_pre_key: bob_keys.signed_pre_key,
                pre_key: None,
                kyber_pre_key: bob_keys.last_resort_kyber_pre_key,
            },
        )
        .unwrap();
    let message = alice.encrypt(BOB, 1, b"hello").unwrap();
    assert_eq!(
        bob.decrypt(ALICE, 1, message.kind, &message.content)
            .unwrap(),
        b"hello"
    );

    // Registration ID собеседника доступен обеим сторонам сессии.
    assert_eq!(
        alice.remote_registration_id(BOB, 1).unwrap(),
        Some(bob_keys.registration_id)
    );
    assert_eq!(
        bob.remote_registration_id(ALICE, 1).unwrap(),
        Some(keys.registration_id)
    );
    assert_eq!(alice.remote_registration_id(BOB, 2).unwrap(), None);
}

#[test]
fn device_without_address_survives_restart() {
    let storage = Arc::new(MemoryStorage::default());
    let keys = LocalDevice::generate(storage.clone())
        .unwrap()
        .device_keys()
        .unwrap();

    // Приложение закрыли до ответа сервера: ключи на месте, адреса нет.
    let mut device = LocalDevice::open(storage.clone()).unwrap().unwrap();
    assert_eq!(device.address(), None);
    assert_eq!(device.device_keys().unwrap(), keys);

    device.set_address(ALICE, 1).unwrap();
    drop(device);
    let device = LocalDevice::open(storage).unwrap().unwrap();
    assert_eq!(device.address(), Some((ALICE.to_owned(), 1)));
}

#[test]
fn address_is_normalized_and_validated() {
    let mut device = LocalDevice::generate(Arc::new(MemoryStorage::default())).unwrap();
    assert!(matches!(
        device.set_address("not-a-uuid", 1),
        Err(CryptoError::InvalidAccountId(_))
    ));
    assert!(matches!(
        device.set_address(ALICE, 0),
        Err(CryptoError::InvalidDeviceId(0))
    ));
    device.set_address(&ALICE.to_uppercase(), 1).unwrap();
    assert_eq!(device.address(), Some((ALICE.to_owned(), 1)));
}

#[test]
fn generate_refuses_existing_device() {
    let storage = Arc::new(MemoryStorage::default());
    LocalDevice::generate(storage.clone()).unwrap();
    assert!(matches!(
        LocalDevice::generate(storage),
        Err(CryptoError::AlreadyExists)
    ));
}
