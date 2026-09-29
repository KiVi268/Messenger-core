//! Сквозной сценарий из PRD Phase 1: два устройства устанавливают сессию по
//! ключам с сервера и обмениваются сообщениями в обе стороны.

use std::sync::Arc;

use kivi_crypto::{CryptoError, EnvelopeKind, LocalDevice, MemoryStorage, RemoteDeviceBundle};

const ALICE: &str = "7f1c2e4a-9b3d-4c5e-8f6a-1b2c3d4e5f60";
const BOB: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";

/// Новое устройство с собственным хранилищем в памяти.
fn new_device(account_id: &str) -> LocalDevice {
    LocalDevice::create(Arc::new(MemoryStorage::default()), account_id, 1).unwrap()
}

/// Собирает ключи Боба так, как их выдал бы сервер (`GetPreKeyBundle`).
fn bundle_of(device: &LocalDevice, device_id: u32, with_one_time_keys: bool) -> RemoteDeviceBundle {
    let keys = device.device_keys().unwrap();
    let (pre_key, kyber_pre_key) = if with_one_time_keys {
        let pre_key = device.generate_pre_keys(1).unwrap().remove(0);
        let kyber = device.generate_kyber_pre_keys(1).unwrap().remove(0);
        (Some(pre_key), kyber)
    } else {
        // Одноразовые ключи закончились: сервер отдаёт Kyber-ключ «последней надежды».
        (None, keys.last_resort_kyber_pre_key.clone())
    };
    RemoteDeviceBundle {
        device_id,
        registration_id: keys.registration_id,
        identity_public_key: keys.identity_public_key,
        signed_pre_key: keys.signed_pre_key,
        pre_key,
        kyber_pre_key,
    }
}

#[test]
fn first_message_establishes_session_and_both_sides_can_talk() {
    let alice = new_device(ALICE);
    let bob = new_device(BOB);

    let bundle = bundle_of(&bob, 1, true);
    alice.process_bundle(BOB, &bundle).unwrap();
    assert!(alice.has_session(BOB, 1).unwrap());

    let first = alice.encrypt(BOB, 1, b"hello").unwrap();
    assert_eq!(first.kind, EnvelopeKind::PreKeyMessage);
    assert_eq!(
        bob.decrypt(ALICE, 1, first.kind, &first.content).unwrap(),
        b"hello"
    );
    assert!(bob.has_session(ALICE, 1).unwrap());

    let reply = bob.encrypt(ALICE, 1, b"hi").unwrap();
    assert_eq!(reply.kind, EnvelopeKind::Ciphertext);
    assert_eq!(
        alice.decrypt(BOB, 1, reply.kind, &reply.content).unwrap(),
        b"hi"
    );

    // После ответа Алиса пишет уже обычными сообщениями.
    let next = alice.encrypt(BOB, 1, b"how are you?").unwrap();
    assert_eq!(next.kind, EnvelopeKind::Ciphertext);
    assert_eq!(
        bob.decrypt(ALICE, 1, next.kind, &next.content).unwrap(),
        b"how are you?"
    );
}

#[test]
fn session_works_without_one_time_pre_keys() {
    let alice = new_device(ALICE);
    let bob = new_device(BOB);

    alice
        .process_bundle(BOB, &bundle_of(&bob, 1, false))
        .unwrap();
    let message = alice.encrypt(BOB, 1, b"no one-time keys").unwrap();
    assert_eq!(
        bob.decrypt(ALICE, 1, message.kind, &message.content)
            .unwrap(),
        b"no one-time keys"
    );
}

#[test]
fn out_of_order_messages_are_decrypted() {
    let alice = new_device(ALICE);
    let bob = new_device(BOB);
    alice
        .process_bundle(BOB, &bundle_of(&bob, 1, true))
        .unwrap();

    let first = alice.encrypt(BOB, 1, b"1").unwrap();
    bob.decrypt(ALICE, 1, first.kind, &first.content).unwrap();
    let reply = bob.encrypt(ALICE, 1, b"ok").unwrap();
    alice.decrypt(BOB, 1, reply.kind, &reply.content).unwrap();

    let second = alice.encrypt(BOB, 1, b"2").unwrap();
    let third = alice.encrypt(BOB, 1, b"3").unwrap();
    assert_eq!(
        bob.decrypt(ALICE, 1, third.kind, &third.content).unwrap(),
        b"3"
    );
    assert_eq!(
        bob.decrypt(ALICE, 1, second.kind, &second.content).unwrap(),
        b"2"
    );
}

#[test]
fn replayed_message_is_rejected() {
    let alice = new_device(ALICE);
    let bob = new_device(BOB);
    alice
        .process_bundle(BOB, &bundle_of(&bob, 1, true))
        .unwrap();

    let first = alice.encrypt(BOB, 1, b"once").unwrap();
    bob.decrypt(ALICE, 1, first.kind, &first.content).unwrap();
    let reply = bob.encrypt(ALICE, 1, b"ok").unwrap();
    alice.decrypt(BOB, 1, reply.kind, &reply.content).unwrap();

    let message = alice.encrypt(BOB, 1, b"once more").unwrap();
    bob.decrypt(ALICE, 1, message.kind, &message.content)
        .unwrap();
    // Повторная доставка того же конверта (ACK потерялся) не должна
    // расшифровываться второй раз — клиент отбрасывает дубликат по server_guid.
    assert!(
        bob.decrypt(ALICE, 1, message.kind, &message.content)
            .is_err()
    );
}

#[test]
fn tampered_ciphertext_is_rejected() {
    let alice = new_device(ALICE);
    let bob = new_device(BOB);
    alice
        .process_bundle(BOB, &bundle_of(&bob, 1, true))
        .unwrap();

    let mut message = alice.encrypt(BOB, 1, b"secret").unwrap();
    let last = message.content.len() - 1;
    message.content[last] ^= 0x01;
    assert!(
        bob.decrypt(ALICE, 1, message.kind, &message.content)
            .is_err()
    );
}

#[test]
fn bundle_with_forged_signature_is_rejected() {
    let alice = new_device(ALICE);
    let bob = new_device(BOB);

    let mut bundle = bundle_of(&bob, 1, true);
    bundle.signed_pre_key.signature[0] ^= 0x01;
    assert!(alice.process_bundle(BOB, &bundle).is_err());
    assert!(!alice.has_session(BOB, 1).unwrap());
}

#[test]
fn encrypt_without_session_fails() {
    let alice = new_device(ALICE);
    assert!(matches!(
        alice.encrypt(BOB, 1, b"x"),
        Err(CryptoError::NoSession(_))
    ));
}

#[test]
fn invalid_addresses_are_rejected() {
    let storage = || Arc::new(MemoryStorage::default());
    assert!(matches!(
        LocalDevice::create(storage(), "not-a-uuid", 1),
        Err(CryptoError::InvalidAccountId(_))
    ));
    // libsignal поддерживает номера устройств 1..=127.
    assert!(matches!(
        LocalDevice::create(storage(), ALICE, 0),
        Err(CryptoError::InvalidDeviceId(0))
    ));
    assert!(matches!(
        LocalDevice::create(storage(), ALICE, 128),
        Err(CryptoError::InvalidDeviceId(128))
    ));
}

#[test]
fn generated_key_ids_are_unique() {
    let bob = new_device(BOB);
    let first = bob.generate_pre_keys(3).unwrap();
    let second = bob.generate_pre_keys(3).unwrap();
    let mut ids: Vec<u32> = first.iter().chain(&second).map(|k| k.key_id).collect();
    ids.dedup();
    assert_eq!(ids, vec![1, 2, 3, 4, 5, 6]);

    // Kyber-ключ «последней надежды» имеет ID 1, одноразовые начинаются с 2.
    let kyber = bob.generate_kyber_pre_keys(2).unwrap();
    assert_eq!(
        bob.device_keys().unwrap().last_resort_kyber_pre_key.key_id,
        1
    );
    assert_eq!(
        kyber.iter().map(|k| k.key_id).collect::<Vec<_>>(),
        vec![2, 3]
    );
}
