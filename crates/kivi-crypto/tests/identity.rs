//! Смена ключа собеседника и номера безопасности (safety numbers).
//! Ключ идентичности общий на аккаунт (ADR-0003 в Messenger-KiVi).

use std::sync::Arc;

use kivi_crypto::{
    CryptoError, EnvelopeKind, IdentityStatus, LocalDevice, MemoryStorage, RecordKind,
    RemoteDeviceBundle, Storage as _,
};

const ALICE: &str = "7f1c2e4a-9b3d-4c5e-8f6a-1b2c3d4e5f60";
const BOB: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";

fn new_device(account_id: &str) -> LocalDevice {
    LocalDevice::create(Arc::new(MemoryStorage::default()), account_id, 1).unwrap()
}

fn bundle_of(device: &LocalDevice) -> RemoteDeviceBundle {
    let keys = device.device_keys().unwrap();
    RemoteDeviceBundle {
        device_id: 1,
        registration_id: keys.registration_id,
        identity_public_key: keys.identity_public_key,
        signed_pre_key: keys.signed_pre_key,
        pre_key: Some(device.generate_pre_keys(1).unwrap().remove(0)),
        kyber_pre_key: device.generate_kyber_pre_keys(1).unwrap().remove(0),
    }
}

/// Алиса пишет Бобу первой, Боб получает сообщение: сессия в обе стороны.
fn talk(alice: &LocalDevice, bob: &LocalDevice) {
    alice.process_bundle(BOB, &bundle_of(bob)).unwrap();
    let message = alice.encrypt(BOB, 1, b"hi").unwrap();
    bob.decrypt(ALICE, 1, message.kind, &message.content)
        .unwrap();
}

#[test]
fn both_sides_see_the_same_safety_number() {
    let alice = new_device(ALICE);
    let bob = new_device(BOB);
    assert_eq!(alice.identity_status(BOB).unwrap(), IdentityStatus::Unknown);
    assert_eq!(alice.safety_number(BOB).unwrap(), None);

    talk(&alice, &bob);
    let at_alice = alice.safety_number(BOB).unwrap().unwrap();
    let at_bob = bob.safety_number(ALICE).unwrap().unwrap();
    assert_eq!(at_alice.digits, at_bob.digits);
    assert_eq!(at_alice.digits.len(), 60);
    assert!(at_alice.digits.chars().all(|c| c.is_ascii_digit()));

    // QR-код Боба сходится у Алисы, и наоборот.
    assert!(alice.compare_safety_number(BOB, &at_bob.scannable).unwrap());
    assert!(
        bob.compare_safety_number(ALICE, &at_alice.scannable)
            .unwrap()
    );
    // Собственный QR-код Алисы — не номер Боба (стороны переставлены).
    assert!(
        !alice
            .compare_safety_number(BOB, &at_alice.scannable)
            .unwrap()
    );
}

#[test]
fn changed_key_blocks_sending_until_trusted() {
    let alice = new_device(ALICE);
    let bob = new_device(BOB);
    talk(&alice, &bob);
    let old_number = alice.safety_number(BOB).unwrap().unwrap().digits;

    // Боб переустановил приложение: новый ключ под тем же аккаунтом.
    let new_bob = new_device(BOB);
    let new_bundle = bundle_of(&new_bob);
    assert!(matches!(
        alice.process_bundle(BOB, &new_bundle),
        Err(CryptoError::UntrustedIdentity(_))
    ));
    assert_eq!(alice.identity_status(BOB).unwrap(), IdentityStatus::Changed);
    // Номер уже для нового ключа — его и сверяет пользователь.
    let new_number = alice.safety_number(BOB).unwrap().unwrap();
    assert_ne!(new_number.digits, old_number);
    // Сессия со старым ключом больше не используется.
    assert!(!alice.has_session(BOB, 1).unwrap());

    alice.trust_identity(BOB).unwrap();
    assert_eq!(alice.identity_status(BOB).unwrap(), IdentityStatus::Trusted);
    alice.process_bundle(BOB, &new_bundle).unwrap();
    let message = alice.encrypt(BOB, 1, b"again").unwrap();
    assert_eq!(
        new_bob
            .decrypt(ALICE, 1, message.kind, &message.content)
            .unwrap(),
        b"again"
    );
    // У нового Боба тот же номер, что Алиса увидела до подтверждения.
    assert_eq!(
        new_bob.safety_number(ALICE).unwrap().unwrap().digits,
        new_number.digits
    );
}

#[test]
fn message_from_changed_key_is_received_and_reply_waits_for_trust() {
    let alice = new_device(ALICE);
    let bob = new_device(BOB);
    talk(&alice, &bob);

    // Переустановивший приложение Боб пишет первым.
    let new_bob = new_device(BOB);
    new_bob.process_bundle(ALICE, &bundle_of(&alice)).unwrap();
    let message = new_bob.encrypt(ALICE, 1, b"new phone").unwrap();
    assert_eq!(message.kind, EnvelopeKind::PreKeyMessage);

    // Сообщение не теряется.
    assert_eq!(
        alice
            .decrypt(BOB, 1, message.kind, &message.content)
            .unwrap(),
        b"new phone"
    );
    assert_eq!(alice.identity_status(BOB).unwrap(), IdentityStatus::Changed);
    assert!(matches!(
        alice.encrypt(BOB, 1, b"reply"),
        Err(CryptoError::UntrustedIdentity(_))
    ));

    alice.trust_identity(BOB).unwrap();
    let reply = alice.encrypt(BOB, 1, b"reply").unwrap();
    assert_eq!(
        new_bob
            .decrypt(ALICE, 1, reply.kind, &reply.content)
            .unwrap(),
        b"reply"
    );
}

#[test]
fn verification_does_not_carry_over_to_a_new_key() {
    let alice = new_device(ALICE);
    let bob = new_device(BOB);
    talk(&alice, &bob);

    alice.set_verified(BOB, true).unwrap();
    assert_eq!(
        alice.identity_status(BOB).unwrap(),
        IdentityStatus::Verified
    );
    alice.set_verified(BOB, false).unwrap();
    assert_eq!(alice.identity_status(BOB).unwrap(), IdentityStatus::Trusted);
    alice.set_verified(BOB, true).unwrap();

    let new_bob = new_device(BOB);
    assert!(alice.process_bundle(BOB, &bundle_of(&new_bob)).is_err());
    assert_eq!(alice.identity_status(BOB).unwrap(), IdentityStatus::Changed);
    alice.trust_identity(BOB).unwrap();
    assert_eq!(alice.identity_status(BOB).unwrap(), IdentityStatus::Trusted);
}

#[test]
fn forged_bundle_does_not_replace_the_key() {
    let alice = new_device(ALICE);
    let bob = new_device(BOB);
    talk(&alice, &bob);
    let number = alice.safety_number(BOB).unwrap().unwrap().digits;

    // Чужой ключ идентичности с ключами Боба: подпись не сходится.
    let mut forged = bundle_of(&bob);
    forged.identity_public_key = new_device(BOB).device_keys().unwrap().identity_public_key;
    assert!(matches!(
        alice.process_bundle(BOB, &forged),
        Err(CryptoError::Protocol(_))
    ));
    assert_eq!(alice.identity_status(BOB).unwrap(), IdentityStatus::Trusted);
    assert_eq!(alice.safety_number(BOB).unwrap().unwrap().digits, number);
}

#[test]
fn key_stored_before_trust_records_stays_trusted() {
    // Хранилище версии, где был только RemoteIdentity: смена ключа всё равно ловится.
    let storage = Arc::new(MemoryStorage::default());
    let alice = LocalDevice::create(storage.clone(), ALICE, 1).unwrap();
    let bob = new_device(BOB);
    talk(&alice, &bob);
    storage.remove(RecordKind::TrustedIdentity, BOB).unwrap();
    assert_eq!(alice.identity_status(BOB).unwrap(), IdentityStatus::Trusted);

    assert!(matches!(
        alice.process_bundle(BOB, &bundle_of(&new_device(BOB))),
        Err(CryptoError::UntrustedIdentity(_))
    ));
    assert_eq!(alice.identity_status(BOB).unwrap(), IdentityStatus::Changed);
}
