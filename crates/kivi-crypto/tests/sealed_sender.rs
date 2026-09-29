//! Sealed sender целиком: сертификат, подписанный «как на сервере»
//! (Ed25519 без libsignal), шифрование и расшифровка через ядро.

mod common;

use std::sync::Arc;

use common::{ServerKey, sender_certificate, server_certificate};
use kivi_crypto::{CryptoError, LocalDevice, MemoryStorage, RemoteDeviceBundle};

const ALICE: &str = "7f1c2e4a-9b3d-4c5e-8f6a-1b2c3d4e5f60";
const BOB: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
const DAY: u64 = 24 * 60 * 60 * 1000;

struct Server {
    trust_root: ServerKey,
    key: ServerKey,
}

impl Server {
    fn new() -> Self {
        Self {
            trust_root: ServerKey::random(),
            key: ServerKey::random(),
        }
    }

    fn trust_root(&self) -> Vec<u8> {
        self.trust_root
            .libsignal_public_key()
            .serialize()
            .into_vec()
    }

    /// То, что вернёт `CertificateService.GetSenderCertificate`.
    fn certificate_for(&self, device: &LocalDevice, expires: u64) -> Vec<u8> {
        let (account, device_id) = device.address().unwrap();
        sender_certificate(
            &self.key,
            server_certificate(&self.trust_root, &self.key, 1),
            (uuid::Uuid::parse_str(&account).unwrap(), device_id),
            &device.device_keys().unwrap().identity_public_key,
            expires,
        )
    }
}

fn device(account: &str) -> LocalDevice {
    LocalDevice::create(Arc::new(MemoryStorage::default()), account, 1).unwrap()
}

/// Алиса устанавливает сессию с Бобом по его ключам (как после GetPreKeyBundle).
fn start_session(alice: &LocalDevice, bob: &LocalDevice) {
    let keys = bob.device_keys().unwrap();
    alice
        .process_bundle(
            BOB,
            &RemoteDeviceBundle {
                device_id: 1,
                registration_id: keys.registration_id,
                identity_public_key: keys.identity_public_key,
                signed_pre_key: keys.signed_pre_key,
                pre_key: bob.generate_pre_keys(1).unwrap().pop(),
                kyber_pre_key: keys.last_resort_kyber_pre_key,
            },
        )
        .unwrap();
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[test]
fn first_and_following_messages_hide_sender_from_server() {
    let server = Server::new();
    let (alice, bob) = (device(ALICE), device(BOB));
    start_session(&alice, &bob);
    let certificate = server.certificate_for(&alice, now() + DAY);

    // Первое сообщение несёт установку сессии (PreKey) внутри sealed sender.
    for text in ["привет", "как дела?"] {
        let sealed = alice
            .sealed_sender_encrypt(BOB, 1, &certificate, text.as_bytes())
            .unwrap();
        let message = bob
            .sealed_sender_decrypt(&sealed, &server.trust_root(), now())
            .unwrap();
        assert_eq!(message.sender_account_id, ALICE);
        assert_eq!(message.sender_device_id, 1);
        assert_eq!(message.plaintext, text.as_bytes());
    }

    // Ответ Боба — тоже sealed sender, по сессии, полученной входящим сообщением.
    let bob_certificate = server.certificate_for(&bob, now() + DAY);
    let reply = bob
        .sealed_sender_encrypt(ALICE, 1, &bob_certificate, b"ok")
        .unwrap();
    let message = alice
        .sealed_sender_decrypt(&reply, &server.trust_root(), now())
        .unwrap();
    assert_eq!(message.sender_account_id, BOB);
    assert_eq!(message.plaintext, b"ok");
}

#[test]
fn certificate_from_another_trust_root_is_rejected() {
    let server = Server::new();
    let (alice, bob) = (device(ALICE), device(BOB));
    start_session(&alice, &bob);
    let sealed = alice
        .sealed_sender_encrypt(BOB, 1, &server.certificate_for(&alice, now() + DAY), b"x")
        .unwrap();

    let other = Server::new();
    assert!(matches!(
        bob.sealed_sender_decrypt(&sealed, &other.trust_root(), now()),
        Err(CryptoError::Protocol(_))
    ));
}

#[test]
fn expired_certificate_is_rejected() {
    let server = Server::new();
    let (alice, bob) = (device(ALICE), device(BOB));
    start_session(&alice, &bob);
    let expires = now() + DAY;
    let sealed = alice
        .sealed_sender_encrypt(BOB, 1, &server.certificate_for(&alice, expires), b"x")
        .unwrap();
    // Сервер принял сообщение уже после истечения сертификата.
    assert!(
        bob.sealed_sender_decrypt(&sealed, &server.trust_root(), expires + 1)
            .is_err()
    );
}

#[test]
fn certificate_of_another_device_is_refused_on_send() {
    let server = Server::new();
    let (alice, bob) = (device(ALICE), device(BOB));
    start_session(&alice, &bob);
    let bobs = server.certificate_for(&bob, now() + DAY);
    assert!(matches!(
        alice.sealed_sender_encrypt(BOB, 1, &bobs, b"x"),
        Err(CryptoError::Malformed(_))
    ));
}

#[test]
fn certificate_with_wrong_identity_key_is_rejected() {
    let server = Server::new();
    let (alice, bob) = (device(ALICE), device(BOB));
    start_session(&alice, &bob);
    // Сертификат на адрес Алисы, но с чужим ключом идентичности.
    let impostor = device(ALICE);
    let forged = sender_certificate(
        &server.key,
        server_certificate(&server.trust_root, &server.key, 1),
        (uuid::Uuid::parse_str(ALICE).unwrap(), 1),
        &impostor.device_keys().unwrap().identity_public_key,
        now() + DAY,
    );
    let sealed = alice.sealed_sender_encrypt(BOB, 1, &forged, b"x").unwrap();
    assert!(
        bob.sealed_sender_decrypt(&sealed, &server.trust_root(), now())
            .is_err()
    );
}
