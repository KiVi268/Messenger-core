//! Проверка решения ADR-0002: сервер без libsignal может выпускать
//! сертификаты sealed sender, которые принимает libsignal.
//!
//! Сервер подписывает сертификаты обычным Ed25519 (как это сделает JDK или
//! BouncyCastle) и сериализует их в формате libsignal (`sealed_sender.proto`).
//! libsignal проверяет подписи по схеме XEdDSA: берёт ключ в форме Curve25519
//! (Montgomery), а знаковый бит Edwards-точки — из старшего бита последнего
//! байта подписи. Поэтому серверу достаточно:
//! 1. публиковать публичный ключ в форме Curve25519 (u-координата);
//! 2. переносить знаковый бит своего Ed25519-ключа в `signature[63]`.
//!
//! Тест воспроизводит ровно то, что будет делать сервер, и проверяет
//! результат настоящей валидацией libsignal.

mod common;

use common::{
    ServerCertificateDataPb, ServerCertificatePb, ServerKey, sender_certificate, server_certificate,
};
use ed25519_dalek::Signer as _;
use libsignal_protocol::{IdentityKeyPair, SenderCertificate, ServerCertificate, Timestamp};
use prost::Message as _;
use rand::RngCore as _;

const NOW: u64 = 1_790_000_000_000;
const DAY: u64 = 24 * 60 * 60 * 1000;

struct Fixture {
    trust_root: ServerKey,
    server: ServerKey,
    sender_identity: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        Self {
            trust_root: ServerKey::random(),
            server: ServerKey::random(),
            sender_identity: IdentityKeyPair::generate(&mut rand::rng())
                .identity_key()
                .serialize()
                .into_vec(),
        }
    }

    fn sender_certificate(&self) -> SenderCertificate {
        let signer = server_certificate(&self.trust_root, &self.server, 1);
        let sender = uuid::Uuid::from_u128(rand::rng().next_u64().into());
        let bytes = sender_certificate(
            &self.server,
            signer,
            (sender, 1),
            &self.sender_identity,
            NOW + DAY,
        );
        SenderCertificate::deserialize(&bytes).unwrap()
    }
}

#[test]
fn libsignal_accepts_certificates_signed_with_plain_ed25519() {
    // Много итераций: знаковый бит случайного ключа равен 0 или 1 примерно
    // поровну, проверяем оба случая.
    for _ in 0..32 {
        let fx = Fixture::new();
        let certificate = fx.sender_certificate();
        assert!(
            certificate
                .validate(
                    &fx.trust_root.libsignal_public_key(),
                    Timestamp::from_epoch_millis(NOW)
                )
                .unwrap()
        );
        assert_eq!(
            certificate.sender_device_id().unwrap(),
            1.try_into().unwrap()
        );
        assert_eq!(
            certificate.key().unwrap().serialize().as_ref(),
            fx.sender_identity.as_slice()
        );
    }
}

#[test]
fn server_certificate_alone_validates_against_trust_root() {
    let fx = Fixture::new();
    let bytes = server_certificate(&fx.trust_root, &fx.server, 7);
    let certificate = ServerCertificate::deserialize(&bytes).unwrap();
    assert!(
        certificate
            .validate(&fx.trust_root.libsignal_public_key())
            .unwrap()
    );
    assert_eq!(certificate.key_id().unwrap(), 7);
}

#[test]
fn certificate_from_another_trust_root_is_rejected() {
    let fx = Fixture::new();
    let other_root = ServerKey::random();
    assert!(
        !fx.sender_certificate()
            .validate(
                &other_root.libsignal_public_key(),
                Timestamp::from_epoch_millis(NOW)
            )
            .unwrap()
    );
}

#[test]
fn expired_certificate_is_rejected() {
    let fx = Fixture::new();
    assert!(
        !fx.sender_certificate()
            .validate(
                &fx.trust_root.libsignal_public_key(),
                Timestamp::from_epoch_millis(NOW + 2 * DAY)
            )
            .unwrap()
    );
}

#[test]
fn signature_without_sign_bit_fails_for_keys_with_negative_x() {
    // Если сервер забудет перенести знаковый бит, libsignal отвергнет
    // подпись для ключей с установленным знаковым битом. Тест фиксирует,
    // что перенос бита действительно нужен.
    let fx = loop {
        let fx = Fixture::new();
        if fx.trust_root.0.verifying_key().to_bytes()[31] & 0x80 != 0 {
            break fx;
        }
    };
    let certificate = ServerCertificateDataPb {
        id: Some(1),
        key: Some(fx.server.libsignal_public_key().serialize().into_vec()),
    }
    .encode_to_vec();
    let plain_signature = fx.trust_root.0.sign(&certificate).to_bytes().to_vec();
    let bytes = ServerCertificatePb {
        certificate: Some(certificate),
        signature: Some(plain_signature),
    }
    .encode_to_vec();
    let parsed = ServerCertificate::deserialize(&bytes).unwrap();
    assert!(
        !parsed
            .validate(&fx.trust_root.libsignal_public_key())
            .unwrap()
    );
}
