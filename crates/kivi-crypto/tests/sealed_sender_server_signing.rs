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

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signer as _, SigningKey};
use libsignal_protocol::{
    IdentityKeyPair, PublicKey, SenderCertificate, ServerCertificate, Timestamp,
};
use prost::Message as _;
use rand::RngCore as _;

/// `sealed_sender.proto` из libsignal: ServerCertificate и его содержимое.
#[derive(Clone, PartialEq, prost::Message)]
struct ServerCertificatePb {
    #[prost(bytes = "vec", optional, tag = "1")]
    certificate: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "2")]
    signature: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct ServerCertificateDataPb {
    #[prost(uint32, optional, tag = "1")]
    id: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    key: Option<Vec<u8>>,
}

/// `sealed_sender.proto` из libsignal: SenderCertificate. Сертификат-обёртка
/// имеет ту же структуру, что и ServerCertificatePb.
#[derive(Clone, PartialEq, prost::Message)]
struct SenderCertificateDataPb {
    #[prost(uint32, optional, tag = "2")]
    sender_device: Option<u32>,
    #[prost(fixed64, optional, tag = "3")]
    expires: Option<u64>,
    #[prost(bytes = "vec", optional, tag = "4")]
    identity_key: Option<Vec<u8>>,
    /// Вариант `signer.certificate` из oneof: встроенный ServerCertificate.
    #[prost(bytes = "vec", optional, tag = "5")]
    signer_certificate: Option<Vec<u8>>,
    /// Вариант `senderUuid.uuidBytes` из oneof: UUID, 16 байт.
    #[prost(bytes = "vec", optional, tag = "7")]
    uuid_bytes: Option<Vec<u8>>,
}

/// Ключ, которым «сервер» подписывает сертификаты.
struct ServerKey(SigningKey);

impl ServerKey {
    fn random() -> Self {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        Self(SigningKey::from_bytes(&seed))
    }

    /// Публичный ключ в формате libsignal: 0x05 + u-координата Curve25519.
    fn libsignal_public_key(&self) -> PublicKey {
        let edwards = CompressedEdwardsY(self.0.verifying_key().to_bytes())
            .decompress()
            .expect("valid Ed25519 public key");
        PublicKey::from_djb_public_key_bytes(&edwards.to_montgomery().to_bytes()).unwrap()
    }

    /// Обычная подпись Ed25519 + знаковый бит ключа в старшем бите последнего байта.
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut signature = self.0.sign(message).to_bytes();
        signature[63] |= self.0.verifying_key().to_bytes()[31] & 0x80;
        signature.to_vec()
    }
}

fn server_certificate(trust_root: &ServerKey, server: &ServerKey, key_id: u32) -> Vec<u8> {
    let certificate = ServerCertificateDataPb {
        id: Some(key_id),
        key: Some(server.libsignal_public_key().serialize().into_vec()),
    }
    .encode_to_vec();
    ServerCertificatePb {
        signature: Some(trust_root.sign(&certificate)),
        certificate: Some(certificate),
    }
    .encode_to_vec()
}

fn sender_certificate(
    server: &ServerKey,
    signer: Vec<u8>,
    identity_key: &[u8],
    expires: u64,
) -> Vec<u8> {
    let certificate = SenderCertificateDataPb {
        sender_device: Some(1),
        expires: Some(expires),
        identity_key: Some(identity_key.to_vec()),
        signer_certificate: Some(signer),
        uuid_bytes: Some(
            uuid::Uuid::from_u128(rand::rng().next_u64().into())
                .into_bytes()
                .to_vec(),
        ),
    }
    .encode_to_vec();
    ServerCertificatePb {
        signature: Some(server.sign(&certificate)),
        certificate: Some(certificate),
    }
    .encode_to_vec()
}

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
        let bytes = sender_certificate(&self.server, signer, &self.sender_identity, NOW + DAY);
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
