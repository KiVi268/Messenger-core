//! Подпись сертификатов sealed sender «как на сервере»: обычный Ed25519
//! без libsignal (ADR-0002). Общее для интеграционных тестов.

#![allow(dead_code)]

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signer as _, SigningKey};
use libsignal_protocol::PublicKey;
use prost::Message as _;
use rand::RngCore as _;

/// `sealed_sender.proto` из libsignal: ServerCertificate и его содержимое.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ServerCertificatePb {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub certificate: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub signature: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ServerCertificateDataPb {
    #[prost(uint32, optional, tag = "1")]
    pub id: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub key: Option<Vec<u8>>,
}

/// `sealed_sender.proto` из libsignal: SenderCertificate. Сертификат-обёртка
/// имеет ту же структуру, что и ServerCertificatePb.
#[derive(Clone, PartialEq, prost::Message)]
pub struct SenderCertificateDataPb {
    #[prost(uint32, optional, tag = "2")]
    pub sender_device: Option<u32>,
    #[prost(fixed64, optional, tag = "3")]
    pub expires: Option<u64>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub identity_key: Option<Vec<u8>>,
    /// Вариант `signer.certificate` из oneof: встроенный ServerCertificate.
    #[prost(bytes = "vec", optional, tag = "5")]
    pub signer_certificate: Option<Vec<u8>>,
    /// Вариант `senderUuid.uuidBytes` из oneof: UUID, 16 байт.
    #[prost(bytes = "vec", optional, tag = "7")]
    pub uuid_bytes: Option<Vec<u8>>,
}

/// Ключ, которым «сервер» подписывает сертификаты.
pub struct ServerKey(pub SigningKey);

impl ServerKey {
    pub fn random() -> Self {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        Self(SigningKey::from_bytes(&seed))
    }

    /// Публичный ключ в формате libsignal: 0x05 + u-координата Curve25519.
    pub fn libsignal_public_key(&self) -> PublicKey {
        let edwards = CompressedEdwardsY(self.0.verifying_key().to_bytes())
            .decompress()
            .expect("valid Ed25519 public key");
        PublicKey::from_djb_public_key_bytes(&edwards.to_montgomery().to_bytes()).unwrap()
    }

    /// Обычная подпись Ed25519 + знаковый бит ключа в старшем бите последнего байта.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut signature = self.0.sign(message).to_bytes();
        signature[63] |= self.0.verifying_key().to_bytes()[31] & 0x80;
        signature.to_vec()
    }
}

pub fn server_certificate(trust_root: &ServerKey, server: &ServerKey, key_id: u32) -> Vec<u8> {
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

pub fn sender_certificate(
    server: &ServerKey,
    signer: Vec<u8>,
    sender: (uuid::Uuid, u32),
    identity_key: &[u8],
    expires: u64,
) -> Vec<u8> {
    let certificate = SenderCertificateDataPb {
        sender_device: Some(sender.1),
        expires: Some(expires),
        identity_key: Some(identity_key.to_vec()),
        signer_certificate: Some(signer),
        uuid_bytes: Some(sender.0.into_bytes().to_vec()),
    }
    .encode_to_vec();
    ServerCertificatePb {
        signature: Some(server.sign(&certificate)),
        certificate: Some(certificate),
    }
    .encode_to_vec()
}
