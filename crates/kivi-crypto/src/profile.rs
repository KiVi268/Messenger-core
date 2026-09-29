//! Profile key и unidentified access key (UAK) для sealed sender.
//!
//! Profile key — 32 случайных байта аккаунта. Клиент передаёт его
//! собеседникам внутри E2EE (`kivi.content.v1.Content.profile_key`), а
//! серверу — только UAK, выведенный из него. Сервер пропускает запрос
//! sealed sender, если в нём верный UAK получателя (messenger-protocol,
//! README, «Sealed sender»).

use hmac::{Hmac, KeyInit as _, Mac as _};
use rand::RngCore as _;
use sha2::Sha256;

use crate::error::CryptoError;

pub const PROFILE_KEY_LEN: usize = 32;
pub const UNIDENTIFIED_ACCESS_KEY_LEN: usize = 16;

const UAK_LABEL: &[u8] = b"KiVi unidentified access key v1";

/// Новый случайный profile key.
pub fn generate_profile_key() -> Vec<u8> {
    let mut key = vec![0u8; PROFILE_KEY_LEN];
    rand::rng().fill_bytes(&mut key);
    key
}

/// `UAK = HMAC-SHA256(profile_key, "KiVi unidentified access key v1")[0..16]`.
pub fn unidentified_access_key(profile_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if profile_key.len() != PROFILE_KEY_LEN {
        return Err(CryptoError::Malformed(format!(
            "profile key must be {PROFILE_KEY_LEN} bytes, got {}",
            profile_key.len()
        )));
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(profile_key).expect("HMAC accepts any key length");
    mac.update(UAK_LABEL);
    Ok(mac.finalize().into_bytes()[..UNIDENTIFIED_ACCESS_KEY_LEN].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answer() {
        // Эталон для других реализаций (сервер тестов, iOS):
        // python3 -c "import hmac,hashlib; print(hmac.new(bytes(range(32)), b'KiVi unidentified access key v1', hashlib.sha256).hexdigest()[:32])"
        let key: Vec<u8> = (0u8..32).collect();
        let uak = unidentified_access_key(&key).unwrap();
        assert_eq!(uak.len(), 16);
        assert_eq!(hex(&uak), KNOWN_UAK);
    }

    #[test]
    fn rejects_wrong_length_and_differs_per_key() {
        assert!(unidentified_access_key(&[0u8; 16]).is_err());
        let a = unidentified_access_key(&generate_profile_key()).unwrap();
        let b = unidentified_access_key(&generate_profile_key()).unwrap();
        assert_ne!(a, b);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    const KNOWN_UAK: &str = "8cb73289e55b9603e553a50feb3a3037";
}
