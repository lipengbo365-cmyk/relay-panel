use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};

pub const CREDENTIAL_KEY_VERSION: i32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialError {
    KeyMissing,
    KeyInvalid,
    EncryptFailed,
    DecryptFailed,
    UnsupportedVersion,
}

#[derive(Clone)]
pub struct CredentialCipher(XChaCha20Poly1305);

impl CredentialCipher {
    pub fn from_config(raw: Option<&str>) -> Result<Self, CredentialError> {
        let raw = raw.ok_or(CredentialError::KeyMissing)?.trim();
        let bytes = if raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit()) {
            decode_hex(raw).ok_or(CredentialError::KeyInvalid)?
        } else {
            STANDARD
                .decode(raw)
                .map_err(|_| CredentialError::KeyInvalid)?
        };
        if bytes.len() != 32 {
            return Err(CredentialError::KeyInvalid);
        }
        Ok(Self(
            XChaCha20Poly1305::new_from_slice(&bytes).map_err(|_| CredentialError::KeyInvalid)?,
        ))
    }

    pub fn encrypt(
        &self,
        plaintext: &str,
        purpose: &str,
    ) -> Result<(String, String, i32), CredentialError> {
        let mut nonce = [0u8; 24];
        getrandom::getrandom(&mut nonce).map_err(|_| CredentialError::EncryptFailed)?;
        let ciphertext = self
            .0
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: purpose.as_bytes(),
                },
            )
            .map_err(|_| CredentialError::EncryptFailed)?;
        Ok((
            STANDARD.encode(ciphertext),
            STANDARD.encode(nonce),
            CREDENTIAL_KEY_VERSION,
        ))
    }

    pub fn decrypt(
        &self,
        ciphertext: &str,
        nonce: &str,
        version: i32,
        purpose: &str,
    ) -> Result<String, CredentialError> {
        if version != CREDENTIAL_KEY_VERSION {
            return Err(CredentialError::UnsupportedVersion);
        }
        let ciphertext = STANDARD
            .decode(ciphertext)
            .map_err(|_| CredentialError::DecryptFailed)?;
        let nonce = STANDARD
            .decode(nonce)
            .map_err(|_| CredentialError::DecryptFailed)?;
        if nonce.len() != 24 {
            return Err(CredentialError::DecryptFailed);
        }
        let plaintext = self
            .0
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: purpose.as_bytes(),
                },
            )
            .map_err(|_| CredentialError::DecryptFailed)?;
        String::from_utf8(plaintext).map_err(|_| CredentialError::DecryptFailed)
    }
}

fn decode_hex(raw: &str) -> Option<Vec<u8>> {
    (0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn encrypts_round_trip_without_plaintext() {
        let cipher = CredentialCipher::from_config(Some(&"11".repeat(32))).unwrap();
        let (encrypted, nonce, version) = cipher.encrypt("upstream-secret", "resource:7").unwrap();
        assert!(!encrypted.contains("upstream-secret"));
        assert_eq!(
            cipher
                .decrypt(&encrypted, &nonce, version, "resource:7")
                .unwrap(),
            "upstream-secret"
        );
        assert_eq!(
            cipher.decrypt(&encrypted, &nonce, version, "resource:8"),
            Err(CredentialError::DecryptFailed)
        );
    }

    #[test]
    fn rejects_missing_or_wrong_length_key() {
        assert_eq!(
            CredentialCipher::from_config(None).err(),
            Some(CredentialError::KeyMissing)
        );
        assert_eq!(
            CredentialCipher::from_config(Some("abcd")).err(),
            Some(CredentialError::KeyInvalid)
        );
    }

    #[test]
    fn nonces_are_unique_and_purposes_are_cryptographically_isolated() {
        let cipher = CredentialCipher::from_config(Some(&"22".repeat(32))).unwrap();
        let mut nonces = HashSet::new();
        for _ in 0..1_024 {
            let (encrypted, nonce, version) = cipher
                .encrypt("same-secret", "socks5-resource-password")
                .unwrap();
            assert!(nonces.insert(nonce.clone()), "nonce reuse detected");
            assert_eq!(
                cipher.decrypt(&encrypted, &nonce, version, "socks5-relay-password"),
                Err(CredentialError::DecryptFailed),
                "resource ciphertext must not decrypt under relay AAD"
            );
        }
    }
}
