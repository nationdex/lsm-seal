use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::error::{Error, Result};

/// 32-byte AEAD master key. Zeroized on drop. Debug redacted.
pub struct SealKey([u8; 32]);

impl SealKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("getrandom");
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = slice.try_into().map_err(|_| Error::InvalidKey)?;
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for SealKey {
    fn drop(&mut self) {
        for b in self.0.iter_mut() {
            unsafe {
                std::ptr::write_volatile(b, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl fmt::Debug for SealKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SealKey(REDACTED)")
    }
}

/// Position-bound AEAD. Nonce derives from the entry sequence number
/// (unique per entry under one key); AAD binds the entry key and seq so
/// ciphertext cannot be spliced or reordered across keys or positions.
#[derive(Clone)]
pub struct Cipher {
    aead: ChaCha20Poly1305,
}

impl Cipher {
    pub fn new(key: &SealKey) -> Self {
        Self {
            aead: ChaCha20Poly1305::new(Key::from_slice(&key.0)),
        }
    }

    fn nonce(seq: u64) -> Nonce {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&seq.to_le_bytes());
        *Nonce::from_slice(&n)
    }

    fn aad(seq: u64, entry_key: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(8 + entry_key.len());
        aad.extend_from_slice(&seq.to_le_bytes());
        aad.extend_from_slice(entry_key);
        aad
    }

    pub fn seal(&self, seq: u64, entry_key: &[u8], frame: &[u8]) -> Result<Vec<u8>> {
        let aad = Self::aad(seq, entry_key);
        self.aead
            .encrypt(
                &Self::nonce(seq),
                Payload {
                    msg: frame,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto)
    }

    pub fn open(&self, seq: u64, entry_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let aad = Self::aad(seq, entry_key);
        self.aead
            .decrypt(
                &Self::nonce(seq),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = SealKey::generate();
        let c = Cipher::new(&key);
        let ct = c.seal(7, b"abc", b"hello").unwrap();
        assert_eq!(c.open(7, b"abc", &ct).unwrap(), b"hello");
    }

    #[test]
    fn aad_binds_key_and_seq() {
        let c = Cipher::new(&SealKey::generate());
        let ct = c.seal(1, b"k1", b"v").unwrap();
        assert!(c.open(1, b"k2", &ct).is_err());
        assert!(c.open(2, b"k1", &ct).is_err());
        assert!(c.open(1, b"k1", &ct).is_ok());
    }

    #[test]
    fn tamper_detected() {
        let c = Cipher::new(&SealKey::generate());
        let mut ct = c.seal(1, b"k", b"v").unwrap();
        ct[0] ^= 1;
        assert!(c.open(1, b"k", &ct).is_err());
    }
}
