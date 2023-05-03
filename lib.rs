#![forbid(unsafe_code)]

//! The end-to-end encrypted `serde::Serializer` and `serde::Deserializer`.
//! **wasm-ready**.
//!
//! ## Example
//!
//! ```rust
//! use ring::rand::{SecureRandom, SystemRandom};
//! use serde::{Deserialize, Serialize};
//! use serde_crypt::{setup};
//!
//! #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
//! struct Example {
//!     #[serde(with = "serde_crypt")]
//!     private: String,
//!     public: String,
//! }
//!
//! let mut key: [u8; 256] = [0; 256];
//! let rand_gen = SystemRandom::new();
//! rand_gen.fill(&mut key).unwrap();
//!
//! setup(key.to_vec());
//! let data = Example {
//!     private: "private data".to_string(),
//!     public: "public data".to_string(),
//! };
//!
//! let serialized = serde_json::to_string(&data).unwrap();
//! let deserialized: Example = serde_json::from_str(&serialized).unwrap();
//!
//! assert_eq!(deserialized, data);
//! ```
//!

use std::error::Error;
use std::fmt::Display;
use std::sync::Mutex;

use base64::engine::general_purpose;
use base64::Engine;
use once_cell::sync::Lazy;
use ring::aead::{
    Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM, NONCE_LEN,
};
use ring::digest::{self, digest};
use ring::error::{self, Unspecified};
use ring::rand::{SecureRandom, SystemRandom};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde::{Deserializer, Serializer};

static MASTER_KEY: Lazy<Mutex<Vec<u8>>> = Lazy::new(|| Mutex::new(vec![]));

#[allow(dead_code)]
pub fn serialize<S: Serializer, T: Serialize>(v: T, s: S) -> Result<S::Ok, S::Error> {
    let base64 = e(v).map_err(serde::ser::Error::custom)?;
    String::serialize(&base64, s)
}

#[allow(dead_code)]
pub fn deserialize<'de, D: Deserializer<'de>, T: DeserializeOwned>(de: D) -> Result<T, D::Error> {
    let base64 = String::deserialize(de)?;
    d(base64).map_err(serde::de::Error::custom)
}

pub fn setup(master_key: Vec<u8>) {
    *MASTER_KEY.lock().unwrap() = master_key;
}

pub fn e<T: Serialize>(source: T) -> Result<String, Box<dyn Error>> {
    let nonce = generate_random_nonce();
    let serialized = serde_json::to_string(&source).map(|t| t.as_bytes().to_vec())?;
    let mut encrypted = encrypt(serialized, nonce)?;
    let mut nonce_encrypted = nonce.to_vec();
    nonce_encrypted.append(&mut encrypted);
    Ok(general_purpose::URL_SAFE_NO_PAD.encode(nonce_encrypted))
}

pub fn d<T: DeserializeOwned>(source: String) -> Result<T, Box<dyn Error>> {
    let decoded = general_purpose::URL_SAFE_NO_PAD.decode(source.as_bytes())?;
    let nonce = decoded[..NONCE_LEN].try_into().unwrap();
    let data = decoded[NONCE_LEN..].to_vec();
    let decrypted = decrypt(data, nonce)?;
    let decrypted = std::str::from_utf8(&decrypted)?;
    Ok(serde_json::from_str(decrypted)?)
}

fn encrypt(mut data: Vec<u8>, nonce: [u8; NONCE_LEN]) -> Result<Vec<u8>, Box<dyn Error>> {
    let key = MASTER_KEY.lock().unwrap();
    let (key, nonce) = prepare_key(&key, nonce);
    let mut encryption_key = SealingKey::new(key, nonce);
    encryption_key
        .seal_in_place_append_tag(Aad::empty(), &mut data)
        .map_err(CryptError::EncryptionError)?;

    Ok(data)
}

fn decrypt(mut data: Vec<u8>, nonce: [u8; NONCE_LEN]) -> Result<Vec<u8>, Box<dyn Error>> {
    let key = MASTER_KEY.lock().unwrap();
    let (key, nonce) = prepare_key(&key, nonce);
    let mut decryption_key = OpeningKey::new(key, nonce);
    decryption_key
        .open_in_place(Aad::empty(), &mut data)
        .map_err(CryptError::DecryptionError)?;
    let length = data.len() - AES_256_GCM.tag_len();

    Ok(data[..length].to_vec())
}

#[derive(Debug)]
pub enum CryptError {
    DecryptionError(Unspecified),
    EncryptionError(Unspecified),
}

impl Display for CryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DecryptionError(e) => e.fmt(f),
            Self::EncryptionError(e) => e.fmt(f),
        }
    }
}

impl Error for CryptError {}

struct INonceSequence(Option<Nonce>);

impl INonceSequence {
    fn new(nonce: Nonce) -> Self {
        Self(Some(nonce))
    }
}

impl NonceSequence for INonceSequence {
    fn advance(&mut self) -> Result<Nonce, error::Unspecified> {
        self.0.take().ok_or(error::Unspecified)
    }
}

fn generate_random_nonce() -> [u8; NONCE_LEN] {
    let rand_gen = SystemRandom::new();
    let mut raw_nonce = [0u8; NONCE_LEN];
    rand_gen.fill(&mut raw_nonce).unwrap();
    raw_nonce
}

fn prepare_key(key: &Vec<u8>, nonce: [u8; NONCE_LEN]) -> (UnboundKey, INonceSequence) {
    let digest = digest(&digest::SHA256, key.as_slice());
    let key = digest.as_ref();
    let nonce_sequence = INonceSequence::new(Nonce::assume_unique_for_key(nonce));
    (UnboundKey::new(&AES_256_GCM, key).unwrap(), nonce_sequence)
}

#[cfg(test)]
mod test {
    use ring::rand::{SecureRandom, SystemRandom};
    use serde::{Deserialize, Serialize};

    use crate::setup;

    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
    struct Other {
        #[serde(with = "crate")]
        field: Vec<u8>,
        plain: String,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
    struct Test {
        #[serde(with = "crate")]
        field: Vec<u8>,
        #[serde(with = "crate")]
        other: Other,
        plain: String,
    }

    #[test]
    fn flow() -> Result<(), serde_json::Error> {
        let mut key: [u8; 256] = [0; 256];
        let rand_gen = SystemRandom::new();
        rand_gen.fill(&mut key).unwrap();

        setup(key.to_vec());
        let instance = Test {
            field: "a secret message".as_bytes().to_vec(),
            other: Other {
                field: "another secret message".as_bytes().to_vec(),
                plain: "this is a plain nested string".to_string(),
            },
            plain: "this is a plain string".to_string(),
        };

        let serialized = serde_json::to_string(&instance)?;
        let deserialized: Test = serde_json::from_str(&serialized)?;

        assert_eq!(deserialized, instance);
        Ok(())
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
    struct Example {
        #[serde(with = "crate")]
        private: String,
        public: String,
    }

    #[test]
    fn readme() -> Result<(), serde_json::Error> {
        let mut key: [u8; 256] = [0; 256];
        let rand_gen = SystemRandom::new();
        rand_gen.fill(&mut key).unwrap();

        setup(key.to_vec());
        let data = Example {
            private: "private data".to_string(),
            public: "public data".to_string(),
        };

        let serialized = serde_json::to_string(&data)?;
        let deserialized: Example = serde_json::from_str(&serialized)?;

        assert_eq!(deserialized, data);
        Ok(())
    }
}
