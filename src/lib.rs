use std::cell::RefCell;
use std::error::Error;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose;
use base64::Engine;
use lazy_static::lazy_static;
use ring::aead::{
    Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM, NONCE_LEN,
};
use ring::digest::{self, digest};
use ring::error;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde::{Deserializer, Serializer};

pub const MASTER_KEY_LEN: usize = 32;

lazy_static! {
    pub static ref MASTER_KEY: Arc<Mutex<RefCell<[u8; MASTER_KEY_LEN]>>> =
        Arc::new(Mutex::new(RefCell::new([0; MASTER_KEY_LEN])));
}

#[allow(dead_code)]
pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
    let nonce = generate_random_nonce();
    let encrypted = encrypt(v.clone(), nonce).map_err(|e| serde::ser::Error::custom(e))?;
    let encrypted = std::str::from_utf8(&encrypted).map_err(|e| serde::ser::Error::custom(e))?;
    let nonce = std::str::from_utf8(&nonce).map_err(|e| serde::ser::Error::custom(e))?;
    let base64 = general_purpose::URL_SAFE_NO_PAD.encode([nonce, encrypted].join("."));
    String::serialize(&base64, s)
}

#[allow(dead_code)]
pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let base64 = String::deserialize(d)?;
    let decoded = general_purpose::URL_SAFE_NO_PAD
        .decode(base64.as_bytes())
        .map_err(|e| serde::de::Error::custom(e))?;
    let decoded = std::str::from_utf8(&decoded).map_err(|e| serde::de::Error::custom(e))?;
    let mut it = decoded.split('.');
    let nonce = it
        .next()
        .unwrap()
        .as_bytes()
        .try_into()
        .map_err(|e| serde::de::Error::custom(e))?;
    let data = it.next().unwrap().as_bytes().to_vec();
    decrypt(data, nonce).map_err(|e| serde::de::Error::custom(e))
}

pub fn setup(master_key: [u8; MASTER_KEY_LEN]) -> Result<(), Box<dyn Error>> {
    let key = Arc::clone(&MASTER_KEY);
    let key = key.lock().unwrap();
    let mut key = key.borrow_mut();
    *key = master_key;

    Ok(())
}

fn encrypt(mut data: Vec<u8>, nonce: [u8; NONCE_LEN]) -> Result<Vec<u8>, Box<dyn Error>> {
    let key = Arc::clone(&MASTER_KEY);
    let key = key.lock().unwrap();
    let key = key.borrow_mut();
    let (key, nonce) = prepare_key(*key, nonce);
    let mut encryption_key = SealingKey::new(key, nonce);
    encryption_key
        .seal_in_place_append_tag(Aad::empty(), &mut data)
        .unwrap();

    Ok(data)
}

fn decrypt(mut data: Vec<u8>, nonce: [u8; NONCE_LEN]) -> Result<Vec<u8>, Box<dyn Error>> {
    let key = Arc::clone(&MASTER_KEY);
    let key = key.lock().unwrap();
    let key = key.borrow_mut();
    let (key, nonce) = prepare_key(*key, nonce);
    let mut decryption_key = OpeningKey::new(key, nonce);
    decryption_key
        .open_in_place(Aad::empty(), &mut data)
        .unwrap();
    let length = data.len() - AES_256_GCM.tag_len();

    Ok(data[..length].to_vec())
}

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

fn prepare_key(key: [u8; MASTER_KEY_LEN], nonce: [u8; NONCE_LEN]) -> (UnboundKey, INonceSequence) {
    let digest = digest(&digest::SHA256, &key);
    let key = digest.as_ref();
    let nonce_sequence = INonceSequence::new(Nonce::assume_unique_for_key(nonce));
    (UnboundKey::new(&AES_256_GCM, &key).unwrap(), nonce_sequence)
}
