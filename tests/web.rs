//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;

wasm_bindgen_test_configure!(run_in_browser);

use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use serde_crypt::{setup, MASTER_KEY_LEN};
use std::{error::Error, println};
use wasm_bindgen_test::*;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct Test {
    #[serde(with = "serde_crypt")]
    field: Vec<u8>,
    #[serde(with = "serde_crypt")]
    r#struct: Other,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct Other {
    #[serde(with = "serde_crypt")]
    field: Vec<u8>,
}

#[wasm_bindgen_test]
fn flow() -> Result<(), Box<dyn Error>> {
    let mut key: [u8; MASTER_KEY_LEN] = [0; MASTER_KEY_LEN];
    let rand_gen = SystemRandom::new();
    rand_gen.fill(&mut key).unwrap();

    setup(key)?;
    let instance = Test {
        field: "a super secret message".as_bytes().to_vec(),
        r#struct: Other {
            field: "another secret message".as_bytes().to_vec(),
        },
    };
    let serialized = serde_json::to_string(&instance)?;
    let deserialized: Test = serde_json::from_str(&serialized)?;
    dbg!(&serialized);

    assert_eq!(deserialized.field, instance.field);

    Ok(())
}
