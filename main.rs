use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use serde_crypt::{setup, MASTER_KEY_LEN};
use std::error::Error;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct Test {
    #[serde(with = "serde_crypt")]
    field: Vec<u8>,
    #[serde(with = "serde_crypt")]
    r#struct: Other,
    plain: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct Other {
    field: Vec<u8>,
    hello: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut key: [u8; MASTER_KEY_LEN] = [0; MASTER_KEY_LEN];
    let rand_gen = SystemRandom::new();
    rand_gen.fill(&mut key).unwrap();

    setup(key)?;
    let instance = Test {
        field: "a super secret message".as_bytes().to_vec(),
        r#struct: Other {
            field: "another secret message".as_bytes().to_vec(),
            hello: "this is a test string".to_string(),
        },
        plain: "this is a plaintext message".to_string(),
    };
    dbg!(&instance);
    let serialized = serde_json::to_string(&instance)?;
    dbg!(&serialized);
    let deserialized: Test = serde_json::from_str(&serialized)?;
    dbg!(&deserialized);

    assert_eq!(deserialized.field, instance.field);

    Ok(())
}
