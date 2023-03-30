use std::error::Error;

use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use serde_crypt::{setup, MASTER_KEY_LEN};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct Test {
    #[serde(with = "serde_crypt")]
    field: String,
    #[serde(with = "serde_crypt")]
    other: Other,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct Other {
    field: String,
    key: [u8; MASTER_KEY_LEN],
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut key: [u8; MASTER_KEY_LEN] = [0; MASTER_KEY_LEN];
    let rand_gen = SystemRandom::new();
    rand_gen.fill(&mut key).unwrap();

    setup(key)?;
    let instance = Test {
        field: "a super secret message".to_string(),
        other: Other {
            field: "another secret message".to_string(),
            key,
        },
    };
    let serialized = serde_json::to_string(&instance)?;
    dbg!(&serialized);
    let deserialized: Test = serde_json::from_str(&serialized)?;
    dbg!(&deserialized);

    Ok(())
}
