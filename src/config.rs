use std::path::Path;
use std::{fs, io};

use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Config {
    pub local_addr: String,
    pub server_addr: String,
    pub username: String,
    pub password: String,
}

impl Config {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Config, io::Error> {
        let contents = fs::read_to_string(path)?;
        let config = match serde_json::from_str(&contents) {
            Ok(c) => c,
            Err(e) => {
                log::error!("parse config error {}", e);
                return Err(io::Error::new(io::ErrorKind::Other, e));
            }
        };

        Ok(config)
    }
}
