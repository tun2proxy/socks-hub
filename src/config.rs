use crate::std_io_error_other;
use serde_derive::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Config {
    pub local_addr: String,
    pub server_addr: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Config {
    pub fn new<P: AsRef<Path>>(path: P) -> std::io::Result<Config> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = match serde_json::from_str(&contents) {
            Ok(c) => c,
            Err(e) => {
                log::error!("parse config error {}", e);
                return Err(std_io_error_other(e));
            }
        };

        if let (None, Some(_)) = (&config.username, &config.password) {
            let err = "username/password invalid";
            log::error!("{err}");
            return Err(std_io_error_other(err));
        }

        Ok(config)
    }
}
