//! Usage:
//! 1. `cargo run -- -l 127.0.0.1:8100 -s 127.0.0.1:1080`
//! 2. In Linux, configurate `http_proxy` in command line
//!    $ export http_proxy=http://127.0.0.1:8100
//!    $ export https_proxy=http://127.0.0.1:8100
//! 3. send requests
//!    $ curl -i https://www.google.com/

use http2socks::{main_entry, BoxError, Config};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let config = Config::default();

    dotenvy::dotenv().ok();
    // let level = format!("{}={:?}", module_path!(), config.verbosity);
    let level = config.verbosity.to_string();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).init();

    log::info!("config: {}", serde_json::to_string_pretty(&config)?);

    main_entry(&config).await?;
    Ok(())
}
