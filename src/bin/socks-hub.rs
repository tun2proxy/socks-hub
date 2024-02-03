//! Usage:
//! 1. `cargo run -- -l 127.0.0.1:8080 -s 127.0.0.1:1080`
//! 2. In Linux, configurate `http_proxy` in command line
//!    $ export http_proxy=http://127.0.0.1:8080
//!    $ export https_proxy=http://127.0.0.1:8080
//! 3. send requests
//!    $ curl -i https://www.google.com/

use socks_hub::{main_entry, BoxError, Config};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let config = Config::parse_args();

    dotenvy::dotenv().ok();
    // let level = format!("{}={:?}", module_path!(), config.verbosity);
    let level = config.verbosity.to_string();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).init();

    log::info!("config: {}", serde_json::to_string_pretty(&config)?);

    let (tx, quit) = tokio::sync::mpsc::channel::<()>(1);
    ctrlc2::set_async_handler(async move {
        tx.send(()).await.unwrap();
    })
    .await;

    main_entry(&config, quit).await?;
    Ok(())
}
