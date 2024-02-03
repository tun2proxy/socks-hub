pub mod config;
pub use config::{Config, Credentials};

pub mod base64_wrapper;
pub use base64_wrapper::{base64_decode, base64_encode, Base64Engine};

mod tokiort;
pub use tokiort::{TokioExecutor, TokioIo, TokioTimer};

mod http2socks;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T, E = BoxError> = std::result::Result<T, E>;

pub async fn main_entry(config: &Config, quit: tokio::sync::mpsc::Receiver<()>) -> Result<(), BoxError> {
    http2socks::main_entry(config, quit).await
}
