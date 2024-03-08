pub mod config;
pub use config::{ArgVerbosity, Config, Credentials, ProxyType};

pub mod base64_wrapper;
pub use base64_wrapper::{base64_decode, base64_encode, Base64Engine};

mod tokiort;
use tokiort::TokioIo;

mod http2socks;
mod socks2socks;

#[cfg(feature = "acl")]
pub mod acl;
mod api;
mod dump_logger;
mod ffi;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T, E = BoxError> = std::result::Result<T, E>;

use socks5_impl::protocol::{Address, UserKey};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    net::{TcpStream, ToSocketAddrs},
    sync::mpsc::Receiver,
    time::timeout,
};

pub async fn main_entry<F>(config: &Config, quit: Receiver<()>, callback: Option<F>) -> Result<(), BoxError>
where
    F: FnOnce(SocketAddr) + Send + Sync + 'static,
{
    match config.source_type {
        ProxyType::Http => http2socks::main_entry(config, quit, callback).await,
        ProxyType::Socks5 => socks2socks::main_entry(config, quit, callback).await,
    }
}

pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) async fn create_s5_connect<A: ToSocketAddrs>(
    server: A,
    dur: Duration,
    dst: &Address,
    auth: Option<UserKey>,
) -> std::io::Result<tokio::io::BufStream<TcpStream>> {
    let stream = timeout(dur, TcpStream::connect(server)).await??;
    let mut stream = tokio::io::BufStream::new(stream);
    socks5_impl::client::connect(&mut stream, dst, auth).await?;
    Ok(stream)
}

pub(crate) fn std_io_error_other<E: Into<BoxError>>(err: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, err)
}
