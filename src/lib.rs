cfg_if::cfg_if! {
    if #[cfg(feature = "base64")] {
        mod base64_wrapper;
        pub use base64_wrapper::{base64_decode, base64_encode, Base64Engine};
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "acl")] {
        mod acl;
        pub use acl::AccessControl;
    }
}

//
// can't use cfg_if here, because it will cause cbindgen to can't generate ffi.h correctly.
// see this issue: https://github.com/mozilla/cbindgen/issues/935
//
// cfg_if::cfg_if! {
//     if #[cfg(feature = "sockshub")] {

#[cfg(feature = "sockshub")]
mod config;
#[cfg(feature = "sockshub")]
pub use config::{ArgVerbosity, Config, Credentials, ProxyType};

#[cfg(feature = "sockshub")]
mod tokiort;
#[cfg(feature = "sockshub")]
use tokiort::TokioIo;

#[cfg(feature = "sockshub")]
mod http2socks;
#[cfg(feature = "sockshub")]
mod socks2socks;

#[cfg(feature = "sockshub")]
mod api;
#[cfg(feature = "sockshub")]
mod dump_logger;
#[cfg(feature = "sockshub")]
mod ffi;

#[cfg(feature = "sockshub")]
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
#[cfg(feature = "sockshub")]
pub type Result<T, E = BoxError> = std::result::Result<T, E>;

#[cfg(feature = "sockshub")]
pub async fn main_entry<F>(config: &Config, quit: tokio::sync::mpsc::Receiver<()>, callback: Option<F>) -> Result<(), BoxError>
where
    F: FnOnce(std::net::SocketAddr) + Send + Sync + 'static,
{
    match config.source_type {
        ProxyType::Http => http2socks::main_entry(config, quit, callback).await,
        ProxyType::Socks5 => socks2socks::main_entry(config, quit, callback).await,
    }
}

#[cfg(feature = "sockshub")]
pub(crate) const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(feature = "sockshub")]
pub(crate) async fn create_s5_connect<A: tokio::net::ToSocketAddrs>(
    server: A,
    dur: std::time::Duration,
    dst: &socks5_impl::protocol::Address,
    auth: Option<socks5_impl::protocol::UserKey>,
) -> std::io::Result<tokio::io::BufStream<tokio::net::TcpStream>> {
    let stream = tokio::time::timeout(dur, tokio::net::TcpStream::connect(server)).await??;
    let mut stream = tokio::io::BufStream::new(stream);
    socks5_impl::client::connect(&mut stream, dst, auth).await?;
    Ok(stream)
}

#[cfg(feature = "sockshub")]
pub(crate) fn std_io_error_other<E: Into<BoxError>>(err: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, err)
}

//     }
// }
