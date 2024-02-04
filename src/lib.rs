pub mod config;
pub use config::{ArgVerbosity, Config, Credentials, SourceType};

pub mod base64_wrapper;
pub use base64_wrapper::{base64_decode, base64_encode, Base64Engine};

mod tokiort;
pub use tokiort::{TokioExecutor, TokioIo, TokioTimer};

mod http2socks;
mod socks2socks;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T, E = BoxError> = std::result::Result<T, E>;

use socks5_impl::protocol::{self, handshake, Address, AsyncStreamOperation, AuthMethod, Command};
use std::time::Duration;
use tokio::{net::TcpStream, sync::mpsc::Receiver, time::timeout};

pub async fn main_entry(config: &Config, quit: Receiver<()>) -> Result<(), BoxError> {
    match config.source_type {
        SourceType::Http => http2socks::main_entry(config, quit).await,
        SourceType::Socks5 => socks2socks::main_entry(config, quit).await,
    }
}

pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) async fn s5_handshake(conn: &mut TcpStream, dur: Duration, dst: Address) -> std::io::Result<()> {
    let fut = async move {
        log::trace!("write socks5 version and auth method");
        let s5req = handshake::Request::new(vec![AuthMethod::NoAuth]);
        s5req.write_to_async_stream(conn).await?;

        log::trace!("read server socks version and mthod");
        let _s5resp = handshake::Response::retrieve_from_async_stream(conn).await?;

        log::trace!("write socks5 version, command, address type and address");
        let s5req = protocol::Request::new(Command::Connect, dst);
        s5req.write_to_async_stream(conn).await?;

        log::trace!("read server response");
        let s5resp = protocol::Response::retrieve_from_async_stream(conn).await?;
        log::trace!("server response: {:?}", s5resp);

        Ok(())
    };
    timeout(dur, fut).await?
}

pub(crate) fn std_io_error_other<E: Into<BoxError>>(err: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, err)
}
