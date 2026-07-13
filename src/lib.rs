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
pub use config::{ArgVerbosity, Config};

#[cfg(feature = "httpproxy")]
mod tokiort;
#[cfg(feature = "httpproxy")]
pub use socks5_impl::protocol::{Address, Command, ProxyParameters, ProxyType, UserKey};
#[cfg(feature = "sockshub")]
use socks5_impl::protocol::{AsyncStreamOperation, Reply, Response as SocksResponse, UdpHeader};
#[cfg(feature = "sockshub")]
use tokio::{io::AsyncWriteExt, net::UdpSocket};
#[cfg(feature = "httpproxy")]
use tokiort::TokioIo;

#[cfg(feature = "sockshub")]
mod http2socks;
#[cfg(feature = "sockshub")]
mod socks2socks;

#[cfg(feature = "httpproxy")]
mod httpproxy;
#[cfg(feature = "httpproxy")]
pub use httpproxy::run_http_service;

#[cfg(feature = "sockshub")]
mod api;
#[cfg(feature = "sockshub")]
mod dump_logger;
#[cfg(feature = "sockshub")]
mod ffi;

#[cfg(feature = "httpproxy")]
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;
#[cfg(feature = "sockshub")]
pub type Result<T, E = BoxError> = std::result::Result<T, E>;

#[cfg(feature = "sockshub")]
pub async fn main_entry<F>(config: &Config, cancel_token: tokio_util::sync::CancellationToken, callback: Option<F>) -> Result<(), BoxError>
where
    F: FnOnce(std::net::SocketAddr) + Send + Sync + 'static,
{
    if config.remote_server.proxy_type != ProxyType::Socks5 {
        return Err("remote server must be socks5".into());
    }
    if let Some(middle_server) = &config.middle_server {
        if middle_server.proxy_type != ProxyType::Socks5 {
            return Err("middle server must be socks5".into());
        }
    }
    match config.listen_proxy_role.proxy_type {
        ProxyType::Http => http2socks::main_entry(config, cancel_token, callback).await,
        ProxyType::Socks5 => socks2socks::main_entry(config, cancel_token, callback).await,
        ProxyType::None => mixed_main_entry(config, cancel_token, callback).await,
        _ => Err("listen proxy must be http, socks5, or none (mixed)".into()),
    }
}

#[cfg(feature = "sockshub")]
pub async fn mixed_main_entry<F>(
    config: &Config,
    cancel_token: tokio_util::sync::CancellationToken,
    callback: Option<F>,
) -> Result<(), BoxError>
where
    F: FnOnce(std::net::SocketAddr) + Send + Sync + 'static,
{
    let listen_addr: std::net::SocketAddr = config.listen_proxy_role.addr.clone().try_into()?;

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;

    if let Some(callback) = callback {
        callback(listener.local_addr()?);
    } else {
        log::info!("Listening on {}", config.listen_proxy_role);
    }

    let config = std::sync::Arc::new(config.clone());

    loop {
        let config = config.clone();
        tokio::select! {
            _ = cancel_token.cancelled() => {
                log::info!("quit signal received");
                break;
            }
            result = listener.accept() => {
                let (stream, incoming) = result?;
                tokio::task::spawn(async move {
                    if let Err(err) = service_connection(stream, config).await {
                        log::error!("service on incoming {incoming} error: {err}");
                    }
                });
            }
        }
    }
    Ok(())
}

#[cfg(feature = "sockshub")]
async fn service_connection(mut stream: tokio::net::TcpStream, config: std::sync::Arc<Config>) -> Result<(), BoxError> {
    let mut peek_buf = [0u8; 10];
    let n = stream.peek(&mut peek_buf).await?;
    if n == 0 {
        return Ok(());
    }

    match peek_buf[0] {
        0x05 => {
            log::trace!("socks5 client detected");
            let credentials = config.get_listen_credentials();
            let auth: socks5_impl::server::auth::AuthAdaptor = if credentials.to_string().is_empty() {
                std::sync::Arc::new(socks5_impl::server::auth::NoAuth)
            } else {
                std::sync::Arc::new(socks5_impl::server::auth::UserKeyAuth::from(credentials))
            };
            let req = socks5_impl::server::socks5_service_handshake(&mut stream, auth).await?;
            match req.command {
                Command::Connect => crate::socks2socks::handle_socks5_connect(stream, req.address, config.remote_server.clone()).await,
                Command::Bind => {
                    let resp = SocksResponse::new(Reply::CommandNotSupported, Address::unspecified());
                    resp.write_to_async_stream(&mut stream).await.map_err(std_io_error_other)?;
                    stream.shutdown().await.map_err(std_io_error_other)?;
                    Ok(())
                }
                Command::UdpAssociate => {
                    let client_ip = stream.local_addr()?.ip();
                    let udp_listener = UdpSocket::bind(std::net::SocketAddr::from((client_ip, 0))).await?;
                    let listen_addr = udp_listener.local_addr()?;
                    let resp = SocksResponse::new(Reply::Succeeded, Address::from(listen_addr));
                    resp.write_to_async_stream(&mut stream).await.map_err(std_io_error_other)?;

                    let buf_size = 1500 - UdpHeader::max_serialized_len();
                    let listen_udp = std::sync::Arc::new(socks5_impl::server::AssociatedUdpSocket::from((udp_listener, buf_size)));
                    let s5_udp_client =
                        create_s5_udp_client(config.remote_server.clone(), CONNECT_TIMEOUT, config.middle_server.clone()).await?;

                    crate::socks2socks::run_udp_associate_relay(listen_udp, s5_udp_client, &mut stream, listen_addr).await
                }
            }
        }
        0x04 => {
            log::warn!("socks4 client detected, but only SOCKS5/HTTP mixed mode is supported");
            let _ = stream.shutdown().await;
            Ok(())
        }
        _ => {
            let first_bytes = &peek_buf[..n];
            let is_http = if let Ok(text) = std::str::from_utf8(first_bytes) {
                let methods = [
                    "CONNECT", "GET", "POST", "HEAD", "PUT", "OPTIONS", "DELETE", "TRACE", "PATCH", "LOCK", "UNLOCK", "PROPFIND", "MKCOL",
                    "COPY", "MOVE",
                ];
                methods
                    .iter()
                    .any(|method| text[..method.len()].eq_ignore_ascii_case(method) && text.as_bytes().get(method.len()) == Some(&b' '))
            } else {
                false
            };

            if !is_http {
                log::warn!("unknown client type detected, first byte: 0x{:02x}", first_bytes[0]);
                let _ = stream.shutdown().await;
                return Ok(());
            }
            log::trace!("http client detected by method peek");

            let server = config.remote_server.clone();
            let credentials = config.listen_proxy_role.credentials.clone().unwrap_or_default();
            let middle_server = config.middle_server.clone();
            let middle_server_for_conn = middle_server.clone();
            let connector: crate::httpproxy::HttpConnector = std::sync::Arc::new(move |dst| {
                let server = server.clone();
                let middle_server = middle_server_for_conn.clone();
                Box::pin(async move {
                    let stream = crate::create_s5_connect(server, CONNECT_TIMEOUT, &dst, middle_server).await?;
                    Ok(Box::new(stream) as crate::httpproxy::BoxedStream)
                })
            });
            httpproxy::run_http_service(stream, connector, credentials).await?;
            Ok(())
        }
    }
}

#[cfg(feature = "sockshub")]
pub(crate) const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(feature = "sockshub")]
pub(crate) async fn create_s5_connect(
    server: ProxyParameters,
    dur: std::time::Duration,
    dst: &socks5_impl::protocol::Address,
    middle_server: Option<ProxyParameters>,
) -> std::io::Result<tokio::io::BufStream<tokio::net::TcpStream>> {
    let auth = server.credentials.clone();
    let mut stream = connect_proxy_stream(server, dur, middle_server).await?;
    socks5_impl::client::connect(&mut stream, dst, auth)
        .await
        .map_err(std_io_error_other)?;
    Ok(stream)
}

#[cfg(feature = "sockshub")]
async fn connect_proxy_stream(
    server: ProxyParameters,
    dur: std::time::Duration,
    middle_server: Option<ProxyParameters>,
) -> std::io::Result<tokio::io::BufStream<tokio::net::TcpStream>> {
    let stream = if let Some(middle_server) = middle_server {
        let middle_addr: std::net::SocketAddr = middle_server.addr.try_into()?;
        let stream = tokio::time::timeout(dur, tokio::net::TcpStream::connect(middle_addr)).await??;
        let mut stream = tokio::io::BufStream::new(stream);
        let middle_auth = middle_server.credentials.clone();
        socks5_impl::client::connect(&mut stream, server.addr, middle_auth)
            .await
            .map_err(std_io_error_other)?;
        stream
    } else {
        let server_addr: std::net::SocketAddr = server.addr.try_into()?;
        let stream = tokio::time::timeout(dur, tokio::net::TcpStream::connect(server_addr)).await??;
        tokio::io::BufStream::new(stream)
    };
    Ok(stream)
}

#[cfg(feature = "sockshub")]
pub(crate) async fn create_s5_udp_client(
    server: ProxyParameters,
    dur: std::time::Duration,
    middle_server: Option<ProxyParameters>,
) -> std::io::Result<socks5_impl::client::SocksUdpClient> {
    let stream = connect_proxy_stream(server.clone(), dur, middle_server).await?;
    let client_addr = if server.addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let client = tokio::net::UdpSocket::bind(client_addr).await?;
    let auth = server.credentials.clone();
    socks5_impl::client::SocksDatagram::udp_associate(stream, client, auth)
        .await
        .map_err(std_io_error_other)
}

#[cfg(feature = "httpproxy")]
pub(crate) fn std_io_error_other<E: Into<BoxError>>(err: E) -> std::io::Error {
    std::io::Error::other(err)
}

//     }
// }
