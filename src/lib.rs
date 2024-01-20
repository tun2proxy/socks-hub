pub mod config;
pub use config::{Config, Credentials};

pub mod base64_wrapper;
pub use base64_wrapper::{base64_decode, base64_encode, Base64Engine};

use hyper::{
    client::Client,
    header::{HeaderValue, AUTHORIZATION},
    server::Server,
    service::{make_service_fn, service_fn, Service},
    upgrade::Upgraded,
    Body, Method, Request, Response, Uri,
};
use socks5_impl::protocol::{self, handshake, Address, AsyncStreamOperation, AuthMethod, Command};
use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{io::copy_bidirectional, net::TcpStream, time::timeout};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
struct SocksConnector {
    addr: SocketAddr,
}

impl SocksConnector {
    fn new(addr: SocketAddr) -> SocksConnector {
        SocksConnector { addr }
    }
}

impl Service<Uri> for SocksConnector {
    type Response = TcpStream;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let host = uri.host().map(|v| v.to_string()).unwrap_or_default();
        let port = uri.port_u16().unwrap_or(80);
        let s5addr = Address::from((host, port));
        let addr = self.addr;
        let fut = async move {
            log::debug!("destination address {}", s5addr);
            log::debug!("connect to SOCKS5 proxy server {:?}", addr);
            let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await??;
            s5_handshake(&mut stream, CONNECT_TIMEOUT, s5addr).await?;
            Ok(stream)
        };
        Box::pin(fut)
    }
}

pub async fn main_entry(config: &Config) -> Result<(), BoxError> {
    let local_addr = config.local_addr;
    let server_addr = config.server_addr;

    let client = Client::builder()
        .http1_title_case_headers(true)
        .http1_preserve_header_case(true)
        .build::<_, hyper::Body>(SocksConnector::new(server_addr));
    let credentials = config.get_credentials();

    let make_service = make_service_fn(move |_| {
        let client = client.clone();
        let credentials = credentials.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                let client = client.clone();
                let credentials = credentials.clone();
                async move { proxy(client, req, server_addr, credentials).await }
            }))
        }
    });

    let server = Server::bind(&local_addr)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(make_service);

    log::info!("Listening on http://{}", local_addr);
    server.await?;
    Ok(())
}

fn verify_basic_authorization(credentials: &Credentials, header_value: Option<&HeaderValue>) -> bool {
    if header_value.is_none() && credentials.is_empty() {
        return true;
    }
    header_value
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Basic "))
        .and_then(|v| base64_decode(v, Base64Engine::Standard).ok())
        .map_or(false, |v| v == credentials.to_vec())
}

async fn proxy(
    client: Client<SocksConnector>,
    mut req: Request<Body>,
    server: SocketAddr,
    credentials: Credentials,
) -> Result<Response<Body>, BoxError> {
    log::debug!("req: {:?}", req);
    if !verify_basic_authorization(&credentials, req.headers().get(AUTHORIZATION)) {
        log::error!("authorization fail");
        let mut resp = Response::new(Body::empty());
        *resp.status_mut() = hyper::StatusCode::UNAUTHORIZED;
        return Ok(resp);
    }
    let _ = req.headers_mut().remove(AUTHORIZATION);

    if Method::CONNECT == req.method() {
        // Received an HTTP request like:
        // ```
        // CONNECT www.domain.com:443 HTTP/1.1
        // Host: www.domain.com:443
        // Proxy-Connection: Keep-Alive
        // ```
        //
        // When HTTP method is CONNECT we should return an empty body
        // then we can eventually upgrade the connection and talk a new protocol.
        //
        // Note: only after client received an empty body with STATUS_OK can the
        // connection be upgraded, so we can't return a response inside
        // `on_upgrade` future.
        if req.uri().authority().is_some() {
            let host = req.uri().host().map(|v| v.to_string()).unwrap_or_default();
            let port = req.uri().port_u16().unwrap_or(80);
            let s5addr = Address::from((host, port));
            tokio::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = tunnel(upgraded, s5addr, server).await {
                            log::error!("tunnel io error: {}", e);
                        };
                    }
                    Err(e) => log::error!("upgrade error: {}", e),
                }
            });
            Ok(Response::new(Body::empty()))
        } else {
            log::error!("CONNECT host is not socket addr: {:?}", req.uri());
            let mut resp = Response::new(Body::from("CONNECT must be to a socket address"));
            *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
            Ok(resp)
        }
    } else {
        client.request(req).await.or_else(|e| {
            log::error!("client request error {:?}", e);
            let mut resp = Response::new(Body::from(format!("proxy server interval error {:?}", e)));
            *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
            Ok(resp)
        })
    }
}

// Create a TCP connection to host:port, build a tunnel between the connection and
// the upgraded connection
async fn tunnel(mut upgraded: Upgraded, dst: Address, server: SocketAddr) -> std::io::Result<()> {
    let mut server = timeout(CONNECT_TIMEOUT, TcpStream::connect(server)).await??;
    s5_handshake(&mut server, CONNECT_TIMEOUT, dst).await?;
    let (n1, n2) = copy_bidirectional(&mut upgraded, &mut server).await?;
    log::debug!("client wrote {} bytes and received {} bytes", n1, n2);
    Ok(())
}

async fn s5_handshake(conn: &mut TcpStream, dur: Duration, dst: Address) -> std::io::Result<()> {
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

pub fn std_io_error_other<E: Into<BoxError>>(err: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, err)
}
