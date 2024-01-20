//! To try this example:
//! 1. File `tmp/config.json` content:
//!      ```json
//!      {
//!          "local_addr": "127.0.0.1:8100",
//!          "server_addr": "127.0.0.1:1080"
//!      }
//!      ```
//! 2. `cargo run -- -c tmp/config.json`
//! 3. In Linux, configurate `http_proxy` in command line
//!    $ export http_proxy=http://127.0.0.1:8100
//!    $ export https_proxy=http://127.0.0.1:8100
//! 4. send requests
//!    $ curl -i https://www.google.com/

use base64::{alphabet, engine::general_purpose::PAD, engine::GeneralPurpose, Engine};
use http2socks::{args::parse_args, std_io_error_other};
use hyper::{
    client::Client,
    header::{HeaderValue, PROXY_AUTHORIZATION},
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

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone)]
struct SocksConnector {
    addr: SocketAddr,
}

impl SocksConnector {
    fn new(addr: SocketAddr) -> SocksConnector {
        SocksConnector { addr }
    }
}

type SocksClient = Client<SocksConnector>;

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
        log::debug!("proxy address {}:{}", host, port);
        let addr = self.addr;
        let fut = async move {
            log::debug!("connect to address {:?}", addr);
            let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await??;
            s5_handshake(&mut stream, CONNECT_TIMEOUT, host, port).await?;
            Ok(stream)
        };
        Box::pin(fut)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();
    let config = parse_args("http2socks").ok_or("parse args error")?;
    log::info!("config: {}", serde_json::to_string_pretty(&config)?);

    let local_addr = config.local_addr.parse()?;
    let server_addr = config.server_addr.parse()?;

    let client = Client::builder()
        .http1_title_case_headers(true)
        .http1_preserve_header_case(true)
        .build::<_, hyper::Body>(SocksConnector::new(server_addr));
    let authorization = match (&config.username, &config.password) {
        (Some(u), Some(p)) => format!("{}:{}", u, p).as_bytes().to_vec(),
        _ => b":".to_vec(),
    };

    let make_service = make_service_fn(move |_| {
        let client = client.clone();
        let authorization = authorization.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                let client = client.clone();
                let authorization = authorization.clone();
                async move { proxy(client, req, server_addr, authorization).await }
            }))
        }
    });

    let server = Server::bind(&local_addr)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(make_service);

    println!("Listening on http://{}", local_addr);

    server.await.map_err(std_io_error_other)?;
    Ok(())
}

fn proxy_authorization(authorization: &[u8], header_value: Option<&HeaderValue>) -> bool {
    if authorization == b":" {
        return true;
    }
    match header_value {
        Some(v) => match v.to_str().unwrap_or_default().strip_prefix("Basic ") {
            Some(v) => match GeneralPurpose::new(&alphabet::STANDARD, PAD).decode(v) {
                Ok(v) => v == authorization,
                Err(_) => false,
            },
            None => false,
        },
        None => false,
    }
}

async fn proxy(
    client: SocksClient,
    mut req: Request<Body>,
    server_addr: SocketAddr,
    authorization: Vec<u8>,
) -> Result<Response<Body>, hyper::Error> {
    log::debug!("req: {:?}", req);
    if !proxy_authorization(&authorization, req.headers().get(PROXY_AUTHORIZATION)) {
        log::error!("authorization fail");
        let mut resp = Response::new(Body::empty());
        *resp.status_mut() = http::StatusCode::PROXY_AUTHENTICATION_REQUIRED;
        return Ok(resp);
    }
    let _ = req.headers_mut().remove(PROXY_AUTHORIZATION);

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
            tokio::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = tunnel(upgraded, host, port, server_addr).await {
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
            *resp.status_mut() = http::StatusCode::BAD_REQUEST;
            Ok(resp)
        }
    } else {
        client.request(req).await.or_else(|e| {
            log::error!("client request error {:?}", e);
            let mut resp =
                Response::new(Body::from(format!("proxy server interval error {:?}", e)));
            *resp.status_mut() = http::StatusCode::BAD_REQUEST;
            Ok(resp)
        })
    }
}

// Create a TCP connection to host:port, build a tunnel between the connection and
// the upgraded connection
async fn tunnel(
    mut upgraded: Upgraded,
    host: String,
    port: u16,
    server_addr: SocketAddr,
) -> std::io::Result<()> {
    let mut server = timeout(CONNECT_TIMEOUT, TcpStream::connect(server_addr)).await??;
    s5_handshake(&mut server, CONNECT_TIMEOUT, host, port).await?;
    let (n1, n2) = copy_bidirectional(&mut upgraded, &mut server).await?;
    log::debug!("client wrote {} bytes and received {} bytes", n1, n2);
    Ok(())
}

async fn s5_handshake(
    conn: &mut TcpStream,
    dur: Duration,
    host: String,
    port: u16,
) -> std::io::Result<()> {
    let fut = async move {
        log::trace!("write socks5 version and auth method");
        let s5req = handshake::Request::new(vec![AuthMethod::NoAuth]);
        s5req.write_to_async_stream(conn).await?;

        log::trace!("read server socks version and mthod");
        let _s5resp = handshake::Response::retrieve_from_async_stream(conn).await?;

        log::trace!("write socks5 version, command, address type and address");
        let s5req = protocol::Request::new(Command::Connect, Address::from((host, port)));
        s5req.write_to_async_stream(conn).await?;

        log::trace!("read server response");
        let s5resp = protocol::Response::retrieve_from_async_stream(conn).await?;
        log::trace!("server response: {:?}", s5resp);

        Ok(())
    };
    timeout(dur, fut).await?
}
