use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::task::{Context, Poll};
use std::time::Duration;

use hyper::client::Client;
use hyper::server::Server;
use hyper::service::{make_service_fn, service_fn, Service};
use hyper::upgrade::Upgraded;
use hyper::{Body, Method, Request, Response, Uri};
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use http2socks::args::parse_args;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone)]
struct SocksConnector {
    address: SocketAddr,
}

impl SocksConnector {
    fn new(address: SocketAddr) -> SocksConnector {
        SocksConnector { address }
    }
}

type SocksClient = Client<SocksConnector>;

impl Service<Uri> for SocksConnector {
    type Response = TcpStream;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let host = uri.host().map(|v| v.to_string()).unwrap_or_default();
        let port = uri.port_u16().unwrap_or_else(|| 80);
        log::debug!("proxy address {}:{}", host, port);
        let address = self.address;
        let fut = async move {
            log::debug!("connect to address {:?}", address);
            let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(address)).await??;
            handshake(&mut stream, CONNECT_TIMEOUT, host, port).await?;
            Ok(stream)
        };
        Box::pin(fut)
    }
}

fn other(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg)
}

pub mod v5 {
    pub const VERSION: u8 = 5;
    pub const METH_NO_AUTH: u8 = 0;
    pub const CMD_CONNECT: u8 = 1;
    pub const TYPE_IPV4: u8 = 1;
    pub const TYPE_IPV6: u8 = 4;
    pub const TYPE_DOMAIN: u8 = 3;
    pub const REPLY_SUCESS: u8 = 0;
}

async fn handshake(conn: &mut TcpStream, dur: Duration, host: String, port: u16) -> io::Result<()> {
    let fut = async move {
        log::trace!("write socks5 version and auth method");
        let n_meth_auth: u8 = 1;
        conn.write_all(&[v5::VERSION, n_meth_auth, v5::METH_NO_AUTH])
            .await?;
        let buf1 = &mut [0u8; 2];

        log::trace!("read server socks version and mthod");
        conn.read_exact(buf1).await?;
        if buf1[0] != v5::VERSION {
            return Err(other("unknown version"));
        }
        if buf1[1] != v5::METH_NO_AUTH {
            return Err(other("unknow auth method"));
        }

        log::trace!("write socks5 version and command");
        conn.write_all(&[v5::VERSION, v5::CMD_CONNECT, 0u8]).await?;

        log::trace!("write address type and address");
        // write address
        let (address_type, mut address_bytes) = if let Ok(addr) = IpAddr::from_str(&host) {
            match addr {
                IpAddr::V4(v) => (v5::TYPE_IPV4, v.octets().to_vec()),
                IpAddr::V6(v) => (v5::TYPE_IPV6, v.octets().to_vec()),
            }
        } else {
            let domain_len = host.len() as u8;
            let mut domain_bytes = vec![domain_len];
            domain_bytes.extend_from_slice(&host.into_bytes());
            (v5::TYPE_DOMAIN, domain_bytes)
        };
        conn.write_all(&[address_type]).await?;
        address_bytes.extend_from_slice(&port.to_be_bytes());
        conn.write_all(&address_bytes).await?;

        log::trace!("read server response");
        let mut resp = vec![0u8; 4 + address_bytes.len()];
        conn.read_exact(&mut resp).await?;

        Ok(())
    };
    timeout(dur, fut).await?
}

// To try this example:
// 1. cargo run --example http_proxy
// 2. config http_proxy in command line
//    $ export http_proxy=http://127.0.0.1:8100
//    $ export https_proxy=http://127.0.0.1:8100
// 3. send requests
//    $ curl -i https://www.google.com/
#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init();
    let config = parse_args("http2socks").unwrap();
    log::info!("config: {}", serde_json::to_string_pretty(&config).unwrap());

    let local_addr = config
        .local_addr
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid local address"))?;
    let server_addr = config
        .server_addr
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid server address"))?;

    let client = Client::builder()
        .http1_title_case_headers(true)
        .http1_preserve_header_case(true)
        .build::<_, hyper::Body>(SocksConnector::new(server_addr));

    let make_service = make_service_fn(move |_| {
        let client = client.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                let client = client.clone();
                let fut = async move { proxy(client, req, server_addr).await };
                fut
            }))
        }
    });

    let server = Server::bind(&local_addr)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(make_service);

    println!("Listening on http://{}", local_addr);

    server.await.map_err(|e| other(&e.to_string()))?;
    Ok(())
}

async fn proxy(
    client: SocksClient,
    req: Request<Body>,
    server_addr: SocketAddr,
) -> Result<Response<Body>, hyper::Error> {
    log::debug!("req: {:?}", req);

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
            let port = req.uri().port_u16().unwrap_or_else(|| 80);
            tokio::task::spawn(async move {
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
) -> io::Result<()> {
    let mut server = timeout(CONNECT_TIMEOUT, TcpStream::connect(server_addr)).await??;
    handshake(&mut server, CONNECT_TIMEOUT, host, port).await?;
    let (n1, n2) = copy_bidirectional(&mut upgraded, &mut server).await?;
    log::debug!("client wrote {} bytes and received {} bytes", n1, n2);

    Ok(())
}
