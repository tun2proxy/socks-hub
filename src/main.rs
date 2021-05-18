use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::task::{Context, Poll};
use std::time::Duration;

use hyper::{
    client::Client,
    server::Server,
    service::{make_service_fn, service_fn, Service},
    upgrade::Upgraded,
    Body, Method, Request, Response, Uri,
};
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Clone)]
struct SocksConnector {
    address: SocketAddr,
}

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
            let mut stream = TcpStream::connect(address).await?;
            handshake(&mut stream, Duration::from_secs(3), host, port).await?;
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
    timeout(dur, handshake_inner(conn, host, port)).await?
}

async fn handshake_inner(conn: &mut TcpStream, host: String, port: u16) -> io::Result<()> {
    let n_meth_auth: u8 = 1;
    conn.write_all(&[v5::VERSION, n_meth_auth, v5::METH_NO_AUTH])
        .await?;
    let buf1 = &mut [0u8; 2];

    conn.read_exact(buf1).await?;
    if buf1[0] != v5::VERSION {
        return Err(other("unknown version"));
    }
    if buf1[1] != v5::METH_NO_AUTH {
        return Err(other("unknow auth method"));
    }

    conn.write_all(&[v5::VERSION, v5::CMD_CONNECT, 0u8]).await?;

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

    let mut resp = vec![0u8; 4 + address_bytes.len()];
    conn.read_exact(&mut resp).await?;

    Ok(())
}

type SocksClient = Client<SocksConnector>;

// To try this example:
// 1. cargo run --example http_proxy
// 2. config http_proxy in command line
//    $ export http_proxy=http://127.0.0.1:8100
//    $ export https_proxy=http://127.0.0.1:8100
// 3. send requests
//    $ curl -i https://www.some_domain.com/
#[tokio::main]
async fn main() {
    env_logger::init();

    let addr = SocketAddr::from(([127, 0, 0, 1], 8100));

    let connector = SocksConnector {
        address: "127.0.0.1:8080".parse().unwrap(),
    };
    let client = Client::builder()
        .http1_title_case_headers(true)
        .http1_preserve_header_case(true)
        .build::<_, hyper::Body>(connector);

    let make_service = make_service_fn(move |_| {
        let client = client.clone();
        async move { Ok::<_, hyper::Error>(service_fn(move |req| proxy(client.clone(), req))) }
    });

    let server = Server::bind(&addr)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(make_service);

    println!("Listening on http://{}", addr);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}

async fn proxy(client: SocksClient, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    println!("req: {:?}", req);

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
        if let Some(addr) = host_addr(req.uri()) {
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = tunnel(upgraded, addr).await {
                            eprintln!("server io error: {}", e);
                        };
                    }
                    Err(e) => eprintln!("upgrade error: {}", e),
                }
            });

            Ok(Response::new(Body::empty()))
        } else {
            eprintln!("CONNECT host is not socket addr: {:?}", req.uri());
            let mut resp = Response::new(Body::from("CONNECT must be to a socket address"));
            *resp.status_mut() = http::StatusCode::BAD_REQUEST;

            Ok(resp)
        }
    } else {
        client.request(req).await
    }
}

fn host_addr(uri: &http::Uri) -> Option<String> {
    uri.authority().and_then(|auth| Some(auth.to_string()))
}

// Create a TCP connection to host:port, build a tunnel between the connection and
// the upgraded connection
async fn tunnel(mut upgraded: Upgraded, addr: String) -> std::io::Result<()> {
    // Connect to remote server
    let mut server = TcpStream::connect(addr).await?;

    // Proxying data
    let (from_client, from_server) = copy_bidirectional(&mut upgraded, &mut server).await?;

    // Print message when done
    println!(
        "client wrote {} bytes and received {} bytes",
        from_client, from_server
    );

    Ok(())
}
