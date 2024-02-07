use crate::{base64_decode, std_io_error_other, Base64Engine, BoxError, Config, Credentials, TokioIo, CONNECT_TIMEOUT};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::{
    header::{HeaderValue, AUTHORIZATION},
    service::service_fn,
    upgrade::Upgraded,
    Method, Request, Response,
};
use socks5_impl::protocol::Address;
use std::net::SocketAddr;
use tokio::{net::TcpListener, sync::mpsc::Receiver};

pub async fn main_entry<F>(config: &Config, mut quit: Receiver<()>, callback: Option<F>) -> Result<(), BoxError>
where
    F: FnOnce(SocketAddr) + Send + Sync + 'static,
{
    let local_addr = config.local_addr;

    let listener = TcpListener::bind(local_addr).await?;

    if let Some(callback) = callback {
        callback(listener.local_addr()?);
    } else {
        log::info!("Listening on http://{}", listener.local_addr()?);
    }

    let config = std::sync::Arc::new(config.clone());

    loop {
        let config = config.clone();
        tokio::select! {
            _ = quit.recv() => {
                log::info!("quit signal received");
                break;
            }
            result = listener.accept() => {
                let (stream, incoming) = result?;
                tokio::task::spawn(async move {
                    if let Err(err) = build_http_service(stream, config).await {
                        log::error!("http service on incoming {} error: {}", incoming, err);
                    }
                });
            }
        }
    }
    Ok(())
}

async fn build_http_service(stream: tokio::net::TcpStream, config: std::sync::Arc<Config>) -> Result<(), BoxError> {
    let io = TokioIo::new(stream);
    hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(
            io,
            service_fn(|req: Request<hyper::body::Incoming>| {
                let config = config.clone();
                async move { proxy(req, config).await }
            }),
        )
        .with_upgrades()
        .await?;
    Ok(())
}

async fn proxy(
    mut req: Request<hyper::body::Incoming>,
    config: std::sync::Arc<Config>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, std::io::Error> {
    //
    // https://github.com/hyperium/hyper/blob/90eb95f62a32981cb662b0f750027231d8a2586b/examples/http_proxy.rs#L51
    //
    log::trace!("req: {:?}", req);

    let server = config.server_addr;
    let credentials = config.get_credentials();

    if !verify_basic_authorization(&credentials, req.headers().get(AUTHORIZATION)) {
        log::error!("authorization fail");
        let mut resp = Response::new(empty());
        *resp.status_mut() = hyper::StatusCode::UNAUTHORIZED;
        return Ok(resp);
    }
    let _ = req.headers_mut().remove(AUTHORIZATION);

    if Method::CONNECT == req.method() {
        if let Some(host) = req.uri().host() {
            let port = req.uri().port_u16().unwrap_or(80);
            let s5addr = Address::from((host, port));

            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = tunnel(upgraded, s5addr, server).await {
                            log::error!("server io error: {}", e);
                        };
                    }
                    Err(e) => log::error!("upgrade error: {}", e),
                }
            });
            Ok(Response::new(empty()))
        } else {
            log::error!("CONNECT host is not socket addr: {:?}", req.uri());
            let mut resp = Response::new(full("CONNECT must be to a socket address"));
            *resp.status_mut() = hyper::http::StatusCode::BAD_REQUEST;
            Ok(resp)
        }
    } else {
        let host = req.uri().host().unwrap_or_default();
        let port = req.uri().port_u16().unwrap_or(80);
        let s5addr = Address::from((host, port));

        log::debug!("destination address {}", s5addr);
        log::debug!("connect to SOCKS5 proxy server {:?}", server);
        let stream = crate::create_s5_connect(server, CONNECT_TIMEOUT, &s5addr, None).await?;
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .handshake(io)
            .await
            .map_err(std_io_error_other)?;
        tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                log::error!("Connection failed: {:?}", err);
            }
        });
        let resp = sender.send_request(req).await.map_err(std_io_error_other)?;
        Ok(resp.map(|b| b.boxed()))
    }
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    http_body_util::Empty::<Bytes>::new().map_err(|never| match never {}).boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    http_body_util::Full::new(chunk.into()).map_err(|never| match never {}).boxed()
}

// Create a TCP connection to host:port, build a tunnel between the connection and
// the upgraded connection
async fn tunnel(upgraded: Upgraded, dst: Address, server: SocketAddr) -> std::io::Result<()> {
    let mut upgraded = TokioIo::new(upgraded);
    let mut server = crate::create_s5_connect(server, CONNECT_TIMEOUT, &dst, None).await?;
    let (from_client, from_server) = tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;
    log::debug!("client wrote {} bytes and received {} bytes", from_client, from_server);
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
