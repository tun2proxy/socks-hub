use crate::{base64_decode, std_io_error_other, Base64Engine, BoxError, Config, Credentials, TokioIo, CONNECT_TIMEOUT};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::{
    header::{HeaderName, HeaderValue, AUTHORIZATION, PROXY_AUTHORIZATION},
    service::service_fn,
    upgrade::Upgraded,
    Method, Request, Response,
};
use socks5_impl::protocol::{Address, UserKey};
use std::net::SocketAddr;
use tokio::{net::TcpListener, sync::mpsc::Receiver};

#[cfg(feature = "acl")]
static ACL_CENTER: std::sync::OnceLock<Option<crate::acl::AccessControl>> = std::sync::OnceLock::new();

pub async fn main_entry<F>(config: &Config, mut quit: Receiver<()>, callback: Option<F>) -> Result<(), BoxError>
where
    F: FnOnce(SocketAddr) + Send + Sync + 'static,
{
    #[cfg(feature = "acl")]
    ACL_CENTER.get_or_init(|| {
        config
            .acl_file
            .as_ref()
            .and_then(|acl_file| crate::acl::AccessControl::load_from_file(acl_file).ok())
    });

    let listen_addr = config.listen_proxy_role.addr;

    let listener = TcpListener::bind(listen_addr).await?;

    if let Some(callback) = callback {
        callback(listener.local_addr()?);
    } else {
        log::info!("Listening on {}", config.listen_proxy_role);
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

    let server = config.remote_server.addr;
    let credentials = config.get_credentials();
    let s5_auth = config.get_s5_credentials().try_into().ok();

    fn get_proxy_authorization(req: &Request<hyper::body::Incoming>) -> (Option<HeaderName>, Option<&HeaderValue>) {
        if let Some(header) = req.headers().get(AUTHORIZATION) {
            (Some(AUTHORIZATION), Some(header))
        } else if let Some(header) = req.headers().get(PROXY_AUTHORIZATION) {
            (Some(PROXY_AUTHORIZATION), Some(header))
        } else {
            (None, None)
        }
    }

    let (auth_header, auth_value) = get_proxy_authorization(&req);
    // Sometimes the CONNECT method will missing the authorization header, I think it's a bug of the browser.
    if Method::CONNECT != req.method() || auth_header.is_some() {
        if !verify_basic_authorization(&credentials, auth_value) {
            log::error!("authorization fail");
            let mut resp = Response::new(empty());
            *resp.status_mut() = hyper::StatusCode::UNAUTHORIZED;
            return Ok(resp);
        }
        if let Some(auth_header) = auth_header {
            let _ = req.headers_mut().remove(auth_header);
        }
    }

    if Method::CONNECT == req.method() {
        if let Some(host) = req.uri().host() {
            let port = req.uri().port_u16().unwrap_or(80);
            let s5addr = Address::from((host, port));

            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = tunnel(upgraded, s5addr, server, s5_auth).await {
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

        #[cfg(feature = "acl")]
        {
            let mut must_proxied = true;
            if let Some(Some(acl)) = ACL_CENTER.get() {
                must_proxied = acl.check_host_in_proxy_list(host).unwrap_or_default();
            }
            if !must_proxied {
                log::debug!("connect to destination address {:?} without proxy", s5addr);
                let stream = tokio::net::TcpStream::connect((host, port)).await?;
                return proxy_internal(stream, req).await;
            }
        }

        log::debug!("connect to SOCKS5 proxy server {:?}", server);
        let stream = crate::create_s5_connect(server, CONNECT_TIMEOUT, &s5addr, s5_auth).await?;
        proxy_internal(stream, req).await
    }
}

async fn proxy_internal<S>(stream: S, req: Request<hyper::body::Incoming>) -> Result<Response<BoxBody<Bytes, hyper::Error>>, std::io::Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + 'static + Unpin,
{
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

fn empty() -> BoxBody<Bytes, hyper::Error> {
    http_body_util::Empty::<Bytes>::new().map_err(|never| match never {}).boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    http_body_util::Full::new(chunk.into()).map_err(|never| match never {}).boxed()
}

// Create a TCP connection to host:port, build a tunnel between the connection and
// the upgraded connection
async fn tunnel(upgraded: Upgraded, dst: Address, server: SocketAddr, auth: Option<UserKey>) -> std::io::Result<()> {
    #[cfg(feature = "acl")]
    {
        let mut must_proxied = true;
        if let Some(Some(acl)) = ACL_CENTER.get() {
            must_proxied = acl.check_host_in_proxy_list(&dst.domain()).unwrap_or_default();
        }
        if !must_proxied {
            log::debug!("connect to destination address {:?} without proxy", dst);
            let mut upgraded = TokioIo::new(upgraded);
            use std::net::ToSocketAddrs;
            let addr = dst.to_socket_addrs()?.next().ok_or(std_io_error_other("no address found"))?;
            let mut server = tokio::net::TcpStream::connect(addr).await?;
            let (from_client, from_server) = tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;
            log::debug!("client wrote {} bytes and received {} bytes", from_client, from_server);
            return Ok(());
        }
    }

    let mut upgraded = TokioIo::new(upgraded);
    let mut server = crate::create_s5_connect(server, CONNECT_TIMEOUT, &dst, auth).await?;
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
