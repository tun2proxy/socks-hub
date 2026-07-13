use crate::{TokioIo, std_io_error_other};
use bytes::Bytes;
use http_body_util::{BodyExt, combinators::BoxBody};
use hyper::{
    Method, Request, Response,
    header::{CONNECTION, HeaderMap, HeaderValue, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION},
    service::service_fn,
    upgrade::Upgraded,
};
use socks5_impl::protocol::{Address, UserKey};
use std::{future::Future, pin::Pin, sync::Arc};

const HTTP_DEFAULT_PORT: u16 = 80;

pub trait TokioStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + Unpin> TokioStream for T {}

pub type BoxedStream = Box<dyn TokioStream>;
pub type BoxedConnectFuture = Pin<Box<dyn Future<Output = std::io::Result<BoxedStream>> + Send + 'static>>;
pub type HttpConnector = Arc<dyn Fn(Address) -> BoxedConnectFuture + Send + Sync>;

#[cfg(feature = "acl")]
use crate::acl::TargetDecision;

#[cfg(feature = "acl")]
static ACL_CENTER: std::sync::OnceLock<Option<crate::acl::AccessControl>> = std::sync::OnceLock::new();

pub async fn run_http_service(stream: tokio::net::TcpStream, connector: HttpConnector, credentials: UserKey) -> std::io::Result<()> {
    let io = TokioIo::new(stream);
    hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(
            io,
            service_fn(|req: Request<hyper::body::Incoming>| {
                let connector = connector.clone();
                let credentials = credentials.clone();
                async move { proxy(req, connector, credentials).await }
            }),
        )
        .with_upgrades()
        .await
        .map_err(std_io_error_other)?;
    Ok(())
}

async fn proxy(
    mut req: Request<hyper::body::Incoming>,
    connector: HttpConnector,
    credentials: UserKey,
) -> std::io::Result<Response<BoxBody<Bytes, hyper::Error>>> {
    //
    // https://github.com/hyperium/hyper/blob/90eb95f62a32981cb662b0f750027231d8a2586b/examples/http_proxy.rs#L51
    //
    log::trace!("req: {req:?}");

    let auth_value = req.headers().get(PROXY_AUTHORIZATION);
    // Some clients may omit proxy auth on the first CONNECT request and retry after a 407 challenge.
    if !is_proxy_authorized(&credentials, auth_value) {
        log::warn!("authorization fail");
        let mut resp = Response::new(empty());
        *resp.status_mut() = hyper::StatusCode::PROXY_AUTHENTICATION_REQUIRED;
        resp.headers_mut()
            .insert(PROXY_AUTHENTICATE, HeaderValue::from_static("Basic realm=\"socks-hub\""));
        return Ok(resp);
    }
    if auth_value.is_some() {
        let _ = req.headers_mut().remove(PROXY_AUTHORIZATION);
    }

    if Method::CONNECT == req.method() {
        if let Some(host) = req.uri().host() {
            let port = req.uri().port_u16().unwrap_or(HTTP_DEFAULT_PORT);
            let up_addr = Address::from((host, port));

            #[cfg(feature = "acl")]
            {
                if let Some(Some(acl)) = ACL_CENTER.get() {
                    match acl.decide_target(&up_addr).await {
                        TargetDecision::Proxy | TargetDecision::Bypass => {}
                        TargetDecision::Block => {
                            let mut resp = Response::new(full("blocked by ACL"));
                            *resp.status_mut() = hyper::http::StatusCode::FORBIDDEN;
                            return Ok(resp);
                        }
                    }
                }
            }

            let connector = connector.clone();
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = tunnel(upgraded, up_addr, connector).await {
                            log::error!("server io error: {e}");
                        };
                    }
                    Err(e) => log::error!("upgrade error: {e}"),
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
        remove_hop_by_hop_headers(req.headers_mut());
        let host = req.uri().host().unwrap_or_default();
        let port = req.uri().port_u16().unwrap_or(HTTP_DEFAULT_PORT);
        let up_addr = Address::from((host, port));

        log::debug!("destination address {up_addr}");

        #[cfg(feature = "acl")]
        {
            let mut must_proxied = true;
            if let Some(Some(acl)) = ACL_CENTER.get() {
                match acl.decide_target(&up_addr).await {
                    TargetDecision::Proxy => must_proxied = true,
                    TargetDecision::Bypass => must_proxied = false,
                    TargetDecision::Block => {
                        let mut resp = Response::new(full("blocked by ACL"));
                        *resp.status_mut() = hyper::http::StatusCode::FORBIDDEN;
                        return Ok(resp);
                    }
                }
            }
            if !must_proxied {
                log::debug!("connect to destination address {up_addr:?} without proxy");
                let stream = tokio::net::TcpStream::connect((host, port)).await?;
                return proxy_internal(stream, req).await;
            }
        }

        log::debug!("connect to upstream proxy for {up_addr:?}");
        let stream = connector(up_addr).await?;
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
            log::error!("Connection failed: {err:?}");
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

fn remove_hop_by_hop_headers(headers: &mut HeaderMap<HeaderValue>) {
    let connection_values = headers
        .get(CONNECTION)
        .and_then(|connection| connection.to_str().ok())
        .map(|connection_value| connection_value.to_owned());

    if let Some(connection_value) = connection_values {
        for name in connection_value.split(',') {
            let name = name.trim();
            if !name.is_empty() {
                headers.remove(name);
            }
        }
    }

    for header_name in &[
        "connection",
        "proxy-authorization",
        "proxy-authenticate",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
    ] {
        headers.remove(*header_name);
    }
}

// Create a TCP connection to host:port, build a tunnel between the connection and
// the upgraded connection
async fn tunnel(upgraded: Upgraded, dst: Address, connector: HttpConnector) -> std::io::Result<()> {
    #[cfg(feature = "acl")]
    {
        let mut must_proxied = true;
        if let Some(Some(acl)) = ACL_CENTER.get() {
            match acl.decide_target(&dst).await {
                TargetDecision::Proxy => must_proxied = true,
                TargetDecision::Bypass => must_proxied = false,
                TargetDecision::Block => {
                    return Err(std_io_error_other("blocked by ACL"));
                }
            }
        }
        if !must_proxied {
            log::debug!("connect to destination address {dst:?} without proxy");
            let mut upgraded = TokioIo::new(upgraded);
            use std::net::ToSocketAddrs;
            let addr = dst.to_socket_addrs()?.next().ok_or(std_io_error_other("no address found"))?;
            let mut server = tokio::net::TcpStream::connect(addr).await?;
            let (from_client, from_server) = tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;
            log::debug!("client wrote {from_client} bytes and received {from_server} bytes");
            return Ok(());
        }
    }

    let mut upgraded = TokioIo::new(upgraded);
    let mut server = connector(dst).await?;
    let (from_client, from_server) = tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;
    log::debug!("client wrote {from_client} bytes and received {from_server} bytes");
    Ok(())
}

fn verify_basic_authorization(credentials: &UserKey, header_value: Option<&HeaderValue>) -> bool {
    if header_value.is_none() && credentials.to_string().is_empty() {
        return true;
    }
    header_value
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            let s = s.trim();
            let mut parts = s.splitn(2, ' ');
            let scheme = parts.next()?;
            let encoded = parts.next()?.trim();
            if !scheme.eq_ignore_ascii_case("Basic") {
                return None;
            }
            base64easy::decode(encoded, base64easy::EngineKind::Standard).ok()
        })
        .is_some_and(|v| v == credentials.to_string().as_bytes().to_vec())
}

fn is_proxy_authorized(credentials: &UserKey, header_value: Option<&HeaderValue>) -> bool {
    credentials.to_string().is_empty() || verify_basic_authorization(credentials, header_value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{AUTHORIZATION, PROXY_AUTHORIZATION, UPGRADE};

    #[test]
    fn connect_requires_proxy_auth_when_credentials_are_configured() {
        let credentials = UserKey::new("alice", "secret");
        assert!(!is_proxy_authorized(&credentials, None));
    }

    #[test]
    fn connect_allows_missing_proxy_auth_when_no_credentials_are_configured() {
        let credentials = UserKey::default();
        assert!(is_proxy_authorized(&credentials, None));
    }

    #[test]
    fn proxy_authorization_header_is_used_for_proxy_auth() {
        let credentials = UserKey::new("alice", "secret");
        let value = HeaderValue::from_str("Basic YWxpY2U6c2VjcmV0").unwrap();
        assert!(is_proxy_authorized(&credentials, Some(&value)));
    }

    #[test]
    fn authorization_header_is_not_used_for_proxy_auth() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic YWxpY2U6c2VjcmV0"));
        assert!(headers.get(PROXY_AUTHORIZATION).is_none());
    }

    #[test]
    fn remove_hop_by_hop_headers_strips_connection_values() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("keep-alive, Upgrade"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5, max=1000"));
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(PROXY_AUTHORIZATION, HeaderValue::from_static("Basic test"));

        remove_hop_by_hop_headers(&mut headers);

        assert!(headers.get(CONNECTION).is_none());
        assert!(headers.get("keep-alive").is_none());
        assert!(headers.get(UPGRADE).is_none());
        assert!(headers.get(PROXY_AUTHORIZATION).is_none());
    }
}
