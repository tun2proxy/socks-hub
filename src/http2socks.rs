use crate::{BoxError, CONNECT_TIMEOUT, Config};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;

#[cfg(feature = "acl")]
static ACL_CENTER: std::sync::OnceLock<Option<crate::acl::AccessControl>> = std::sync::OnceLock::new();

pub async fn main_entry<F>(config: &Config, cancel_token: tokio_util::sync::CancellationToken, callback: Option<F>) -> Result<(), BoxError>
where
    F: FnOnce(SocketAddr) + Send + Sync + 'static,
{
    #[cfg(feature = "acl")]
    ACL_CENTER.get_or_init(|| {
        config
            .acl_file
            .as_ref()
            .and_then(|acl_file| match crate::acl::AccessControl::load_from_file(acl_file) {
                Ok(ac) => Some(ac),
                Err(e) => {
                    log::warn!("Could not init ACL: {e}");
                    None
                }
            })
    });

    let listen_addr: SocketAddr = config.listen_proxy_role.addr.clone().try_into()?;

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
            _ = cancel_token.cancelled() => {
                log::info!("quit signal received");
                break;
            }
            result = listener.accept() => {
                let (stream, incoming) = result?;
                tokio::task::spawn(async move {
                    let server = config.remote_server.clone();
                    let credentials = config.listen_proxy_role.credentials.clone().unwrap_or_default();
                    let middle_server = config.middle_server.clone();
                    let middle_server_for_conn = middle_server.clone();
                    let connector: crate::httpproxy::HttpConnector = Arc::new(move |dst| {
                        let server = server.clone();
                        let middle_server = middle_server_for_conn.clone();
                        Box::pin(async move {
                            let stream = crate::create_s5_connect(server, CONNECT_TIMEOUT, &dst, middle_server).await?;
                            Ok(Box::new(stream) as crate::httpproxy::BoxedStream)
                        })
                    });
                    if let Err(err) = crate::httpproxy::run_http_service(stream, connector, credentials).await {
                        log::error!("http service on incoming {incoming} error: {err}");
                    }
                });
            }
        }
    }
    Ok(())
}
