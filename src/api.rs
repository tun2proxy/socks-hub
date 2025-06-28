use crate::Config;
use std::{net::SocketAddr, os::raw::c_int, sync::LazyLock, sync::Mutex};

static TUN_QUIT: LazyLock<Mutex<Option<tokio_util::sync::CancellationToken>>> = LazyLock::new(|| Mutex::new(None));

pub(crate) fn api_internal_run<F>(config: Config, callback: Option<F>) -> c_int
where
    F: FnOnce(SocketAddr) + Send + Sync + 'static,
{
    if TUN_QUIT.lock().unwrap().is_some() {
        log::error!("socks-hub already started");
        return -1;
    }

    let block = async move {
        log::info!("config: {}", serde_json::to_string_pretty(&config)?);

        let cancel_token = tokio_util::sync::CancellationToken::new();

        TUN_QUIT.lock().unwrap().replace(cancel_token.clone());

        crate::main_entry(&config, cancel_token, callback).await?;
        Ok::<_, crate::BoxError>(())
    };

    match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Err(_err) => {
            log::error!("failed to create tokio runtime with error: {_err:?}");
            -1
        }
        Ok(rt) => match rt.block_on(block) {
            Ok(_) => 0,
            Err(_err) => {
                log::error!("failed to run socks-hub with error: {_err:?}");
                -2
            }
        },
    }
}

pub(crate) fn api_internal_stop() -> c_int {
    match TUN_QUIT.lock().unwrap().take() {
        None => {
            log::error!("socks-hub not started");
            -1
        }
        Some(tun_quit) => {
            tun_quit.cancel();
            0
        }
    }
}
