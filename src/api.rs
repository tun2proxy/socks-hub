use crate::Config;
use std::{net::SocketAddr, os::raw::c_int, sync::LazyLock, sync::Mutex};

static TUN_QUIT: LazyLock<Mutex<Option<tokio::sync::mpsc::Sender<()>>>> = LazyLock::new(|| Mutex::new(None));

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

        let (tx, quit) = tokio::sync::mpsc::channel::<()>(1);

        TUN_QUIT.lock().unwrap().replace(tx);

        crate::main_entry(&config, quit, callback).await?;
        Ok::<_, crate::BoxError>(())
    };

    match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Err(_err) => {
            log::error!("failed to create tokio runtime with error: {:?}", _err);
            -1
        }
        Ok(rt) => match rt.block_on(block) {
            Ok(_) => 0,
            Err(_err) => {
                log::error!("failed to run socks-hub with error: {:?}", _err);
                -2
            }
        },
    }
}

pub(crate) fn api_internal_stop() -> c_int {
    let res = match TUN_QUIT.lock().unwrap().take() {
        None => {
            log::error!("socks-hub not started");
            -1
        }
        Some(tun_quit) => match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
            Err(_err) => {
                log::error!("failed to create tokio runtime with error: {:?}", _err);
                -2
            }
            Ok(rt) => match rt.block_on(async move { tun_quit.send(()).await }) {
                Ok(_) => 0,
                Err(_err) => {
                    log::error!("failed to stop socks-hub with error: {:?}", _err);
                    -3
                }
            },
        },
    };
    res
}
