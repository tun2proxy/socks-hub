#![cfg(not(target_os = "android"))]

use crate::{ArgVerbosity, Config};
use std::{
    net::SocketAddr,
    os::raw::{c_char, c_int, c_void},
};

#[derive(Clone)]
pub struct CCallback(pub Option<unsafe extern "C" fn(c_int, *mut c_void)>, pub *mut c_void);

impl CCallback {
    pub unsafe fn call(self, arg: c_int) {
        if let Some(cb) = self.0 {
            cb(arg, self.1);
        }
    }
}

unsafe impl Send for CCallback {}
unsafe impl Sync for CCallback {}

/// # Safety
///
/// Run the socks-hub component with some arguments, this function will block the current thread
/// until the `socks_hub_stop` function is called in another thread.
/// - `listen_proxy_role`: The local listen address and the proxy role, which is a string in the format of
///   "http://username:password@127.0.0.1:8080" or "socks5://[username[:password]@]host:port".
/// - `remote_server`: The remote SOCKS5 server address, which is a string in the format of "socks5://[username[:password]@]host:port".
/// - `verbosity`: The verbosity level, which is an integer from 0 to 5,
///   where 0 means off, 1 means error, 2 means warn, 3 means info, 4 means debug, and 5 means trace.
/// - `callback`: A function pointer, which is an optional callback function that will be called when the server is listening on the local address.
/// - `ctx`: A pointer to the context, which is an optional pointer that will be passed to the callback function.
#[no_mangle]
pub unsafe extern "C" fn socks_hub_run(
    listen_proxy_role: *const c_char,
    remote_server: *const c_char,
    verbosity: ArgVerbosity,
    callback: Option<unsafe extern "C" fn(c_int, *mut c_void)>,
    ctx: *mut c_void,
) -> c_int {
    log::set_max_level(verbosity.into());
    if let Err(err) = log::set_boxed_logger(Box::<crate::dump_logger::DumpLogger>::default()) {
        log::warn!("Failed to set logger: {}", err);
    }

    let listen_proxy_role = std::ffi::CStr::from_ptr(listen_proxy_role).to_str().unwrap();

    let remote_server = std::ffi::CStr::from_ptr(remote_server).to_str().unwrap();

    let ccb = CCallback(callback, ctx);
    let cb = |addr: SocketAddr| {
        log::info!("Listening on {}", addr);
        let port = addr.port() as c_int;
        unsafe {
            ccb.call(port);
        }
    };

    let mut config = Config::default();
    config
        .listen_proxy_role(listen_proxy_role)
        .verbosity(verbosity)
        .remote_server(remote_server);

    crate::api::api_internal_run(config, Some(cb))
}

/// # Safety
///
/// Shutdown the socks-hub component.
/// This function must be called in another thread to stop the `socks_hub_run` function.
#[no_mangle]
pub unsafe extern "C" fn socks_hub_stop() -> c_int {
    crate::api::api_internal_stop()
}
