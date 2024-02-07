#![cfg(not(target_os = "android"))]

use crate::{ArgVerbosity, Config, SourceType};
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
/// Run the socks-hub component with some arguments, this function will block the current thread until the `socks_hub_stop` function is called in another thread.
/// The `source_type` argument is the source type, which is an integer from 0 to 1, where 0 means HTTP and 1 means SOCKS5.
/// The `local_addr` argument is the local listening address, which is a string in the format of "IP:port".
/// The `server_addr` argument is the remote SOCKS5 server address, which is a string in the format of "IP:port".
/// The `verbosity` argument is the verbosity level, which is an integer from 0 to 5, where 0 means off, 1 means error, 2 means warn, 3 means info, 4 means debug, and 5 means trace.
/// The `callback` argument is a function pointer, which is an optional callback function that will be called when the server is listening on the local address.
/// The `ctx` argument is a pointer to the context, which is an optional pointer that will be passed to the callback function.
#[no_mangle]
pub unsafe extern "C" fn socks_hub_run(
    source_type: SourceType,
    local_addr: *const c_char,
    server_addr: *const c_char,
    verbosity: ArgVerbosity,
    callback: Option<unsafe extern "C" fn(c_int, *mut c_void)>,
    ctx: *mut c_void,
) -> c_int {
    log::set_max_level(verbosity.into());
    log::set_boxed_logger(Box::<crate::dump_logger::DumpLogger>::default()).unwrap();

    let local_addr = std::ffi::CStr::from_ptr(local_addr).to_str().unwrap();
    let local_addr = local_addr.parse().unwrap();

    let server_addr = std::ffi::CStr::from_ptr(server_addr).to_str().unwrap();
    let server_addr = server_addr.parse().unwrap();

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
        .source_type(source_type)
        .verbosity(verbosity)
        .local_addr(local_addr)
        .server_addr(server_addr);

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
