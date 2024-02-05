#![cfg(not(target_os = "android"))]

use crate::{ArgVerbosity, Config, SourceType};
use std::os::raw::{c_char, c_int};

/// # Safety
///
/// Run the socks-hub component with some arguments, this function will block the current thread until the `socks_hub_stop` function is called in another thread.
/// The `source_type` argument is the source type, which is an integer from 0 to 1, where 0 means HTTP and 1 means SOCKS5.
/// The `local_addr` argument is the local listening address, which is a string in the format of "IP:port".
/// The `server_addr` argument is the remote SOCKS5 server address, which is a string in the format of "IP:port".
/// The `verbosity` argument is the verbosity level, which is an integer from 0 to 5, where 0 means off, 1 means error, 2 means warn, 3 means info, 4 means debug, and 5 means trace.
#[no_mangle]
pub unsafe extern "C" fn socks_hub_run(
    source_type: SourceType,
    local_addr: *const c_char,
    server_addr: *const c_char,
    verbosity: ArgVerbosity,
) -> c_int {
    log::set_max_level(verbosity.into());
    log::set_boxed_logger(Box::<crate::dump_logger::DumpLogger>::default()).unwrap();

    let local_addr = std::ffi::CStr::from_ptr(local_addr).to_str().unwrap();
    let local_addr = local_addr.parse().unwrap();

    let server_addr = std::ffi::CStr::from_ptr(server_addr).to_str().unwrap();
    let server_addr = server_addr.parse().unwrap();

    let mut config = Config::default();
    config
        .source_type(source_type)
        .verbosity(verbosity)
        .local_addr(local_addr)
        .server_addr(server_addr);

    crate::api::api_internal_run(config)
}

/// # Safety
///
/// Shutdown the socks-hub component.
/// This function must be called in another thread to stop the `socks_hub_run` function.
#[no_mangle]
pub unsafe extern "C" fn socks_hub_stop() -> c_int {
    crate::api::api_internal_stop()
}
