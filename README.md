# socks-hub

[![Crates.io](https://img.shields.io/crates/v/socks-hub.svg)](https://crates.io/crates/socks-hub)
[![socks-hub](https://docs.rs/socks-hub/badge.svg)](https://crates.io/crates/socks-hub)
[![Documentation](https://img.shields.io/badge/docs-release-brightgreen.svg?style=flat)](https://docs.rs/socks-hub)
[![Download](https://img.shields.io/crates/d/socks-hub.svg)](https://crates.io/crates/socks-hub)
[![License](https://img.shields.io/crates/l/socks-hub.svg?style=flat)](https://github.com/ssrlive/socks-hub/blob/master/LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-blue.svg?maxAge=3600)](https://github.com/ssrlive/socks-hub)

`SOCKS-HUB` is a [SOCKS5](https://en.wikipedia.org/wiki/SOCKS#SOCKS5) proxy `hub`.
It can convert `HTTP`/`HTTPS` proxy to `SOCKS5` proxy, and can also forward `SOCKS5` proxy.

It is a simple and efficient alternative to [privoxy](https://www.privoxy.org/).
Compared with the tens of thousands of lines of `privoxy` code, `SOCKS-HUB` has only 800 lines of code,
so you won't have any mental burden when using it.

Wish you happy using it.

## Installation

### Install from binary

Download the binary from [releases](https://github.com/ssrlive/socks-hub/releases) and put it in your `PATH`.

### Install from source

If you have [rust](https://rustup.rs/) toolchain installed, this should work:
```shell
cargo install socks-hub
```

## Usage

```plaintext
SOCKS5 hub for downstreams proxy of HTTP or SOCKS5.

Usage: socks-hub.exe [OPTIONS] --listen-proxy-role <URL> --remote-server <URL>

Options:
  -l, --listen-proxy-role <URL>  Source proxy role, URL in the form proto://[username[:password]@]host:port, where proto is one of socks5,
                                 http. Username and password are encoded in percent encoding. For  
                                 example: http://myname:pass%40word@127.0.0.1:1080
  -m, --middle-server <URL>      Optional middle SOCKS5 server, URL in form of socks5://[username[:password]@]host:port
  -r, --remote-server <URL>      Remote SOCKS5 server, URL in form of socks5://[username[:password]@]host:port
  -a, --acl-file <path>          ACL (Access Control List) file path, optional
  -v, --verbosity <level>        Log verbosity level [default: info] [possible values: off, error, warn, info, debug, trace]
  -h, --help                     Print help
  -V, --version                  Print version
```

If you want a SOCKS5 chain, pass `-m` for the middle hop and `-r` for the final target SOCKS5 server.

The C API exports the same option as the second argument of `socks_hub_run`; pass `NULL` to skip the middle hop.

ACL files use a new explicit routing model:

- `[default proxy]` , `[default direct]` or `[default block]` selects the fallback action.
- `[proxy]` contains targets that must go through proxy.
- `[direct]` contains targets that must connect directly.
- `[outbound_block]` or `[block]` contains targets that must be blocked.
- Rules are evaluated within a section in file order, and the first match wins.

> Before running any test, generate the ACL file first:
> ```shell
> python3 genacl_proxy_gfw_bypass_china_ip.py --default-action block
> ```
> This generator builds the shared ACL file used by both client-side and server-side target routing,
> so the generated `proxy` and `direct` sections stay aligned with the current ACL behavior.
> Use `--default-action proxy`, `direct`, or `block` to choose the fallback behavior.

### Smoke tests

By default they use `target/debug/socks-hub`. Set `SOCKS_HUB_BIN` if the binary lives somewhere else.

The repository includes small Python smoke tests for the chained SOCKS5 flow:

```shell
python3 scripts/smoke_tcp_chain.py
python3 scripts/smoke_udp_chain.py
python3 scripts/smoke_tcp_direct.py
python3 scripts/smoke_udp_direct.py
```
