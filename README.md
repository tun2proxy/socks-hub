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
  -r, --remote-server <URL>      Remote SOCKS5 server, URL in form of socks5://[username[:password]@]host:port
  -a, --acl-file <path>          ACL (Access Control List) file path, optional
  -v, --verbosity <level>        Log verbosity level [default: info] [possible values: off, error, warn, info, debug, trace]
  -h, --help                     Print help
  -V, --version                  Print version
```
