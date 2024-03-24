# socks-hub

[![Crates.io](https://img.shields.io/crates/v/socks-hub.svg)](https://crates.io/crates/socks-hub)
![socks-hub](https://docs.rs/socks-hub/badge.svg)
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

Usage: socks-hub [OPTIONS] --listen-addr <IP:port> --server-addr <IP:port>

Options:
  -t, --source-type <http|socks5>  Source proxy type [default: http] [possible values: http, socks5]
  -l, --listen-addr <IP:port>      Local listening address
  -u, --username <username>        Client authentication username, available both for HTTP and SOCKS5, optional
  -p, --password <password>        Client authentication password, available both for HTTP and SOCKS5, optional
  -s, --server-addr <IP:port>      Remote SOCKS5 server address
      --s5-username <username>     Remote SOCKS5 server authentication username, optional
      --s5-password <password>     Remote SOCKS5 server authentication password, optional
  -a, --acl-file <path>            ACL (Access Control List) file path, optional
  -v, --verbosity <level>          Log verbosity level [default: info] [possible values: off, error, warn, info, debug, trace]
  -h, --help                       Print help
  -V, --version                    Print version
```
