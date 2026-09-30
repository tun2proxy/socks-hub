use serde_derive::{Deserialize, Serialize};
use socks5_impl::protocol::{ProxyParameters, UserKey};

/// Proxy tunnel from HTTP or SOCKS5 to SOCKS5
#[derive(Debug, Clone, clap::Parser, Serialize, Deserialize)]
#[command(author, version, about = "SOCKS5 hub for downstreams proxy of HTTP or SOCKS5.", long_about = None)]
pub struct Config {
    /// Source proxy role, URL in the form proto://[username[:password]@]host:port,
    /// where proto is one of socks5, http, or none.
    /// If proto is none, the program will detect the protocol automatically.
    /// Username and password are encoded in percent encoding. For example:
    /// none://myname:pass%40word@127.0.0.1:1080
    #[arg(short, long, value_parser = |s: &str| ProxyParameters::try_from(s), value_name = "URL")]
    pub listen_proxy_role: ProxyParameters,

    /// Optional middle SOCKS5 server, URL in form of socks5://[username[:password]@]host:port
    #[arg(short, long, value_parser = |s: &str| ProxyParameters::try_from(s), value_name = "URL")]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub middle_server: Option<ProxyParameters>,

    /// Target SOCKS5 server, URL in form of socks5://[username[:password]@]host:port
    #[arg(short, long, value_parser = |s: &str| ProxyParameters::try_from(s), value_name = "URL")]
    pub remote_server: ProxyParameters,

    /// ACL (Access Control List) file path, optional
    #[arg(short, long, value_name = "path")]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub acl_file: Option<std::path::PathBuf>,

    /// Log verbosity level, ranging from off, error, warn, info, debug, to trace.
    #[arg(short, long, value_name = "level", default_value = "info")]
    pub verbosity: log::LevelFilter,
}

impl Default for Config {
    fn default() -> Self {
        let remote_server: ProxyParameters = "socks5://127.0.0.1:1080".try_into().unwrap();
        Config {
            listen_proxy_role: ProxyParameters::default(),
            middle_server: None,
            remote_server,
            acl_file: None,
            verbosity: log::LevelFilter::Info,
        }
    }
}

impl Config {
    pub fn parse_args() -> Self {
        <Self as clap::Parser>::parse()
    }

    pub fn new(listen_proxy_role: &str, remote_server: &str) -> Self {
        Config {
            listen_proxy_role: listen_proxy_role.try_into().unwrap(),
            middle_server: None,
            remote_server: remote_server.try_into().unwrap(),
            ..Config::default()
        }
    }

    pub fn listen_proxy_role(&mut self, listen_proxy_role: &str) -> &mut Self {
        self.listen_proxy_role = listen_proxy_role.try_into().unwrap();
        self
    }

    pub fn remote_server(&mut self, remote_server: &str) -> &mut Self {
        self.remote_server = remote_server.try_into().unwrap();
        self
    }

    pub fn middle_server(&mut self, middle_server: &str) -> &mut Self {
        self.middle_server = Some(middle_server.try_into().unwrap());
        self
    }

    pub fn middle_server_opt(&mut self, middle_server: Option<&str>) -> &mut Self {
        if let Some(middle_server) = middle_server {
            self.middle_server(middle_server);
        }
        self
    }

    pub fn acl_file<P: Into<std::path::PathBuf>>(&mut self, acl_file: P) -> &mut Self {
        self.acl_file = Some(acl_file.into());
        self
    }

    pub fn verbosity(&mut self, verbosity: log::LevelFilter) -> &mut Self {
        self.verbosity = verbosity;
        self
    }

    pub fn get_listen_credentials(&self) -> UserKey {
        self.listen_proxy_role.credentials.clone().unwrap_or_default()
    }

    pub fn get_s5_credentials(&self) -> UserKey {
        self.remote_server.credentials.clone().unwrap_or_default()
    }

    pub fn get_middle_s5_credentials(&self) -> UserKey {
        self.middle_server
            .as_ref()
            .and_then(|proxy| proxy.credentials.clone())
            .unwrap_or_default()
    }
}
