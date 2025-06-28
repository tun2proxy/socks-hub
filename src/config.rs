use serde_derive::{Deserialize, Serialize};
use socks5_impl::protocol::UserKey;
use std::net::SocketAddr;

/// Proxy tunnel from HTTP or SOCKS5 to SOCKS5
#[derive(Debug, Clone, clap::Parser, Serialize, Deserialize)]
#[command(author, version, about = "SOCKS5 hub for downstreams proxy of HTTP or SOCKS5.", long_about = None)]
pub struct Config {
    /// Source proxy role, URL in the form proto://[username[:password]@]host:port,
    /// where proto is one of socks5, http.
    /// Username and password are encoded in percent encoding. For example:
    /// http://myname:pass%40word@127.0.0.1:1080
    #[arg(short, long, value_parser = |s: &str| ArgProxy::try_from(s), value_name = "URL")]
    pub listen_proxy_role: ArgProxy,

    /// Remote SOCKS5 server, URL in form of socks5://[username[:password]@]host:port
    #[arg(short, long, value_parser = |s: &str| ArgProxy::try_from(s), value_name = "URL")]
    pub remote_server: ArgProxy,

    /// ACL (Access Control List) file path, optional
    #[arg(short, long, value_name = "path")]
    pub acl_file: Option<std::path::PathBuf>,

    /// Log verbosity level
    #[arg(short, long, value_name = "level", default_value = "info")]
    pub verbosity: ArgVerbosity,
}

impl Default for Config {
    fn default() -> Self {
        let remote_server: ArgProxy = "socks5://127.0.0.1:1080".try_into().unwrap();
        Config {
            listen_proxy_role: ArgProxy::default(),
            remote_server,
            acl_file: None,
            verbosity: ArgVerbosity::Info,
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

    pub fn acl_file<P: Into<std::path::PathBuf>>(&mut self, acl_file: P) -> &mut Self {
        self.acl_file = Some(acl_file.into());
        self
    }

    pub fn verbosity(&mut self, verbosity: ArgVerbosity) -> &mut Self {
        self.verbosity = verbosity;
        self
    }

    pub fn get_credentials(&self) -> Credentials {
        self.listen_proxy_role.credentials.clone().unwrap_or_default()
    }

    pub fn get_s5_credentials(&self) -> Credentials {
        self.remote_server.credentials.clone().unwrap_or_default()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArgProxy {
    pub proxy_type: ProxyType,
    pub addr: SocketAddr,
    pub credentials: Option<Credentials>,
}

impl Default for ArgProxy {
    fn default() -> Self {
        ArgProxy {
            proxy_type: ProxyType::Http,
            addr: "127.0.0.1:8080".parse().unwrap(),
            credentials: None,
        }
    }
}

impl std::fmt::Display for ArgProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let auth = match &self.credentials {
            Some(creds) => format!("{creds}"),
            None => "".to_owned(),
        };
        if auth.is_empty() {
            write!(f, "{}://{}", &self.proxy_type, &self.addr)
        } else {
            write!(f, "{}://{}@{}", &self.proxy_type, auth, &self.addr)
        }
    }
}

impl TryFrom<&str> for ArgProxy {
    type Error = std::io::Error;
    fn try_from(s: &str) -> std::result::Result<Self, Self::Error> {
        use std::io::{Error, ErrorKind::InvalidInput};
        let e = format!("`{s}` is not a valid proxy URL");
        let url = url::Url::parse(s).map_err(|_| Error::new(InvalidInput, e.clone()))?;
        let e = format!("`{s}` does not contain a host");
        let host = url.host_str().ok_or(Error::new(InvalidInput, e))?;

        let e = format!("`{s}` does not contain a port");
        let port = url.port_or_known_default().ok_or(Error::new(InvalidInput, e))?;

        let e2 = format!("`{host}` does not resolve to a usable IP address");
        use std::net::ToSocketAddrs;
        let addr = (host, port).to_socket_addrs()?.next().ok_or(Error::new(InvalidInput, e2))?;

        let credentials = if url.username() == "" && url.password().is_none() {
            None
        } else {
            use percent_encoding::percent_decode;
            let username = percent_decode(url.username().as_bytes())
                .decode_utf8()
                .map_err(|e| Error::new(InvalidInput, e))?;
            let password = percent_decode(url.password().unwrap_or("").as_bytes())
                .decode_utf8()
                .map_err(|e| Error::new(InvalidInput, e))?;
            Some(Credentials::new(&username, &password))
        };

        let proxy_type = url.scheme().to_ascii_lowercase().as_str().try_into()?;

        Ok(ArgProxy {
            proxy_type,
            addr,
            credentials,
        })
    }
}

#[repr(C)]
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize)]
pub enum ProxyType {
    #[default]
    Http = 0,
    Socks5,
}

impl std::fmt::Display for ProxyType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ProxyType::Http => write!(f, "http"),
            ProxyType::Socks5 => write!(f, "socks5"),
        }
    }
}

impl TryFrom<&str> for ProxyType {
    type Error = std::io::Error;
    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        use std::io::{Error, ErrorKind::InvalidInput};
        match value {
            "http" => Ok(ProxyType::Http),
            "socks5" => Ok(ProxyType::Socks5),
            scheme => Err(Error::new(InvalidInput, format!("`{scheme}` is an invalid proxy type"))),
        }
    }
}

#[repr(C)]
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize)]
pub enum ArgVerbosity {
    Off = 0,
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl From<ArgVerbosity> for log::LevelFilter {
    fn from(verbosity: ArgVerbosity) -> Self {
        match verbosity {
            ArgVerbosity::Off => log::LevelFilter::Off,
            ArgVerbosity::Error => log::LevelFilter::Error,
            ArgVerbosity::Warn => log::LevelFilter::Warn,
            ArgVerbosity::Info => log::LevelFilter::Info,
            ArgVerbosity::Debug => log::LevelFilter::Debug,
            ArgVerbosity::Trace => log::LevelFilter::Trace,
        }
    }
}

impl From<log::Level> for ArgVerbosity {
    fn from(level: log::Level) -> Self {
        match level {
            log::Level::Error => ArgVerbosity::Error,
            log::Level::Warn => ArgVerbosity::Warn,
            log::Level::Info => ArgVerbosity::Info,
            log::Level::Debug => ArgVerbosity::Debug,
            log::Level::Trace => ArgVerbosity::Trace,
        }
    }
}

impl std::fmt::Display for ArgVerbosity {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ArgVerbosity::Off => write!(f, "off"),
            ArgVerbosity::Error => write!(f, "error"),
            ArgVerbosity::Warn => write!(f, "warn"),
            ArgVerbosity::Info => write!(f, "info"),
            ArgVerbosity::Debug => write!(f, "debug"),
            ArgVerbosity::Trace => write!(f, "trace"),
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Credentials {
    pub fn new(username: &str, password: &str) -> Self {
        Credentials {
            username: Some(username.to_string()),
            password: Some(password.to_string()),
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.to_string().as_bytes().to_vec()
    }

    pub fn is_empty(&self) -> bool {
        self.to_vec().is_empty()
    }
}

impl TryFrom<Credentials> for UserKey {
    type Error = std::io::Error;
    fn try_from(creds: Credentials) -> Result<Self, Self::Error> {
        match (creds.username, creds.password) {
            (Some(u), Some(p)) => Ok(UserKey::new(u, p)),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "username and password")),
        }
    }
}

impl std::fmt::Display for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use percent_encoding::{NON_ALPHANUMERIC, percent_encode};
        let empty = "".to_owned();
        let u = percent_encode(self.username.as_ref().unwrap_or(&empty).as_bytes(), NON_ALPHANUMERIC).to_string();
        let p = percent_encode(self.password.as_ref().unwrap_or(&empty).as_bytes(), NON_ALPHANUMERIC).to_string();
        match (u.is_empty(), p.is_empty()) {
            (true, true) => write!(f, ""),
            (true, false) => write!(f, ":{p}"),
            (false, true) => write!(f, "{u}:"),
            (false, false) => write!(f, "{u}:{p}"),
        }
    }
}
