use serde_derive::{Deserialize, Serialize};
use socks5_impl::protocol::UserKey;
use std::net::SocketAddr;

/// Proxy tunnel from HTTP or SOCKS5 to SOCKS5
#[derive(Debug, Clone, clap::Parser, Serialize, Deserialize)]
#[command(author, version, about = "SOCKS5 hub for downstreams proxy of HTTP or SOCKS5.", long_about = None)]
pub struct Config {
    /// Source proxy type
    #[arg(short = 't', long, value_name = "http|socks5", default_value = "http")]
    pub source_type: ProxyType,

    /// Local listening address
    #[arg(short, long, value_name = "IP:port")]
    pub listen_addr: SocketAddr,

    /// Remote SOCKS5 server address
    #[arg(short, long, value_name = "IP:port")]
    pub server_addr: SocketAddr,

    /// Client authentication username, available both for HTTP and SOCKS5, optional
    #[arg(short, long, value_name = "username")]
    pub username: Option<String>,

    /// Client authentication password, available both for HTTP and SOCKS5, optional
    #[arg(short, long, value_name = "password")]
    pub password: Option<String>,

    /// SOCKS5 server authentication username, optional
    #[arg(long, value_name = "username")]
    pub s5_username: Option<String>,

    /// SOCKS5 server authentication password, optional
    #[arg(long, value_name = "password")]
    pub s5_password: Option<String>,

    /// ACL file path
    #[arg(short, long, value_name = "path")]
    pub acl_file: Option<std::path::PathBuf>,

    /// Log verbosity level
    #[arg(short, long, value_name = "level", default_value = "info")]
    pub verbosity: ArgVerbosity,
}

impl Default for Config {
    fn default() -> Self {
        let listen_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let server_addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        Config {
            source_type: ProxyType::Http,
            listen_addr,
            server_addr,
            username: None,
            password: None,
            s5_username: None,
            s5_password: None,
            acl_file: None,
            verbosity: ArgVerbosity::Info,
        }
    }
}

impl Config {
    pub fn parse_args() -> Self {
        use clap::Parser;
        Self::parse()
    }

    pub fn new(listen_addr: SocketAddr, server_addr: SocketAddr) -> Self {
        Config {
            listen_addr,
            server_addr,
            ..Config::default()
        }
    }

    pub fn source_type(&mut self, source_type: ProxyType) -> &mut Self {
        self.source_type = source_type;
        self
    }

    pub fn listen_addr(&mut self, listen_addr: SocketAddr) -> &mut Self {
        self.listen_addr = listen_addr;
        self
    }

    pub fn server_addr(&mut self, server_addr: SocketAddr) -> &mut Self {
        self.server_addr = server_addr;
        self
    }

    pub fn username(&mut self, username: &str) -> &mut Self {
        self.username = Some(username.to_string());
        self
    }

    pub fn password(&mut self, password: &str) -> &mut Self {
        self.password = Some(password.to_string());
        self
    }

    pub fn s5_username(&mut self, s5_username: &str) -> &mut Self {
        self.s5_username = Some(s5_username.to_string());
        self
    }

    pub fn s5_password(&mut self, s5_password: &str) -> &mut Self {
        self.s5_password = Some(s5_password.to_string());
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
        Credentials {
            username: self.username.clone(),
            password: self.password.clone(),
        }
    }

    pub fn get_s5_credentials(&self) -> Credentials {
        Credentials {
            username: self.s5_username.clone(),
            password: self.s5_password.clone(),
        }
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
        let empty = "".to_owned();
        let u = self.username.as_ref().unwrap_or(&empty);
        let p = self.password.as_ref().unwrap_or(&empty);
        match (u.is_empty(), p.is_empty()) {
            (true, true) => b"".to_vec(),
            (true, false) => format!(":{}", p).as_bytes().to_vec(),
            (false, true) => format!("{}:", u).as_bytes().to_vec(),
            (false, false) => format!("{}:{}", u, p).as_bytes().to_vec(),
        }
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
