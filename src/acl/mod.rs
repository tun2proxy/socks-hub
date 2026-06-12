//! Access Control List (ACL) from shadowsocks
//!
//! This is for advance controlling server behaviors in both local and proxy servers.
//!
//! The ACL has one shared target-routing rule set used by both client-side and server-side
//! proxy decisions. Server-only rules are limited to peer blocking and outbound blocking.
//!
//! source link https://github.com/shadowsocks/shadowsocks-rust/blob/master/crates/shadowsocks-service/src/acl/mod.rs
//!

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use iprange::IpRange;
use regex::bytes::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
pub use socks5_impl::protocol::Address;
use std::{
    borrow::Cow,
    collections::HashSet,
    fmt,
    fs::File,
    io::{self, BufRead, BufReader, Error},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    str,
};

mod sub_domains_tree;
use sub_domains_tree::SubDomainsTree;

/// Result of evaluating how a target should be handled.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TargetDecision {
    Proxy,
    Bypass,
    Block,
}

impl TargetDecision {
    pub fn should_proxy(self) -> bool {
        matches!(self, TargetDecision::Proxy)
    }

    pub fn should_bypass(self) -> bool {
        matches!(self, TargetDecision::Bypass)
    }

    pub fn should_block(self) -> bool {
        matches!(self, TargetDecision::Block)
    }
}

#[derive(Clone)]
struct Rules {
    ipv4: IpRange<Ipv4Net>,
    ipv6: IpRange<Ipv6Net>,
    rule_regex: RegexSet,
    rule_set: HashSet<String>,
    rule_tree: SubDomainsTree,
}

impl fmt::Debug for Rules {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Rules {{ ipv4: {:?}, ipv6: {:?}, rule_regex: [", self.ipv4, self.ipv6)?;

        let max_len = 2;
        let has_more = self.rule_regex.len() > max_len;

        for (idx, r) in self.rule_regex.patterns().iter().take(max_len).enumerate() {
            if idx > 0 {
                f.write_str(", ")?;
            }
            f.write_str(r)?;
        }

        if has_more {
            f.write_str(", ...")?;
        }

        write!(f, "], rule_set: [")?;

        let has_more = self.rule_set.len() > max_len;
        for (idx, r) in self.rule_set.iter().take(max_len).enumerate() {
            if idx > 0 {
                f.write_str(", ")?;
            }
            f.write_str(r)?;
        }

        if has_more {
            f.write_str(", ...")?;
        }

        write!(f, "], rule_tree: {:?} }}", self.rule_tree)
    }
}

impl Rules {
    /// Create a new rule
    fn new(
        mut ipv4: IpRange<Ipv4Net>,
        mut ipv6: IpRange<Ipv6Net>,
        rule_regex: RegexSet,
        rule_set: HashSet<String>,
        rule_tree: SubDomainsTree,
    ) -> Rules {
        // Optimization, merging networks
        ipv4.simplify();
        ipv6.simplify();

        Rules {
            ipv4,
            ipv6,
            rule_regex,
            rule_set,
            rule_tree,
        }
    }

    /// Check if the specified address matches these rules
    #[allow(dead_code)]
    fn check_address_matched(&self, addr: &Address) -> bool {
        match *addr {
            Address::SocketAddress(ref saddr) => self.check_ip_matched(&saddr.ip()),
            Address::DomainAddress(ref domain, ..) => self.check_host_matched(domain),
        }
    }

    /// Check if the specified address matches any rules
    fn check_ip_matched(&self, addr: &IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => {
                if self.ipv4.contains(v4) {
                    return true;
                }

                let mapped_ipv6 = v4.to_ipv6_mapped();
                self.ipv6.contains(&mapped_ipv6)
            }
            IpAddr::V6(v6) => {
                if self.ipv6.contains(v6) {
                    return true;
                }

                if let Some(mapped_ipv4) = v6.to_ipv4_mapped() {
                    return self.ipv4.contains(&mapped_ipv4);
                }

                false
            }
        }
    }

    /// Check if the specified ASCII host matches any rules
    fn check_host_matched(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.'); // FQDN, removes the last `.`
        self.rule_set.contains(host) || self.rule_tree.contains(host) || self.rule_regex.is_match(host.as_bytes())
    }

    /// Check if there are no rules for IP addresses
    fn is_ip_empty(&self) -> bool {
        self.ipv4.is_empty() && self.ipv6.is_empty()
    }

    /// Check if there are no rules for domain names
    fn is_host_empty(&self) -> bool {
        self.rule_set.is_empty() && self.rule_tree.is_empty() && self.rule_regex.is_empty()
    }
}

struct ParsingRules {
    name: &'static str,
    ipv4: IpRange<Ipv4Net>,
    ipv6: IpRange<Ipv6Net>,
    rules_regex: Vec<String>,
    rules_set: HashSet<String>,
    rules_tree: SubDomainsTree,
}

impl ParsingRules {
    fn new(name: &'static str) -> Self {
        ParsingRules {
            name,
            ipv4: IpRange::new(),
            ipv6: IpRange::new(),
            rules_regex: Vec::new(),
            rules_set: HashSet::new(),
            rules_tree: SubDomainsTree::new(),
        }
    }

    fn add_ipv4_rule(&mut self, rule: impl Into<Ipv4Net>) {
        let rule = rule.into();
        // log::trace!("IPV4-RULE {}", rule);
        self.ipv4.add(rule);
    }

    fn add_ipv6_rule(&mut self, rule: impl Into<Ipv6Net>) {
        let rule = rule.into();
        log::trace!("IPV6-RULE {rule}");
        self.ipv6.add(rule);
    }

    fn add_regex_rule(&mut self, mut rule: String) {
        static TREE_SET_RULE_EQUIV: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let regex = TREE_SET_RULE_EQUIV.get_or_init(|| {
            RegexBuilder::new(r#"^(?:(?:\((?:\?:)?\^\|\\\.\)|(?:\^\.(?:\+|\*))?\\\.)((?:[\w-]+(?:\\\.)?)+)|\^((?:[\w-]+(?:\\\.)?)+))\$?$"#)
                .unicode(false)
                .build()
                .unwrap()
        });

        if let Some(caps) = regex.captures(rule.as_bytes()) {
            if let Some(tree_rule) = caps.get(1) {
                if let Ok(tree_rule) = str::from_utf8(tree_rule.as_bytes()) {
                    let tree_rule = tree_rule.replace("\\.", ".");
                    if self.add_tree_rule_inner(&tree_rule).is_ok() {
                        // log::trace!("REGEX-RULE {} => TREE-RULE {}", rule, tree_rule);
                        return;
                    }
                }
            } else if let Some(set_rule) = caps.get(2) {
                if let Ok(set_rule) = str::from_utf8(set_rule.as_bytes()) {
                    let set_rule = set_rule.replace("\\.", ".");
                    if self.add_set_rule_inner(&set_rule).is_ok() {
                        // log::trace!("REGEX-RULE {} => SET-RULE {}", rule, set_rule);
                        return;
                    }
                }
            }
        }

        // log::trace!("REGEX-RULE {}", rule);

        rule.make_ascii_lowercase();

        // Handle it as a normal REGEX
        // FIXME: If this line is not a valid regex, how can we know without actually compile it?
        self.rules_regex.push(rule);
    }

    #[inline]
    fn add_set_rule(&mut self, rule: &str) -> io::Result<()> {
        log::trace!("SET-RULE {rule}");
        self.add_set_rule_inner(rule)
    }

    fn add_set_rule_inner(&mut self, rule: &str) -> io::Result<()> {
        self.rules_set.insert(self.check_is_ascii(rule)?.to_ascii_lowercase());
        Ok(())
    }

    #[inline]
    fn add_tree_rule(&mut self, rule: &str) -> io::Result<()> {
        log::trace!("TREE-RULE {rule}");
        self.add_tree_rule_inner(rule)
    }

    fn add_rule_line(&mut self, line: &str) -> io::Result<()> {
        if let Some(rule) = line.strip_prefix("||") {
            self.add_tree_rule(rule)?;
            return Ok(());
        }

        if let Some(rule) = line.strip_prefix('|') {
            self.add_set_rule(rule)?;
            return Ok(());
        }

        match line.parse::<IpNet>() {
            Ok(IpNet::V4(v4)) => {
                self.add_ipv4_rule(v4);
                Ok(())
            }
            Ok(IpNet::V6(v6)) => {
                self.add_ipv6_rule(v6);
                Ok(())
            }
            Err(..) => match line.parse::<IpAddr>() {
                Ok(IpAddr::V4(v4)) => {
                    self.add_ipv4_rule(v4);
                    Ok(())
                }
                Ok(IpAddr::V6(v6)) => {
                    self.add_ipv6_rule(v6);
                    Ok(())
                }
                Err(..) => {
                    self.add_regex_rule(line.to_owned());
                    Ok(())
                }
            },
        }
    }

    fn add_tree_rule_inner(&mut self, rule: &str) -> io::Result<()> {
        // SubDomainsTree do lowercase conversion inside insert
        self.rules_tree.insert(self.check_is_ascii(rule)?);
        Ok(())
    }

    fn check_is_ascii<'a>(&self, str: &'a str) -> io::Result<&'a str> {
        if str.is_ascii() {
            // Remove the last `.` of FQDN
            Ok(str.trim_end_matches('.'))
        } else {
            Err(Error::other(format!(
                "{} parsing error: Unicode not allowed here `{str}`",
                self.name
            )))
        }
    }

    fn compile_regex(name: &'static str, regex_rules: Vec<String>) -> io::Result<RegexSet> {
        const REGEX_SIZE_LIMIT: usize = usize::MAX;
        RegexSetBuilder::new(regex_rules)
            .size_limit(REGEX_SIZE_LIMIT)
            .unicode(false)
            .build()
            .map_err(|err| Error::other(format!("{name} regex error: {err}")))
    }

    fn into_rules(self) -> io::Result<Rules> {
        Ok(Rules::new(
            self.ipv4,
            self.ipv6,
            Self::compile_regex(self.name, self.rules_regex)?,
            self.rules_set,
            self.rules_tree,
        ))
    }
}

/// ACL rules v2
///
/// ACL files are small ordered routing tables. They have one default action and a handful of
/// explicit sections:
///
/// - `[default proxy]` / `[default direct]` / `[default block]` - one line, specifies the default action
/// - `[proxy_rules]` - targets that must go through proxy
/// - `[direct_rules]` - targets that must connect directly
/// - `[client_block]` - client addresses that must be rejected by the server
/// - `[outbound_block]` / `[block]` - targets that must be blocked
///
/// Rule lines can be one of:
///
/// - CIDR network, like `10.9.0.32/16`
/// - IP address, like `127.0.0.1` or `::1`
/// - Exact domain, like `|google.com`
/// - Domain suffix, like `||google.com`
/// - Regular expression, like `(^|\.)gmail\.com$`
#[derive(Debug, Clone)]
pub struct AccessControl {
    default_action: TargetDecision,
    proxy_rules: Rules,
    direct_rules: Rules,
    client_block: Rules,
    outbound_block: Rules,
    file_path: PathBuf,
}

impl AccessControl {
    /// Load ACL rules from a file
    pub fn load_from_file<P: AsRef<Path>>(p: P) -> io::Result<AccessControl> {
        log::trace!("ACL loading from {:?}", p.as_ref());

        let file_path_ref = p.as_ref();
        let file_path = file_path_ref.to_path_buf();

        let fp = File::open(file_path_ref)?;
        let r = BufReader::new(fp);

        let mut default_action = None;

        let mut proxy = ParsingRules::new("[proxy_rules]");
        let mut direct = ParsingRules::new("[direct_rules]");
        let mut client_block = ParsingRules::new("[client_block]");
        let mut outbound_block = ParsingRules::new("[outbound_block]");
        let mut curr = &mut direct;

        enum Section {
            Default,
            ProxyRules,
            DirectRules,
            ClientBlock,
            OutboundBlock,
        }

        let mut section = Section::Default;

        for line in r.lines() {
            let line = line?;
            let line = line.trim();

            if line.is_empty() {
                continue;
            }

            // Comments
            if line.starts_with('#') {
                continue;
            }

            if !line.is_ascii() {
                log::warn!("ACL rule {line} containing non-ASCII characters, skipped");
                continue;
            }

            if line.starts_with('[') && line.ends_with(']') {
                let header = line[1..line.len() - 1].trim().to_ascii_lowercase();
                match header.as_str() {
                    "default proxy" => {
                        section = Section::Default;
                        default_action = Some(TargetDecision::Proxy);
                        curr = &mut direct;
                    }
                    "default direct" => {
                        section = Section::Default;
                        default_action = Some(TargetDecision::Bypass);
                        curr = &mut direct;
                    }
                    "default block" => {
                        section = Section::Default;
                        default_action = Some(TargetDecision::Block);
                        curr = &mut direct;
                    }
                    "proxy" | "proxy_rules" => {
                        section = Section::ProxyRules;
                        curr = &mut proxy;
                    }
                    "direct" | "direct_rules" => {
                        section = Section::DirectRules;
                        curr = &mut direct;
                    }
                    "client_block" => {
                        section = Section::ClientBlock;
                        curr = &mut client_block;
                    }
                    "outbound_block" | "block" => {
                        section = Section::OutboundBlock;
                        curr = &mut outbound_block;
                    }
                    _ => {
                        return Err(Error::other(format!("unknown ACL section: {line}")));
                    }
                }

                log::trace!("switch to section {line}");
                continue;
            }

            match section {
                Section::Default => {
                    let value = line.strip_prefix("default ").unwrap_or(line).trim();
                    if default_action.is_none() {
                        return Err(Error::other(format!("invalid default ACL action: {value}")));
                    }
                    log::trace!("set default action to {default_action:?}");
                }
                Section::ProxyRules | Section::DirectRules | Section::ClientBlock | Section::OutboundBlock => {
                    curr.add_rule_line(line)?;
                }
            }
        }

        Ok(AccessControl {
            default_action: default_action.ok_or_else(|| Error::other("default action not specified in ACL file"))?,
            proxy_rules: proxy.into_rules()?,
            direct_rules: direct.into_rules()?,
            client_block: client_block.into_rules()?,
            outbound_block: outbound_block.into_rules()?,
            file_path,
        })
    }

    /// Get ACL file path
    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    /// Check if there are no IP routing rules.
    pub fn is_ip_empty(&self) -> bool {
        self.proxy_rules.is_ip_empty() && self.direct_rules.is_ip_empty()
    }

    /// Check if there are no host routing rules.
    pub fn is_host_empty(&self) -> bool {
        self.proxy_rules.is_host_empty() && self.direct_rules.is_host_empty()
    }

    /// Decide how an ASCII domain should be handled.
    ///
    /// Returns the first matching action, or `None` if no rule matches.
    /// The caller can then fall back to the default action.
    pub fn decide_host(&self, host: &str) -> Option<TargetDecision> {
        let host = Self::normalize_host(host);
        if self.direct_rules.check_host_matched(&host) {
            return Some(TargetDecision::Bypass);
        }
        if self.proxy_rules.check_host_matched(&host) {
            return Some(TargetDecision::Proxy);
        }
        None
    }

    /// Normalize a domain name for rule matching.
    ///
    /// Hostnames are converted to ASCII when possible, then folded to lower-case because
    /// rule storage is case-insensitive.
    fn normalize_host(host: &str) -> Cow<'_, str> {
        idna::domain_to_ascii(host)
            .map(|host| Cow::Owned(host.to_ascii_lowercase()))
            .unwrap_or_else(|_| Cow::Owned(host.to_ascii_lowercase()))
    }

    /// Decide how a target should be handled.
    pub async fn decide_target(&self, addr: &Address) -> TargetDecision {
        match *addr {
            Address::SocketAddress(ref addr) => {
                if self.outbound_block.check_ip_matched(&addr.ip()) {
                    return TargetDecision::Block;
                }
                self.decide_socket_addr(&addr.ip())
            }
            Address::DomainAddress(ref host, port) => {
                if self.outbound_block.check_host_matched(&Self::normalize_host(host)) {
                    return TargetDecision::Block;
                }
                if let Some(value) = self.decide_host(host) {
                    return value;
                }
                if self.proxy_rules.is_ip_empty() && self.direct_rules.is_ip_empty() {
                    return self.default_action;
                }
                if let Ok(vaddr) = dns_resolve(host, port).await {
                    if vaddr.iter().any(|addr| self.outbound_block.check_ip_matched(&addr.ip())) {
                        return TargetDecision::Block;
                    }
                    if let Some(decision) = self.decide_resolved_ips(&vaddr) {
                        return decision;
                    }
                }
                self.default_action
            }
        }
    }

    /// Check if client address should be blocked (for server)
    pub fn check_client_blocked(&self, addr: &SocketAddr) -> bool {
        self.client_block.check_ip_matched(&addr.ip())
    }

    /// Check if outbound address is blocked (for server)
    ///
    /// NOTE: `Address::DomainAddress` is only validated by regex rules,
    ///       resolved addresses are checked in the `lookup_outbound_then!` macro
    pub async fn check_outbound_blocked(&self, outbound: &Address) -> bool {
        self.decide_target(outbound).await.should_block()
    }

    fn decide_socket_addr(&self, ip: &IpAddr) -> TargetDecision {
        if self.direct_rules.check_ip_matched(ip) {
            return TargetDecision::Bypass;
        }
        if self.proxy_rules.check_ip_matched(ip) {
            return TargetDecision::Proxy;
        }

        self.default_action
    }

    fn decide_resolved_ips(&self, addrs: &[SocketAddr]) -> Option<TargetDecision> {
        if addrs.iter().any(|addr| self.direct_rules.check_ip_matched(&addr.ip())) {
            return Some(TargetDecision::Bypass);
        }
        if addrs.iter().any(|addr| self.proxy_rules.check_ip_matched(&addr.ip())) {
            return Some(TargetDecision::Proxy);
        }

        None
    }
}

async fn dns_resolve(domain: &str, port: u16) -> std::io::Result<Vec<std::net::SocketAddr>> {
    let addrs = tokio::net::lookup_host((domain, port)).await?;
    Ok(addrs.collect())
}

#[tokio::test]
async fn test_dns_resolve() {
    let addrs = dns_resolve("baidu.com", 80).await.unwrap();
    println!("Resolved addresses: {addrs:?}");
    assert!(!addrs.is_empty());

    let addrs = dns_resolve("localhost", 80).await.unwrap();
    println!("Resolved addresses: {addrs:?}");
    assert!(!addrs.is_empty());

    let addrs = dns_resolve("123.45.67.89", 65535).await.unwrap();
    println!("Resolved addresses: {addrs:?}");
    assert!(!addrs.is_empty());

    let addrs = dns_resolve("xxxxsasasasd", 65535).await;
    assert!(addrs.is_err());
}

#[tokio::test]
async fn test_acl() {
    let acl_path = std::env::temp_dir().join(format!(
        "socks-hub-acl-v2-{}-{}.acl",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    std::fs::write(
        &acl_path,
        r#"
[default proxy]
[proxy]
||google.com
|sex.com
[direct]
127.0.0.1
||baidu.com
|example.com
192.168.0.0/16
[block]
10.0.0.0/8
"#,
    )
    .unwrap();

    let acl = AccessControl::load_from_file(&acl_path).unwrap();
    let _ = std::fs::remove_file(&acl_path);

    assert!(!acl.is_ip_empty());
    assert!(!acl.is_host_empty());

    assert_eq!(acl.decide_host("www.google.com"), Some(TargetDecision::Proxy));
    assert_eq!(acl.decide_host("www.baidu.com"), Some(TargetDecision::Bypass));
    assert_eq!(acl.decide_host("sex.com"), Some(TargetDecision::Proxy));
    assert_eq!(acl.decide_host("example.com"), Some(TargetDecision::Bypass));
    assert_eq!(acl.decide_host("youtube.com"), None);

    let proxy_addr = Address::SocketAddress(std::net::SocketAddr::from(([127, 0, 0, 1], 80)));
    let direct_addr = Address::SocketAddress(std::net::SocketAddr::from(([192, 168, 1, 10], 80)));
    let blocked_addr = Address::SocketAddress(std::net::SocketAddr::from(([10, 0, 0, 1], 80)));

    assert_eq!(acl.decide_target(&proxy_addr).await, TargetDecision::Bypass);
    assert_eq!(acl.decide_target(&direct_addr).await, TargetDecision::Bypass);
    assert!(acl.check_outbound_blocked(&blocked_addr).await);

    std::fs::write(
        &acl_path,
        r#"
[default block]
[proxy]
||example.com
"#,
    )
    .unwrap();

    let acl = AccessControl::load_from_file(&acl_path).unwrap();
    assert_eq!(
        acl.decide_target(&Address::from(("unmatched.test", 80))).await,
        TargetDecision::Block
    );
}
