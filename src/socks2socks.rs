use crate::{BoxError, Config, Result, CONNECT_TIMEOUT};
use socks5_impl::{
    protocol::{Address, Reply, UdpHeader, UserKey},
    server::{
        auth,
        connection::{associate, connect},
        AssociatedUdpSocket, ClientConnection, Connect, IncomingConnection, Server, UdpAssociate,
    },
};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::UdpSocket;

#[cfg(feature = "acl")]
static ACL_CENTER: std::sync::OnceLock<Option<crate::acl::AccessControl>> = std::sync::OnceLock::new();

pub(crate) static MAX_UDP_RELAY_PACKET_SIZE: usize = 1500;

pub async fn main_entry<F>(config: &Config, cancel_token: tokio_util::sync::CancellationToken, callback: Option<F>) -> Result<(), BoxError>
where
    F: FnOnce(SocketAddr) + Send + Sync + 'static,
{
    #[cfg(feature = "acl")]
    ACL_CENTER.get_or_init(|| {
        config
            .acl_file
            .as_ref()
            .and_then(|acl_file| crate::acl::AccessControl::load_from_file(acl_file).ok())
    });

    let listen_addr = config.listen_proxy_role.addr;
    let server_addr = config.remote_server.addr;
    let credentials = config.get_credentials();
    let s5_auth = config.get_s5_credentials().try_into().ok();
    match (credentials.username, credentials.password) {
        (Some(username), Some(password)) => {
            let auth = Arc::new(auth::UserKeyAuth::new(&username, &password));
            main_loop(auth, listen_addr, server_addr, s5_auth, cancel_token, callback).await?;
        }
        _ => {
            let auth = Arc::new(auth::NoAuth);
            main_loop(auth, listen_addr, server_addr, s5_auth, cancel_token, callback).await?;
        }
    }

    Ok(())
}

async fn main_loop<S, F>(
    auth: auth::AuthAdaptor<S>,
    listen_addr: SocketAddr,
    server: SocketAddr,
    s5_auth: Option<UserKey>,
    cancel_token: tokio_util::sync::CancellationToken,
    callback: Option<F>,
) -> Result<()>
where
    S: Send + Sync + 'static,
    F: FnOnce(SocketAddr) + Send + Sync + 'static,
{
    let listener = Server::bind(listen_addr, auth).await?;
    if let Some(callback) = callback {
        callback(listener.local_addr()?);
    } else {
        log::info!("Listening on socks5://{}", listener.local_addr()?);
    }
    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                log::info!("quit signal received");
                break;
            }
            result = listener.accept() => {
                let (conn, _) = result?;
                let s5_auth = s5_auth.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle(conn, server, s5_auth).await {
                        log::error!("{err}");
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle<S>(conn: IncomingConnection<S>, server: SocketAddr, s5_auth: Option<UserKey>) -> Result<()>
where
    S: Send + Sync + 'static,
{
    let (conn, res) = conn.authenticate().await?;

    let res = &res as &dyn std::any::Any;
    if let Some(res) = res.downcast_ref::<std::io::Result<bool>>() {
        let res = *res.as_ref().map_err(|err| err.to_string())?;
        if !res {
            log::info!("authentication failed");
            return Ok(());
        }
    }

    match conn.wait_request().await? {
        ClientConnection::UdpAssociate(associate, _) => {
            handle_s5_upd_associate(associate, server, s5_auth).await?;
        }
        ClientConnection::Bind(bind, _) => {
            let mut conn = bind.reply(Reply::CommandNotSupported, Address::unspecified()).await?;
            conn.shutdown().await?;
        }
        ClientConnection::Connect(connect, dst) => {
            handle_s5_client_connection(connect, dst, server, s5_auth).await?;
        }
    }

    Ok(())
}

async fn handle_s5_client_connection(
    connect: Connect<connect::NeedReply>,
    dst: Address,
    server: SocketAddr,
    s5_auth: Option<UserKey>,
) -> Result<()> {
    #[cfg(feature = "acl")]
    {
        let mut must_proxied = true;
        if let Some(Some(acl)) = ACL_CENTER.get() {
            must_proxied = acl.check_host_in_proxy_list(&dst.domain()).unwrap_or_default();
        }
        if !must_proxied {
            log::debug!("connect to destination address {:?} without proxy", dst);
            use std::net::ToSocketAddrs;
            let addr = dst.to_socket_addrs()?.next().ok_or(crate::std_io_error_other("no address found"))?;
            let mut server = tokio::net::TcpStream::connect(addr).await?;
            let mut conn = connect.reply(Reply::Succeeded, Address::unspecified()).await?;
            log::trace!("{} -> {}", conn.peer_addr()?, dst);
            tokio::io::copy_bidirectional(&mut server, &mut conn).await?;
            return Ok(());
        }
    }

    let mut stream = crate::create_s5_connect(server, CONNECT_TIMEOUT, &dst, s5_auth).await?;
    let mut conn = connect.reply(Reply::Succeeded, Address::unspecified()).await?;
    log::trace!("{} -> {}", conn.peer_addr()?, dst);

    tokio::io::copy_bidirectional(&mut stream, &mut conn).await?;

    Ok(())
}

pub(crate) async fn handle_s5_upd_associate(
    associate: UdpAssociate<associate::NeedReply>,
    server: SocketAddr,
    s5_auth: Option<UserKey>,
) -> Result<()> {
    // listen on a random port
    let listen_ip = associate.local_addr()?.ip();
    let udp_listener = UdpSocket::bind(SocketAddr::from((listen_ip, 0))).await;

    let result = udp_listener.and_then(|socket| socket.local_addr().map(|addr| (socket, addr)));
    if let Err(err) = result {
        let mut conn = associate.reply(Reply::GeneralFailure, Address::unspecified()).await?;
        conn.shutdown().await?;
        return Err(err.into());
    }
    let (listen_udp, listen_addr) = result?;
    log::info!("[UDP] {listen_addr} listen on");

    let s5_listen_addr = Address::from(listen_addr);
    let mut reply_listener = associate.reply(Reply::Succeeded, s5_listen_addr).await?;

    let buf_size = MAX_UDP_RELAY_PACKET_SIZE - UdpHeader::max_serialized_len();
    let listen_udp = Arc::new(AssociatedUdpSocket::from((listen_udp, buf_size)));

    let incoming_addr = std::sync::OnceLock::new();

    // TODO: UserKey is always None, this is a bug
    let s5_udp_client = socks5_impl::client::create_udp_client(server, s5_auth).await?;

    let res = loop {
        tokio::select! {
            res = async {
                let buf_size = MAX_UDP_RELAY_PACKET_SIZE - UdpHeader::max_serialized_len();
                listen_udp.set_max_packet_size(buf_size);

                let (pkt, frag, dst_addr, src_addr) = listen_udp.recv_from().await?;
                if frag != 0 {
                    return Err("[UDP] packet fragment is not supported".into());
                }

                let _a = incoming_addr.get_or_init(|| src_addr);

                log::trace!("[UDP] {src_addr} -> {dst_addr} incoming packet size {}", pkt.len());
                let _ = s5_udp_client.send_to(&pkt, dst_addr).await?;
                Ok::<_, BoxError>(())
            } => {
                if res.is_err() {
                    break res;
                }
            },
            res = async {
                let mut buf = vec![0u8; MAX_UDP_RELAY_PACKET_SIZE];
                let (len, remote_addr) = s5_udp_client.recv_from(CONNECT_TIMEOUT, &mut buf).await?;
                let incoming_addr = *incoming_addr.get().ok_or("incoming address not set")?;
                log::trace!("[UDP] {incoming_addr} <- {remote_addr} feedback to incoming");
                listen_udp.send_to(&buf[..len], 0, remote_addr, incoming_addr).await?;
                Ok::<_, BoxError>(())
            } => {
                if res.is_err() {
                    break res;
                }
            },
            _ = reply_listener.wait_until_closed() => {
                log::trace!("[UDP] {} listener closed", listen_addr);
                break Ok::<_, BoxError>(());
            },
        };
    };

    reply_listener.shutdown().await?;

    res
}
