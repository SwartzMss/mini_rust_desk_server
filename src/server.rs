use std::net::SocketAddr;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock, Weak},
    time::Duration,
};
use bytes::Bytes;
use mini_rust_desk_common::{
    config::{CONNECT_TIMEOUT,RELAY_PORT},
    log,
    bail,
    message_proto::*,
    protobuf::{Enum, Message as _},
    rendezvous_proto::*,
    socket_client,
    ResultType, 
    sodiumoxide::crypto::{box_, sign},
    Stream,
    timeout,
    tcp
};


#[tokio::main]
pub async fn start_server(rendezvous_server:String) {

    crate::RendezvousMediator::start_all(rendezvous_server).await;
}

pub async fn create_relay_connection(
    relay_server: String,
    uuid: String,
    peer_addr: SocketAddr,
    ipv4: bool,
) {
    if let Err(err) =
        create_relay_connection_(relay_server, uuid.clone(), peer_addr, ipv4).await
    {
        log::error!(
            "Failed to create relay connection for {} with uuid {}: {}",
            peer_addr,
            uuid,
            err
        );
    }
}

pub async fn create_relay_connection_(
    relay_server: String,
    uuid: String,
    peer_addr: SocketAddr,
    ipv4: bool,
) -> ResultType<()> {
    let mut stream = socket_client::connect_tcp(
        socket_client::ipv4_to_ipv6(crate::check_port(relay_server, RELAY_PORT), ipv4),
        CONNECT_TIMEOUT,
    )
    .await?;
    let mut msg_out = RendezvousMessage::new();
    let licence_key = crate::common::get_arg("key");
    msg_out.set_request_relay(RequestRelay {
        licence_key,
        uuid,
        ..Default::default()
    });
    stream.send(&msg_out).await?;
    create_tcp_connection(stream, peer_addr).await?;
    Ok(())
}

pub async fn create_tcp_connection(
    stream: Stream,
    addr: SocketAddr,
) -> ResultType<()> {
    let mut stream = stream;
    // Connection::start(addr, stream, 0, Arc::downgrade(&server)).await;
    Ok(())
}