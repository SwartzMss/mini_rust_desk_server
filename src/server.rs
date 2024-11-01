use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex, RwLock, Weak},
    time::Duration,
};

use bytes::Bytes;

use mini_rust_desk_common::config::Config2;
use mini_rust_desk_common::tcp::{self, new_listener};
use mini_rust_desk_common::{
    allow_err,
    anyhow::Context,
    bail,
    config::{Config, CONNECT_TIMEOUT, RELAY_PORT},
    log,
    message_proto::*,
    protobuf::{Enum, Message as _},
    rendezvous_proto::*,
    socket_client,
    sodiumoxide::crypto::{box_, sign},
    timeout, tokio, ResultType, Stream,
};



pub type Childs = Arc<Mutex<Vec<std::process::Child>>>;


lazy_static::lazy_static! {
    pub static ref CHILD_PROCESS: Childs = Default::default();
}


#[tokio::main]
pub async fn start_server() {
    std::thread::spawn(move || {
        if let Err(err) = crate::ipc::start("") {
            log::error!("Failed to start ipc: {}", err);
            std::process::exit(-1);
        }
    });
    crate::RendezvousMediator::start_all().await;
}
