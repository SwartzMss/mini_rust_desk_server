use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, Mutex, RwLock},
    task::Poll,
};

use serde_json::Value;

use mini_rust_desk_common::{
    allow_err,
    anyhow::{anyhow, Context},
    bail, base64,
    bytes::Bytes,
    config::{self, Config, CONNECT_TIMEOUT, READ_TIMEOUT, RENDEZVOUS_PORT},
    futures_util::future::poll_fn,
    get_version_number, log,
    message_proto::*,
    protobuf::{Enum, Message as _},
    rendezvous_proto::*,
    socket_client,
    sodiumoxide::crypto::{box_, secretbox, sign},
    tcp::FramedStream,
    timeout,
    tokio::{
        self,
        time::{Duration, Instant, Interval},
    },
    ResultType,
};

#[derive(Debug, Eq, PartialEq)]
pub enum GrabState {
    Ready,
    Run,
    Wait,
    Exit,
}

pub type NotifyMessageBox = fn(String, String, String, String) -> dyn Future<Output = ()>;

pub const TIMER_OUT: Duration = Duration::from_secs(1);
pub const DEFAULT_KEEP_ALIVE: i32 = 60_000;

const MIN_VER_MULTI_UI_SESSION: &str = "1.2.4";

lazy_static::lazy_static! {
    pub static ref DEVICE_ID: Arc<Mutex<String>> = Default::default();
    pub static ref DEVICE_NAME: Arc<Mutex<String>> = Default::default();
}

pub struct SimpleCallOnReturn {
    pub b: bool,
    pub f: Box<dyn Fn() + 'static>,
}

impl Drop for SimpleCallOnReturn {
    fn drop(&mut self) {
        if self.b {
            (self.f)();
        }
    }
}

pub fn test_nat_type() {
    let mut i = 0;
    std::thread::spawn(move || loop {
        match test_nat_type_() {
            Ok(true) => break,
            Err(err) => {
                log::error!("test nat: {}", err);
            }
            _ => {}
        }
        if Config::get_nat_type() != 0 {
            break;
        }
        i = i * 2 + 1;
        if i > 300 {
            i = 300;
        }
        std::thread::sleep(std::time::Duration::from_secs(i));
    });
}

#[inline]
pub fn increase_port<T: std::string::ToString>(host: T, offset: i32) -> String {
    mini_rust_desk_common::socket_client::increase_port(host, offset)
}

pub async fn get_next_nonkeyexchange_msg(
    conn: &mut FramedStream,
    timeout: Option<u64>,
) -> Option<RendezvousMessage> {
    let timeout = timeout.unwrap_or(READ_TIMEOUT);
    for _ in 0..2 {
        if let Some(Ok(bytes)) = conn.next_timeout(timeout).await {
            if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                match &msg_in.union {
                    Some(rendezvous_message::Union::KeyExchange(_)) => {
                        continue;
                    }
                    _ => {
                        return Some(msg_in);
                    }
                }
            }
        }
        break;
    }
    None
}

#[tokio::main(flavor = "current_thread")]
async fn test_nat_type_() -> ResultType<bool> {
    log::info!("Testing nat ...");
    let start = std::time::Instant::now();
    let (rendezvous_server, _, _) = get_rendezvous_server(1_000).await;
    let server1 = rendezvous_server;
    let server2 = increase_port(&server1, -1);
    let mut msg_out = RendezvousMessage::new();
    let serial = Config::get_serial();
    msg_out.set_test_nat_request(TestNatRequest {
        serial,
        ..Default::default()
    });
    let mut port1 = 0;
    let mut port2 = 0;
    let mut local_addr = None;
    for i in 0..2 {
        let server = if i == 0 { &*server1 } else { &*server2 };
        let mut socket =
            socket_client::connect_tcp_local(server, local_addr, CONNECT_TIMEOUT).await?;
        if i == 0 {
            // reuse the local addr is required for nat test
            local_addr = Some(socket.local_addr());
            Config::set_option(
                "local-ip-addr".to_owned(),
                socket.local_addr().ip().to_string(),
            );
        }
        socket.send(&msg_out).await?;
        if let Some(msg_in) = get_next_nonkeyexchange_msg(&mut socket, None).await {
            if let Some(rendezvous_message::Union::TestNatResponse(tnr)) = msg_in.union {
                log::debug!("Got nat response from {}: port={}", server, tnr.port);
                if i == 0 {
                    port1 = tnr.port;
                } else {
                    port2 = tnr.port;
                }
                if let Some(cu) = tnr.cu.as_ref() {
                    Config::set_option(
                        "rendezvous-servers".to_owned(),
                        cu.rendezvous_servers.join(","),
                    );
                    Config::set_serial(cu.serial);
                }
            }
        } else {
            break;
        }
    }
    let ok = port1 > 0 && port2 > 0;
    if ok {
        let t = if port1 == port2 {
            NatType::ASYMMETRIC
        } else {
            NatType::SYMMETRIC
        };
        Config::set_nat_type(t as _);
        log::info!("Tested nat type: {:?} in {:?}", t, start.elapsed());
    }
    Ok(ok)
}

pub async fn get_rendezvous_server(ms_timeout: u64) -> (String, Vec<String>, bool) {
    let (mut a, mut b) = get_rendezvous_server_(ms_timeout).await;
    let mut b: Vec<String> = b
        .drain(..)
        .map(|x| socket_client::check_port(x, config::RENDEZVOUS_PORT))
        .collect();
    let c = if b.contains(&a) {
        b = b.drain(..).filter(|x| x != &a).collect();
        true
    } else {
        a = b.pop().unwrap_or(a);
        false
    };
    (a, b, c)
}

#[inline]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn get_rendezvous_server_(ms_timeout: u64) -> (String, Vec<String>) {
    crate::ipc::get_rendezvous_server(ms_timeout).await
}

#[inline]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub async fn get_nat_type(ms_timeout: u64) -> i32 {
    crate::ipc::get_nat_type(ms_timeout).await
}


#[inline]
pub fn username() -> String {
    return whoami::username().trim_end_matches('\0').to_owned();
}

#[inline]
pub fn hostname() -> String {
    {
        #[allow(unused_mut)]
        let mut name = whoami::hostname();
        name
    }
}

#[inline]
pub fn check_port<T: std::string::ToString>(host: T, port: i32) -> String {
    mini_rust_desk_common::socket_client::check_port(host, port)
}

#[inline]
pub fn get_app_name() -> String {
    mini_rust_desk_common::config::APP_NAME
        .read()
        .unwrap()
        .clone()
}

#[inline]
pub fn get_uri_prefix() -> String {
    format!("{}://", get_app_name().to_lowercase())
}

pub fn encode64<T: AsRef<[u8]>>(input: T) -> String {
    #[allow(deprecated)]
    base64::encode(input)
}

pub fn decode64<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, base64::DecodeError> {
    #[allow(deprecated)]
    base64::decode(input)
}

pub async fn get_key(sync: bool) -> String {
    let mut key = if sync {
        Config::get_option("key")
    } else {
        let mut options = crate::ipc::get_options_async().await;
        options.remove("key").unwrap_or_default()
    };
    if key.is_empty() {
        key = config::RS_PUB_KEY.to_owned();
    }
    key
}

fn get_pk(pk: &[u8]) -> Option<[u8; 32]> {
    if pk.len() == 32 {
        let mut tmp = [0u8; 32];
        tmp[..].copy_from_slice(&pk);
        Some(tmp)
    } else {
        None
    }
}

pub fn decode_id_pk(signed: &[u8], key: &sign::PublicKey) -> ResultType<(String, [u8; 32])> {
    let res = IdPk::parse_from_bytes(
        &sign::verify(signed, key).map_err(|_| anyhow!("Signature mismatch"))?,
    )?;
    if let Some(pk) = get_pk(&res.pk) {
        Ok((res.id, pk))
    } else {
        bail!("Wrong their public length");
    }
}

pub fn create_symmetric_key_msg(their_pk_b: [u8; 32]) -> (Bytes, Bytes, secretbox::Key) {
    let their_pk_b = box_::PublicKey(their_pk_b);
    let (our_pk_b, out_sk_b) = box_::gen_keypair();
    let key = secretbox::gen_key();
    let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
    let sealed_key = box_::seal(&key.0, &nonce, &their_pk_b, &out_sk_b);
    (Vec::from(our_pk_b.0).into(), sealed_key.into(), key)
}

#[inline]
pub fn rustdesk_interval(i: Interval) -> ThrottledInterval {
    ThrottledInterval::new(i)
}
pub struct ThrottledInterval {
    interval: Interval,
    next_tick: Instant,
    min_interval: Duration,
}

impl ThrottledInterval {
    pub fn new(i: Interval) -> ThrottledInterval {
        let period = i.period();
        ThrottledInterval {
            interval: i,
            next_tick: Instant::now(),
            min_interval: Duration::from_secs_f64(period.as_secs_f64() * 0.9),
        }
    }

    pub async fn tick(&mut self) -> Instant {
        let instant = poll_fn(|cx| self.poll_tick(cx));
        instant.await
    }

    pub fn poll_tick(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Instant> {
        match self.interval.poll_tick(cx) {
            Poll::Ready(instant) => {
                let now = Instant::now();
                if self.next_tick <= now {
                    self.next_tick = now + self.min_interval;
                    Poll::Ready(instant)
                } else {
                    // This call is required since tokio 1.27
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
