use std::{
     future::Future, sync::{Arc, Mutex}, task::Poll
};
use ini::Ini;

use mini_rust_desk_common::{
    anyhow::anyhow, bail, base64, bytes::Bytes, config:: READ_TIMEOUT, futures_util::future::poll_fn, log, message_proto::*, protobuf::Message as _, rendezvous_proto::*, sodiumoxide::crypto::{box_, secretbox, sign}, tcp::FramedStream, tokio::time::{Duration, Instant, Interval}, ResultType
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
#[allow(dead_code)]
#[inline]
pub fn get_arg(name: &str) -> String {
    get_arg_or(name, "".to_owned())
}

#[allow(dead_code)]
#[inline]
pub fn get_arg_or(name: &str, default: String) -> String {
    std::env::var(name).unwrap_or(default)
}

fn generate_id() -> Option<String> {
    let mut id = 0u32;
    if let Ok(Some(ma)) = mac_address::get_mac_address() {
        for x in &ma.bytes()[2..] {
            id = (id << 8) | (*x as u32);
        }
        id &= 0x1FFFFFFF;
        Some(id.to_string())
    } else {
        None
    }
}
type KeyPair = (Vec<u8>, Vec<u8>);
lazy_static::lazy_static! {
    static ref KEY_PAIR: Mutex<Option<KeyPair>> = Default::default();
}
pub fn get_key_pair() -> KeyPair {
    let mut lock = KEY_PAIR.lock().unwrap();
    if let Some(p) = lock.as_ref() {
        return p.clone();
    }
    log::info!("Generated new keypair");
    let (pk, sk) = sign::gen_keypair();
    let key_pair = (sk.0.to_vec(), pk.0.into());
    *lock = Some(key_pair.clone());
    key_pair
}

pub fn parse_and_init_params() {
    if let Ok(v) = Ini::load_from_file(".env") {
        log::info!(".env has been found");
        if let Some(section) = v.section(None::<String>) {
            section
                .iter()
                .for_each(|(k, v)|{
                    std::env::set_var(k, v);}
                );
        }
    }
    else {
        log::info!("cannot find .env file");
        std::thread::sleep(std::time::Duration::from_secs(1)); 
        std::process::exit(-1);
    }

    if let Some(tmp) = generate_id() {
        std::env::set_var("id", tmp);
    }
    else {
        log::info!("generate_id failed");
        std::thread::sleep(std::time::Duration::from_secs(1)); 
        std::process::exit(-1);
    }
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

#[inline]
pub fn username() -> String {
    return whoami::username().trim_end_matches('\0').to_owned();
}


#[inline]
pub fn check_port<T: std::string::ToString>(host: T, port: i32) -> String {
    mini_rust_desk_common::socket_client::check_port(host, port)
}

pub fn encode64<T: AsRef<[u8]>>(input: T) -> String {
    #[allow(deprecated)]
    base64::encode(input)
}

pub fn decode64<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, base64::DecodeError> {
    #[allow(deprecated)]
    base64::decode(input)
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
