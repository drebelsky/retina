use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use retina_core::config::load_config;
use retina_core::subscription::connection::Connection;
use retina_core::utils::base64;
use retina_core::Runtime;
use retina_filtergen::filter;

use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;

use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Parser;

mod categorize_ip;
use categorize_ip::{categorize, create_table, Category, Table};

#[derive(Serialize)]
enum IpType {
    Private,
    Public,
}

// Define command-line arguments.
#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "ports.jsonl"
    )]
    outfile: PathBuf,
}

#[derive(Serialize)]
struct IpData {
    #[serde(serialize_with = "base64::serialize")]
    ip: [u8; 32],
    port: u16,
    kind: IpType,
    category: Category,
}

#[derive(Serialize)]
struct Data {
    orig: IpData,
    resp: IpData,
    proto: usize,
    ts: Duration,
    #[serde(serialize_with = "base64::serialize")]
    orig_data: Vec<u8>,
    #[serde(serialize_with = "base64::serialize")]
    resp_data: Vec<u8>,
    total_bytes: u64,
    total_pkts: u64,
}

fn hmac(ip: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(salt).unwrap();
    mac.update(ip);
    return mac.finalize().into_bytes()[..].try_into().unwrap();
}

fn handle_ip(addr: SocketAddr, salt: &[u8], table: &Table) -> IpData {
    let (ip, kind) = match addr.ip() {
        IpAddr::V4(ip) => (
            hmac(&ip.octets(), salt),
            if ip.is_private() {
                IpType::Private
            } else {
                IpType::Public
            },
        ),
        IpAddr::V6(ip) => (
            hmac(&ip.octets(), salt),
            if (ip.segments()[0] & 0xfe00) == 0xfc00 {
                // is_unique_local() is unstable, just use source code
                // https://doc.rust-lang.org/stable/src/std/net/ip_addr.rs.html#1417-1419
                IpType::Private
            } else {
                IpType::Public
            },
        ),
    };
    IpData {
        ip,
        port: addr.port(),
        kind,
        category: categorize(addr.ip(), table),
    }
}

impl Data {
    fn from(conn: &Connection, ts: Duration, salt: &[u8], table: &Table) -> Self {
        let orig = conn.five_tuple.orig;
        let resp = conn.five_tuple.resp;
        let proto = conn.five_tuple.proto;
        let orig_data = conn.orig.data();
        let resp_data = conn.resp.data();

        Self {
            orig: handle_ip(orig, salt, table),
            resp: handle_ip(resp, salt, table),
            orig_data,
            resp_data,
            proto,
            ts,
            total_bytes: conn.total_bytes(),
            total_pkts: conn.total_pkts(),
        }
    }
}

#[filter("")]
fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);

    // Use `BufWriter` to improve the speed of repeated write calls to the same file.
    let file = Mutex::new(BufWriter::new(File::create(&args.outfile)?));
    let cnt = AtomicUsize::new(0);

    let mut rng = ChaCha20Rng::from_entropy();
    let mut salt: [u8; 256] = [0; 256];
    rng.fill_bytes(&mut salt);

    let table = create_table();

    let start = Instant::now();

    let callback = |conn: Connection| {
        let data = Data::from(&conn, conn.ts - start, &salt, &table);
        let serialized = serde_json::to_string(&data).unwrap();
        let mut wtr = file.lock().unwrap();
        wtr.write_all(serialized.as_bytes()).unwrap();
        wtr.write_all(b"\n").unwrap();
        cnt.fetch_add(1, Ordering::Relaxed);
    };
    let mut runtime = Runtime::new(config, filter, callback)?;
    runtime.run();

    let mut wtr = file.lock().unwrap();
    wtr.flush()?;
    println!("Done. Logged {:?} connections to {:?}", cnt, &args.outfile);
    Ok(())
}
