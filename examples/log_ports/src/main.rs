use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use retina_core::config::load_config;
use retina_core::subscription::connection::Connection;
use retina_core::Runtime;
use retina_filtergen::filter;

use serde::Serialize;
use sha2::{Digest, Sha256};

use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Parser;

#[derive(Serialize)]
enum IpType {
    Private,
    Public,
    V6, // TODO: is there a way to distinguish public/private in this case?
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
struct Data {
    src_ip: [u8; 32],
    src_port: u16,
    src_type: IpType,
    dst_ip: [u8; 32],
    dst_port: u16,
    dst_type: IpType,
    proto: usize,
    ts: Duration,
}

// TODO: is this secure enough?
fn hash(ip: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(ip);
    return hasher.finalize()[..].try_into().unwrap();
}

fn handle_ip(ip: IpAddr, salt: &[u8]) -> ([u8; 32], IpType) {
    match ip {
        IpAddr::V4(ip) => (
            hash(&ip.octets(), salt),
            if ip.is_private() {
                IpType::Private
            } else {
                IpType::Public
            },
        ),
        IpAddr::V6(ip) => (hash(&ip.octets(), salt), IpType::V6),
    }
}

impl Data {
    fn from(conn: &Connection, ts: Duration, salt: &[u8]) -> Self {
        let src = conn.five_tuple.orig;
        let dst = conn.five_tuple.resp;
        let proto = conn.five_tuple.proto;
        let (src_ip, src_type) = handle_ip(src.ip(), salt);
        let (dst_ip, dst_type) = handle_ip(dst.ip(), salt);
        Self {
            src_ip,
            src_port: src.port(),
            src_type,
            dst_ip,
            dst_port: dst.port(),
            dst_type,
            proto,
            ts,
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
    let mut salt: [u8; 512] = [0; 512];
    rng.fill_bytes(&mut salt);

    let start = Instant::now();

    let callback = |conn: Connection| {
        let data = Data::from(&conn, conn.ts - start, &salt);
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
