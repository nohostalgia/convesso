//! Runs the official vectors of convesso's primitives on an embedded target,
//! under QEMU, and exits with 0 when every vector passes and 1 otherwise. The
//! failure, or the count of vectors checked, is printed through semihosting.

#![no_std]
#![no_main]

use semihosting::{println, process};

#[cfg(target_arch = "arm")]
use cortex_m_rt::entry;
#[cfg(target_arch = "riscv32")]
use riscv_rt::entry;

#[path = "../handshake.rs"]
mod handshake;
#[path = "../relay.rs"]
mod relay;
#[path = "../relay_vectors.rs"]
#[rustfmt::skip]
mod relay_vectors;
#[path = "../stream_vectors.rs"]
#[rustfmt::skip]
mod stream_vectors;

/// The stream frame vectors (`stream-v1.json`): every frame decodes and
/// encodes back to its bytes, every malformed one is refused. Returns how
/// many were checked.
fn stream_vectors() -> Result<usize, &'static str> {
    use convesso_stream::frame::{Ack, Data, MAX_DATA_LEN};

    let mut checked = 0;
    let mut out = [0u8; MAX_DATA_LEN];
    for bytes in stream_vectors::DATA {
        let frame = Data::decode(bytes).map_err(|_| "a stream data vector did not decode")?;
        let len = frame
            .encode(&mut out)
            .map_err(|_| "a stream data frame did not encode")?;
        if out.get(..len) != Some(*bytes) {
            return Err("a stream data frame encoded to other bytes");
        }
        checked += 1;
    }
    for bytes in stream_vectors::ACKS {
        let frame = Ack::decode(bytes).map_err(|_| "a stream acknowledgement did not decode")?;
        let len = frame
            .encode(&mut out)
            .map_err(|_| "a stream acknowledgement did not encode")?;
        if out.get(..len) != Some(*bytes) {
            return Err("a stream acknowledgement encoded to other bytes");
        }
        checked += 1;
    }
    for bytes in stream_vectors::MALFORMED_DATA {
        if Data::decode(bytes).is_ok() {
            return Err("a malformed stream data frame decoded");
        }
        checked += 1;
    }
    for bytes in stream_vectors::MALFORMED_ACKS {
        if Ack::decode(bytes).is_ok() {
            return Err("a malformed stream acknowledgement decoded");
        }
        checked += 1;
    }
    Ok(checked)
}

/// The relay frame and TCP framing vectors (`relay-v1.json`): every frame
/// decodes and encodes back to its bytes, every malformed one is refused, and
/// every stream yields its packets. Returns how many were checked.
fn relay_vectors() -> Result<usize, &'static str> {
    use convesso_core::relay::framing::{Deframed, Deframer};
    use convesso_core::relay::{decode, encode};

    let mut checked = 0;
    for bytes in relay_vectors::FRAMES {
        let frame = decode(bytes).map_err(|_| "a relay frame vector did not decode")?;
        let mut out = [0u8; 1500];
        let len = encode(&frame, &mut out).map_err(|_| "a relay frame did not encode")?;
        if out.get(..len) != Some(*bytes) {
            return Err("a relay frame encoded to other bytes");
        }
        checked += 1;
    }
    for bytes in relay_vectors::MALFORMED {
        if decode(bytes).is_ok() {
            return Err("a malformed relay frame decoded");
        }
        checked += 1;
    }
    for stream in relay_vectors::STREAMS {
        let mut deframer = Deframer::default();
        let (mut at, mut packets, mut keepalives, mut closed) = (0, 0, 0, false);
        loop {
            let (used, result) = deframer.feed(stream.bytes.get(at..).unwrap_or_default());
            at += used;
            match result {
                Deframed::NeedMore => break,
                Deframed::KeepAlive => keepalives += 1,
                Deframed::Packet(packet) => {
                    if stream.packets.get(packets) != Some(&packet) {
                        return Err("a stream yielded another packet");
                    }
                    packets += 1;
                }
                Deframed::Closed(_) => {
                    closed = true;
                    break;
                }
            }
        }
        if packets != stream.packets.len()
            || keepalives != stream.keepalives
            || closed != stream.closed
        {
            return Err("a stream did not frame as its vector says");
        }
        checked += 1;
    }
    Ok(checked)
}

#[entry]
fn main() -> ! {
    if let Err(failure) = relay_vectors().and_then(|_| stream_vectors()) {
        println!("FAIL: {}", failure);
        process::exit(1)
    }
    match convesso_vectors::run_all() {
        Ok(checked)
            if handshake::run()
                && handshake::under_load()
                && handshake::endpoints()
                && relay::client() =>
        {
            println!(
                "ok: {} vectors, {} relay vectors, {} stream vectors, a complete handshake, a cookie under load, two endpoints, and a client through a relay",
                checked,
                relay_vectors().unwrap_or(0),
                stream_vectors().unwrap_or(0)
            );
            process::exit(0)
        }
        Ok(_) => {
            println!(
                "FAIL: the handshake, the cookie under load, the endpoints, or the relay client"
            );
            process::exit(1)
        }
        Err(failure) => {
            println!("FAIL: {}", failure);
            process::exit(1)
        }
    }
}
