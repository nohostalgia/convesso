//! Measurements. Ignored by default: only a release build measures
//! anything. Run them with
//! `cargo test -p convesso-relay --release --lib measure -- --ignored --nocapture`.

use std::time::Instant as Clock;

use convesso_core::endpoint::{Output, To};
use convesso_core::relay::Link;
use convesso_core::relay::framing::{Deframed, Deframer};

use super::world::*;
use crate::{Action, Config, Limits, Open};

const DATAGRAM: usize = 1280;

/// A, sending, and B, on a link, with sessions through the relay; limits high
/// enough not to be what is measured.
fn ready() -> World<Open> {
    let unlimited = Limits {
        bytes_per_second: u64::MAX / 2000,
        bytes_burst: u64::MAX / 2000,
        packets_per_second: u64::MAX / 2000,
        packets_burst: u64::MAX / 2000,
    };
    let config = Config {
        limits: unlimited,
        ..Config::default()
    };
    let mut world = World::new(Open, config, 2);
    world.open_link(1);
    world.run_for(1000);
    world.send(0, 1, b"warm").unwrap();
    world.run_for(2000);
    world
}

/// A's next datagram to B, sealed and wrapped for the relay by the core.
fn forward_from_a(world: &mut World<Open>, data: &[u8]) -> Vec<u8> {
    let b = world.clients[1].address();
    let now = world.instant();
    let client = &mut world.clients[0];
    let mut out = [0u8; 2048];
    let Ok(Output::Transmit {
        to: To::Relay(_),
        len,
    }) = client.endpoint.send(
        convesso_core::endpoint::Target::Address(&b),
        SESSION,
        data,
        RELAY_PATH_MAX,
        now,
        &mut client.policy,
        &mut client.entropy,
        &mut out,
    )
    else {
        panic!("A has a session with B, through the relay");
    };
    out[..len].to_vec()
}

#[test]
#[ignore = "a measurement, meaningful only in release"]
fn relay_forwarding_rate() {
    let mut world = ready();
    let data = [0x5au8; DATAGRAM];
    let packets: Vec<Vec<u8>> = (0..20_000)
        .map(|_| forward_from_a(&mut world, &data))
        .collect();
    let from = world.clients[0].nat;
    let now = world.instant();
    let start = Clock::now();
    let mut delivered = 0usize;
    for packet in &packets {
        world.relay.udp(packet, from, now);
        while let Some(action) = world.relay.next_action() {
            if matches!(action, Action::Link { .. } | Action::Udp { .. }) {
                delivered += 1;
            }
        }
        let b_link = world.relay.clients[world.clients[1].peer_id().as_bytes()]
            .link
            .unwrap();
        world.relay.set_link_backlog(b_link, 0);
    }
    let elapsed = start.elapsed();
    let rate = packets.len() as f64 / elapsed.as_secs_f64();
    std::println!(
        "relay, one core: {} forwards of {DATAGRAM}-byte datagrams in {:?}: {:.0} packets/s, {:.0} Mbit/s; {} delivered",
        packets.len(),
        elapsed,
        rate,
        rate * DATAGRAM as f64 * 8.0 / 1e6,
        delivered
    );
    assert_eq!(delivered, packets.len());
}

#[test]
#[ignore = "a measurement, meaningful only in release"]
fn client_wrap_and_unwrap() {
    let mut world = ready();
    let data = [0x5au8; DATAGRAM];
    // Wrapping: the time of through_relay alone, on a packet already sealed.
    let b = world.clients[1].peer_id();
    let now = world.instant();
    let mut times = Vec::new();
    for _ in 0..2000 {
        let client = &mut world.clients[0];
        let mut out = [0u8; 2048];
        out[..DATAGRAM + 31].fill(0x01);
        let start = Clock::now();
        let result = client.endpoint.through_relay(
            b,
            DATAGRAM + 31,
            now,
            &mut client.policy,
            &mut client.entropy,
            &mut out,
        );
        times.push(start.elapsed());
        assert!(result.is_ok());
    }
    times.sort();
    let wrap = times[times.len() / 2];

    // Unwrapping: B handling delivers from the relay.
    let packets: Vec<Vec<u8>> = (0..2000)
        .map(|_| forward_from_a(&mut world, &data))
        .collect();
    let from = world.clients[0].nat;
    let mut delivers = Vec::new();
    let mut deframer = Deframer::default();
    let mut started = false;
    for packet in &packets {
        world.relay.udp(packet, from, now);
        while let Some(action) = world.relay.next_action() {
            if let Action::Udp { packet, .. } = &action {
                delivers.push(packet.clone());
            }
            if let Action::Link { bytes, .. } = action {
                let mut stream = bytes;
                if !started {
                    stream.splice(0..0, convesso_core::relay::framing::PREAMBLE);
                    started = true;
                }
                let mut at = 0;
                loop {
                    let (used, result) = deframer.feed(&stream[at..]);
                    at += used;
                    match result {
                        Deframed::Packet(p) => delivers.push(p.to_vec()),
                        Deframed::NeedMore | Deframed::Closed(_) => break,
                        Deframed::KeepAlive => {}
                    }
                }
            }
        }
    }
    let mut times = Vec::new();
    let client = &mut world.clients[1];
    for packet in &mut delivers {
        let mut out = [0u8; 2048];
        let start = Clock::now();
        let output = client.endpoint.handle_relay_packet(
            packet,
            Link::Tcp,
            now,
            &mut client.policy,
            &mut client.entropy,
            &mut out,
        );
        times.push(start.elapsed());
        assert!(matches!(output, Output::Event(_)), "{output:?}");
    }
    times.sort();
    let unwrap = times[times.len() / 2];
    std::println!(
        "client, {DATAGRAM}-byte datagram: wrap and seal a forward {wrap:?}, open a deliver and its datagram {unwrap:?} (medians)"
    );
}

#[test]
#[ignore = "a measurement, meaningful only in release"]
fn a_wake_on_the_relay() {
    let mut world = ready();
    let wake = world.clients[0].udp_log[0].clone();
    let from = world.clients[0].nat;
    let mut times = Vec::new();
    for _ in 0..200 {
        world.run_for(5_100);
        let now = world.instant();
        let start = Clock::now();
        world.relay.udp(&wake, from, now);
        times.push(start.elapsed());
        world.relay_actions();
    }
    times.sort();
    std::println!(
        "relay, a wake (first contact with a forward, two Diffie-Hellmans and the forward): {:?} (median)",
        times[times.len() / 2]
    );
}
