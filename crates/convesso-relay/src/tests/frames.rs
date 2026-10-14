//! Stream frames through the relay (`PROTOCOL.md §5`).

use convesso_core::endpoint::FrameKind;
use convesso_core::relay::ROUTED_HEADER_LEN;
use convesso_core::transport::OVERHEAD;

use super::world::*;
use crate::{Config, Open};

/// Scenario: a frame is sent as a datagram would be. Through the relay, the
/// largest frame is one 1,380-byte transport packet, and the peer's core hands
/// it up whole, marked relayed.
#[test]
fn the_largest_frame_crosses_the_relay_whole() {
    let mut world = World::new(Open, Config::default(), 3);
    world.open_link(1);
    world.run_for(1000);
    world.send(0, 1, b"hello").unwrap();
    world.run_for(2000);

    let logged = world.clients[0].udp_log.len();
    let frame: Vec<u8> = (0..1349u32).map(|i| (i % 251) as u8).collect();
    world.send_frame(0, 1, FrameKind::Data, &frame).unwrap();
    world.run_for(2000);
    // The relay session's packet around a forward of the 1,380-byte packet.
    let carried = 1380 + ROUTED_HEADER_LEN + OVERHEAD;
    let sizes: Vec<_> = world.clients[0].udp_log[logged..]
        .iter()
        .map(Vec::len)
        .filter(|&len| len > 1000)
        .collect();
    assert_eq!(sizes, vec![carried], "one forward, of the largest packet");

    let frames: Vec<_> = world.clients[1]
        .events
        .iter()
        .filter_map(|event| match event {
            Ev::Frame {
                kind,
                data,
                relayed,
                ..
            } => Some((*kind, data.clone(), *relayed)),
            _ => None,
        })
        .collect();
    assert_eq!(frames, vec![(FrameKind::Data, frame, true)]);
    assert!(
        world.clients[1]
            .datagrams()
            .iter()
            .all(|(data, _)| data == b"hello"),
        "never a datagram"
    );
}
