//! Reliable messages in the simulated world (`PROTOCOL.md §8`): the stream
//! layer on both clients, over the core, the relay, NATs and lossy links.

use convesso_core::paths::PathKind;
use convesso_stream::Reason;

use super::world::*;
use crate::{Config, Open};

/// Message `i` of a long run: mostly up to 2 KiB, every hundredth large.
fn message(i: usize) -> Vec<u8> {
    let len = if i % 100 == 99 {
        262_144 - i
    } else {
        1 + (i * 37 + 11) % 2048
    };
    (0..len).map(|j| (i * 13 + j * 7) as u8).collect()
}

/// Two clients with reliable messages on a hinted direct path.
fn direct_pair() -> World<Open> {
    let mut world = World::new(Open, Config::default(), 2);
    world.with_streams();
    world.lossy_direct = true;
    world.hint(0, 1);
    world
}

/// A direct pair whose session is open before the link turns lossy, the
/// second client also reachable through the relay: what is measured is the
/// channel under loss, not the opening of the session.
fn established_pair() -> World<Open> {
    let mut world = direct_pair();
    world.open_link(1);
    world.run_for(1000);
    world.send(0, 1, b"open").unwrap();
    world.run_for(1000);
    assert_eq!(world.clients[1].datagrams().len(), 1);
    world
}

/// Sends `messages` from 0 to 1, waiting for room when the buffer is full.
fn send_all(world: &mut World<Open>, messages: &[Vec<u8>]) {
    for m in messages {
        loop {
            match world.send_message(0, 1, m) {
                Ok(()) => break,
                Err(convesso_stream::SendError::Full) => world.run_for(50),
                Err(e) => panic!("{e:?}"),
            }
        }
    }
}

/// Scenario: a lossy, reordering network delivers in order: 1,000 messages
/// of 1 byte to the maximum, over a direct path that loses 10%, duplicates
/// 5% and delays 10 to 60 ms, with 20 seeds.
#[test]
fn a_lossy_reordering_network_delivers_in_order() {
    let messages: Vec<_> = (0..1000).map(message).collect();
    // From 1: the simulator's xorshift stays at 0 from a seed of 0.
    for seed in 1..=20 {
        let mut world = established_pair();
        world.chaos = Some(seed);
        send_all(&mut world, &messages);
        world.run_for(120_000);
        assert_eq!(
            world.clients[1].messages.len(),
            messages.len(),
            "seed {seed}"
        );
        assert!(
            world.clients[1].messages == messages,
            "seed {seed}: in order, whole, once"
        );
        assert!(world.clients[0].stream_resets.is_empty(), "seed {seed}");
    }
}

/// Scenario: a change of path in mid-message loses nothing: a 200 KiB
/// message starts through the relay and ends on the punched direct path.
#[test]
fn a_change_of_path_in_mid_message_loses_nothing() {
    let eim = (Mapping::Independent, Filtering::AddressAndPort);
    let mut world = World::new(Open, Config::default(), 2);
    world.with_streams();
    world.direct = false;
    world.behind(0, eim.0, eim.1);
    world.behind(1, eim.0, eim.1);
    world.open_link(1);
    world.run_for(1000);
    let big: Vec<u8> = (0..200 * 1024).map(|j| (j % 251) as u8).collect();
    let start = world.now;
    world.send_message(0, 1, &big).unwrap();
    world.run_for(20_000);
    assert_eq!(world.clients[1].messages, vec![big], "whole, once");
    let delivered = world.clients[1].message_at[0];
    let moved = world.clients[0]
        .events
        .iter()
        .zip(&world.clients[0].event_at)
        .find_map(|(e, at)| matches!(e, Ev::PathChanged(_, PathKind::Direct(_))).then_some(*at))
        .expect("the session moved to a direct path");
    assert!(
        start < moved && moved < delivered,
        "the path changed during the transfer: {start} < {moved} < {delivered}"
    );
}

/// Scenario: a blocked channel does not hold datagrams back.
#[test]
fn a_blocked_channel_does_not_hold_datagrams_back() {
    let mut world = direct_pair();
    world.clients[1].deliver = false;
    let mut i = 0;
    while world.send_message(0, 1, &[7u8; 60_000]).is_ok() {
        i += 1;
        world.run_for(500);
        assert!(i < 100, "the buffer fills");
    }
    world.run_for(2000);
    let before = world.clients[1].datagrams().len();
    let sent_at = world.now;
    world.send(0, 1, b"not behind the messages").unwrap();
    world.run_for(2 * world.delay + 10);
    let datagrams = world.clients[1].datagrams();
    assert_eq!(datagrams.len(), before + 1, "sent at once, at {sent_at}");
    assert_eq!(datagrams[before].0, b"not behind the messages".to_vec());
}

/// Every packet client `i` sent: to the relay, on its link, and directly.
fn packets(world: &World<Open>, i: usize) -> usize {
    world.clients[i].transmitted
}

/// Scenario: a peer switched off resets the channel within 30 s, and the
/// packets it cost are counted: a few, on the doubling timeout, then none.
#[test]
fn a_peer_switched_off_resets_the_channel_within_30_s() {
    let mut world = direct_pair();
    world.send_message(0, 1, b"hello").unwrap();
    world.run_for(1000);
    assert_eq!(world.clients[1].messages.len(), 1);
    // The peer is gone: nothing reaches it, directly or through the relay.
    world.direct = false;
    world.clients[1].udp_blocked = true;
    let before = packets(&world, 0);
    let start = world.now;
    world.send_message(0, 1, &[1u8; 2000]).unwrap();
    world.run_for(31_000);
    assert_eq!(world.clients[0].stream_resets, vec![Reason::NoProgress]);
    let cost = packets(&world, 0) - before;
    std::println!(
        "a vanished peer cost {cost} packets in {} ms",
        world.now - start
    );
    assert!(cost <= 12, "a bounded number: {cost}");
    let after = packets(&world, 0);
    world.run_for(600_000);
    assert_eq!(packets(&world, 0), after, "nothing after the reset");
}

/// Scenario: a device that restarted is recognised at once.
#[test]
fn a_restarted_device_is_recognised_at_once() {
    let mut world = World::new(Open, Config::default(), 2);
    world.with_streams();
    world.open_link(0);
    world.run_for(1000);
    world.send_message(1, 0, b"before").unwrap();
    world.send_message(0, 1, b"and back").unwrap();
    world.run_for(2000);
    assert_eq!(world.clients[0].messages, vec![b"before".to_vec()]);
    world.restart(1);
    world.send_message(1, 0, b"after the restart").unwrap();
    world.run_for(3000);
    assert_eq!(world.clients[0].stream_resets, vec![Reason::PeerRestarted]);
    assert_eq!(
        world.clients[0].messages,
        vec![b"before".to_vec(), b"after the restart".to_vec()]
    );
}

/// Scenario: a device that restarted tells a sender at once, once it has a
/// fresh session: its peer's next message on the old channel is answered
/// with RESET, and the one after is delivered.
#[test]
fn a_restarted_device_tells_a_sender_at_once() {
    let mut world = World::new(Open, Config::default(), 2);
    world.with_streams();
    world.open_link(1);
    world.run_for(1000);
    world.send_message(0, 1, b"before").unwrap();
    world.run_for(2000);
    world.restart(1);
    let before = world.clients[1].messages.len();
    world.open_link(1);
    world.run_for(1000);
    // The device wakes and opens a fresh session, as a waking device does.
    world.send(1, 0, b"awake").unwrap();
    world.run_for(1000);
    world
        .send_message(0, 1, b"to a device that forgot")
        .unwrap();
    world.run_for(2000);
    assert_eq!(world.clients[0].stream_resets, vec![Reason::ResetByPeer]);
    world.send_message(0, 1, b"again").unwrap();
    world.run_for(2000);
    assert_eq!(world.clients[1].messages[before..], [b"again".to_vec()]);
}

/// The packets two clients send in a month after an exchange, messages or
/// datagrams, and whether their channels hold a deadline after it.
fn an_idle_month(messages: bool) -> (usize, usize, usize, bool) {
    let mut world = World::new(Open, Config::default(), 2);
    world.with_streams();
    world.open_link(1);
    world.run_for(1000);
    for i in 0..100 {
        if messages {
            world.send_message(0, 1, &[i as u8; 300]).unwrap();
        } else {
            world.send(0, 1, &[i as u8; 300]).unwrap();
        }
        world.run_for(100);
    }
    world.run_for(10_000);
    if messages {
        assert_eq!(world.clients[1].messages.len(), 100);
    }
    let at_rest = (0..2).all(|i| world.stream_idle(i));
    let before: Vec<_> = world
        .clients
        .iter()
        .map(|c| c.sent.udp + c.sent.tcp)
        .collect();
    world.run_for(30 * 24 * 3600 * 1000);
    let after: Vec<_> = world
        .clients
        .iter()
        .map(|c| c.sent.udp + c.sent.tcp)
        .collect();
    (
        after[0] - before[0],
        after[1] - before[1],
        world.clients[1].sent.keepalives,
        at_rest,
    )
}

/// Scenario: an idle month after an exchange sends nothing of the channel:
/// the same packets as after an exchange of datagrams, and no deadline of
/// the channel after the last acknowledgement.
#[test]
fn an_idle_month_after_an_exchange_sends_nothing() {
    let with = an_idle_month(true);
    let without = an_idle_month(false);
    std::println!("a month after messages {with:?}, after datagrams {without:?}");
    assert!(with.3, "no deadline of the channel");
    assert_eq!((with.0, with.1), (without.0, without.1));
}

/// A loss sweep: 0, 1, 2, 5 and 10% loss on a direct path, 20
/// seeds each; every message must arrive. Prints goodput and retransmissions
/// per message. Slow in debug: run with
/// `cargo test --release -p convesso-relay -- --ignored loss_sweep --nocapture`.
#[test]
#[ignore = "a measurement, run on demand in release"]
fn loss_sweep() {
    let messages: Vec<_> = (0..200).map(message).collect();
    let bytes: usize = messages.iter().map(Vec::len).sum();
    let fragments: usize = messages.iter().map(|m| m.len().div_ceil(1332)).sum();
    std::println!("loss | delivered | goodput (KB/s) | retransmissions per message");
    for loss in [0, 1, 2, 5, 10] {
        let (mut delivered, mut elapsed, mut sent) = (0, 0, 0);
        for seed in 1..=20 {
            let mut world = established_pair();
            if loss > 0 {
                world.loss = Some((seed, loss));
            }
            let start = world.now;
            let packets = world.clients[0].transmitted;
            send_all(&mut world, &messages);
            world.run_for(300_000);
            assert!(
                world.clients[1].messages == messages,
                "loss {loss}, seed {seed}"
            );
            delivered += world.clients[1].messages.len();
            elapsed += world.clients[1].message_at.last().copied().unwrap_or(start) - start;
            sent += world.clients[0].transmitted - packets;
        }
        let goodput = (bytes * 20) as f64 / elapsed as f64;
        let retransmissions = (sent as f64 / 20.0 - fragments as f64) / messages.len() as f64;
        std::println!(
            "{loss:>3}% | {delivered}/{} | {goodput:.0} | {retransmissions:.2}",
            messages.len() * 20
        );
    }
}
