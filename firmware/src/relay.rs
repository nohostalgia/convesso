//! A client with a pinned relay, against an in-memory relay peer and a third
//! endpoint, shared by the reference and the vectors firmware: a wake, then a
//! forward and a deliver each way (`PROTOCOL.md §6`).
//!
//! The relay peer is a core endpoint serving the relay context; it forwards by
//! hand what a relay server would, so that the firmware links the client's side
//! of the protocol and only that.

use core::hint::black_box;

use convesso_core::dos::Source;
use convesso_core::endpoint::{Endpoint, Event, Output, Poll, Target, To};
use convesso_core::identity::{Address, Identity};
use convesso_core::relay::{self, Frame, Link};
use convesso_core::storage::Mcu;
use convesso_core::time::Instant;

use crate::handshake::{AcceptAll, Sequence, hex32};

const RELAY_SCALAR: [u8; 32] =
    hex32("357c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de90f");
const RELAY_ADDRESS: [u8; 32] =
    hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
const CLIENT_SCALAR: [u8; 32] =
    hex32("6ebd9ed75882d52815a97585caf4790a7f6c6b3b7f821c5e259a24b02e502e11");
const CLIENT_ADDRESS: [u8; 32] =
    hex32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
const PEER_SCALAR: [u8; 32] =
    hex32("909a8b755ed902849023a55b15c23d11ba4d7f4ec5c2f51b1325a181991ea99c");
const PEER_ADDRESS: [u8; 32] =
    hex32("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");

const CLIENT_SOURCE: &[u8] = &[10, 0, 0, 1, 0, 1];
const RELAY_SOURCE: &[u8] = &[10, 0, 0, 9, 0, 9];

fn identity(scalar: [u8; 32], address: [u8; 32]) -> Option<(Identity, Address)> {
    let address = Address::parse(black_box(address)).ok()?;
    Some((
        Identity::from_parts(black_box(scalar), address).ok()?,
        address,
    ))
}

/// What the relay peer received from the client: the packet a frame carries,
/// copied into `packet`, and its length.
fn relay_receives(
    relay_ep: &mut Endpoint<Mcu>,
    from_client: &mut [u8],
    now: Instant,
    entropy: &mut Sequence,
    packet: &mut [u8; 1500],
) -> Option<usize> {
    let mut out = [0u8; 2048];
    let data = match relay_ep.handle_packet(
        from_client,
        Source::Direct(CLIENT_SOURCE),
        now,
        &mut AcceptAll,
        entropy,
        &mut out,
    ) {
        Output::Event(Event::Payload { data, .. } | Event::Datagram { data, .. }) => data,
        _ => return None,
    };
    let Ok(Frame::Forward {
        packet: carried, ..
    }) = relay::decode(data)
    else {
        return None;
    };
    packet.get_mut(..carried.len())?.copy_from_slice(carried);
    Some(carried.len())
}

/// The relay peer delivers `packet` from `sender` to the client; returns what
/// the client's endpoint made of it, with its answer, if any, in `out`.
#[allow(
    clippy::too_many_arguments,
    reason = "three endpoints' worth of sans-IO inputs"
)]
fn deliver<'a>(
    relay_ep: &mut Endpoint<Mcu>,
    client: &mut Endpoint<Mcu>,
    sender: &Address,
    packet: &[u8],
    now: Instant,
    entropies: (&mut Sequence, &mut Sequence),
    wire: &'a mut [u8; 2048],
    out: &mut [u8; 2048],
) -> Option<Output<'a>> {
    let mut frame = [0u8; 1500];
    let len = relay::encode(
        &Frame::Deliver {
            sender: *sender.peer_id().as_bytes(),
            packet,
        },
        &mut frame,
    )
    .ok()?;
    let Ok(Output::Transmit { len, .. }) = relay_ep.send(
        Target::Peer(client.identity().peer_id()),
        relay::CONTEXT,
        frame.get(..len)?,
        1500,
        now,
        &mut AcceptAll,
        entropies.0,
        wire,
    ) else {
        return None;
    };
    Some(client.handle_relay_packet(
        wire.get_mut(..len)?,
        Link::Udp,
        now,
        &mut AcceptAll,
        entropies.1,
        out,
    ))
}

/// Runs the scenario; returns whether each step did what the spec says.
pub fn client() -> bool {
    run().is_some()
}

fn run() -> Option<()> {
    let (relay_identity, relay_address) = identity(RELAY_SCALAR, RELAY_ADDRESS)?;
    let (client_identity, client_address) = identity(CLIENT_SCALAR, CLIENT_ADDRESS)?;
    let (peer_identity, peer_address) = identity(PEER_SCALAR, PEER_ADDRESS)?;
    let now = Instant::from_millis(black_box(0));
    let mut relay_ep = Endpoint::<Mcu>::new(relay_identity, &[relay::CONTEXT]).ok()?;
    relay_ep.accept_payload(relay::CONTEXT).ok()?;
    let mut client = Endpoint::<Mcu>::new(client_identity, &[b"session"]).ok()?;
    client.pin_relay(relay_address, now).ok()?;
    let mut peer = Endpoint::<Mcu>::new(peer_identity, &[b"session"]).ok()?;
    let (mut er, mut ec, mut ep) = (
        Sequence(black_box(5)),
        Sequence(black_box(6)),
        Sequence(black_box(7)),
    );
    let mut out = [0u8; 2048];
    let mut wire = [0u8; 2048];
    let mut carried = [0u8; 1500];

    // The wake: the client dials the peer, and the core sends it through the
    // relay, in one datagram of 302 bytes: the relay's first contact carrying
    // the forward.
    let Ok(Output::Transmit {
        to: To::Relay(_),
        len: 302,
    }) = client.connect(
        &peer_address,
        b"session",
        now,
        &mut AcceptAll,
        &mut ec,
        &mut out,
    )
    else {
        return None;
    };
    wire.get_mut(..302)?.copy_from_slice(out.get(..302)?);
    let first = relay_receives(
        &mut relay_ep,
        wire.get_mut(..302)?,
        now,
        &mut er,
        &mut carried,
    )?;
    // The relay's response, then the client's confirmation.
    let Poll::Transmit { len, .. } = relay_ep.poll(now, &mut AcceptAll, &mut er, &mut wire) else {
        return None;
    };
    let _ = client.handle_relay_packet(
        wire.get_mut(..len)?,
        Link::Udp,
        now,
        &mut AcceptAll,
        &mut ec,
        &mut out,
    );
    let Poll::Transmit {
        to: To::Relay(_),
        len,
    } = client.poll(now, &mut AcceptAll, &mut ec, &mut out)
    else {
        return None;
    };
    wire.get_mut(..len)?.copy_from_slice(out.get(..len)?);
    let _ = relay_ep.handle_packet(
        wire.get_mut(..len)?,
        Source::Direct(CLIENT_SOURCE),
        now,
        &mut AcceptAll,
        &mut er,
        &mut out,
    );

    // The peer answers the forwarded first contact; the relay delivers the
    // answer, which completes the client's dial.
    let mut packet = [0u8; 1500];
    packet
        .get_mut(..first)?
        .copy_from_slice(carried.get(..first)?);
    let Output::Transmit { len, .. } = peer.handle_packet(
        packet.get_mut(..first)?,
        Source::Direct(RELAY_SOURCE),
        now,
        &mut AcceptAll,
        &mut ep,
        &mut out,
    ) else {
        return None;
    };
    let response = out;
    let mut client_out = [0u8; 2048];
    let Some(Output::Event(Event::Connected { .. })) = deliver(
        &mut relay_ep,
        &mut client,
        &peer_address,
        response.get(..len)?,
        now,
        (&mut er, &mut ec),
        &mut wire,
        &mut client_out,
    ) else {
        return None;
    };

    // A forward: the client's datagram to the peer, which the core sends
    // through the relay, where it heard the peer.
    let Ok(Output::Transmit {
        to: To::Relay(_),
        len,
    }) = client.send(
        Target::Address(&peer_address),
        b"session",
        black_box(b"reading"),
        relay::MAX_CARRIED,
        now,
        &mut AcceptAll,
        &mut ec,
        &mut out,
    )
    else {
        return None;
    };
    wire.get_mut(..len)?.copy_from_slice(out.get(..len)?);
    let carried_len = relay_receives(
        &mut relay_ep,
        wire.get_mut(..len)?,
        now,
        &mut er,
        &mut carried,
    )?;
    packet
        .get_mut(..carried_len)?
        .copy_from_slice(carried.get(..carried_len)?);
    let Output::Event(Event::Datagram {
        data: b"reading", ..
    }) = peer.handle_packet(
        packet.get_mut(..carried_len)?,
        Source::Direct(RELAY_SOURCE),
        now,
        &mut AcceptAll,
        &mut ep,
        &mut out,
    )
    else {
        return None;
    };

    // A deliver: the peer's reply, marked relayed at the client.
    let Ok(Output::Transmit { len, .. }) = peer.send(
        Target::Peer(client_address.peer_id()),
        b"session",
        black_box(b"ack"),
        1400,
        now,
        &mut AcceptAll,
        &mut ep,
        &mut out,
    ) else {
        return None;
    };
    let reply = out;
    let Some(Output::Event(Event::Datagram {
        data: b"ack",
        relayed: true,
        ..
    })) = deliver(
        &mut relay_ep,
        &mut client,
        &peer_address,
        reply.get(..len)?,
        now,
        (&mut er, &mut ec),
        &mut wire,
        &mut client_out,
    )
    else {
        return None;
    };
    Some(())
}
