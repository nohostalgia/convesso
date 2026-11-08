//! The `Boot` profile: sizes given when the endpoint starts, allocated then,
//! once (`DESIGN.md §2`). A counting allocator checks that a day of sessions
//! opening and going idle allocates nothing after the start.

#![cfg(all(feature = "alloc", feature = "ed25519-seed"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a test: a panic is a failure"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use convesso_core::dos::Source;
use convesso_core::endpoint::{Endpoint, Output, Poll, SendError, Target, To};
use convesso_core::handshake::{Admission, Decision, Entropy};
use convesso_core::identity::{Identity, PeerId};
use convesso_core::storage::{Boot, Sizes};
use convesso_core::time::Instant;

/// Counts the allocations each thread makes, so that the tests running beside
/// the one measured count nothing in it.
struct Counting;

thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

fn allocations() -> usize {
    ALLOCATIONS.with(Cell::get)
}

// SAFETY: every call is forwarded to the system allocator unchanged.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
        // SAFETY: as the caller's contract with `GlobalAlloc::alloc`.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: as the caller's contract with `GlobalAlloc::dealloc`.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

struct Accept;

impl Admission for Accept {
    fn admit(&mut self, _peer: &PeerId, _context: &[u8]) -> Decision {
        Decision::Accept { psk: None }
    }
}

struct Counter(u64);

impl Entropy for Counter {
    fn fill(&mut self, dest: &mut [u8]) {
        for byte in dest {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *byte = (self.0 >> 56) as u8;
        }
    }
}

const SOURCES: [[u8; 6]; 2] = [[10, 0, 0, 1, 0, 1], [10, 0, 0, 2, 0, 2]];

fn identity(i: u8) -> Identity {
    Identity::from_ed25519_seed(&[i + 1; 32]).unwrap()
}

/// A `Boot` endpoint of identity `i`, given `sizes` before it starts.
fn boot(i: u8, sizes: Option<&Sizes>) -> Box<Endpoint<Boot>> {
    let mut endpoint = Box::new(Endpoint::<Boot>::EMPTY);
    if let Some(sizes) = sizes {
        endpoint.reserve(sizes);
    }
    let contexts: &[&[u8]] = if sizes.is_some() { &[b"session"] } else { &[] };
    endpoint.start(identity(i), contexts).unwrap();
    endpoint
}

/// Two endpoints that reach each other directly, moved by hand with stack
/// buffers only, so that the test allocates nothing of its own.
struct Pair {
    nodes: [Box<Endpoint<Boot>>; 2],
    entropy: [Counter; 2],
    received: usize,
}

impl Pair {
    /// Hands `packet` (in `buffer[..len]`) from `from` to the other, and
    /// whatever it answers back, until nothing is answered.
    fn carry(&mut self, from: usize, buffer: &mut [u8; 2048], len: usize, now: Instant) {
        let (mut from, mut len) = (from, len);
        loop {
            let to = 1 - from;
            let mut out = [0u8; 2048];
            let output = self.nodes[to].handle_packet(
                &mut buffer[..len],
                Source::Direct(&SOURCES[from]),
                now,
                &mut Accept,
                &mut self.entropy[to],
                &mut out,
            );
            match output {
                Output::Transmit { len: answer, .. } => {
                    buffer[..answer].copy_from_slice(&out[..answer]);
                    from = to;
                    len = answer;
                }
                Output::Event(convesso_core::endpoint::Event::Datagram { .. }) => {
                    self.received += 1;
                    return;
                }
                Output::Event(_) | Output::Nothing => return,
            }
        }
    }

    /// Polls both until neither has anything to send now.
    fn settle(&mut self, now: Instant) {
        for _ in 0..100 {
            let mut moved = false;
            for i in 0..2 {
                let mut out = [0u8; 2048];
                match self.nodes[i].poll(now, &mut Accept, &mut self.entropy[i], &mut out) {
                    Poll::Transmit {
                        to: To::Direct(_) | To::Source,
                        len,
                    } => {
                        moved = true;
                        self.carry(i, &mut out, len, now);
                    }
                    Poll::Event(convesso_core::endpoint::Event::Datagram { .. }) => {
                        moved = true;
                        self.received += 1;
                    }
                    Poll::Event(_) | Poll::Transmit { .. } => moved = true,
                    Poll::Wait(_) | Poll::Idle | Poll::OpenRelayLink | Poll::CloseRelayLink => {}
                }
            }
            if !moved {
                return;
            }
        }
    }

    fn send(&mut self, from: usize, data: &[u8], now: Instant) -> Result<(), SendError> {
        let address = *self.nodes[1 - from].identity().unwrap().address();
        let mut out = [0u8; 2048];
        let output = self.nodes[from].send(
            Target::Address(&address),
            b"session",
            data,
            1400,
            now,
            &mut Accept,
            &mut self.entropy[from],
            &mut out,
        )?;
        if let Output::Transmit { len, .. } = output {
            self.carry(from, &mut out, len, now);
        }
        self.settle(now);
        Ok(())
    }
}

/// Scenario: sizes given at start bound the tables, and a simulated day of
/// sessions opening and going idle allocates nothing after the start.
#[test]
fn sizes_given_at_start_bound_the_tables_and_allocate_once() {
    let sizes = Sizes {
        sessions: 6,
        dials: 3,
        ..Boot::SIZES
    };
    let mut pair = Pair {
        nodes: [boot(0, Some(&sizes)), boot(1, Some(&sizes))],
        entropy: [Counter(1), Counter(2)],
        received: 0,
    };
    let peer = pair.nodes[1].identity().unwrap().peer_id();
    pair.nodes[0]
        .set_hints(peer, &[&SOURCES[1]], Instant::from_millis(0))
        .unwrap();
    let before = allocations();
    // Every 10 minutes for a day: each send reopens a session gone idle.
    for step in 0..144u64 {
        let now = Instant::from_millis(step * 600_000);
        pair.settle(now);
        pair.send(0, &step.to_le_bytes(), now).unwrap();
    }
    let after = allocations();
    assert_eq!(pair.received, 144, "every datagram arrived");
    assert_eq!(after, before, "nothing allocated after the start");
}

/// Scenario: a start-sized endpoint given no sizes holds nothing, and refuses
/// by name.
#[test]
fn a_boot_endpoint_given_no_sizes_refuses_by_name() {
    let mut endpoint = boot(0, None);
    let address = *identity(1).address();
    let mut out = [0u8; 2048];
    let sent = endpoint.send(
        Target::AddressAt(&address, &SOURCES[1]),
        b"session",
        b"nowhere",
        1400,
        Instant::from_millis(0),
        &mut Accept,
        &mut Counter(3),
        &mut out,
    );
    assert!(matches!(sent, Err(SendError::Capacity)), "{sent:?}");
}

/// Sizes given after the start change nothing.
#[test]
fn sizes_after_the_start_change_nothing() {
    let mut endpoint = boot(0, None);
    endpoint.reserve(&Boot::SIZES);
    assert_eq!(endpoint.session_count(), 0);
    let address = *identity(1).address();
    let mut out = [0u8; 2048];
    let sent = endpoint.send(
        Target::AddressAt(&address, &SOURCES[1]),
        b"session",
        b"nowhere",
        1400,
        Instant::from_millis(0),
        &mut Accept,
        &mut Counter(4),
        &mut out,
    );
    assert!(matches!(sent, Err(SendError::Capacity)));
}

/// Scenario: the sessions given at start bound the table. With room for one
/// session, held by the application in a context, a second in another
/// context is refused by name.
#[test]
fn a_session_beyond_the_sizes_given_is_refused() {
    let sizes = Sizes {
        sessions: 1,
        ..Boot::SIZES
    };
    let mut pair = Pair {
        nodes: [boot(0, Some(&sizes)), boot(1, Some(&sizes))],
        entropy: [Counter(5), Counter(6)],
        received: 0,
    };
    let peer = pair.nodes[1].identity().unwrap().peer_id();
    let now = Instant::from_millis(0);
    pair.nodes[0].set_hints(peer, &[&SOURCES[1]], now).unwrap();
    pair.send(0, b"first", now).unwrap();
    assert_eq!(pair.received, 1);
    pair.nodes[0].hold(peer, b"session", true).unwrap();
    let address = *pair.nodes[1].identity().unwrap().address();
    let mut out = [0u8; 2048];
    let sent = pair.nodes[0].send(
        Target::Address(&address),
        b"other",
        b"second",
        1400,
        now,
        &mut Accept,
        &mut Counter(7),
        &mut out,
    );
    assert!(matches!(sent, Err(SendError::Capacity)), "{sent:?}");
}
