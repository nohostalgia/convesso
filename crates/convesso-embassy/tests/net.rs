//! The socket interface over `embassy-net`, on an Ethernet device in memory
//! that answers ARP for some neighbours and not for others.

#![cfg(feature = "embassy-net")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::task::{Context, Waker};
use std::time::{Duration, Instant};

use convesso_embassy::net::{HOLD, NetDatagrams, STALL};
use convesso_embassy::socket::{Datagrams, SocketError};
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{Config, Ipv4Cidr, StackResources, StaticConfigV4};
use embassy_net_driver::{Capabilities, Checksum, HardwareAddress, LinkState};
use tokio::time::{sleep, timeout};

const OURS: [u8; 6] = [2, 0, 0, 0, 0, 2];

fn mac(ip: Ipv4Addr) -> [u8; 6] {
    let [a, b, c, d] = ip.octets();
    [2, 0, a, b, c, d]
}

/// The wire: frames to the device, frames it sent, and who answers ARP.
#[derive(Default)]
struct Wire {
    incoming: VecDeque<Vec<u8>>,
    sent: Vec<Vec<u8>>,
    waker: Option<Waker>,
    answering: Vec<Ipv4Addr>,
}

impl Wire {
    fn deliver(&mut self, frame: Vec<u8>) {
        self.incoming.push_back(frame);
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }

    /// Records a frame the device sent, and answers an ARP request for a
    /// neighbour that is there.
    fn sent(&mut self, frame: Vec<u8>) {
        if let Some(asked) = arp_request(&frame)
            && self.answering.contains(&asked)
        {
            let mut reply = Vec::new();
            reply.extend_from_slice(&OURS);
            reply.extend_from_slice(&mac(asked));
            reply.extend_from_slice(&[0x08, 0x06, 0, 1, 0x08, 0, 6, 4, 0, 2]);
            reply.extend_from_slice(&mac(asked));
            reply.extend_from_slice(&asked.octets());
            reply.extend_from_slice(&frame[22..32]);
            self.deliver(reply);
        }
        self.sent.push(frame);
    }

    fn arp_requests_for(&self, ip: Ipv4Addr) -> usize {
        self.sent
            .iter()
            .filter(|frame| arp_request(frame) == Some(ip))
            .count()
    }

    /// The payloads of the UDP datagrams sent to `ip`.
    fn udp_to(&self, ip: Ipv4Addr) -> Vec<Vec<u8>> {
        self.sent
            .iter()
            .filter(|f| {
                f.len() > 42 && f[12..14] == [8, 0] && f[23] == 17 && f[30..34] == ip.octets()
            })
            .map(|f| f[42..].to_vec())
            .collect()
    }
}

/// The address an ARP request asks for.
fn arp_request(frame: &[u8]) -> Option<Ipv4Addr> {
    (frame.len() >= 42 && frame[12..14] == [8, 6] && frame[20..22] == [0, 1])
        .then(|| Ipv4Addr::new(frame[38], frame[39], frame[40], frame[41]))
}

/// A UDP datagram from `from` to the device, with no checksums.
fn udp_frame(from: SocketAddr, to: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let (SocketAddr::V4(from), SocketAddr::V4(to)) = (from, to) else {
        panic!("IPv4 only");
    };
    let total = u16::try_from(28 + payload.len()).unwrap();
    let mut frame = Vec::new();
    frame.extend_from_slice(&OURS);
    frame.extend_from_slice(&mac(*from.ip()));
    frame.extend_from_slice(&[8, 0, 0x45, 0]);
    frame.extend_from_slice(&total.to_be_bytes());
    frame.extend_from_slice(&[0, 0, 0x40, 0, 64, 17, 0, 0]);
    frame.extend_from_slice(&from.ip().octets());
    frame.extend_from_slice(&to.ip().octets());
    frame.extend_from_slice(&from.port().to_be_bytes());
    frame.extend_from_slice(&to.port().to_be_bytes());
    frame.extend_from_slice(&(total - 20).to_be_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(payload);
    frame
}

struct Device(Rc<RefCell<Wire>>);
struct Rx(Vec<u8>);
struct Tx(Rc<RefCell<Wire>>);

impl embassy_net_driver::RxToken for Rx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(mut self, f: F) -> R {
        f(&mut self.0)
    }
}

impl embassy_net_driver::TxToken for Tx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut frame = vec![0; len];
        let r = f(&mut frame);
        self.0.borrow_mut().sent(frame);
        r
    }
}

impl embassy_net_driver::Driver for Device {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx;

    fn receive(&mut self, cx: &mut Context) -> Option<(Rx, Tx)> {
        let mut wire = self.0.borrow_mut();
        if let Some(frame) = wire.incoming.pop_front() {
            Some((Rx(frame), Tx(self.0.clone())))
        } else {
            wire.waker = Some(cx.waker().clone());
            None
        }
    }

    fn transmit(&mut self, _cx: &mut Context) -> Option<Tx> {
        Some(Tx(self.0.clone()))
    }

    fn link_state(&mut self, _cx: &mut Context) -> LinkState {
        LinkState::Up
    }

    fn capabilities(&self) -> Capabilities {
        let mut capabilities = Capabilities::default();
        capabilities.max_transmission_unit = 1514;
        // The frames the test builds carry no checksums; none is checked.
        capabilities.checksum.ipv4 = Checksum::Tx;
        capabilities.checksum.udp = Checksum::Tx;
        capabilities
    }

    fn hardware_address(&self) -> HardwareAddress {
        HardwareAddress::Ethernet(OURS)
    }
}

fn leak<T>(value: T) -> &'static mut T {
    Box::leak(Box::new(value))
}

/// The device at 10.0.0.2/24 behind 10.0.0.1, its stack running, and its
/// socket on port 7500.
fn device(wire: &Rc<RefCell<Wire>>) -> NetDatagrams<'static> {
    let config = Config::ipv4_static(StaticConfigV4 {
        address: Ipv4Cidr::new(Ipv4Addr::new(10, 0, 0, 2), 24),
        gateway: Some(Ipv4Addr::new(10, 0, 0, 1)),
        dns_servers: Default::default(),
    });
    let (stack, mut runner) = embassy_net::new(
        Device(wire.clone()),
        config,
        leak(StackResources::<2>::new()),
        7,
    );
    tokio::task::spawn_local(async move { runner.run().await });
    let mut socket = UdpSocket::new(
        stack,
        leak([PacketMetadata::EMPTY; 4]),
        leak([0; 3072]),
        leak([PacketMetadata::EMPTY; 4]),
        leak([0; 3072]),
    );
    socket.bind(7500).unwrap();
    NetDatagrams::new(socket)
}

fn at(text: &str) -> SocketAddr {
    text.parse().unwrap()
}

/// A destination on the local subnet that nobody answers costs one stall,
/// then is refused; the datagrams after it leave, the device stops asking for
/// it, and the socket still receives.
#[tokio::test(flavor = "current_thread")]
async fn an_unanswered_neighbour_does_not_block_the_socket() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let nobody = Ipv4Addr::new(10, 0, 0, 99);
            let neighbour = Ipv4Addr::new(10, 0, 0, 3);
            let wire = Rc::new(RefCell::new(Wire {
                answering: vec![Ipv4Addr::new(10, 0, 0, 1), neighbour],
                ..Wire::default()
            }));
            let datagrams = device(&wire);
            // A device has already reached its relay, through its gateway.
            let out = datagrams.send_to(b"out", at("192.0.2.1:7400"));
            timeout(Duration::from_millis(500), out)
                .await
                .expect("the gateway answers")
                .unwrap();

            let started = Instant::now();
            let sent = datagrams.send_to(b"probe", at("10.0.0.99:7500")).await;
            assert_eq!(sent, Err(SocketError::SendFailed));
            let stalled = started.elapsed();
            let stall = Duration::from_millis(STALL.as_millis());
            assert!(
                stalled >= stall && stalled < stall + Duration::from_secs(1),
                "{stalled:?}"
            );
            assert!(wire.borrow().arp_requests_for(nobody) >= 2);

            // smoltcp asks for one unknown neighbour a second, whichever it is.
            let hello = datagrams.send_to(b"hello", at("10.0.0.3:7500"));
            timeout(Duration::from_millis(1500), hello)
                .await
                .expect("the socket is not blocked")
                .unwrap();
            assert_eq!(wire.borrow().udp_to(neighbour), vec![b"hello".to_vec()]);
            let out = datagrams.send_to(b"out", at("192.0.2.1:7400"));
            timeout(Duration::from_millis(500), out)
                .await
                .expect("nor is the gateway")
                .unwrap();

            let again = datagrams.send_to(b"probe", at("10.0.0.99:7500"));
            let refused = timeout(Duration::from_millis(50), again)
                .await
                .expect("refused at once");
            assert_eq!(refused, Err(SocketError::SendFailed));
            assert!(HOLD.as_secs() > 3, "still refused after the wait below");

            let asked = wire.borrow().arp_requests_for(nobody);
            sleep(Duration::from_secs(3)).await;
            assert_eq!(
                wire.borrow().arp_requests_for(nobody),
                asked,
                "silent about it"
            );
            assert!(wire.borrow().udp_to(nobody).is_empty());

            wire.borrow_mut()
                .deliver(udp_frame(at("10.0.0.3:7500"), at("10.0.0.2:7500"), b"back"));
            let mut buf = [0u8; 64];
            let (len, from) = timeout(Duration::from_secs(1), datagrams.recv_from(&mut buf))
                .await
                .expect("the socket receives")
                .unwrap();
            assert_eq!((&buf[..len], from), (&b"back"[..], at("10.0.0.3:7500")));
        })
        .await;
}
