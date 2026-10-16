//! An in-memory network for the driver's tests: datagram sockets in both
//! families, stream connections with listeners, and a relay host that runs
//! the sans-IO relay in the same process. A second implementation of the
//! socket interface, beside `embassy-net`'s.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::type_complexity,
    unreachable_pub
)]

use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::poll_fn;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::task::{Poll, Waker};

use convesso_embassy::socket::{Datagrams, Interfaces, SocketError, Streams, canonical};

/// One end of a stream connection.
#[derive(Default)]
struct Pipe {
    /// Bytes towards the side that connected, and towards the listener.
    to_client: VecDeque<u8>,
    to_server: VecDeque<u8>,
    closed: bool,
    client_waker: Option<Waker>,
    server_waker: Option<Waker>,
}

type PipeRef = Rc<RefCell<Pipe>>;

#[derive(Default)]
struct State {
    queues: HashMap<SocketAddr, VecDeque<(Vec<u8>, SocketAddr)>>,
    wakers: HashMap<SocketAddr, Vec<Waker>>,
    listeners: HashMap<SocketAddr, (VecDeque<(PipeRef, SocketAddr)>, Option<Waker>)>,
    /// Sources whose sends fail, as if the interface were down.
    failing: HashSet<IpAddr>,
    /// Every datagram sent: from, to, the packet.
    log: Vec<(SocketAddr, SocketAddr, Vec<u8>)>,
    /// The relay's addresses, and whether nodes reach each other directly.
    relay_ips: HashSet<IpAddr>,
    no_direct: bool,
    /// Stream connections to these are refused, as if the port were closed.
    refused: HashSet<SocketAddr>,
    /// Stream connections attempted.
    connects: usize,
    next_port: u16,
}

/// The network: cheap to clone, one thread.
#[derive(Clone, Default)]
pub struct Net(Rc<RefCell<State>>);

impl Net {
    pub fn new() -> Self {
        let net = Self::default();
        net.0.borrow_mut().next_port = 50000;
        net
    }

    /// A datagram socket bound at `port` on each of `ips`.
    pub fn bind(&self, ips: &[IpAddr], port: u16) -> MemDatagrams {
        MemDatagrams {
            net: self.clone(),
            local: ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect(),
        }
    }

    /// A stream socket whose connections leave from `ip`.
    pub fn stream(&self, ip: IpAddr) -> MemStream {
        MemStream {
            net: self.clone(),
            ip,
            pipe: None,
        }
    }

    pub fn listen(&self, at: SocketAddr) -> MemListener {
        self.0
            .borrow_mut()
            .listeners
            .insert(at, (VecDeque::new(), None));
        MemListener {
            net: self.clone(),
            at,
        }
    }

    /// Nodes reach each other only through the relay, as behind NATs that
    /// filter, or reach each other directly again.
    pub fn no_direct(&self, no_direct: bool) {
        self.0.borrow_mut().no_direct = no_direct;
    }

    /// Refuses stream connections to `at`, or accepts them again.
    pub fn refuse(&self, at: SocketAddr, refused: bool) {
        let mut state = self.0.borrow_mut();
        if refused {
            state.refused.insert(at);
        } else {
            state.refused.remove(&at);
        }
    }

    /// Stream connections attempted so far.
    pub fn connects(&self) -> usize {
        self.0.borrow().connects
    }

    /// Makes every send from `ip` fail, or stop failing.
    pub fn fail_sends_from(&self, ip: IpAddr, failing: bool) {
        let mut state = self.0.borrow_mut();
        if failing {
            state.failing.insert(ip);
        } else {
            state.failing.remove(&ip);
        }
    }

    /// The last packet sent from `from` to `to`, if any.
    pub fn last_packet(&self, from: SocketAddr, to: SocketAddr) -> Option<Vec<u8>> {
        self.0
            .borrow()
            .log
            .iter()
            .rev()
            .find(|(f, t, _)| *f == from && *t == to)
            .map(|(_, _, packet)| packet.clone())
    }

    /// Puts `packet` on the network, as if `from` had sent it to `to`.
    pub fn inject(&self, from: SocketAddr, to: SocketAddr, packet: &[u8]) {
        self.deliver(from, to, packet);
    }

    /// Datagrams waiting at `at`, not yet received.
    pub fn waiting(&self, at: SocketAddr) -> usize {
        self.0.borrow().queues.get(&at).map_or(0, VecDeque::len)
    }

    /// Datagrams sent so far, from `from` or to `to`.
    pub fn sent(&self, filter: impl Fn(SocketAddr, SocketAddr) -> bool) -> usize {
        self.0
            .borrow()
            .log
            .iter()
            .filter(|(from, to, _)| filter(*from, *to))
            .count()
    }

    fn deliver(&self, from: SocketAddr, to: SocketAddr, packet: &[u8]) {
        let mut state = self.0.borrow_mut();
        state.log.push((from, to, packet.to_vec()));
        let through_relay =
            state.relay_ips.contains(&from.ip()) || state.relay_ips.contains(&to.ip());
        if state.no_direct && !through_relay {
            return;
        }
        state
            .queues
            .entry(to)
            .or_default()
            .push_back((packet.to_vec(), from));
        for waker in state.wakers.remove(&to).unwrap_or_default() {
            waker.wake();
        }
    }

    fn try_recv(&self, local: &[SocketAddr]) -> Option<(Vec<u8>, SocketAddr)> {
        let mut state = self.0.borrow_mut();
        local
            .iter()
            .find_map(|at| state.queues.get_mut(at).and_then(VecDeque::pop_front))
    }

    fn park(&self, local: &[SocketAddr], waker: &Waker) {
        let mut state = self.0.borrow_mut();
        for at in local {
            state.wakers.entry(*at).or_default().push(waker.clone());
        }
    }
}

/// A datagram socket of the in-memory network.
pub struct MemDatagrams {
    net: Net,
    local: Vec<SocketAddr>,
}

impl MemDatagrams {
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.local
    }

    /// Takes a datagram if one is waiting, without blocking.
    pub fn try_recv(&self) -> Option<(Vec<u8>, SocketAddr)> {
        self.net.try_recv(&self.local)
    }
}

impl Datagrams for MemDatagrams {
    async fn send_to(&self, packet: &[u8], to: SocketAddr) -> Result<(), SocketError> {
        let to = canonical(to);
        let from = self
            .local
            .iter()
            .find(|local| local.is_ipv4() == to.is_ipv4())
            .copied()
            .ok_or(SocketError::SendFailed)?;
        if self.net.0.borrow().failing.contains(&from.ip()) {
            return Err(SocketError::SendFailed);
        }
        self.net.deliver(from, to, packet);
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), SocketError> {
        let (packet, from) = poll_fn(|cx| match self.net.try_recv(&self.local) {
            Some(datagram) => Poll::Ready(datagram),
            None => {
                self.net.park(&self.local, cx.waker());
                Poll::Pending
            }
        })
        .await;
        let len = packet.len().min(buf.len());
        buf[..len].copy_from_slice(&packet[..len]);
        Ok((len, from))
    }

    fn local_port(&self) -> u16 {
        self.local[0].port()
    }
}

/// The interfaces of an in-memory node, which a test can change.
#[derive(Clone)]
pub struct MemInterfaces(pub Rc<RefCell<Vec<IpAddr>>>);

impl MemInterfaces {
    pub fn new(ips: &[IpAddr]) -> Self {
        Self(Rc::new(RefCell::new(ips.to_vec())))
    }
}

impl Interfaces for MemInterfaces {
    fn local_addresses(&self, out: &mut [IpAddr]) -> usize {
        let ips = self.0.borrow();
        let n = ips.len().min(out.len());
        out[..n].copy_from_slice(&ips[..n]);
        n
    }
}

/// The error of an in-memory stream.
#[derive(Debug, Clone, Copy)]
pub struct MemError;

impl std::fmt::Display for MemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the in-memory stream failed")
    }
}

impl std::error::Error for MemError {}

impl embedded_io_async::Error for MemError {
    fn kind(&self) -> embedded_io_async::ErrorKind {
        embedded_io_async::ErrorKind::Other
    }
}

/// The connecting side of a stream.
pub struct MemStream {
    net: Net,
    ip: IpAddr,
    pipe: Option<PipeRef>,
}

impl embedded_io_async::ErrorType for MemStream {
    type Error = MemError;
}

impl embedded_io_async::Read for MemStream {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, MemError> {
        let Some(pipe) = self.pipe.clone() else {
            return Err(MemError);
        };
        poll_fn(|cx| {
            let mut pipe = pipe.borrow_mut();
            if !pipe.to_client.is_empty() {
                let n = buf.len().min(pipe.to_client.len());
                for (slot, byte) in buf.iter_mut().zip(pipe.to_client.drain(..n)) {
                    *slot = byte;
                }
                Poll::Ready(Ok(n))
            } else if pipe.closed {
                Poll::Ready(Ok(0))
            } else {
                pipe.client_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        })
        .await
    }
}

impl embedded_io_async::Write for MemStream {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, MemError> {
        let pipe = self.pipe.as_ref().ok_or(MemError)?;
        let mut pipe = pipe.borrow_mut();
        if pipe.closed {
            return Err(MemError);
        }
        pipe.to_server.extend(buf);
        if let Some(waker) = pipe.server_waker.take() {
            waker.wake();
        }
        Ok(buf.len())
    }

    async fn flush(&mut self) -> Result<(), MemError> {
        Ok(())
    }
}

impl Streams for MemStream {
    async fn connect(&mut self, to: SocketAddr) -> Result<(), SocketError> {
        self.close();
        let mut state = self.net.0.borrow_mut();
        state.next_port += 1;
        state.connects += 1;
        let from = SocketAddr::new(self.ip, state.next_port);
        if state.refused.contains(&to) {
            return Err(SocketError::ConnectFailed);
        }
        let Some((queue, waker)) = state.listeners.get_mut(&to) else {
            return Err(SocketError::ConnectFailed);
        };
        let pipe = PipeRef::default();
        queue.push_back((pipe.clone(), from));
        if let Some(waker) = waker.take() {
            waker.wake();
        }
        drop(state);
        self.pipe = Some(pipe);
        Ok(())
    }

    fn close(&mut self) {
        if let Some(pipe) = self.pipe.take() {
            let mut pipe = pipe.borrow_mut();
            pipe.closed = true;
            if let Some(waker) = pipe.server_waker.take() {
                waker.wake();
            }
        }
    }
}

/// The accepting side of a stream.
pub struct Accepted {
    pipe: PipeRef,
    pub from: SocketAddr,
}

impl Accepted {
    /// Bytes waiting from the client, and whether the client closed.
    pub fn take(&self, waker: Option<&Waker>) -> (Vec<u8>, bool) {
        let mut pipe = self.pipe.borrow_mut();
        let bytes: Vec<u8> = pipe.to_server.drain(..).collect();
        if let Some(waker) = waker {
            pipe.server_waker = Some(waker.clone());
        }
        (bytes, pipe.closed)
    }

    pub fn write(&self, bytes: &[u8]) {
        let mut pipe = self.pipe.borrow_mut();
        pipe.to_client.extend(bytes);
        if let Some(waker) = pipe.client_waker.take() {
            waker.wake();
        }
    }

    pub fn close(&self) {
        let mut pipe = self.pipe.borrow_mut();
        pipe.closed = true;
        if let Some(waker) = pipe.client_waker.take() {
            waker.wake();
        }
    }
}

pub struct MemListener {
    net: Net,
    at: SocketAddr,
}

impl MemListener {
    pub fn try_accept(&self, waker: Option<&Waker>) -> Option<Accepted> {
        let mut state = self.net.0.borrow_mut();
        let (queue, parked) = state.listeners.get_mut(&self.at)?;
        match queue.pop_front() {
            Some((pipe, from)) => Some(Accepted { pipe, from }),
            None => {
                if let Some(waker) = waker {
                    *parked = Some(waker.clone());
                }
                None
            }
        }
    }

    pub async fn accept(&self) -> Accepted {
        poll_fn(|cx| match self.try_accept(Some(cx.waker())) {
            Some(accepted) => Poll::Ready(accepted),
            None => Poll::Pending,
        })
        .await
    }
}

// --- identities and the relay host ------------------------------------------------------

/// The `i`-th identity of `identity.json`, through a provisioning record.
pub fn identity(i: usize) -> convesso_core::identity::Identity {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../../../convesso-core/vectors/identity.json")).unwrap();
    let hex = |v: &serde_json::Value| -> Vec<u8> {
        let text = v.as_str().unwrap();
        (0..text.len())
            .step_by(2)
            .map(|j| u8::from_str_radix(&text[j..j + 2], 16).unwrap())
            .collect()
    };
    let key = &vectors["keys"][i];
    let mut record = [0u8; convesso_embassy::record::RECORD_LEN];
    record[..32].copy_from_slice(&hex(&key["x25519_scalar"]));
    record[32..].copy_from_slice(&hex(&key["address"]));
    convesso_embassy::record::identity(&record).unwrap()
}

/// Deterministic entropy for the relay host.
pub struct Counter(pub u64);

impl convesso_core::handshake::Entropy for Counter {
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

/// The core's time from Embassy's clock.
pub fn now() -> convesso_core::time::Instant {
    convesso_core::time::Instant::from_millis(embassy_time::Instant::now().as_millis())
}

/// Where the relay host is.
#[derive(Clone)]
pub struct RelayHost {
    pub address: convesso_core::identity::Address,
    /// Its UDP addresses, one per family; its TCP listener is on the first.
    pub udp: Vec<SocketAddr>,
}

/// Starts a relay host on the current `LocalSet`, with identity 0, on `ips`
/// at `port` (UDP, and TCP on the first address).
pub fn spawn_relay(net: &Net, ips: &[IpAddr], port: u16) -> RelayHost {
    spawn_relay_with(net, 0, ips, port)
}

/// [`spawn_relay`] with identity `key`.
pub fn spawn_relay_with(net: &Net, key: usize, ips: &[IpAddr], port: u16) -> RelayHost {
    let identity = identity(key);
    let address = *identity.address();
    let relay = convesso_relay::Relay::new(
        identity,
        convesso_relay::Open,
        Counter(7),
        convesso_relay::Config::default(),
        now(),
    )
    .unwrap();
    let udp = net.bind(ips, port);
    let addresses = udp.addresses().to_vec();
    net.0.borrow_mut().relay_ips.extend(ips.iter().copied());
    let listener = net.listen(addresses[0]);
    tokio::task::spawn_local(serve(relay, udp, listener));
    RelayHost {
        address,
        udp: addresses,
    }
}

async fn serve(
    mut relay: convesso_relay::Relay<convesso_relay::Open, Counter>,
    udp: MemDatagrams,
    listener: MemListener,
) {
    let mut links: HashMap<convesso_relay::LinkId, Accepted> = HashMap::new();
    let mut next_id = 1;
    loop {
        let now = now();
        while let Some(accepted) = listener.try_accept(None) {
            let id = next_id;
            next_id += 1;
            if relay.link_opened(id, accepted.from, now) {
                links.insert(id, accepted);
            } else {
                accepted.close();
            }
        }
        let mut closed = Vec::new();
        for (id, link) in &links {
            let (bytes, gone) = link.take(None);
            if !bytes.is_empty() {
                relay.link_bytes(*id, &bytes, now);
            }
            if gone {
                closed.push(*id);
            }
        }
        for id in closed {
            relay.link_closed(id);
            links.remove(&id);
        }
        while let Some((packet, from)) = udp.try_recv() {
            relay.udp(&packet, from, now);
        }
        let deadline = relay.poll(now);
        while let Some(action) = relay.next_action() {
            match action {
                convesso_relay::Action::Udp { to, packet } => {
                    let _ = udp.send_to(&packet, to).await;
                }
                convesso_relay::Action::Link { id, bytes } => {
                    if let Some(link) = links.get(&id) {
                        link.write(&bytes);
                    }
                }
                convesso_relay::Action::Close { id } => {
                    if let Some(link) = links.remove(&id) {
                        link.close();
                    }
                }
            }
        }
        // Until something arrives, or the relay's deadline.
        let activity = poll_fn(|cx| {
            let waker = cx.waker();
            let mut ready = false;
            if let Some(accepted) = listener.try_accept(Some(waker)) {
                // Put it back for the next turn.
                listener
                    .net
                    .0
                    .borrow_mut()
                    .listeners
                    .get_mut(&listener.at)
                    .unwrap()
                    .0
                    .push_front((accepted.pipe, accepted.from));
                ready = true;
            }
            for link in links.values() {
                let pipe = link.pipe.borrow();
                ready |= !pipe.to_server.is_empty() || pipe.closed;
                drop(pipe);
                link.pipe.borrow_mut().server_waker = Some(waker.clone());
            }
            let pending = {
                let state = udp.net.0.borrow();
                udp.local
                    .iter()
                    .any(|at| state.queues.get(at).is_some_and(|q| !q.is_empty()))
            };
            ready |= pending;
            udp.net.park(&udp.local, waker);
            if ready {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        });
        match deadline {
            Some(at) => {
                let at = embassy_time::Instant::from_millis(at.as_millis());
                embassy_futures::select::select(activity, embassy_time::Timer::at(at)).await;
            }
            None => activity.await,
        }
    }
}
