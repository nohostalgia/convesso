//! The reference firmware of the embedded driver: convesso-embassy over
//! embassy-net (UDP, TCP, IPv4, IPv6, Ethernet), with an executor, a network
//! device that sends nothing and a clock that only counts. Its flash and static
//! RAM are what the driver's footprint budget measures (`footprint-budget.toml`,
//! `reference-embassy`): what a device on the driver links, on inputs the
//! optimiser cannot see through.

#![no_std]
#![no_main]

use core::cell::Cell;
use core::hint::black_box;
use core::task::Context;

use convesso_core::identity::Address;
use convesso_core::storage::Mcu;
use convesso_embassy::net::{
    NetDatagrams, NetInterfaces, NetStream, TCP_LEN, UDP_RX_LEN, UDP_RX_PACKETS, UDP_TX_LEN,
    UDP_TX_PACKETS,
};
use convesso_embassy::rng::{RngFailed, SecureRng};
use convesso_embassy::{
    Access, ContextEvent, ContextOptions, ContextSlot, EVENTS_LEN, RelayLocation, Slot,
};
use critical_section::Mutex as CsMutex;
use embassy_executor::{Executor, Spawner};
use embassy_net::tcp::TcpSocket;
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{Config, StackResources};
use embassy_net_driver::{Capabilities, HardwareAddress, LinkState};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use panic_halt as _;
use static_cell::{ConstStaticCell, StaticCell};

// The critical sections of a single-core chip, which embassy-sync uses.
#[cfg(target_arch = "arm")]
use cortex_m as _;
#[cfg(target_arch = "arm")]
use cortex_m_rt::entry;
#[cfg(target_arch = "riscv32")]
use riscv as _;
#[cfg(target_arch = "riscv32")]
use riscv_rt::entry;

// --- a clock that only counts, and a device that sends nothing --------------------------

struct Clock;

static TICKS: CsMutex<Cell<u64>> = CsMutex::new(Cell::new(0));

impl embassy_time_driver::Driver for Clock {
    fn now(&self) -> u64 {
        critical_section::with(|cs| {
            let ticks = TICKS.borrow(cs);
            ticks.set(ticks.get() + 1);
            ticks.get()
        })
    }

    fn schedule_wake(&self, _at: u64, waker: &core::task::Waker) {
        waker.wake_by_ref();
    }
}

embassy_time_driver::time_driver_impl!(static CLOCK: Clock = Clock);

struct Silent;
struct Nothing;
struct Dropped;

impl embassy_net_driver::RxToken for Nothing {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, f: F) -> R {
        f(&mut [])
    }
}

impl embassy_net_driver::TxToken for Dropped {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut frame = [0u8; 1514];
        f(frame.get_mut(..len).unwrap_or_default())
    }
}

impl embassy_net_driver::Driver for Silent {
    type RxToken<'a> = Nothing;
    type TxToken<'a> = Dropped;

    fn receive(&mut self, _cx: &mut Context) -> Option<(Nothing, Dropped)> {
        None
    }

    fn transmit(&mut self, _cx: &mut Context) -> Option<Dropped> {
        Some(Dropped)
    }

    fn link_state(&mut self, _cx: &mut Context) -> LinkState {
        LinkState::Up
    }

    fn capabilities(&self) -> Capabilities {
        let mut capabilities = Capabilities::default();
        capabilities.max_transmission_unit = 1514;
        capabilities
    }

    fn hardware_address(&self) -> HardwareAddress {
        HardwareAddress::Ethernet([0x02, 0, 0, 0, 0, 1])
    }
}

/// The chip's generator, as far as the optimiser can tell.
struct Generator;

impl SecureRng for Generator {
    fn try_fill(&mut self, dest: &mut [u8]) -> Result<(), RngFailed> {
        for byte in dest.iter_mut() {
            *byte = black_box(0x5a);
        }
        Ok(())
    }
}

// --- the driver ---------------------------------------------------------------------------

type Datagrams = NetDatagrams<'static>;
type Runner = convesso_embassy::Runner<
    'static,
    NoopRawMutex,
    Mcu,
    Datagrams,
    NetStream<'static>,
    NetInterfaces<'static>,
>;

// Built at compile time, in .bss: taken once, never copied through the stack.
static EXECUTOR: StaticCell<Executor> = StaticCell::new();
static RESOURCES: ConstStaticCell<StackResources<4>> = ConstStaticCell::new(StackResources::new());
static RX_META: ConstStaticCell<[PacketMetadata; UDP_RX_PACKETS]> =
    ConstStaticCell::new([PacketMetadata::EMPTY; UDP_RX_PACKETS]);
static TX_META: ConstStaticCell<[PacketMetadata; UDP_TX_PACKETS]> =
    ConstStaticCell::new([PacketMetadata::EMPTY; UDP_TX_PACKETS]);
static RX: ConstStaticCell<[u8; UDP_RX_LEN]> = ConstStaticCell::new([0; UDP_RX_LEN]);
static TX: ConstStaticCell<[u8; UDP_TX_LEN]> = ConstStaticCell::new([0; UDP_TX_LEN]);
static TCP_RX: ConstStaticCell<[u8; TCP_LEN]> = ConstStaticCell::new([0; TCP_LEN]);
static TCP_TX: ConstStaticCell<[u8; TCP_LEN]> = ConstStaticCell::new([0; TCP_LEN]);
static DATAGRAMS: StaticCell<Datagrams> = StaticCell::new();
static GENERATOR: StaticCell<Generator> = StaticCell::new();
static EVENTS: ConstStaticCell<[u8; EVENTS_LEN]> = ConstStaticCell::new([0; EVENTS_LEN]);
static APP: ConstStaticCell<ContextSlot<'static, NoopRawMutex>> =
    ConstStaticCell::new(ContextSlot::new());
// The node's slot: built at compile time, written once from its constant.
static SHARED: StaticCell<Slot<'static, NoopRawMutex, Mcu>> = StaticCell::new();

#[embassy_executor::task]
async fn network(mut runner: embassy_net::Runner<'static, Silent>) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn driver(runner: Runner) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn application(spawner: Spawner) {
    let record = black_box([0u8; 64]);
    let Ok(identity) = convesso_embassy::record::identity(&record) else {
        return;
    };
    let (stack, net_runner) =
        embassy_net::new(Silent, Config::default(), RESOURCES.take(), black_box(7));
    if let Ok(token) = network(net_runner) {
        spawner.spawn(token);
    }
    let mut udp = UdpSocket::new(stack, RX_META.take(), RX.take(), TX_META.take(), TX.take());
    if udp.bind(7500).is_err() {
        return;
    }
    let datagrams = DATAGRAMS.init(NetDatagrams::new(udp));
    let tcp = TcpSocket::new(stack, TCP_RX.take(), TCP_TX.take());
    let relay = black_box([1u8; 32]);
    let Ok(relay) = Address::parse(relay) else {
        return;
    };
    let started = convesso_embassy::start(
        identity,
        convesso_embassy::Config {
            relay: Some(RelayLocation {
                address: relay,
                primary: black_box(core::net::SocketAddr::from(([192, 0, 2, 1], 7400))),
                other: None,
            }),
            ..Default::default()
        },
        datagrams,
        NetStream::new(tcp),
        NetInterfaces::new(stack),
        GENERATOR.init(Generator),
        // The node's own events carry no data.
        &mut [],
        SHARED.init_with(|| const { Slot::new() }),
    );
    let Ok((node, runner, _node_events)) = started else {
        return;
    };
    if let Ok(token) = driver(runner) {
        spawner.spawn(token);
    }
    let opened = node
        .context(
            b"app",
            ContextOptions {
                access: Access::Everyone,
                events: EVENTS.take(),
                slot: APP.take(),
                #[cfg(feature = "stream")]
                credit: false,
                #[cfg(feature = "stream")]
                max_message: None,
                passive_keepalive: false,
                early_data: false,
            },
        )
        .await;
    let Ok((app, mut events)) = opened else {
        return;
    };
    node.set_reachable(true).await;
    let _ = app.send(&relay, &black_box([0u8; 16])).await;
    let mut buf = [0u8; 1452];
    if let Some(ContextEvent::Datagram { peer, data, .. }) = events.next(&mut buf).await {
        let _ = app.send_to_peer(peer, data).await;
    }
}

#[entry]
fn main() -> ! {
    let executor = EXECUTOR.init(Executor::new());
    executor.run(|spawner| {
        if let Ok(token) = application(spawner) {
            spawner.spawn(token);
        }
    })
}
