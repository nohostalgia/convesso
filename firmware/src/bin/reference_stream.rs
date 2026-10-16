//! The reference firmware of the embedded driver with reliable messages
//! (feature `stream`, the `Mcu` configuration of convesso-stream): as
//! `reference-embassy`, and a message sent and echoed. Its flash and static
//! RAM have a budget of their own (`footprint-budget.toml`, `reference-stream`):
//! what reliable messages cost a device, against `reference-embassy`.

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
    Access, ContextEvent, ContextOptions, ContextSlot, EVENTS_LEN, RelayLocation, Shared,
};
use critical_section::Mutex as CsMutex;
use embassy_executor::{Executor, Spawner};
use embassy_net::tcp::TcpSocket;
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{Config, StackResources};
use embassy_net_driver::{Capabilities, HardwareAddress, LinkState};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use panic_halt as _;
use static_cell::StaticCell;

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

static EXECUTOR: StaticCell<Executor> = StaticCell::new();
static RESOURCES: StaticCell<StackResources<4>> = StaticCell::new();
static RX_META: StaticCell<[PacketMetadata; UDP_RX_PACKETS]> = StaticCell::new();
static TX_META: StaticCell<[PacketMetadata; UDP_TX_PACKETS]> = StaticCell::new();
static RX: StaticCell<[u8; UDP_RX_LEN]> = StaticCell::new();
static TX: StaticCell<[u8; UDP_TX_LEN]> = StaticCell::new();
static TCP_RX: StaticCell<[u8; TCP_LEN]> = StaticCell::new();
static TCP_TX: StaticCell<[u8; TCP_LEN]> = StaticCell::new();
static DATAGRAMS: StaticCell<Datagrams> = StaticCell::new();
static GENERATOR: StaticCell<Generator> = StaticCell::new();
static EVENTS: StaticCell<[u8; EVENTS_LEN]> = StaticCell::new();
static APP: StaticCell<ContextSlot<'static, NoopRawMutex>> = StaticCell::new();
static SHARED: StaticCell<Option<Shared<'static, NoopRawMutex, Mcu, Datagrams>>> =
    StaticCell::new();

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
    let (stack, net_runner) = embassy_net::new(
        Silent,
        Config::default(),
        RESOURCES.init(StackResources::new()),
        black_box(7),
    );
    if let Ok(token) = network(net_runner) {
        spawner.spawn(token);
    }
    let mut udp = UdpSocket::new(
        stack,
        RX_META.init([PacketMetadata::EMPTY; UDP_RX_PACKETS]),
        RX.init([0; UDP_RX_LEN]),
        TX_META.init([PacketMetadata::EMPTY; UDP_TX_PACKETS]),
        TX.init([0; UDP_TX_LEN]),
    );
    if udp.bind(7500).is_err() {
        return;
    }
    let datagrams = DATAGRAMS.init(NetDatagrams::new(udp));
    let tcp = TcpSocket::new(stack, TCP_RX.init([0; TCP_LEN]), TCP_TX.init([0; TCP_LEN]));
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
        },
        datagrams,
        NetStream::new(tcp),
        NetInterfaces::new(stack),
        GENERATOR.init(Generator),
        // The node's own events carry no data.
        &mut [],
        SHARED.init(None),
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
                events: EVENTS.init([0; EVENTS_LEN]),
                slot: APP.init(ContextSlot::new()),
                #[cfg(feature = "stream")]
                credit: false,
                #[cfg(feature = "stream")]
                max_message: None,
            },
        )
        .await;
    let Ok((app, mut events)) = opened else {
        return;
    };
    node.set_reachable(true).await;
    let _ = app.send(&relay, &black_box([0u8; 16])).await;
    let _ = app.send_message(&relay, &black_box([0u8; 64])).await;
    let mut buf = [0u8; 2048];
    match events.next(&mut buf).await {
        Some(ContextEvent::Datagram { peer, data, .. }) => {
            let _ = app.send_to_peer(peer, data).await;
        }
        Some(ContextEvent::Message { peer, data }) => {
            let _ = app.send_message_to_peer(peer, data).await;
        }
        _ => {}
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
