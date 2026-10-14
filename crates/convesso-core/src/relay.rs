//! The relay protocol's bytes (`PROTOCOL.md §6`): the frames a client
//! and a relay exchange inside their session, and the framing of a TCP link.
//!
//! ```text
//! frames (the data of a datagram in the context `convesso-relay`):
//!   0x01 forward    kind 0x01 | recipient (32) | packet (1..=1380)   client -> relay
//!   0x02 deliver    kind 0x01 | sender (32)    | packet (1..=1380)   relay -> client
//!   0x03 not conn.  kind 0x01 | recipient (32)                        relay -> client
//!   0x04 register   address (32)                                      client -> relay
//!   0x05 observed   link (1) | family (1) | address (4|16) | port (2, LE)
//! TCP link:
//!   preamble "convesso" 0x01, once in each direction
//!   length (2, LE) | packet          length 0: keep-alive, at most 1,500
//! ```
//!
//! Recipients and senders travel as the 32 bytes of a `PeerId`, unchecked:
//! checking that a key is canonical costs about a Diffie-Hellman, which a relay
//! cannot spend per packet, and a key that is not one names nobody. Decoders
//! never panic, allocate, or loop beyond their input.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The context of every relay session.
pub const CONTEXT: &[u8] = b"convesso-relay";

/// The longest packet a forward or deliver carries.
pub const MAX_CARRIED: usize = 1380;

/// What a forward or deliver adds to the packet it carries: type, kind, key.
pub const ROUTED_HEADER_LEN: usize = 34;

/// Frame types.
pub mod frame_type {
    /// Client to relay: carry a packet to a recipient.
    pub const FORWARD: u8 = 0x01;
    /// Relay to client: a packet from a sender.
    pub const DELIVER: u8 = 0x02;
    /// Relay to client: the recipient of a forward cannot be reached.
    pub const NOT_CONNECTED: u8 = 0x03;
    /// Client to relay: the client's address, to reopen a dormant session.
    pub const REGISTER: u8 = 0x04;
    /// Relay to client: the address the relay sees the client at.
    pub const OBSERVED: u8 = 0x05;
}

/// The only recipient kind of this version: a `PeerId`.
pub const KIND_PEER_ID: u8 = 0x01;

/// Which link of a client an address was observed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Link {
    /// Datagrams.
    Udp,
    /// The TCP link.
    Tcp,
}

impl Link {
    const fn byte(self) -> u8 {
        match self {
            Self::Udp => 0x00,
            Self::Tcp => 0x01,
        }
    }
}

/// A relay frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    /// Carry `packet` to `recipient`.
    Forward {
        /// The recipient's `PeerId` bytes.
        recipient: [u8; 32],
        /// The packet, opaque to the relay.
        packet: &'a [u8],
    },
    /// `packet`, from `sender`, as the relay authenticated it.
    Deliver {
        /// The sender's `PeerId` bytes.
        sender: [u8; 32],
        /// The packet.
        packet: &'a [u8],
    },
    /// The relay cannot reach `recipient`.
    NotConnected {
        /// The recipient's `PeerId` bytes.
        recipient: [u8; 32],
    },
    /// The client's address.
    Register {
        /// Its 32 bytes.
        address: [u8; 32],
    },
    /// The address the relay sees the client at, on `link`.
    Observed {
        /// The link.
        link: Link,
        /// The address and port.
        address: SocketAddr,
    },
}

/// Why bytes are not a relay frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// No bytes.
    Empty,
    /// A frame type this version does not define.
    UnknownType,
    /// A recipient or sender kind other than `0x01`.
    ReservedKind,
    /// The wrong length for its type.
    WrongLength,
    /// A carried packet of 0 bytes, or more than [`MAX_CARRIED`].
    PacketLength,
    /// A carried packet whose byte 0 is `0xFF`.
    ReservedVersion,
    /// A link other than UDP or TCP.
    UnknownLink,
    /// An address family other than `0x04` or `0x06`.
    UnknownFamily,
    /// The output buffer is too small.
    BufferTooSmall,
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Empty => "an empty relay frame",
            Self::UnknownType => "an unknown relay frame type",
            Self::ReservedKind => "a reserved recipient kind",
            Self::WrongLength => "a relay frame of the wrong length",
            Self::PacketLength => "a carried packet of 0 or more than 1,380 bytes",
            Self::ReservedVersion => "a carried packet starting with 0xFF",
            Self::UnknownLink => "an unknown link",
            Self::UnknownFamily => "an unknown address family",
            Self::BufferTooSmall => "the output buffer is too small for the frame",
        })
    }
}

impl core::error::Error for FrameError {}

fn key(bytes: &[u8]) -> Result<[u8; 32], FrameError> {
    bytes.try_into().map_err(|_| FrameError::WrongLength)
}

fn carried(packet: &[u8]) -> Result<&[u8], FrameError> {
    match packet {
        [] => Err(FrameError::PacketLength),
        _ if packet.len() > MAX_CARRIED => Err(FrameError::PacketLength),
        [0xFF, ..] => Err(FrameError::ReservedVersion),
        _ => Ok(packet),
    }
}

/// Reads a relay frame.
///
/// # Errors
///
/// A [`FrameError`] naming the first defect found.
pub fn decode(bytes: &[u8]) -> Result<Frame<'_>, FrameError> {
    let (&kind_of_frame, rest) = bytes.split_first().ok_or(FrameError::Empty)?;
    match kind_of_frame {
        frame_type::FORWARD | frame_type::DELIVER => {
            let (&kind, rest) = rest.split_first().ok_or(FrameError::WrongLength)?;
            if kind != KIND_PEER_ID {
                return Err(FrameError::ReservedKind);
            }
            let (peer, packet) = rest.split_at_checked(32).ok_or(FrameError::WrongLength)?;
            let peer = key(peer)?;
            let packet = carried(packet)?;
            Ok(if kind_of_frame == frame_type::FORWARD {
                Frame::Forward {
                    recipient: peer,
                    packet,
                }
            } else {
                Frame::Deliver {
                    sender: peer,
                    packet,
                }
            })
        }
        frame_type::NOT_CONNECTED => match rest {
            [KIND_PEER_ID, peer @ ..] => Ok(Frame::NotConnected {
                recipient: key(peer)?,
            }),
            [_, peer @ ..] if peer.len() == 32 => Err(FrameError::ReservedKind),
            _ => Err(FrameError::WrongLength),
        },
        frame_type::REGISTER => Ok(Frame::Register {
            address: key(rest)?,
        }),
        frame_type::OBSERVED => {
            let (&link, rest) = rest.split_first().ok_or(FrameError::WrongLength)?;
            let link = match link {
                0x00 => Link::Udp,
                0x01 => Link::Tcp,
                _ => return Err(FrameError::UnknownLink),
            };
            let (&family, rest) = rest.split_first().ok_or(FrameError::WrongLength)?;
            let ip = match (family, rest.len()) {
                (0x04, 6) => {
                    let octets: [u8; 4] = key4(rest)?;
                    IpAddr::V4(Ipv4Addr::from(octets))
                }
                (0x06, 18) => {
                    let octets: [u8; 16] = rest
                        .get(..16)
                        .and_then(|o| o.try_into().ok())
                        .ok_or(FrameError::WrongLength)?;
                    IpAddr::V6(Ipv6Addr::from(octets))
                }
                (0x04 | 0x06, _) => return Err(FrameError::WrongLength),
                _ => return Err(FrameError::UnknownFamily),
            };
            let port = rest
                .len()
                .checked_sub(2)
                .and_then(|at| rest.get(at..))
                .and_then(|p| <[u8; 2]>::try_from(p).ok())
                .map(u16::from_le_bytes)
                .ok_or(FrameError::WrongLength)?;
            Ok(Frame::Observed {
                link,
                address: SocketAddr::new(ip, port),
            })
        }
        _ => Err(FrameError::UnknownType),
    }
}

fn key4(bytes: &[u8]) -> Result<[u8; 4], FrameError> {
    bytes
        .get(..4)
        .and_then(|o| o.try_into().ok())
        .ok_or(FrameError::WrongLength)
}

/// Writes the 34 bytes before a forwarded or delivered packet: the frame type,
/// the kind `0x01`, and the key. Lets a caller build a frame around a packet
/// already in place.
///
/// # Errors
///
/// [`FrameError::BufferTooSmall`] when `out` is shorter than 34 bytes.
pub fn write_routed_header(
    frame_type: u8,
    peer: &[u8; 32],
    out: &mut [u8],
) -> Result<(), FrameError> {
    let header = out
        .get_mut(..ROUTED_HEADER_LEN)
        .ok_or(FrameError::BufferTooSmall)?;
    let (head, key) = header.split_at_mut(2);
    head.copy_from_slice(&[frame_type, KIND_PEER_ID]);
    key.copy_from_slice(peer);
    Ok(())
}

/// Writes `frame` into `out`, returning its length.
///
/// # Errors
///
/// [`FrameError::BufferTooSmall`] when it does not fit, or the error
/// [`decode`] would give for a carried packet out of bounds.
pub fn encode(frame: &Frame<'_>, out: &mut [u8]) -> Result<usize, FrameError> {
    match frame {
        Frame::Forward {
            recipient: peer,
            packet,
        }
        | Frame::Deliver {
            sender: peer,
            packet,
        } => {
            let packet = carried(packet)?;
            let kind = if matches!(frame, Frame::Forward { .. }) {
                frame_type::FORWARD
            } else {
                frame_type::DELIVER
            };
            let len = ROUTED_HEADER_LEN + packet.len();
            let out = out.get_mut(..len).ok_or(FrameError::BufferTooSmall)?;
            write_routed_header(kind, peer, out)?;
            out.get_mut(ROUTED_HEADER_LEN..)
                .ok_or(FrameError::BufferTooSmall)?
                .copy_from_slice(packet);
            Ok(len)
        }
        Frame::NotConnected { recipient } => {
            write_routed_header(frame_type::NOT_CONNECTED, recipient, out)?;
            Ok(ROUTED_HEADER_LEN)
        }
        Frame::Register { address } => {
            let out = out.get_mut(..33).ok_or(FrameError::BufferTooSmall)?;
            let (head, field) = out.split_at_mut(1);
            head.copy_from_slice(&[frame_type::REGISTER]);
            field.copy_from_slice(address);
            Ok(33)
        }
        Frame::Observed { link, address } => {
            let mut bytes = [0u8; 21];
            bytes[0] = frame_type::OBSERVED;
            bytes[1] = link.byte();
            let end = match address.ip() {
                IpAddr::V4(ip) => {
                    bytes[2] = 0x04;
                    bytes[3..7].copy_from_slice(&ip.octets());
                    7
                }
                IpAddr::V6(ip) => {
                    bytes[2] = 0x06;
                    bytes[3..19].copy_from_slice(&ip.octets());
                    19
                }
            };
            let len = end + 2;
            bytes
                .get_mut(end..len)
                .ok_or(FrameError::BufferTooSmall)?
                .copy_from_slice(&address.port().to_le_bytes());
            out.get_mut(..len)
                .ok_or(FrameError::BufferTooSmall)?
                .copy_from_slice(bytes.get(..len).unwrap_or_default());
            Ok(len)
        }
    }
}

pub mod framing;

#[cfg(test)]
mod tests;
