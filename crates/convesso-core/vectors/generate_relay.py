"""Generates relay-v1.json: the vectors of convesso's relay frames and TCP framing (PROTOCOL.md §6).

    python crates/convesso-core/vectors/generate_relay.py

Every encoding is built here with Python's `struct`, independently of the Rust encoder, from the
tables of PROTOCOL.md §6. The output is deterministic and committed.

It also writes firmware/src/relay_vectors.rs: the same vectors as Rust constants, so that the
vectors firmware checks the relay codec on each embedded target, where JSON cannot be read.
"""

import hashlib
import ipaddress
import json
import pathlib
import struct

HERE = pathlib.Path(__file__).parent
OUT = HERE / "relay-v1.json"
FIRMWARE_OUT = HERE.parent.parent.parent / "firmware" / "src" / "relay_vectors.rs"

FORWARD, DELIVER, NOT_CONNECTED, REGISTER, OBSERVED = 0x01, 0x02, 0x03, 0x04, 0x05
KIND_PEER_ID = 0x01
LINK = {"udp": 0x00, "tcp": 0x01}
MAX_PACKET = 1380
PREAMBLE = b"convesso\x01"
MAX_FRAME = 1500


def peer_id(label):
    return hashlib.blake2s(b"convesso test relay peer " + label).digest()


def packet(length, first=0x01):
    """A packet of `length` bytes that starts like a version 1 transport packet."""
    body = bytes((i * 7 + 3) % 256 for i in range(length))
    return bytes([first]) + body[1:] if length else b""


def routed(frame_type, peer, carried):
    return struct.pack("<BB", frame_type, KIND_PEER_ID) + peer + carried


def observed(link, address, port):
    ip = ipaddress.ip_address(address)
    family = 0x04 if ip.version == 4 else 0x06
    return struct.pack("<BBB", OBSERVED, LINK[link], family) + ip.packed + struct.pack("<H", port)


def frames():
    a, b = peer_id(b"a"), peer_id(b"b")
    address = hashlib.blake2s(b"convesso test relay address").digest()
    out = []
    for length in (1, 134, MAX_PACKET):
        carried = packet(length)
        out.append({"name": f"forward of {length} bytes", "type": "forward", "peer": a.hex(),
                    "packet": carried.hex(), "bytes": routed(FORWARD, a, carried).hex()})
        out.append({"name": f"deliver of {length} bytes", "type": "deliver", "peer": b.hex(),
                    "packet": carried.hex(), "bytes": routed(DELIVER, b, carried).hex()})
    out.append({"name": "forward of a version-not-supported message", "type": "forward",
                "peer": a.hex(), "packet": packet(18, 0x00).hex(),
                "bytes": routed(FORWARD, a, packet(18, 0x00)).hex()})
    out.append({"name": "not connected", "type": "not_connected", "peer": b.hex(),
                "bytes": (struct.pack("<BB", NOT_CONNECTED, KIND_PEER_ID) + b).hex()})
    out.append({"name": "register", "type": "register", "address": address.hex(),
                "bytes": (bytes([REGISTER]) + address).hex()})
    for link, ip, port in (("udp", "203.0.113.7", 41641), ("tcp", "198.51.100.200", 443),
                           ("udp", "2001:db8::1", 1), ("tcp", "2001:db8:ffff::abcd", 65535)):
        out.append({"name": f"observed {link} {ip} port {port}", "type": "observed",
                    "link": link, "ip": ip, "port": port, "bytes": observed(link, ip, port).hex()})
    for frame in out:
        assert bytes.fromhex(frame["bytes"])[0] in (FORWARD, DELIVER, NOT_CONNECTED, REGISTER, OBSERVED)
    return out


def malformed():
    a = peer_id(b"a")
    cases = [
        ("empty frame", b"", "empty"),
        ("unknown frame type 0x06", bytes([0x06]) + a, "unknown type"),
        ("unknown frame type 0x00", bytes([0x00]) + a, "unknown type"),
        ("forward with reserved kind 0x02", struct.pack("<BB", FORWARD, 0x02) + a + packet(10), "reserved kind"),
        ("deliver with reserved kind 0x00", struct.pack("<BB", DELIVER, 0x00) + a + packet(10), "reserved kind"),
        ("forward with no packet", routed(FORWARD, a, b""), "packet length"),
        ("forward shorter than its recipient", routed(FORWARD, a, b"")[:20], "wrong length"),
        ("forward of 1,381 bytes", routed(FORWARD, a, packet(MAX_PACKET + 1)), "packet length"),
        ("deliver of 1,381 bytes", routed(DELIVER, a, packet(MAX_PACKET + 1)), "packet length"),
        ("forward of a packet starting with 0xFF", routed(FORWARD, a, packet(10, 0xFF)), "reserved version"),
        ("not connected of 35 bytes", struct.pack("<BB", NOT_CONNECTED, KIND_PEER_ID) + a + b"\x00", "wrong length"),
        ("not connected of 33 bytes", struct.pack("<BB", NOT_CONNECTED, KIND_PEER_ID) + a[:31], "wrong length"),
        ("not connected with reserved kind", struct.pack("<BB", NOT_CONNECTED, 0x02) + a, "reserved kind"),
        ("register of 32 bytes", bytes([REGISTER]) + a[:31], "wrong length"),
        ("register of 34 bytes", bytes([REGISTER]) + a + b"\x00", "wrong length"),
        ("observed with unknown link", struct.pack("<BBB", OBSERVED, 0x02, 0x04) + bytes(4) + b"\x01\x00", "unknown link"),
        ("observed with unknown family", struct.pack("<BBB", OBSERVED, 0x00, 0x05) + bytes(4) + b"\x01\x00", "unknown family"),
        ("observed IPv4 of 21 bytes", struct.pack("<BBB", OBSERVED, 0x00, 0x04) + bytes(16) + b"\x01\x00", "wrong length"),
        ("observed IPv6 of 9 bytes", struct.pack("<BBB", OBSERVED, 0x00, 0x06) + bytes(4) + b"\x01\x00", "wrong length"),
    ]
    return [{"name": name, "bytes": data.hex(), "defect": defect} for name, data, defect in cases]


def framed(carried):
    return struct.pack("<H", len(carried)) + carried


def streams():
    small, first_contact, largest = packet(31), packet(134), packet(MAX_FRAME)
    keepalive = struct.pack("<H", 0)
    cases = [
        ("preamble only", PREAMBLE, [], 0, None),
        ("one packet", PREAMBLE + framed(small), [small], 0, None),
        ("keep-alives and packets", PREAMBLE + keepalive + framed(small) + keepalive + keepalive
         + framed(first_contact) + framed(largest), [small, first_contact, largest], 3, None),
        ("a packet cut short waits for the rest", PREAMBLE + framed(small) + framed(first_contact)[:50],
         [small], 0, None),
        ("wrong preamble", b"convesso\x02" + framed(small), [], 0, "wrong preamble"),
        ("a TLS record instead of the preamble", bytes([0x16, 0x03, 0x01, 0x00, 0x05]) + b"hello",
         [], 0, "wrong preamble"),
        ("length 1,501", PREAMBLE + framed(small) + struct.pack("<H", MAX_FRAME + 1) + packet(MAX_FRAME + 1),
         [small], 0, "length"),
    ]
    out = []
    for name, data, packets, keepalives, closed in cases:
        out.append({"name": name, "bytes": data.hex(), "packets": [p.hex() for p in packets],
                    "keepalives": keepalives, "closed": closed})
    return out


def main():
    document = {
        "description": "Vectors for PROTOCOL.md, section 6: relay frames and TCP framing. Generated by "
        "generate_relay.py with Python's struct, independent of the Rust encoder; do not edit.",
        "preamble": PREAMBLE.hex(),
        "frames": frames(),
        "malformed": malformed(),
        "streams": streams(),
    }
    OUT.write_text(json.dumps(document, indent=2) + "\n", encoding="ascii", newline="\n")
    print(f"wrote {OUT}")
    FIRMWARE_OUT.write_text(rust(document), encoding="ascii", newline="\n")
    print(f"wrote {FIRMWARE_OUT}")


def rust_bytes(hex_text):
    data = bytes.fromhex(hex_text)
    return "&[" + ", ".join(f"0x{b:02x}" for b in data) + "]"


def rust(document):
    lines = [
        "//! The vectors of `crates/convesso-core/vectors/relay-v1.json` (PROTOCOL.md, section 6), as constants.",
        "//! Generated by `generate_relay.py`; do not edit.",
        "",
        "/// A TCP stream, the packets it carries, its keep-alives, and whether it closes.",
        "pub struct Stream {",
        "    pub bytes: &'static [u8],",
        "    pub packets: &'static [&'static [u8]],",
        "    pub keepalives: usize,",
        "    pub closed: bool,",
        "}",
        "",
        "/// Valid frames: each decodes, and encodes back to the same bytes.",
        "pub const FRAMES: &[&[u8]] = &[",
    ]
    lines += [f"    {rust_bytes(f['bytes'])}," for f in document["frames"]]
    lines += ["];", "", "/// Malformed frames: each is refused.", "pub const MALFORMED: &[&[u8]] = &["]
    lines += [f"    {rust_bytes(f['bytes'])}," for f in document["malformed"]]
    lines += ["];", "", "/// TCP streams.", "pub const STREAMS: &[Stream] = &["]
    for stream in document["streams"]:
        packets = ", ".join(rust_bytes(p) for p in stream["packets"])
        lines += [
            "    Stream {",
            f"        bytes: {rust_bytes(stream['bytes'])},",
            f"        packets: &[{packets}],",
            f"        keepalives: {stream['keepalives']},",
            f"        closed: {'true' if stream['closed'] else 'false'},",
            "    },",
        ]
    lines += ["];", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    main()
