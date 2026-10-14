"""Generates stream-v1.json: the vectors of the stream frames (PROTOCOL.md §8).

    python crates/convesso-stream/vectors/generate_stream.py

The data of inner types 0x06 (stream data) and 0x07 (stream acknowledgement), built here with
Python's `struct`, independently of the Rust encoder. The output is deterministic and committed.

It also writes firmware/src/stream_vectors.rs: the same frames as Rust constants, so that the
vectors firmware checks the stream codec on each embedded target, where JSON cannot be read.
"""

import json
import pathlib
import struct

HERE = pathlib.Path(__file__).parent
OUT = HERE / "stream-v1.json"
FIRMWARE_OUT = HERE.parent.parent.parent / "firmware" / "src" / "stream_vectors.rs"

FIRST, LAST, START = 0x01, 0x02, 0x04
RESET = 0x01
INCARNATION = bytes.fromhex("8f1e2d3c4b5a6978")
OTHER = bytes.fromhex("0123456789abcdef")


def pattern(n, seed=0):
    return bytes((seed + 7 * i) % 256 for i in range(n))


def data(incarnation, sequence, length, last, start, payload):
    flags = (FIRST if length is not None else 0) | (LAST if last else 0) | (START if start else 0)
    out = incarnation + struct.pack("<IB", sequence, flags)
    if length is not None:
        out += struct.pack("<I", length)
    return out + payload


def ack(incarnation, reset, cumulative, window, max_message, ranges):
    out = incarnation + struct.pack("<BIIIB", RESET if reset else 0, cumulative, window, max_message,
                                    len(ranges))
    for start, end in ranges:
        out += struct.pack("<II", start, end)
    return out


def data_vector(description, incarnation, sequence, length, last, start, payload):
    return {
        "description": description,
        "incarnation": incarnation.hex(),
        "sequence": sequence,
        "length": length,
        "last": last,
        "start": start,
        "bytes": payload.hex(),
        "frame": data(incarnation, sequence, length, last, start, payload).hex(),
    }


def ack_vector(description, incarnation, reset, cumulative, window, max_message, ranges):
    return {
        "description": description,
        "incarnation": incarnation.hex(),
        "reset": reset,
        "cumulative": cumulative,
        "window": window,
        "max_message": max_message,
        "ranges": [list(r) for r in ranges],
        "frame": ack(incarnation, reset, cumulative, window, max_message, ranges).hex(),
    }


def main():
    datas = [
        data_vector("a whole message in one frame, the channel's first", INCARNATION, 0, 5, True, True,
                    b"hello"),
        data_vector("the first fragment of a 3,000-byte message", INCARNATION, 7, 3000, False, False,
                    pattern(1332)),
        data_vector("a middle fragment", INCARNATION, 8, None, False, False, pattern(1332, 1)),
        data_vector("the last fragment", INCARNATION, 9, None, True, False, pattern(336, 2)),
        data_vector("the longest frame: FIRST, LAST, 1,332 bytes", OTHER, 41, 1332, True, False,
                    pattern(1332, 3)),
        data_vector("a sequence about to wrap, START still set", OTHER, 0xFFFFFFFF, 1, True, True,
                    b"\x00"),
        data_vector("a middle fragment of one byte, START set", OTHER, 3, None, False, True, b"\xff"),
    ]
    acks = [
        ack_vector("a cumulative acknowledgement", INCARNATION, False, 10, 2048, 2048, []),
        ack_vector("four ranges beyond a hole", INCARNATION, False, 100, 65536, 262144,
                   [(101, 103), (104, 105), (110, 120), (120, 121)]),
        ack_vector("a reset", OTHER, True, 0, 0, 0, []),
        ack_vector("ranges across the wrap", OTHER, False, 0xFFFFFFFE, 1332, 2048,
                   [(0xFFFFFFFF, 2), (5, 6)]),
    ]
    good = data(INCARNATION, 1, None, False, False, b"abc")
    malformed_data = [
        ("shorter than the header", good[:12]),
        ("a header without bytes", good[:13]),
        ("reserved flag bit 3", INCARNATION + struct.pack("<IB", 1, 0x08) + b"abc"),
        ("FIRST with a length of 0", data(INCARNATION, 1, 0, True, False, b"abc")),
        ("FIRST with a truncated length", INCARNATION + struct.pack("<IB", 1, FIRST) + b"\x01\x00\x00"),
        ("1,333 bytes of fragment", data(INCARNATION, 1, None, False, False, pattern(1333))),
    ]
    ok_ack = ack(INCARNATION, False, 100, 0, 0, [(101, 102)])
    malformed_acks = [
        ("shorter than the header", ok_ack[:21]),
        ("a count of 5", ack(INCARNATION, False, 0, 0, 0, [(1, 2), (3, 4), (5, 6), (7, 8), (9, 10)])),
        ("a trailing byte", ok_ack + b"\x00"),
        ("a range missing", ok_ack[:-8]),
        ("reserved flag bit 1", INCARNATION + struct.pack("<BIIIB", 0x02, 0, 0, 0, 0)),
        ("a range starting at the cumulative point", ack(INCARNATION, False, 100, 0, 0, [(100, 102)])),
        ("a range before the cumulative point", ack(INCARNATION, False, 100, 0, 0, [(90, 95)])),
        ("an empty range", ack(INCARNATION, False, 100, 0, 0, [(105, 105)])),
        ("ranges out of order", ack(INCARNATION, False, 100, 0, 0, [(110, 112), (101, 103)])),
        ("overlapping ranges", ack(INCARNATION, False, 100, 0, 0, [(101, 105), (104, 106)])),
        ("a range spanning 2^31", ack(INCARNATION, False, 100, 0, 0, [(101, 101 + (1 << 31))])),
    ]
    document = {
        "description": "Vectors for PROTOCOL.md, section 8: the stream frames. Generated "
        "by generate_stream.py with Python's struct, independent of the Rust encoder; do not edit.",
        "data": datas,
        "acks": acks,
        "malformed_data": [{"description": d, "frame": f.hex()} for d, f in malformed_data],
        "malformed_acks": [{"description": d, "frame": f.hex()} for d, f in malformed_acks],
    }
    OUT.write_text(json.dumps(document, indent=2) + "\n", encoding="ascii")
    FIRMWARE_OUT.write_text(rust(document), encoding="ascii")
    print(f"wrote {OUT.name} and {FIRMWARE_OUT.name}")


def rust_bytes(hex_text):
    return "&[" + ", ".join(f"0x{b:02x}" for b in bytes.fromhex(hex_text)) + "]"


def rust(document):
    lines = [
        "//! The vectors of `crates/convesso-stream/vectors/stream-v1.json` (PROTOCOL.md, section 8),",
        "//! as constants. Generated by `generate_stream.py`; do not edit.",
        "",
    ]
    for name, key, doc in [
        ("DATA", "data", "Valid data frames: each decodes, and encodes back to the same bytes."),
        ("ACKS", "acks", "Valid acknowledgements: each decodes, and encodes back to the same bytes."),
        ("MALFORMED_DATA", "malformed_data", "Malformed data frames: each is refused."),
        ("MALFORMED_ACKS", "malformed_acks", "Malformed acknowledgements: each is refused."),
    ]:
        lines.append(f"/// {doc}")
        lines.append(f"pub const {name}: &[&[u8]] = &[")
        for vector in document[key]:
            lines.append(f"    {rust_bytes(vector['frame'])},")
        lines.append("];")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
