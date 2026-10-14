"""Generates identity.json: the vectors of convesso's identities (PROTOCOL.md §2).

    python crates/convesso-core/vectors/generate_identity.py

An implementation independent of the dalek crates: field arithmetic modulo 2^255 - 19, Edwards
points as RFC 8032 defines them, the X25519 ladder as RFC 7748 writes it, and hashlib's SHA-512.
It produces, for a few Ed25519 keys, the address, the X25519 scalar and the PeerId; addresses that
must be refused, one per defect; and, for one valid key, every encoding of its static key that
X25519 would treat as equal, each of which must be refused. The output is deterministic and
committed; run this again only to add vectors.
"""

import hashlib
import json
import pathlib

OUT = pathlib.Path(__file__).parent / "identity.json"

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
A24 = 121665
MONTGOMERY_A = 486662


def inv(x):
    return pow(x, P - 2, P)


# --- Edwards points, extended coordinates (RFC 8032 §5.1.4) ----------------------------------

IDENTITY = (0, 1, 1, 0)


def add(p1, p2):
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * 2 * D * t2 % P
    d = z1 * 2 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def mul(k, point):
    result = IDENTITY
    while k > 0:
        if k & 1:
            result = add(result, point)
        point = add(point, point)
        k >>= 1
    return result


def equal(p1, p2):
    x1, y1, z1, _ = p1
    x2, y2, z2, _ = p2
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def affine(point):
    x, y, z, _ = point
    zi = inv(z)
    return x * zi % P, y * zi % P


def encode(point):
    x, y = affine(point)
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def recover_x(y, sign):
    """x for y and the sign bit, or None when y is not the y of a curve point."""
    x2 = (y * y - 1) * inv(D * y * y + 1) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


def decode(data):
    """The point an address encodes, or the defect that makes it no point at all."""
    value = int.from_bytes(data, "little")
    y, sign = value & ((1 << 255) - 1), value >> 255
    if y >= P:
        return "NotCanonical"
    x2 = (y * y - 1) * inv(D * y * y + 1) % P
    if x2 == 0 and sign:
        return "NotCanonical"  # negative zero
    x = recover_x(y, sign)
    if x is None:
        return "NotOnCurve"
    return (x, y, 1, x * y % P)


def classify_address(data):
    point = decode(data)
    if isinstance(point, str):
        return point
    if equal(mul(8, point), IDENTITY):
        return "SmallOrder"
    if not equal(mul(L, point), IDENTITY):
        return "NotTorsionFree"
    return None


BASE = decode((4 * inv(5) % P).to_bytes(32, "little"))


def to_montgomery(point):
    _, y = affine(point)
    return (1 + y) * inv(1 - y) % P


# --- X25519 (RFC 7748 §5) -------------------------------------------------------------------


def clamp(scalar):
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def x25519(scalar, u_bytes):
    k = clamp(scalar)
    u = int.from_bytes(u_bytes, "little") & ((1 << 255) - 1)  # mask bit 255, as RFC 7748 requires
    u %= P  # accept non-canonical values, as RFC 7748 requires
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in reversed(range(255)):
        bit = (k >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % P, (x2 - z2) % P
        aa, bb = a * a % P, b * b % P
        e = (aa - bb) % P
        c, d = (x3 + z3) % P, (x3 - z3) % P
        da, cb = d * a % P, c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + A24 * e) % P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def u_bytes(u):
    return u.to_bytes(32, "little")


def on_montgomery_curve(u):
    rhs = (u * u * u + MONTGOMERY_A * u * u + u) % P
    return rhs == 0 or pow(rhs, (P - 1) // 2, P) == 1


# --- vectors --------------------------------------------------------------------------------


def key(name, seed):
    digest = hashlib.sha512(seed).digest()
    scalar = digest[:32]  # unclamped; X25519 and Ed25519 both clamp it
    address = encode(mul(clamp(scalar), BASE))
    peer_id = x25519(scalar, u_bytes(9))
    assert peer_id == u_bytes(to_montgomery(decode(address)))
    negated = bytes(address[:31]) + bytes([address[31] ^ 0x80])
    assert u_bytes(to_montgomery(decode(negated))) == peer_id
    return {
        "name": name,
        "seed": seed.hex(),
        "address": address.hex(),
        "x25519_scalar": scalar.hex(),
        "peer_id": peer_id.hex(),
        "negated_address": negated.hex(),
    }


def an_order_eight_point():
    for y in range(2, 1000):
        point = decode(y.to_bytes(32, "little"))
        if isinstance(point, str):
            continue
        torsion = mul(L, point)
        if not equal(mul(4, torsion), IDENTITY):
            return torsion
    raise AssertionError("no point of order 8 found")


def invalid_addresses(valid_address):
    out = [
        ("y equal to p + 1", (P + 1).to_bytes(32, "little"), "NotCanonical"),
        ("negative zero", (1 | (1 << 255)).to_bytes(32, "little"), "NotCanonical"),
        ("order 2: (0, -1)", (P - 1).to_bytes(32, "little"), "SmallOrder"),
        ("the identity", (1).to_bytes(32, "little"), "SmallOrder"),
    ]
    y = 2
    while not isinstance(decode(y.to_bytes(32, "little")), str):
        y += 1
    out.append((f"y = {y}, not on the curve", y.to_bytes(32, "little"), "NotOnCurve"))
    t8 = an_order_eight_point()
    out.append(("valid key plus a point of order 8", encode(add(decode(valid_address), t8)), "NotTorsionFree"))
    for name, data, defect in out:
        assert classify_address(data) == defect, (name, classify_address(data))
    return [{"name": n, "address": d.hex(), "defect": defect} for n, d, defect in out]


def equivalent_statics(entry):
    """Every encoding of a valid static key that X25519 treats as equal to it, and must be refused."""
    peer_id = bytes.fromhex(entry["peer_id"])
    point = decode(bytes.fromhex(entry["address"]))
    out = [("bit 255 set", peer_id[:31] + bytes([peer_id[31] | 0x80]), "Bit255Set")]
    t8 = an_order_eight_point()
    seen = {int.from_bytes(peer_id, "little")}
    for k in range(1, 8):
        u = to_montgomery(add(point, mul(k, t8))) if not equal(add(point, mul(k, t8)), IDENTITY) else None
        if u is not None and u not in seen:
            seen.add(u)
            out.append((f"shifted by {k} times a point of order 8", u_bytes(u), "NotTorsionFree"))
    # A responder's scalar cannot tell any of these from the key itself.
    responder = hashlib.sha512(b"convesso test responder").digest()[:32]
    expected = x25519(responder, peer_id)
    for name, static, _ in out:
        assert x25519(responder, static) == expected, name
    return [
        {"name": n, "of_key": entry["name"], "static": s.hex(), "defect": d, "equivalent": True}
        for n, s, d in out
    ]


def other_invalid_statics():
    """Statics that are no key at all: not canonical, or on the twist."""
    out = [("u = p + 9, the base point unreduced", u_bytes(P + 9), "NotCanonical")]
    u = 2
    while on_montgomery_curve(u):
        u += 1
    out.append((f"u = {u}, on the twist", u_bytes(u), "NotOnCurve"))
    return [{"name": n, "static": s.hex(), "defect": d, "equivalent": False} for n, s, d in out]


def main():
    keys = [
        key("RFC 8032 7.1 TEST 1", bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")),
        key("RFC 8032 7.1 TEST 2", bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")),
        key("RFC 8032 7.1 TEST 3", bytes.fromhex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")),
        key("seed 00..1f", bytes(range(32))),
        key("seed ff..ff", bytes([0xFF] * 32)),
    ]
    for entry in keys:
        assert classify_address(bytes.fromhex(entry["address"])) is None, entry["name"]
        assert classify_address(bytes.fromhex(entry["negated_address"])) is None, entry["name"]
    document = {
        "description": "Vectors for PROTOCOL.md, section 2: identities. Generated by "
        "generate_identity.py, independent of the dalek crates; do not edit.",
        "keys": keys,
        "invalid_addresses": invalid_addresses(bytes.fromhex(keys[0]["address"])),
        "invalid_statics": equivalent_statics(keys[0]) + other_invalid_statics(),
    }
    OUT.write_text(json.dumps(document, indent=2) + "\n", encoding="ascii", newline="\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
