"""Generates dos-v1.json: the vectors of convesso's denial-of-service protection (PROTOCOL.md §4).

    python crates/convesso-core/vectors/generate_dos.py

An implementation independent of the RustCrypto crates: keyed BLAKE2s from hashlib, and a pure
Python XChaCha20-Poly1305 (ChaCha20, HChaCha20 and Poly1305 as RFC 8439 and draft-irtf-cfrg-xchacha
define them). Before writing anything, the script checks its XChaCha20-Poly1305 against the
draft's §A.3.1 vector, read from crates/convesso-vectors/src/generated.rs, where it was extracted
from the draft's text; if that check fails, nothing is written. The output is deterministic and
committed; run this again only to add vectors.
"""

import hashlib
import json
import pathlib
import re
import struct
import sys

HERE = pathlib.Path(__file__).parent
OUT = HERE / "dos-v1.json"
GENERATED = HERE.parent.parent / "convesso-vectors" / "src" / "generated.rs"
COOKIE_LABEL = b"convesso-cookie"

MASK32 = 0xFFFFFFFF


# --- ChaCha20 and HChaCha20 (RFC 8439 §2.1-2.3; draft-irtf-cfrg-xchacha §2.2) ---------------


def rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK32


def quarter_round(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & MASK32
    s[d] = rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & MASK32
    s[b] = rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & MASK32
    s[d] = rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & MASK32
    s[b] = rotl(s[b] ^ s[c], 7)


def rounds(state):
    s = list(state)
    for _ in range(10):
        quarter_round(s, 0, 4, 8, 12)
        quarter_round(s, 1, 5, 9, 13)
        quarter_round(s, 2, 6, 10, 14)
        quarter_round(s, 3, 7, 11, 15)
        quarter_round(s, 0, 5, 10, 15)
        quarter_round(s, 1, 6, 11, 12)
        quarter_round(s, 2, 7, 8, 13)
        quarter_round(s, 3, 4, 9, 14)
    return s


CONSTANTS = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]


def chacha20_block(key, counter, nonce):
    state = CONSTANTS + list(struct.unpack("<8I", key)) + [counter] + list(struct.unpack("<3I", nonce))
    mixed = rounds(state)
    return struct.pack("<16I", *[(m + s) & MASK32 for m, s in zip(mixed, state)])


def chacha20_xor(key, counter, nonce, data):
    out = bytearray()
    for i in range(0, len(data), 64):
        block = chacha20_block(key, counter + i // 64, nonce)
        out += bytes(a ^ b for a, b in zip(data[i : i + 64], block))
    return bytes(out)


def hchacha20(key, nonce16):
    state = CONSTANTS + list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16))
    mixed = rounds(state)
    return struct.pack("<8I", *(mixed[0:4] + mixed[12:16]))


# --- Poly1305 (RFC 8439 §2.5) and the AEAD (§2.8) ---------------------------------------------


def poly1305(key, message):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(message), 16):
        block = message[i : i + 16] + b"\x01"
        acc = (acc + int.from_bytes(block, "little")) * r % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def pad16(data):
    return b"\x00" * (-len(data) % 16)


def chacha20_poly1305_seal(key, nonce12, plaintext, aad):
    one_time_key = chacha20_block(key, 0, nonce12)[:32]
    ciphertext = chacha20_xor(key, 1, nonce12, plaintext)
    mac_data = aad + pad16(aad) + ciphertext + pad16(ciphertext)
    mac_data += struct.pack("<QQ", len(aad), len(ciphertext))
    return ciphertext, poly1305(one_time_key, mac_data)


def xchacha20_poly1305_seal(key, nonce24, plaintext, aad):
    subkey = hchacha20(key, nonce24[:16])
    return chacha20_poly1305_seal(subkey, b"\x00" * 4 + nonce24[16:], plaintext, aad)


# --- the draft's vector, as extracted into generated.rs ---------------------------------------


def generated_constant(name):
    text = GENERATED.read_text(encoding="ascii")
    match = re.search(rf"const {name}: &\[u8\] = &\[([^\]]*)\];", text)
    if match is None:
        raise SystemExit(f"{name} is missing from {GENERATED}")
    return bytes(int(b, 16) for b in re.findall(r"0x([0-9a-f]{2})", match.group(1)))


def check_against_the_draft():
    ciphertext, tag = xchacha20_poly1305_seal(
        generated_constant("XAEAD_KEY"),
        generated_constant("XAEAD_NONCE"),
        generated_constant("XAEAD_PLAINTEXT"),
        generated_constant("XAEAD_AAD"),
    )
    if ciphertext != generated_constant("XAEAD_CIPHERTEXT") or tag != generated_constant("XAEAD_TAG"):
        raise SystemExit("XChaCha20-Poly1305 does not reproduce draft-irtf-cfrg-xchacha A.3.1; nothing written")


# --- convesso's constructions --------------------------------------------------------------------

DIRECT, RELAYED = 0x01, 0x02


def cookie(secret, tag, source):
    return hashlib.blake2s(bytes([tag]) + source, key=secret, digest_size=16).digest()


def mac2(cookie_value, prefix):
    return hashlib.blake2s(prefix, key=cookie_value, digest_size=16).digest()


def cookie_reply(address, initiator_index, nonce, cookie_value, mac1):
    key = hashlib.blake2s(COOKIE_LABEL + address).digest()
    ciphertext, tag = xchacha20_poly1305_seal(key, nonce, cookie_value, mac1)
    return bytes([0x01, 0x03]) + struct.pack("<I", initiator_index) + nonce + ciphertext + tag


def main():
    check_against_the_draft()
    assert COOKIE_LABEL == bytes.fromhex("63 6f 6e 76 65 73 73 6f 2d 63 6f 6f 6b 69 65")

    identity = json.loads((HERE / "identity.json").read_text(encoding="ascii"))
    peer_id = bytes.fromhex(identity["keys"][0]["peer_id"])
    address = bytes.fromhex(identity["keys"][0]["address"])
    secret_a = hashlib.blake2s(b"convesso test cookie secret a").digest()
    secret_b = hashlib.blake2s(b"convesso test cookie secret b").digest()
    sources = [
        ("direct, IPv4 192.0.2.1:51820", DIRECT, bytes([192, 0, 2, 1]) + struct.pack(">H", 51820)),
        ("direct, IPv6 [2001:db8::1]:51820", DIRECT, bytes.fromhex("20010db8000000000000000000000001") + struct.pack(">H", 51820)),
        ("relayed, a PeerId", RELAYED, peer_id),
        ("direct, the same 32 bytes as the PeerId", DIRECT, peer_id),
    ]
    cookies = [
        {"name": f"{name}, secret {label}", "secret": secret.hex(), "tag": tag, "source": source.hex(),
         "cookie": cookie(secret, tag, source).hex()}
        for name, tag, source in sources
        for label, secret in (("a", secret_a), ("b", secret_b))
    ]
    assert len({c["cookie"] for c in cookies}) == len(cookies), "every source and secret gives its own cookie"

    cookie_value = bytes.fromhex(cookies[0]["cookie"])
    prefixes = [b"", bytes(range(118)), bytes([0x01]) * 118]
    mac2s = [
        {"cookie": cookie_value.hex(), "prefix": prefix.hex(), "mac2": mac2(cookie_value, prefix).hex()}
        for prefix in prefixes
    ]

    replies = []
    for index, nonce_seed, mac1_seed in [(0x01020304, b"nonce 1", b"mac1 1"), (0xFFFFFFFF, b"nonce 2", b"mac1 2")]:
        nonce = hashlib.blake2s(nonce_seed).digest()[:24]
        mac1 = hashlib.blake2s(mac1_seed).digest()[:16]
        packet = cookie_reply(address, index, nonce, cookie_value, mac1)
        assert len(packet) == 62
        replies.append({"address": address.hex(), "initiator_index": index, "nonce": nonce.hex(),
                        "cookie": cookie_value.hex(), "mac1": mac1.hex(), "packet": packet.hex()})

    document = {
        "description": "Vectors for PROTOCOL.md, section 4. Generated by generate_dos.py, "
        "independent of the RustCrypto crates; do not edit.",
        "cookies": cookies,
        "mac2": mac2s,
        "cookie_replies": replies,
    }
    OUT.write_text(json.dumps(document, indent=2) + "\n", encoding="ascii", newline="\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    sys.exit(main())
