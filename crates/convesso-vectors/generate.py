"""Generates src/generated.rs: the official vectors convesso's primitives are checked against.

    python crates/convesso-vectors/generate.py

Nothing in the output is typed by hand. The RFC vectors are extracted from the RFC texts as
published by rfc-editor.org, and the XChaCha20-Poly1305 vector from the text of
draft-irtf-cfrg-xchacha-03 as published by the IETF, so a vector cannot be mistyped; the HMAC-BLAKE2s vectors, which no
RFC publishes, are computed by an independent implementation, Python's `hmac` over
`hashlib.blake2s`. Run it again only to add vectors; its output is committed.
"""

import hashlib
import hmac
import pathlib
import re
import urllib.request

RFC_URL = "https://www.rfc-editor.org/rfc/rfc{}.txt"
XCHACHA_URL = "https://www.ietf.org/archive/id/draft-irtf-cfrg-xchacha-03.txt"
OUT = pathlib.Path(__file__).parent / "src" / "generated.rs"

# A line of an RFC hex dump: offset, then up to 16 hex bytes, then the ASCII column.
DUMP_LINE = re.compile(r"^\s*\d{3}  ((?:[0-9a-f]{2} ){0,15}[0-9a-f]{2})")
HEX_RUN = re.compile(r"^\s*([0-9a-f]{56,64})\s*$")


def rfc(number):
    with urllib.request.urlopen(RFC_URL.format(number)) as response:
        return response.read().decode("ascii").splitlines()


def section(lines, start, end):
    """The lines from the first starting with `start` up to the next starting with `end`."""
    first = next(i for i, line in enumerate(lines) if line.startswith(start))
    last = next(i for i in range(first + 1, len(lines)) if lines[i].startswith(end))
    return lines[first:last]


def dump_after(lines, label):
    """The bytes of the hex dump that follows the first line containing `label`."""
    start = next(i for i, line in enumerate(lines) if label in line) + 1
    out = bytearray()
    for line in lines[start:]:
        if "[Page " in line or line.startswith("RFC "):
            continue  # a page break inside the dump
        match = DUMP_LINE.match(line)
        if match:
            out += bytes.fromhex(match.group(1))
        elif out and line.strip():
            break
    return bytes(out)


def colons_after(lines, label):
    """The bytes written as `xx:xx:...` on the line after the first line containing `label`."""
    start = next(i for i, line in enumerate(lines) if label in line) + 1
    return bytes.fromhex(lines[start].strip().replace(":", ""))


def hex_after(lines, label, occurrence=0):
    """The 32-byte value on the line after the `occurrence`-th line containing `label`."""
    hits = [i for i, line in enumerate(lines) if label in line]
    value = lines[hits[occurrence] + 1].strip()
    assert HEX_RUN.match(value), (label, value)
    return bytes.fromhex(value)


def rfc7748():
    lines = rfc(7748)
    single = section(lines, "5.2.  Test Vectors", "6.  Diffie-Hellman")
    dh = section(lines, "6.1.  Curve25519", "6.2.  Curve448")
    return {
        "X25519_1_SCALAR": hex_after(single, "Input scalar:", 0),
        "X25519_1_U": hex_after(single, "Input u-coordinate:", 0),
        "X25519_1_OUT": hex_after(single, "Output u-coordinate:", 0),
        "X25519_2_SCALAR": hex_after(single, "Input scalar:", 1),
        "X25519_2_U": hex_after(single, "Input u-coordinate:", 1),
        "X25519_2_OUT": hex_after(single, "Output u-coordinate:", 1),
        "X25519_ITERATED_1": hex_after(single, "After one iteration:", 0),
        "X25519_ITERATED_1000": hex_after(single, "After 1,000 iterations:", 0),
        "X25519_ALICE_PRIVATE": hex_after(dh, "Alice's private key"),
        "X25519_ALICE_PUBLIC": hex_after(dh, "Alice's public key"),
        "X25519_BOB_PRIVATE": hex_after(dh, "Bob's private key"),
        "X25519_BOB_PUBLIC": hex_after(dh, "Bob's public key"),
        "X25519_SHARED": hex_after(dh, "Their shared secret"),
    }


def rfc8439():
    lines = rfc(8439)
    aead = section(lines, "2.8.2.  Example and Test Vector for AEAD", "3.  Implementation Advice")
    decrypt = section(lines, "A.5.  ChaCha20-Poly1305 AEAD Decryption", "Appendix B.")
    return {
        "AEAD_ENCRYPT_PLAINTEXT": dump_after(aead, "Plaintext:"),
        "AEAD_ENCRYPT_AAD": dump_after(aead, "AAD:"),
        "AEAD_ENCRYPT_KEY": dump_after(aead, "Key:"),
        "AEAD_ENCRYPT_NONCE": dump_after(aead, "32-bit fixed-common part:")
        + dump_after(aead, "IV:"),
        "AEAD_ENCRYPT_CIPHERTEXT": dump_after(aead, "Ciphertext:"),
        "AEAD_ENCRYPT_TAG": colons_after(aead, "Tag:"),
        "AEAD_DECRYPT_KEY": dump_after(decrypt, "The ChaCha20 Key"),
        "AEAD_DECRYPT_CIPHERTEXT": dump_after(decrypt, "Ciphertext:"),
        "AEAD_DECRYPT_NONCE": dump_after(decrypt, "The nonce:"),
        "AEAD_DECRYPT_AAD": dump_after(decrypt, "The AAD:"),
        "AEAD_DECRYPT_TAG": dump_after(decrypt, "Received Tag:"),
        "AEAD_DECRYPT_PLAINTEXT": dump_after(decrypt, "Plaintext::"),
    }


def hex_block_after(lines, label):
    """The hex run on the non-empty lines after the first line equal to `label`."""
    start = next(i for i, line in enumerate(lines) if line.strip() == label) + 1
    out = ""
    for line in lines[start:]:
        text = line.strip()
        if not text:
            if out:
                break
            continue
        if not re.fullmatch(r"[0-9a-f]+", text):
            break
        out += text
    return bytes.fromhex(out)


def xchacha():
    with urllib.request.urlopen(XCHACHA_URL) as response:
        lines = response.read().decode("ascii").splitlines()
    aead = section(lines, "A.3.1.  AEAD_XCHACHA20_POLY1305", "A.3.2.  XChaCha20")
    return {
        "XAEAD_PLAINTEXT": hex_block_after(aead, "Plaintext:"),
        "XAEAD_AAD": hex_block_after(aead, "AAD:"),
        "XAEAD_KEY": hex_block_after(aead, "Key:"),
        "XAEAD_NONCE": hex_block_after(aead, "IV:"),
        "XAEAD_CIPHERTEXT": hex_block_after(aead, "Ciphertext:"),
        "XAEAD_TAG": hex_block_after(aead, "Tag:"),
    }


def rfc7693():
    lines = rfc(7693)
    abc = section(lines, "Appendix B.  Example of BLAKE2s Computation", "Appendix C.")
    start = next(i for i, line in enumerate(abc) if 'BLAKE2s-256("abc") =' in line)
    digest = "".join(
        line.split("=")[-1] for line in abc[start : start + 2]
    ).split()
    selftest = section(lines, "Appendix E.", "Acknowledgements")
    first = next(i for i, line in enumerate(selftest) if "blake2s_res[32]" in line) + 1
    grand = re.findall(r"0x([0-9A-F]{2})", " ".join(selftest[first : first + 4]))
    return {
        "BLAKE2S_256_ABC": bytes.fromhex("".join(digest)),
        "BLAKE2S_SELFTEST_GRAND_HASH": bytes.fromhex("".join(grand)),
    }


def hmac_blake2s():
    """Inputs from RFC 4231's HMAC test cases, plus a key between BLAKE2s's output size (32) and
    its block size (64): with the wrong block size of RUSTSEC-2019-0019, that key would be hashed
    first and the result would differ."""
    cases = [
        ("rfc4231_case_1", b"\x0b" * 20, b"Hi There"),
        ("rfc4231_case_2", b"Jefe", b"what do ya want for nothing?"),
        ("rfc4231_case_3", b"\xaa" * 20, b"\xdd" * 50),
        ("rfc4231_case_4", bytes(range(1, 26)), b"\xcd" * 50),
        ("rfc4231_case_6", b"\xaa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First"),
        (
            "rfc4231_case_7",
            b"\xaa" * 131,
            b"This is a test using a larger than block-size key and a larger than block-size "
            b"data. The key needs to be hashed before being used by the HMAC algorithm.",
        ),
        ("key_between_output_and_block_size", bytes(range(48)), b"block size is 64"),
    ]
    assert hashlib.blake2s().block_size == 64
    return [(name, key, data, hmac.new(key, data, hashlib.blake2s).digest()) for name, key, data in cases]


def rust_bytes(value):
    body = ", ".join(f"0x{b:02x}" for b in value)
    return f"&[{body}]"


def main():
    constants = {**rfc7748(), **rfc8439(), **rfc7693(), **xchacha()}
    lengths = {"XAEAD_PLAINTEXT": 114, "XAEAD_AAD": 12, "XAEAD_KEY": 32, "XAEAD_NONCE": 24,
               "XAEAD_CIPHERTEXT": 114, "XAEAD_TAG": 16, "AEAD_ENCRYPT_PLAINTEXT": 114, "AEAD_ENCRYPT_NONCE": 12, "AEAD_ENCRYPT_TAG": 16,
               "AEAD_DECRYPT_CIPHERTEXT": 265, "AEAD_DECRYPT_PLAINTEXT": 265}
    for name, length in lengths.items():
        assert len(constants[name]) == length, (name, len(constants[name]))
    assert hashlib.blake2s(b"abc").digest() == constants["BLAKE2S_256_ABC"]

    out = [
        "// @generated by generate.py from the RFC texts at rfc-editor.org and, for HMAC-BLAKE2s,",
        "// from Python's `hmac` over `hashlib.blake2s`. Do not edit; run generate.py again.",
        "",
    ]
    for name, value in constants.items():
        out.append(f"pub(crate) const {name}: &[u8] = {rust_bytes(value)};")
    out.append("")
    out.append("/// (name, key, data, HMAC-BLAKE2s(key, data))")
    out.append("pub(crate) type HmacVector = (&'static str, &'static [u8], &'static [u8], &'static [u8]);")
    out.append("")
    out.append("pub(crate) const HMAC_BLAKE2S: &[HmacVector] = &[")
    for name, key, data, mac in hmac_blake2s():
        out.append(f'    ("{name}", {rust_bytes(key)}, {rust_bytes(data)}, {rust_bytes(mac)}),')
    out.append("];")
    OUT.write_text("\n".join(out) + "\n", encoding="ascii")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
