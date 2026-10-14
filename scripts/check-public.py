#!/usr/bin/env python3
"""Checks that this repository explains itself.

    python3 scripts/check-public.py [path to leave out]...

It fails when:
- a file names planning that is not published here, or the library's former
  name;
- the code cites a section of DESIGN.md or PROTOCOL.md that does not exist;
- PROTOCOL.md gives the bytes of a label that are not the bytes in the code;
- PROTOCOL.md names a vector file that is not there.

Paths given as arguments are left out: directories that are not part of the
published tree.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SELF = os.path.relpath(os.path.abspath(__file__), ROOT).replace(os.sep, "/")
SKIP_DIRS = {".git", "target", "node_modules", "__pycache__", "artifacts", "corpus", "coverage"}

# What a published file must not hold: the planning's paths and task numbers,
# and the former name.
FORBIDDEN = re.compile(
    "open" + r"spec|specs/[a-z]|[Tt]asks? [0-9]+\.[0-9]+|" + "lite" + "p2p", re.IGNORECASE
)
CITED = re.compile(r"(DESIGN|PROTOCOL)\.md(?: §|, section )(\d+)")

# Each label on the wire: where the code holds it, and how to find it there.
LABELS = [
    ("the mac1 label", "crates/convesso-core/src/wire.rs", r'MAC1_LABEL: [^=]+= b"([^"]+)"'),
    ("the cookie label", "crates/convesso-core/src/dos.rs", r'COOKIE_LABEL: [^=]+= b"([^"]+)"'),
    ("the prologue's name", "crates/convesso-core/src/handshake.rs", r'copy_from_slice\(b"([^"]+)"\)'),
    ("the relay context", "crates/convesso-core/src/relay.rs", r'CONTEXT: [^=]+= b"([^"]+)"'),
    ("the link's preamble", "crates/convesso-core/src/relay/framing.rs", r'PREAMBLE: [^=]+= \*b"([^"]+)"'),
]


def files(left_out):
    for directory, names, entries in os.walk(ROOT):
        names[:] = [n for n in names if n not in SKIP_DIRS]
        for entry in entries:
            path = os.path.relpath(os.path.join(directory, entry), ROOT).replace(os.sep, "/")
            if path == SELF or any(path == p or path.startswith(p + "/") for p in left_out):
                continue
            yield path


def read(path):
    with open(os.path.join(ROOT, path), "rb") as f:
        return f.read().decode("utf-8")


def spaced_hex(text):
    """A Rust byte string's bytes, as `63 6f ...`."""
    raw = text.encode("ascii").decode("unicode_escape").encode("latin-1")
    return " ".join(f"{byte:02x}" for byte in raw)


def main():
    left_out = [p.strip("/").replace("\\", "/") for p in sys.argv[1:]]
    faults = []

    sections = {}
    for name in ("DESIGN", "PROTOCOL"):
        sections[name] = set(re.findall(r"(?m)^## (\d+)\. ", read(f"{name}.md")))

    for path in files(left_out):
        try:
            text = read(path)
        except UnicodeDecodeError:
            continue
        for number, line in enumerate(text.split("\n"), 1):
            found = FORBIDDEN.search(line)
            if found:
                faults.append(f"{path}:{number}: names {found.group(0)!r}")
            for document, section in CITED.findall(line):
                if section not in sections[document]:
                    faults.append(f"{path}:{number}: {document}.md has no section {section}")

    protocol = read("PROTOCOL.md")
    for what, path, pattern in LABELS:
        found = re.search(pattern, read(path))
        if not found:
            faults.append(f"{path}: {what} was not found; update scripts/check-public.py")
        elif spaced_hex(found.group(1)) not in protocol:
            faults.append(f"PROTOCOL.md: the bytes of {what} are not those of {path}")

    for vectors in re.findall(r"`(crates/[\w/.-]+\.json)`", protocol):
        if not os.path.isfile(os.path.join(ROOT, vectors)):
            faults.append(f"PROTOCOL.md: {vectors} does not exist")

    for fault in faults:
        print(fault)
    if faults:
        print(f"check-public: {len(faults)} fault(s)")
        return 1
    print("check-public: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
