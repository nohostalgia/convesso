"""Measures the reference firmware against the committed footprint budget.

    python scripts/footprint.py            # measure, compare, exit 1 if over budget
    python scripts/footprint.py --record   # measure and write the figures as the budget

Two binaries are measured, each with its budget: `reference` (the core) and
`reference-embassy` (the embedded driver over embassy-net). Build the firmware
first, in release, for each target:

    (cd firmware && cargo build --release --target <target>)

Flash is .text + .rodata and static RAM is .data + .bss, each with the RISC-V
small-data variants (.srodata, .sdata, .sbss). Sections are counted by name, so
the runtime's stack and heap reservations, which are not code or data the core
brings, are never counted. The budget lives in footprint-budget.toml at the
repository root; a change that grows the core raises it in the same diff.

It also fails on a constant of the compiler's own, an anonymous read-only
object, larger than 512 bytes: what an empty state with a non-zero byte
leaves in flash, copied from there wherever it is built (`DESIGN.md §2`).
"""

import pathlib
import struct
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
BUDGET = ROOT / "footprint-budget.toml"
TARGETS = ["thumbv7em-none-eabihf", "riscv32imc-unknown-none-elf"]
# Each binary, and the prefix of its tables in the budget.
BINARIES = {
    "reference": "",
    "reference-embassy": "reference-embassy/",
    "reference-stream": "reference-stream/",
}

FLASH = (".text", ".rodata", ".srodata")
RAM = (".data", ".sdata", ".bss", ".sbss")

SHF_ALLOC = 0x2
LARGEST_CONSTANT = 512


def counted(name, prefixes):
    return any(name == p or name.startswith(p + ".") for p in prefixes)


def sections(elf):
    """(name, size) of every allocated section of a little-endian ELF32 file."""
    data = elf.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 1:
        raise SystemExit(f"{elf}: not a little-endian ELF32 file")
    (shoff,) = struct.unpack_from("<I", data, 0x20)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x2E)
    headers = [struct.unpack_from("<10I", data, shoff + i * shentsize) for i in range(shnum)]
    strtab = headers[shstrndx][4]

    def name(offset):
        start = strtab + offset
        return data[start : data.index(b"\0", start)].decode()

    return [(name(h[0]), h[5]) for h in headers if h[2] & SHF_ALLOC]


def large_constants(elf):
    """(name, size) of the anonymous read-only objects over the limit."""
    data = elf.read_bytes()
    (shoff,) = struct.unpack_from("<I", data, 0x20)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x2E)
    headers = [struct.unpack_from("<10I", data, shoff + i * shentsize) for i in range(shnum)]

    def string(table, offset):
        start = table + offset
        return data[start : data.index(b"\0", start)].decode()

    names = [string(headers[shstrndx][4], h[0]) for h in headers]
    rodata = {i for i, name in enumerate(names) if counted(name, (".rodata", ".srodata"))}
    symtab = headers[names.index(".symtab")]
    strings = headers[symtab[6]][4]
    found = []
    for off in range(symtab[4], symtab[4] + symtab[5], 16):
        name, _, size, _, _, section = struct.unpack_from("<IIIBBH", data, off)
        name = string(strings, name)
        if section in rodata and size > LARGEST_CONSTANT and "anon" in name:
            found.append((name, size))
    return found


def measure(target, binary="reference"):
    elf = ROOT / "firmware" / "target" / target / "release" / binary
    if not elf.exists():
        raise SystemExit(f"{elf} is missing: build the reference firmware for {target} first")
    found = sections(elf)
    return {
        "flash": sum(size for name, size in found if counted(name, FLASH)),
        "ram": sum(size for name, size in found if counted(name, RAM)),
        "constants": large_constants(elf),
    }


def record(measured):
    lines = [
        "# The footprint budget: flash (.text + .rodata) and static RAM (.data + .bss) of",
        "# the reference firmware, in bytes, per embedded target: `reference` (the core,",
        "# the tables named by target) and `reference-embassy` (the embedded driver over",
        "# embassy-net, the tables prefixed with its name). Checked by scripts/footprint.py",
        "# on every change. A change that grows either raises its figures in the same",
        "# diff, so the growth is seen in review.",
        "",
    ]
    for binary, prefix in BINARIES.items():
        for target in TARGETS:
            figures = measured[(binary, target)]
            lines += [f'["{prefix}{target}"]', f"flash = {figures['flash']}",
                      f"ram = {figures['ram']}", ""]
    BUDGET.write_text("\n".join(lines), encoding="ascii")
    print(f"recorded the budget in {BUDGET.name}")


def main():
    measured = {
        (binary, target): measure(target, binary) for binary in BINARIES for target in TARGETS
    }
    for (binary, target), figures in measured.items():
        print(f"{binary} {target}: flash {figures['flash']} B, ram {figures['ram']} B")
    if "--record" in sys.argv[1:]:
        record(measured)
        return

    budget = tomllib.loads(BUDGET.read_text(encoding="ascii"))
    over = []
    for (binary, target), figures in measured.items():
        for name, size in figures["constants"]:
            print(f"A {size}-BYTE CONSTANT: {binary} {target} {name}: an empty state with a "
                  "non-zero byte is copied from flash (DESIGN.md §2)", file=sys.stderr)
            over.append(None)
    for (binary, target), figures in measured.items():
        limits = budget.get(BINARIES[binary] + target)
        if limits is None:
            print(f"NO BUDGET: {binary} {target}", file=sys.stderr)
            over.append(None)
            continue
        for section in ("flash", "ram"):
            if figures[section] > limits[section]:
                print(f"OVER BUDGET: {binary} {target} {section} is {figures[section]} B, "
                      f"budget {limits[section]} B", file=sys.stderr)
                over.append(None)
    if over:
        sys.exit(1)
    print("within budget")


if __name__ == "__main__":
    main()
