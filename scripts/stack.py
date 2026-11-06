"""Measures the stack the reference firmware needs against the committed budget.

    python scripts/stack.py                # build, measure, compare, exit 1 if over budget
    python scripts/stack.py --record       # build, measure and write the depths as the budget
    python scripts/stack.py --no-build     # measure the last build again
    python scripts/stack.py --chains       # print every root's deepest chain
    python scripts/stack.py --binary reference-stream --target riscv32imc-unknown-none-elf

What a microcontroller's task needs is the deepest chain of stack frames below
it, not its largest frame: a poll of a few kilobytes that calls a function of a
few kilobytes needs both. For each reference firmware and each embedded target:

- the firmware is built in release, as the footprint's is, with
  `-Z emit-stack-sizes`, which records each function's frame in a section of
  its own, kept by a linker script. The flag needs `RUSTC_BOOTSTRAP=1` on the
  stable toolchain; the build goes to firmware/target/stack, and its .text is
  compared with the footprint build's, when there is one, so that what is
  measured is what is shipped;
- `llvm-objdump` (the `llvm-tools` component of rustup) gives each function's
  calls: the direct ones by their target, and the indirect ones (through a
  register) by where they are made;
- the deepest chain from each root is the longest path over the calls, each
  function counting its frame. The roots are `main`, each task the firmware
  runs, and the driver's `start` when it is not inlined;
- an indirect call counts as the deepest of the targets its class declares in
  stack-budget.toml. An indirect call in convesso's own code that no class
  covers fails, as does a class that matches nothing, and a cycle of calls.

The budget lives in stack-budget.toml at the repository root, in bytes, per
firmware, target and root; a change that deepens a chain raises it in the same
diff. Interrupt handlers are not counted.
"""

import os
import pathlib
import re
import struct
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIRMWARE = ROOT / "firmware"
BUILD = FIRMWARE / "target" / "stack"
BUDGET = ROOT / "stack-budget.toml"
TARGETS = ["thumbv7em-none-eabihf", "riscv32imc-unknown-none-elf"]
BINARIES = ["reference", "reference-embassy", "reference-stream"]

# Keeps the frames' section, which nothing refers to, in the linked binary.
KEEP = "SECTIONS\n{\n  .stack_sizes (INFO) :\n  {\n    KEEP(*(.stack_sizes));\n  }\n}\n"

# Instructions that go to another function: calls, tail calls, and branches.
# RISC-V's far tail call is `auipc` then `jr` with the target named.
BRANCH = re.compile(r"^(c\.)?(j|jr|jal|jalr|tail|call|b|bl|blx|b[a-z]{2,4})(\.w|\.n)?$")
TARGET = re.compile(r"<([^<>]+?)(\+0x[0-9a-f]+)?>\s*$")
# Convesso's own code: its functions, and its implementations of its own
# traits for other types, as `<Option<..> as convesso_embassy::..>::f`.
CONVESSO = re.compile(r"^<?convesso_(core|stream|embassy)::| as convesso_(core|stream|embassy)::")
TASK = re.compile(r"TaskStorage<.*?__(\w+?)_task::")


def run(command, **kwargs):
    done = subprocess.run(command, capture_output=True, text=True, **kwargs)
    if done.returncode != 0:
        sys.stderr.write(done.stdout + done.stderr)
        raise SystemExit(f"failed: {' '.join(map(str, command))}")
    return done.stdout


def tools():
    """llvm-objdump and llvm-nm of the toolchain the firmware is built with."""
    sysroot = pathlib.Path(run(["rustc", "--print", "sysroot"], cwd=FIRMWARE).strip())
    host = re.search(r"^host: (\S+)", run(["rustc", "-vV"], cwd=FIRMWARE), re.M).group(1)
    suffix = ".exe" if os.name == "nt" else ""
    found = []
    for tool in ("llvm-objdump", "llvm-nm"):
        path = sysroot / "lib" / "rustlib" / host / "bin" / (tool + suffix)
        if not path.exists():
            raise SystemExit(f"{tool} is missing: rustup component add llvm-tools")
        found.append(path)
    return found


def build(target):
    config = tomllib.loads((FIRMWARE / ".cargo" / "config.toml").read_text(encoding="utf-8"))
    flags = config.get("target", {}).get(target, {}).get("rustflags", [])
    BUILD.mkdir(parents=True, exist_ok=True)
    script = BUILD / "stack-sizes.x"
    script.write_text(KEEP, encoding="ascii")
    flags = [*flags, "-Z", "emit-stack-sizes", "-C", f"link-arg=-T{script}"]
    env = dict(os.environ, RUSTC_BOOTSTRAP="1", CARGO_TARGET_DIR=str(BUILD),
               CARGO_ENCODED_RUSTFLAGS="\x1f".join(flags))
    env.pop("RUSTFLAGS", None)
    base = ["cargo", "build", "--release", "--target", target]
    run(base, cwd=FIRMWARE, env=env)
    run([*base, "--features", "stream", "--bin", "reference-stream"], cwd=FIRMWARE, env=env)


class Elf:
    """The sections, function symbols and frames of a little-endian ELF32 file."""

    def __init__(self, path):
        data = path.read_bytes()
        if data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 1:
            raise SystemExit(f"{path}: not a little-endian ELF32 file")
        (shoff,) = struct.unpack_from("<I", data, 0x20)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x2E)
        headers = [struct.unpack_from("<10I", data, shoff + i * shentsize) for i in range(shnum)]
        names = headers[shstrndx][4]

        def string(table, offset):
            start = table + offset
            return data[start : data.index(b"\0", start)].decode()

        self.sections = {string(names, h[0]): h for h in headers}
        symtab = self.sections[".symtab"]
        strings = headers[symtab[6]][4]
        self.address = {}
        for off in range(symtab[4], symtab[4] + symtab[5], 16):
            name, value, _, info, _, _ = struct.unpack_from("<IIIBBH", data, off)
            if info & 0xF == 2:  # a function
                self.address[string(strings, name)] = value & ~1
        self.frames = {}
        section = self.sections.get(".stack_sizes")
        if section is None:
            raise SystemExit(f"{path}: no .stack_sizes section; was it built by this script?")
        off, end = section[4], section[4] + section[5]
        while off < end:
            (address,) = struct.unpack_from("<I", data, off)
            off += 4
            size = shift = 0
            while True:
                byte = data[off]
                off += 1
                size |= (byte & 0x7F) << shift
                shift += 7
                if byte < 0x80:
                    break
            self.frames[address & ~1] = size

    def size(self, section):
        header = self.sections.get(section)
        return header[5] if header else 0


class Graph:
    """Who calls whom in a binary, and who calls through a register."""

    def __init__(self, elf, path, objdump, nm):
        self.calls = {}
        self.indirect = {}
        current = None
        text = run([objdump, "-d", "--no-show-raw-insn", path])
        for line in text.splitlines():
            header = re.match(r"^([0-9a-f]+) <(.+)>:$", line)
            if header:
                current = int(header.group(1), 16) & ~1
                self.calls.setdefault(current, set())
                continue
            instruction = re.match(r"^\s*[0-9a-f]+:\s+(\S+)\s*(.*)$", line)
            if current is None or not instruction:
                continue
            mnemonic, operands = instruction.groups()
            # Arm's lines end with a comment, `@ imm = #...`.
            operands = operands.split(" @ ")[0].rstrip()
            if not BRANCH.match(mnemonic):
                continue
            target = TARGET.search(operands)
            if target:
                address = elf.address.get(target.group(1))
                if address is not None and address != current:
                    self.calls[current].add(address)
            elif self.through_register(mnemonic, operands):
                self.indirect[current] = self.indirect.get(current, 0) + 1
        self.names = {}
        for line in run([nm, "-C", "--defined-only", path]).splitlines():
            parts = line.split(" ", 2)
            if len(parts) == 3 and parts[1] in "tTwW":
                self.names.setdefault(int(parts[0], 16) & ~1, parts[2])

    @staticmethod
    def through_register(mnemonic, operands):
        """A call through a register: RISC-V's `jalr`, Arm's `blx` and `bx`.
        A `jr` without a link is a jump table's, within its function, and so
        is Arm's `bx` to the link register, a return."""
        register = operands.split(",")[0].strip()
        if mnemonic in ("jalr", "c.jalr"):
            return True
        if mnemonic == "blx":
            return True
        return mnemonic == "bx" and register != "lr"

    def name(self, address):
        return self.names.get(address, hex(address))


class Classes:
    """The declared targets of indirect calls, by the caller's name."""

    def __init__(self, declared):
        self.declared = [
            (c["name"], re.compile(c["callers"]), re.compile(c["targets"]), c.get("optional", False))
            for c in declared
        ]
        self.used_callers = set()
        self.used_targets = set()

    def targets(self, graph, caller):
        name = graph.name(caller)
        found, covered = set(), False
        for label, callers, targets, _ in self.declared:
            if callers.search(name):
                covered = True
                self.used_callers.add(label)
                for address, other in graph.names.items():
                    if address in graph.calls and targets.search(other):
                        found.add(address)
                        self.used_targets.add(label)
        return covered, found

    def stale(self):
        return [label for label, _, _, optional in self.declared
                if label not in self.used_callers
                or (label not in self.used_targets and not optional)]


class Measure:
    def __init__(self, elf, graph, classes):
        self.elf, self.graph, self.classes = elf, graph, classes
        self.memo = {}
        self.path = []
        self.errors = []
        self.uncovered = {}

    def deepest(self, function):
        """(depth, chain) below `function`, its frame included."""
        if function in self.memo:
            return self.memo[function]
        if function in self.path:
            cycle = self.path[self.path.index(function):] + [function]
            self.errors.append("a cycle of calls: " + " -> ".join(map(self.graph.name, cycle)))
            return (0, ())
        self.path.append(function)
        below = set(self.graph.calls.get(function, ()))
        if self.graph.indirect.get(function):
            covered, targets = self.classes.targets(self.graph, function)
            below |= targets
            if not covered:
                self.uncovered[function] = self.graph.indirect[function]
        best = (0, ())
        for callee in below:
            best = max(best, self.deepest(callee))
        self.path.pop()
        own = self.elf.frames.get(function, 0)
        result = (own + best[0], (function, *best[1]))
        self.memo[function] = result
        return result

    def roots(self):
        # `main` by its symbol: an alias at the same address may name it.
        found = {"main": self.elf.address["main"]} if "main" in self.elf.address else {}
        for address in self.graph.calls:
            name = self.graph.name(address)
            if name.startswith("convesso_embassy::node::start"):
                found["start"] = address
            elif name.endswith(">::poll") and (task := TASK.search(name)):
                found[f"task {task.group(1)}"] = address
        return found


def measure(binary, target, objdump, nm, classes):
    path = BUILD / target / "release" / binary
    if not path.exists():
        raise SystemExit(f"{path} is missing: run without --no-build")
    elf = Elf(path)
    graph = Graph(elf, path, objdump, nm)
    m = Measure(elf, graph, classes)
    depths = {root: m.deepest(address) for root, address in sorted(m.roots().items())}
    for function, sites in sorted(m.uncovered.items()):
        name = graph.name(function)
        if CONVESSO.search(name):
            m.errors.append(f"{sites} indirect call(s) no class covers, in {name}")
    # Every indirect call in convesso's code, counted by function: a class
    # covers its targets, and the count catches one more call where there were
    # some, which a class's pattern alone would let through.
    m.indirect = {}
    for function, sites in graph.indirect.items():
        name = graph.name(function)
        if CONVESSO.search(name):
            m.indirect[name] = m.indirect.get(name, 0) + sites
    shipped = FIRMWARE / "target" / target / "release" / binary
    if shipped.exists():
        footprint = text_size(shipped)
        if footprint != elf.size(".text"):
            m.errors.append(f".text is {elf.size('.text')} B here and {footprint} B in the "
                            "footprint's build: rebuild the firmware, or the flag changed the code")
    largest = sorted(((size, graph.name(a)) for a, size in elf.frames.items()
                      if CONVESSO.search(graph.name(a))), reverse=True)[:10]
    return depths, m, largest


def text_size(path):
    data = path.read_bytes()
    (shoff,) = struct.unpack_from("<I", data, 0x20)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x2E)
    headers = [struct.unpack_from("<10I", data, shoff + i * shentsize) for i in range(shnum)]
    names = headers[shstrndx][4]
    for h in headers:
        start = names + h[0]
        if data[start : data.index(b"\0", start)] == b".text":
            return h[5]
    return 0


def short(name, width=110):
    return name if len(name) <= width else name[: width - 3] + "..."


def show(m, chain, indent="      "):
    for function in chain:
        print(f"{indent}{m.elf.frames.get(function, 0):>7}  {short(m.graph.name(function))}")


def record(budget, measured, classes):
    lines = [
        "# The stack budget: the deepest chain of stack frames below each root of the",
        "# reference firmware, in bytes, per embedded target. Checked by scripts/stack.py",
        "# on every change; a change that deepens a chain raises its figure in the same",
        "# diff, so the growth is seen in review.",
        "#",
        "# Each [[indirect]] class says where calls through a register may go: a call",
        "# made in a function whose name matches `callers` counts as the deepest chain",
        "# of the functions whose names match `targets` (demangled names, regexes).",
        "# A class `optional` may find no target in the reference firmware.",
        "#",
        "# Each firmware's `indirect` table counts the calls through a register in each",
        "# of convesso's functions: one more, or one in a function not listed, fails",
        "# until it is recorded, so that a new call through a trait object or a",
        "# function pointer is seen in review, with the class that covers it.",
        "",
    ]
    for label, callers, targets, optional in classes.declared:
        lines += ["[[indirect]]", f"name = '{label}'", f"callers = '{callers.pattern}'",
                  f"targets = '{targets.pattern}'"]
        lines += ["optional = true", ""] if optional else [""]
    depths = {k: dict(v) for k, v in budget.items() if k != "indirect"}
    for (binary, target), (roots, indirect) in measured.items():
        depths[f"{binary}/{target}"] = {**roots, "indirect": indirect}
    for key in sorted(depths):
        table = dict(depths[key])
        indirect = table.pop("indirect", {})
        lines.append(f'["{key}"]')
        lines += [f'"{root}" = {depth}' for root, depth in sorted(table.items())]
        lines += ["", f'["{key}".indirect]']
        lines += [f'"{name}" = {sites}' for name, sites in sorted(indirect.items())]
        lines.append("")
    BUDGET.write_text("\n".join(lines), encoding="ascii", newline="\n")
    print(f"recorded the budget in {BUDGET.name}")


def option(name):
    args = sys.argv[1:]
    return args[args.index(name) + 1] if name in args else None


def main():
    targets = [option("--target")] if option("--target") else TARGETS
    binaries = [option("--binary")] if option("--binary") else BINARIES
    objdump, nm = tools()
    if "--no-build" not in sys.argv:
        for target in targets:
            build(target)
    budget = tomllib.loads(BUDGET.read_text(encoding="ascii")) if BUDGET.exists() else {}
    classes = Classes(budget.get("indirect", []))
    measured, failures = {}, []
    for binary in binaries:
        for target in targets:
            depths, m, largest = measure(binary, target, objdump, nm, classes)
            measured[(binary, target)] = ({root: d for root, (d, _) in depths.items()}, m.indirect)
            limits = dict(budget.get(f"{binary}/{target}", {}))
            declared = limits.pop("indirect", {})
            for name, sites in sorted(m.indirect.items()):
                if sites > declared.get(name, 0):
                    failures.append(f"{binary} {target}: {sites} indirect call(s), "
                                    f"{declared.get(name, 0)} recorded, in {name}")
            print(f"{binary} {target}:")
            for root, (depth, chain) in depths.items():
                limit = limits.get(root)
                over = limit is None or depth > limit
                print(f"  {root}: {depth} B" + (f" (budget {limit} B)" if limit else " (no budget)"))
                if "--chains" in sys.argv or (over and "--record" not in sys.argv):
                    show(m, chain)
                if over:
                    failures.append(f"{binary} {target} {root}: {depth} B, budget {limit} B")
            print("  largest frames of convesso's functions:")
            for size, name in largest:
                print(f"    {size:>7}  {short(name)}")
            failures += [f"{binary} {target}: {e}" for e in m.errors]
    if len(binaries) == len(BINARIES) and len(targets) == len(TARGETS):
        failures += [f"class '{label}' matches no call or no target" for label in classes.stale()]
    if "--record" in sys.argv:
        hard = [f for f in failures if "budget" not in f and "recorded" not in f]
        if hard:
            raise SystemExit("\n".join(hard))
        record(budget, measured, classes)
        return
    if failures:
        print("\n".join(failures), file=sys.stderr)
        sys.exit(1)
    print("within budget")


if __name__ == "__main__":
    main()
