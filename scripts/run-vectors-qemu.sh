#!/bin/sh
# Runs the vectors firmware for an embedded target under QEMU:
#
#   scripts/run-vectors-qemu.sh <target> [elf]
#
# The firmware prints its result through semihosting and exits 0 when every
# vector passes, 1 when one fails; this script exits with the same status. A
# firmware that hangs is stopped after five minutes and counts as a failure.
set -eu

target="${1:?usage: run-vectors-qemu.sh <target> [elf]}"
elf="${2:-firmware/target/$target/release/vectors}"

case "$target" in
    thumbv7em-none-eabihf) set -- qemu-system-arm -M mps2-an386 ;;           # Cortex-M4
    riscv32imc-unknown-none-elf) set -- qemu-system-riscv32 -M virt -bios none ;;
    *) echo "no QEMU machine is configured for $target" >&2; exit 2 ;;
esac

exec timeout 300 "$@" -nographic -semihosting-config enable=on,target=native -kernel "$elf"
