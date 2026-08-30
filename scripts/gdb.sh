#!/usr/bin/env sh
# Attach gdb to a `cargo kdebug` session (terminal 1: cargo kdebug).
# Pass an alternate ELF as $1 to debug a test image.
set -eu

ELF="${1:-target/riscv64gc-unknown-none-elf/debug/tessera}"

if [ ! -f "$ELF" ]; then
    echo "no kernel ELF at $ELF — run 'cargo build' first" >&2
    exit 1
fi

exec gdb -q \
    -ex "set confirm off" \
    -ex "set architecture riscv:rv64" \
    -ex "set disassemble-next-line on" \
    -ex "file $ELF" \
    -ex "target remote localhost:1234" \
    -ex "break _start" \
    -ex "break kmain" \
    -ex "break rust_begin_unwind" \
    -ex "echo \n--- attached. 'c' to run to _start, 'layout asm' for disassembly ---\n"
