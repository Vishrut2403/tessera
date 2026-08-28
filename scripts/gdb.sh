#!/usr/bin/env sh
# Attach gdb to a `cargo kdebug` session.
#
#   terminal 1:  cargo kdebug          # QEMU starts halted, gdb stub on :1234
#   terminal 2:  ./scripts/gdb.sh      # attach, break at _start
#
# Arch's gdb is built multiarch and already knows riscv:rv64, so there is no
# cross-gdb to install. Pass an alternate ELF as $1 to debug a test image:
#   ./scripts/gdb.sh target/riscv64gc-unknown-none-elf/debug/deps/traps-<hash>
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
