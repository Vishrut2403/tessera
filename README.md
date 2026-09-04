# tessera

A capability-based microkernel for RISC-V, written in Rust. It runs on QEMU's
`virt` machine under OpenSBI. The interesting part is what runs on top of it: a
virtio-blk disk driver, a read-only filesystem server, and a client that reads a
file by name. None of those live in the kernel.

The kernel itself does four things, and only those four: address spaces, threads
and scheduling, synchronous IPC, and capability enforcement. It has no heap and
no allocator of any kind. Everything else in the system, including the page
tables of every process, gets made by userspace retyping untyped memory it holds
a capability to.

## Running it

`cargo run` boots the kernel. It loads one root task from an ELF embedded in the
image, then stays out of the way. The root task builds three more processes from
boot modules, gives each of them only the capabilities it needs, and supervises
them. Here is part of a real run:

```
    driver gets   : 256 KiB, 8 transports, and READ on the block service
    transport 0   : block device, vendor 0x554d4551
    claim         : 0x10008000 raises source 8; 7 unused transports taken back
    driver ok     : status 0xf, 2048 sectors, 1024 KiB
    fs gets       : 128 KiB, WRITE on the block service, READ on its own
    mounted       : 3 files, 64 blocks reserved
    client gets   : 64 KiB and WRITE on the fs service, and nothing else
    crashing      : touching an address we hold no capability for

  ** task 1 faulted at 0xdead0000, pc 0x10000abc **
    torn down     : untyped revoked (Ok(())), source unmasked
    restarted     : a new driver at 0x10000000
    reconnecting  : the driver below us was restarted
    motd          : 69 bytes:
      | tessera
      |   the kernel does four things
      |   userspace asked for the rest
    spans.bin     : 1500 bytes; 200 of them from 500 span two blocks
    client done   : 4 of 4 checks passed, across 1 crash
```

The driver works out which device is its own by probing the virtio transports
the device tree lists. It then asks the supervisor to claim the interrupt, since
the supervisor is the only process holding the right to claim one. The
filesystem sits in the middle, as a client of the driver and a server to
whoever asks it for a file. The client at the top has a filename and an endpoint
it can only send on.

Partway through the run, the driver reads an address it has no capability for,
on purpose. The kernel delivers that fault to the supervisor as an IPC message.
The supervisor suspends the driver, revokes the memory it was given,
acknowledges the interrupt it left masked, and starts a replacement from the
same boot module. The filesystem sees one failed request and reconnects. The
client sees nothing.

## Design

Rights are part of a capability's type. They are a const parameter, and the
operations that need them sit behind marker traits, so using a capability
without the right it requires will not compile. seL4 checks the same thing at
runtime, in C.

The kernel never allocates. When a mapping needs a page table that does not
exist yet, the kernel refuses the mapping and says why, and userspace supplies
the page table.

Page faults are delivered as IPC. Demand paging, copy-on-write and the crash
supervision above all live outside the kernel because of that one decision.

Drivers are ordinary unprivileged processes. Interrupts reach them as IPC and
MMIO regions are capabilities. The block driver never maps its client's memory.
It asks for a physical address and hands that to the device.

IPC is synchronous with a direct switch to the receiver. The sender donates the
rest of its timeslice, so the scheduler does not run on the fast path. A test
keeps it that way by checking that 2 round trips and 16 round trips cost the
same number of run queue operations.

## Numbers

| | |
|---|---|
| trusted computing base | 6107 lines, 1038 unsafe (17.0%) |
| unprivileged userspace | 1987 lines |
| null syscall | 127 instructions |
| IPC round trip | 1134 instructions |
| tests | 264 cases across 19 bootable images |

`BENCHMARK.md` covers how these were measured, how the unsafe line count moved
over time, and a 37% IPC regression that a bisect traced to one commit.

## Building

The target is `riscv64gc-unknown-none-elf`, which ships with the toolchain, so
there is no cross compiler to install. QEMU for RISC-V is the only other thing
you need.

```sh
rustup default nightly
rustup component add rust-src llvm-tools
rustup target add riscv64gc-unknown-none-elf
cargo install cargo-binutils
```

| command | what it does |
|---|---|
| `cargo run` | boot the demo above |
| `cargo test` | 264 cases across 19 images, each its own kernel |
| `cargo bench-ipc --release` | measure the IPC fast path |
| `./scripts/unsafe-audit.sh` | TCB lines against unsafe lines |
| `cargo kdebug` | boot halted on a gdb stub |

`Ctrl-A` then `x` exits QEMU. The disk image the demo reads is written by
`kernel/build.rs` when it is missing, so a fresh clone needs no extra step.

## Layout

`abi/` holds the syscall interface and is linked by both sides, so a constant
has one definition. `kernel/src/` is the whole trusted computing base, with
capabilities under `cap/` and paging under `mm/`. `user/src/` is everything
unprivileged: an ELF loader, a process spawner, a virtio driver, a filesystem,
and the four programs in `user/src/bin/`. Every file in `kernel/tests/` builds
into its own bootable image.

Good places to start reading are `kernel/src/cap/rights.rs`, `user/src/spawn.rs`
and `user/src/bin/root.rs`.

## Known gaps

There is no IOMMU, so a driver holding a device frame can point a bus master at
any physical address. That puts it inside the TCB for integrity. seL4 without an
SMMU has the same problem.

Untyped capabilities can be copied, and each copy keeps its own watermark, so
two copies of one region would hand out overlapping memory. Nothing in the
system does that today, but nothing stops it either. The fix is a move operation
that transfers a capability instead of copying it.

A crash during a request leaves the caller stuck. There is no equivalent of
Fuchsia's `PEER_CLOSED` and no timeout fault, which is why the demo crashes the
driver between requests rather than during one.

Everything runs on a single hart under QEMU, so there has been no concurrency
testing and nothing has run on real hardware. The IPC fast path is also not
hand-written assembly: about 280 of the 1134 instructions in a round trip are
the generic trap entry saving all 31 registers.

Each of the claims above has a test behind it. Where a test could have passed
for the wrong reason, it was first run against a deliberately broken version of
the code to check that it failed.

## License

MIT OR Apache-2.0.
