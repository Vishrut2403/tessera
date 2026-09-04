# tessera: what was measured, and what it means

A capability-based microkernel for RV64 under QEMU `virt`. This document holds
the numbers the project actually produced, how they were obtained, and, with the
same care, what could not be measured and why.

## 1. Why instructions and not cycles

Every number here is instructions retired, counted under `qemu-system-riscv64
-icount shift=0`, which makes the instruction counter track guest execution
rather than host wall-clock time.

Cycles are not available and are not something this target can produce. QEMU's
TCG has no cache, no branch predictor and no pipeline. A cycle count from it
would just be the instruction count with a made-up constant attached. An
instruction count is a real, reproducible property of the code. A cycle count
needs silicon.

The measurement is differential. A null syscall is measured, then a round trip,
and the harness reports the difference against a calibrated floor of one
instruction between adjacent counter reads. One test asserts the floor and
another asserts the ratio, so a broken measurement fails instead of quietly
lying.

Reproduce with `cargo bench-ipc --release`.

## 2. The IPC fast path

An IPC round trip is a `call` from a client and a `reply` from a server. That is
two user to supervisor to user crossings, a four-register message copy in each
direction, two direct process switches, and two address space changes. The run
queue is not consulted once. A test asserts that 2 round trips and 16 round
trips cost the same number of queue pops, which is how invariant 4 is enforced
rather than hoped for.

Measured on QEMU 11.1.0, release profile:

| what | instructions |
|---|---|
| null syscall (`ecall` in, `ecall` out) | 127 |
| IPC round trip, no ASID (full TLB flush) | 963 |
| IPC round trip, ASID-tagged spaces | 961 |
| IPC round trip, one shared address space | 951 |
| round trip / null syscall | 7x |

ASIDs save only 2 instructions here, and that is worth stating rather than
glossing. What they save is a TLB flush, and a TLB flush costs almost nothing in
instructions while being one of the more expensive things a real machine does.
This is the point where an instruction count stops describing a real system, and
the number should not be quoted as though it did.

## 3. A regression, traced and mostly fixed

At M5 this benchmark reported 826 instructions for a round trip. By M8 it
reported 1136, which is 310 more, about 38%. It now reports 963, so 173 of
those have been recovered and 137 remain.

The first question was whether the comparison was even valid, since the M5
figure came from an earlier session on a possibly different toolchain. It is
valid, and this was checked rather than assumed. The M5 tree was extracted with
`git archive`, built with today's toolchain, and run on today's QEMU. It
reproduced 125 / 826 / 824 / 814 exactly. The benchmark harness has only
cosmetic changes since M5, and the hand-assembled client and server programs it
runs are unchanged.

So the regression is real. Bisecting it by building and benchmarking each
commit:

| commit | null syscall | round trip |
|---|---|---|
| M5, synchronous IPC | 125 | 826 |
| M6, faults as IPC and the pager | 127 | 1118 |
| M7a+b, threads as objects, ELF root task | 127 | 1123 |
| M7d, notifications and interrupts | 127 | 1123 |
| M7f, the filesystem server | 127 | 1129 |
| M8, crash and restart | 127 | 1134 |
| with D-049, untyped moved not copied | 127 | 1136 |
| with D-050, capability payload shared | 127 | **963** |

**M6 accounts for 292 of the 310 instructions.** Everything built in M7 and M8,
which is most of the system by line count, adds 18 in total. That is the useful
result: a driver, a filesystem, three more processes and a supervisor cost
almost nothing on the IPC fast path, and one earlier milestone cost a great
deal.

Within M6, three suspects were measured and cleared:

- The badge log that M6 added to both sides of every message delivery does an
  atomic increment on the fast path. Removing both calls and re-measuring moves
  the round trip by **3 instructions**.
- The endpoint rights checks added later in D-042 cost **2 instructions**.
  Typed rights really are as close to free as the project claimed.
- The trap entry is not involved. The null syscall grew by 2 instructions across
  the whole period, so register save and restore is unchanged.

### Where the rest of it went

Reverting features inside one large commit is awkward, so the path was
instrumented instead. `rdinstret` probes were added either side of each stage of
a round trip, on the current tree and on the M5 tree, and the benchmark run
divided by the number of times each probe fired.

One capability lookup, meaning `cspace_of` followed by `cs.read`, costs:

| | instructions |
|---|---|
| M5 | 146 |
| now | 223 |

A round trip performs more than one. The client's `call` resolves the endpoint,
and the server's `reply_recv` resolves it again on the receive half. So the
lookup alone accounts for somewhere between 150 and 230 of the 310, depending on
how many resolutions a given path makes.

The cause is data size, not logic. The hot path functions are unchanged between
M5 and M6 apart from the wrappers already accounted for above.

| | M5 | now |
|---|---|---|
| `RawCap` | 32 bytes | 48 bytes, now 32 again |
| `Slot` | 64 bytes | 128 bytes, now 64 again |

`RawCap` grew when M6 began recording a mapping in the capability that made it
(D-034), adding `mapped_root` and `mapped_vaddr`, and M7 later added `asid`. A
`Slot` is a `RawCap` plus four derivation-tree pointers, so 48 plus 32 is 80,
and a CNode's stride has to be a power of two, which rounded it to 128. Every
lookup then copies a larger `RawCap` by value several times and indexes a slot
array with twice the stride.

The other stages, measured the same way on the current tree: `deliver` costs 107
instructions, `ipc_send` from entry to the end of `deliver` costs 133, and
`switch_direct` costs 32 and runs twice per round trip.

**The fix, applied (D-050).** The fields that grew `RawCap` are mutually
exclusive by object kind. A watermark only means something for untyped, a
mapping only for a frame or a page table, a badge only for an endpoint or a
notification. No capability needs two at once, so they now share two payload
words whose meaning `kind` decides, reached only through accessors that consult
it. `RawCap` is back to 32 bytes and a `Slot` to 64, which also halves what a
CNode occupies.

That took the round trip from 1136 to 963. The 137 instructions still separating
it from M5 are the `deliver` wrapper and the capability-transfer branch M6 added,
plus ordinary code growth, and have not been chased further.

### What is deliberately not optimised

The fast path goes through the same trap entry as everything else, saving and
restoring all 31 registers, which is roughly 280 of the instructions in a round
trip. seL4's fast path saves only what it uses. That is the single largest
remaining optimisation and it was never attempted.

## 4. The comparison that was not made

The project's own roadmap asks for the round trip to be measured against a Linux
pipe and a futex round trip. That comparison is absent, and no number resembling
it appears here.

An honest version needs a RISC-V Linux image booted under the same `-icount`
settings, with the same counter methodology, measuring a pipe write and read
pair and a futex wake and wait pair. Anything else compares different
instruction sets on different emulator configurations and means nothing. That
image does not exist in this project, so the comparison is not made. Numbers
lifted from published benchmarks on other hardware would not be a comparison
either. They would be decoration.

What can be said without it: a round trip costs 7 null syscalls, about a third
of it is a register save and restore the fast path does not need, and of the 310
instructions it had gained since M5, 173 were traced to a cause and removed.

## 5. The trusted computing base

Measured by `./scripts/unsafe-audit.sh`, which strips comments and blank lines
and counts `kernel/src` plus `abi/`, the code the kernel links and therefore
must trust. `user/` is excluded and reported separately, because counting it
would only flatter the number.

| milestone | TCB lines | unsafe | share |
|---|---|---|---|
| M1 boot | 645 | 175 | 27.1% |
| M2 address spaces | 2106 | 302 | 14.3% |
| M3 threads, context switch | 2886 | 603 | 20.9% |
| M4 capabilities, revocation | 3630 | 728 | 20.1% |
| M5 synchronous IPC | 4140 | 839 | 20.3% |
| M6 userspace pager | 4463 | 859 | 19.2% |
| M7 driver and filesystem | 6057 | 1013 | 16.7% |
| M8 crash and restart | 6107 | 1038 | 17.0% |
| untyped moved, not copied | 6177 | 1074 | 17.4% |
| capability payload shared | 6197 | 1074 | 17.3% |

Final figure: 6197 lines, 1074 of them inside `unsafe`, in 190 regions.

Two movements need explaining rather than hiding.

M3 rose from 14.3% to 20.9%, and the headline overstates it. 780 lines arrived
and 301 were unsafe, but two mechanical register lists account for most of that.
The trap entry saves and restores 31 registers twice inside `naked_asm!`, about
130 lines, and the floating-point save and restore is 64 `fsd` and `fld`
instructions inside two blocks. That is roughly 190 lines of transcription, not
190 lines of subtle reasoning. The region count is the fairer measure. It went
from 53 to 87, and the new regions sit exactly where the design says they
should: trap entry, FP state, context switch.

M8 and D-049 together took it from 16.7% to 17.4%, the first rise since M3, and
both are one shape. Recording which queue a blocked thread is on has to be
written through a `NonNull<Tcb>` inside the endpoint and notification queue
methods, which are already the most pointer-dense code in the kernel. Six new
regions, each a field assignment beside an existing one under the same SAFETY
comment. Setting it at the four call sites instead would have been safe code in
more places and a rule enforced in none. D-049's `slot::relocate` is the same
kind of thing: rewriting four pointers across three slots to move a capability
without losing its place in the derivation tree, in one block because it is one
operation rather than four hazards.

The trend between them holds. From M3 to M7 the share fell every milestone while
the kernel nearly doubled, because what was being added was safe code over an
unsafe core that had stopped growing.

### Where the code actually is

| | lines |
|---|---|
| TCB (`kernel/src` and `abi/`) | 6197 |
| userspace (`user/src`), outside the TCB | 2018 |

The most useful single figure the project produced: M7e and M7f, which are a
virtio-blk driver, a filesystem server, a client and the protocols between them,
grew the kernel by 129 lines while userspace went from 556 to 1872. A disk
driver reading real blocks off a real device, completed by a real interrupt,
needed no kernel mechanism that did not already exist. M7e-3, one
interrupt-driven block read, added zero lines to the kernel.

## 6. What the system demonstrates

Four processes deep, none of them privileged: a supervisor, a virtio-blk driver,
a read-only filesystem server, and a client holding a filename and a send-only
endpoint. The client asks for a file by name and gets its bytes, off a disk it
cannot address, through a driver it cannot impersonate.

- Rights are types. A capability without a right is a missing method rather than
  a runtime check, and the runtime checks that do exist cost 2 instructions.
- The kernel never allocates. Every object in the system was retyped from
  untyped memory by userspace, including the page tables of every process.
- Drivers are unprivileged. The block driver holds a device untyped, an
  interrupt handler and one endpoint. It never maps its client's memory. It
  learns a physical address and hands that to the device.
- A crash is survivable. The driver faults, the supervisor is told by IPC,
  reclaims its memory by revoking one capability, and builds another.

## 7. What it does not demonstrate

Stated because a benchmark document that only flatters is not evidence.

- No IOMMU. A driver holding a device frame can aim a bus master at any physical
  address, so it is inside the TCB for integrity. seL4 without an SMMU has the
  same property. This is the largest gap between the architecture and its
  guarantees.
- A crash during a request strands the caller. There is no `PEER_CLOSED` as in
  Fuchsia and no timeout fault as in seL4 MCS, so the demo crashes the driver
  between requests.
- Single hart. Nothing here has been tested with concurrency, and several SAFETY
  comments say "only this hart" and mean it.
- No real hardware. QEMU `virt` only. Nothing has run on silicon, and the
  `sstc`-absent timer path has never executed.
- One client per server. Both servers keep a single connection's worth of state.
- The IPC round trip is still 17% slower than at M5 after the fix in section 3,
  and the remainder has not been chased.

## 8. Reproducing all of it

```sh
cargo test                 # 275 cases across 19 bootable images
cargo test --release       # the same, optimised
cargo run                  # boots the whole demo, ending in a crash and restart
cargo bench-ipc --release  # the numbers in section 2
./scripts/unsafe-audit.sh  # the numbers in section 5
```

The bisect in section 3 is reproducible with `git archive <commit> | tar -x -C
<dir>` followed by `cargo bench-ipc --release` in that directory.

Every milestone's evidence was checked against a deliberately broken version of
the thing it claims: a removed `Resume`, a dropped badge, a revoked capability
left usable, a filesystem that follows only the first direct pointer, a
suspended thread left on a live queue. Each test was believed only after it
failed for the right reason.
