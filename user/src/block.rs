//! The block service protocol, defined once so a driver and its clients cannot
//! drift apart (D-038). Nothing here is specific to virtio.

use crate::abi::label;

/// "Here is the frame I want blocks read into." Carries a frame capability,
/// once, at connect time. A 512-byte block does not fit in four registers,
/// so the message carries the *authority* to memory and not the memory.
pub const CONNECT: u64 = label::APP_BASE + 0x10;
/// "Read block `w0` into the frame I gave you."
pub const READ: u64 = label::APP_BASE + 0x11;
/// "I am finished; stop serving." A server loop needs a way to end, or the run
/// queue never empties.
pub const SHUTDOWN: u64 = label::APP_BASE + 0x12;

/// What a reply says in word 0.
pub const OK: usize = 0;
pub const FAILED: usize = 1;
/// A read was asked for before any frame was connected.
pub const NO_BUFFER: usize = 2;

/// Bytes in a block, which is also virtio-blk's sector size.
pub const BLOCK: usize = 512;
