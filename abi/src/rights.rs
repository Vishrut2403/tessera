//! The rights bits, as they appear on the wire.
//!
//! The kernel re-exports these and adds the typestate machinery that makes a
//! missing right a compile error (invariant 3). Userspace only ever needs the
//! bits, to name them in a `Mint`.

/// Read the object, or receive from an endpoint.
pub const READ: u8 = 1 << 0;
/// Write the object, retype untyped memory, or send to an endpoint.
pub const WRITE: u8 = 1 << 1;
/// Delegate this capability, and carry capabilities in a message.
pub const GRANT: u8 = 1 << 2;

/// Every right. What the initial task holds over its own untyped memory.
pub const ALL: u8 = READ | WRITE | GRANT;

/// The number of distinct masks, and the bound the kernel's tables enumerate.
pub const MASKS: usize = (ALL as usize) + 1;

/// Human-readable mask, for dumps.
pub const fn name(mask: u8) -> &'static str {
    match mask & ALL {
        0 => "none",
        1 => "READ",
        2 => "WRITE",
        3 => "READ|WRITE",
        4 => "GRANT",
        5 => "READ|GRANT",
        6 => "WRITE|GRANT",
        7 => "READ|WRITE|GRANT",
        _ => "?",
    }
}
