//! Rights, carried in the type system (invariant 3).
//!
//! A capability's rights are a `const` bitmask parameter, so an operation that
//! needs a right is only *defined* for masks that contain it. Using a capability
//! without the right is a missing method, not a runtime check.
//!
//! The mask is const, but a capability arrives from userspace as a runtime slot
//! whose rights are only known when it is read. [`CSpace::lookup`] is the seam:
//! it takes the required mask as a const parameter, checks the stored rights
//! contain it once, and hands back a value whose type carries the proof. Every
//! operation after that point is checked by the compiler.

/// Read the object, or receive from an endpoint.
pub const READ: u8 = 1 << 0;
/// Write the object, retype untyped memory, or send to an endpoint.
pub const WRITE: u8 = 1 << 1;
/// Delegate this capability, and carry capabilities in a message.
pub const GRANT: u8 = 1 << 2;

/// Every right. What the initial task holds over its own untyped memory.
pub const ALL: u8 = READ | WRITE | GRANT;

/// The number of distinct masks, and the bound the tables below enumerate.
pub const MASKS: usize = (ALL as usize) + 1;

/// Marker for masks containing [`READ`].
pub trait HasRead {}
/// Marker for masks containing [`WRITE`].
pub trait HasWrite {}
/// Marker for masks containing [`GRANT`].
pub trait HasGrant {}

/// `Subset<A, B>` exists exactly when `B`'s rights are a subset of `A`'s.
///
/// This is what stops [`Cap::reduce`] from being a rights *escalation*: the
/// target mask has to be provably weaker, at compile time.
pub trait Subset<const FROM: u8, const TO: u8> {}

/// The type the marker traits and [`Subset`] are implemented on.
pub struct Mask<const M: u8>;


macro_rules! has {
    ($trait:ident: $($mask:literal)*) => { $( impl $trait for Mask<$mask> {} )* };
}

macro_rules! subsets {
    ($from:literal => $($to:literal)*) => { $( impl Subset<$from, $to> for Mask<$from> {} )* };
}

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

// Masks containing READ.
has!(HasRead: 1 3 5 7);
// Masks containing WRITE.
has!(HasWrite: 2 3 6 7);
// Masks containing GRANT.
has!(HasGrant: 4 5 6 7);

// For each mask, the masks that are subsets of it.
subsets!(0 => 0);
subsets!(1 => 0 1);
subsets!(2 => 0 2);
subsets!(3 => 0 1 2 3);
subsets!(4 => 0 4);
subsets!(5 => 0 1 4 5);
subsets!(6 => 0 2 4 6);
subsets!(7 => 0 1 2 3 4 5 6 7);
