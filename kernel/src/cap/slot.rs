//! Capability slots and the derivation tree they are threaded onto (D-028).

use core::ptr::NonNull;

use super::object::SLOT_BITS;
use super::RawCap;

/// A reference to another slot.
pub type SlotRef = Option<NonNull<Slot>>;

/// One capability, plus its position in the derivation tree.
#[repr(C, align(128))]
pub struct Slot {
    pub cap: RawCap,
    parent: SlotRef,
    first_child: SlotRef,
    next_sib: SlotRef,
    prev_sib: SlotRef,
}

// A slot must fit its stride exactly, or CNode indexing is wrong.
const _: () = assert!(size_of::<Slot>() <= 1 << SLOT_BITS, "a slot no longer fits its stride");
// The `align(128)` above must track SLOT_BITS; this is what catches it if not.
const _: () = assert!(align_of::<Slot>() == 1 << SLOT_BITS, "Slot's align attribute is stale");

impl Slot {
    pub const EMPTY: Slot = Slot {
        cap: RawCap::NULL,
        parent: None,
        first_child: None,
        next_sib: None,
        prev_sib: None,
    };

    pub const fn is_empty(&self) -> bool {
        self.cap.is_null()
    }

    pub const fn has_children(&self) -> bool {
        self.first_child.is_some()
    }

    pub const fn parent(&self) -> SlotRef {
        self.parent
    }

    pub const fn first_child(&self) -> SlotRef {
        self.first_child
    }

    pub const fn next_sibling(&self) -> SlotRef {
        self.next_sib
    }

    /// How many capabilities descend from this one, at any depth.
    pub fn descendants(&self) -> usize {
        let mut n = 0;
        let mut cursor = self.first_child;
        let root = self as *const Slot;

        while let Some(slot) = cursor {
            n += 1;
            // SAFETY: every link in the tree points at a live slot inside a
            // CNode the kernel owns; `&self` means nothing is mutating it.
            let s = unsafe { slot.as_ref() };
            cursor = if let Some(child) = s.first_child {
                Some(child)
            } else {
                // No children: across, or up until there is an "across".
                let mut up = Some(slot);
                loop {
                    // SAFETY: as above.
                    let u = unsafe { up.unwrap().as_ref() };
                    if let Some(sib) = u.next_sib {
                        break Some(sib);
                    }
                    match u.parent {
                        Some(p) if p.as_ptr() as *const Slot != root => up = Some(p),
                        _ => break None,
                    }
                }
            };
        }
        n
    }
}

/// Make `child` a derivative of `parent`, at the front of its child list.
///
/// # Safety
/// Both must be live slots, `child` must not already be in a tree, and the
/// caller must hold exclusive access to the CNodes involved.
pub unsafe fn link(mut parent: NonNull<Slot>, mut child: NonNull<Slot>) {
    // SAFETY: the caller promised exclusive access to live slots.
    unsafe {
        let head = parent.as_ref().first_child;
        child.as_mut().parent = Some(parent);
        child.as_mut().prev_sib = None;
        child.as_mut().next_sib = head;
        if let Some(mut h) = head {
            h.as_mut().prev_sib = Some(child);
        }
        parent.as_mut().first_child = Some(child);
    }
}

/// Take `slot` out of its parent's child list.
///
/// # Safety
/// As [`link`].
pub unsafe fn unlink(mut slot: NonNull<Slot>) {
    // SAFETY: the caller promised exclusive access to live slots.
    unsafe {
        let (prev, next, parent) =
            (slot.as_ref().prev_sib, slot.as_ref().next_sib, slot.as_ref().parent);

        match prev {
            Some(mut p) => p.as_mut().next_sib = next,
            // No previous sibling means this slot was the parent's first child.
            None => {
                if let Some(mut p) = parent {
                    p.as_mut().first_child = next;
                }
            }
        }
        if let Some(mut n) = next {
            n.as_mut().prev_sib = prev;
        }

        slot.as_mut().parent = None;
        slot.as_mut().prev_sib = None;
        slot.as_mut().next_sib = None;
    }
}

/// Destroy every capability derived from `root`, leaving `root` itself alone.
///
/// # Safety
/// `root` must be a live slot and the caller must hold exclusive access to
/// every CNode its descendants live in.
pub unsafe fn revoke(root: NonNull<Slot>) -> usize {
    let mut removed = 0;

    // SAFETY: the caller promised exclusive access to a live tree.
    unsafe {
        let Some(start) = root.as_ref().first_child else { return 0 };
        let mut cursor = start;

        loop {
            // Descend to a leaf.
            while let Some(child) = cursor.as_ref().first_child {
                cursor = child;
            }

            // Decide where to go next *before* the links are torn down.
            let next = match cursor.as_ref().next_sib {
                Some(sibling) => Some(sibling),
                // Last child: the parent is childless now, so it is the next
                // leaf, unless the parent is the root, which we do not touch.
                None => match cursor.as_ref().parent {
                    Some(p) if p != root => Some(p),
                    _ => None,
                },
            };

            unlink(cursor);
            // Destroying a capability that is still mapped would leave the
            // holder reading memory it no longer has any right to (D-034).
            let _ = super::vspace::unmap(&mut cursor.as_mut().cap);
            cursor.as_mut().cap = RawCap::NULL;
            removed += 1;

            match next {
                Some(n) => cursor = n,
                None => break,
            }
        }

        // With every derivative gone, an untyped region can be handed out
        // again.
        if root.as_ref().cap.kind.is_untyped() {
            let mut r = root;
            r.as_mut().cap.watermark = 0;
        }
    }

    removed
}

/// Revoke everything under `slot`, then empty `slot` itself.
///
/// # Safety
/// As [`revoke`].
pub unsafe fn delete(mut slot: NonNull<Slot>) -> usize {
    // SAFETY: the caller promised exclusive access to a live tree.
    unsafe {
        let removed = revoke(slot);
        unlink(slot);
        let _ = super::vspace::unmap(&mut slot.as_mut().cap);
        slot.as_mut().cap = RawCap::NULL;
        removed + 1
    }
}
