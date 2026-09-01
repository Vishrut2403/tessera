//! The kernel side of the object model: the markers that put an object's kind
//! into a capability's type. The kinds themselves are ABI (D-038).

pub use abi::object::{ObjectType, SLOT_BITS};

/// Zero-sized markers naming an object kind in a capability's type.
pub mod kind {
    macro_rules! kinds {
        ($($name:ident => $ty:ident),* $(,)?) => { $(
            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            pub struct $name;
            impl super::ObjectKind for $name {
                const TYPE: super::ObjectType = super::ObjectType::$ty;
            }
        )* };
    }

    kinds! {
        Untyped => Untyped,
        DeviceUntyped => DeviceUntyped,
        CNode => CNode,
        Frame => Frame,
        PageTable => PageTable,
        Tcb => Tcb,
        Endpoint => Endpoint,
        Reply => Reply,
    }
}

/// Ties a marker type to the runtime tag it must match on lookup.
pub trait ObjectKind {
    const TYPE: ObjectType;
}
