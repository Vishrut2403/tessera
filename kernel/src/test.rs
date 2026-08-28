//! The `no_std` test harness (D-010).
//!
//! There is no `libtest` here, so `#![feature(custom_test_frameworks)]` collects
//! every `#[test_case]` into a slice and hands it to [`runner`]. Each test file
//! links into a complete, bootable kernel: `cargo test` builds it, the runner in
//! `.cargo/config.toml` boots it under OpenSBI, it runs its cases and then exits
//! QEMU through the SiFive test device. A passing image exits 0, which is
//! exactly what cargo wants to see.
//!
//! The consequence is coarse granularity — one QEMU boot per *file*, not per
//! case — which is why related assertions get grouped into one file.

use crate::qemu;
use crate::{print, println};

/// Anything runnable as a test case. The blanket impl over `Fn()` is what lets
/// `#[test_case] fn foo() {}` work, and `type_name` recovers the name the
/// harness threw away.
pub trait Testable {
    fn run(&self);
}

impl<T: Fn()> Testable for T {
    fn run(&self) {
        print!("test {} ... ", core::any::type_name::<T>());
        self();
        println!("ok");
    }
}

/// Entry point for a test image. Diverges: it terminates QEMU rather than
/// returning to a caller that does not exist.
///
/// A failing case panics, and the panic handler exits QEMU non-zero (D-009), so
/// there is no failure path through here.
pub fn runner(tests: &[&dyn Testable]) -> ! {
    println!();
    println!("running {} test(s)", tests.len());
    for t in tests {
        t.run();
    }
    println!("all tests passed");
    qemu::exit_success()
}
