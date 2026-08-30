//! The `no_std` test harness (D-010).

use crate::qemu;
use crate::{print, println};

/// Anything runnable as a test case.
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

/// Entry point for a test image; terminates QEMU rather than returning.
pub fn runner(tests: &[&dyn Testable]) -> ! {
    println!();
    println!("running {} test(s)", tests.len());
    for t in tests {
        t.run();
    }
    println!("all tests passed");
    qemu::exit_success()
}
