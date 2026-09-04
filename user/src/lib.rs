//! The tessera userspace runtime: entry point, syscalls, panic, printing.

#![no_std]

pub mod block;
pub mod elf;
pub mod fdt;
pub mod io;
pub mod spawn;
pub mod sys;
pub mod virtio;
pub mod vm;

pub use abi;
pub use sys::{Error, Result};

/// Name the function `_start` should call.
#[macro_export]
macro_rules! entry {
    ($path:path) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn __rt_main() {
            // Named binding first, so the signature is checked here rather than
            // reported inside the macro expansion.
            let f: fn() = $path;
            f();
        }
    };
}

/// The ELF entry point.
#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.start")]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        // norelax, or the assembler would relax this `la` against the `gp` it
        // is in the middle of establishing (the same trap as the kernel,
        // D-012).
        ".option push",
        ".option norelax",
        "la gp, __global_pointer$",
        ".option pop",
        // A zero frame pointer and return address terminate any backtrace here.
        "mv fp, zero",
        "mv ra, zero",
        "call __rt_main",
        // Falling off the end of main is an exit, not undefined behaviour.
        "li a7, {exit}",
        "ecall",
        exit = const abi::syscall::EXIT,
    )
}

/// Name the function a *new thread* starts in.
#[macro_export]
macro_rules! thread_entry {
    ($name:ident => $body:path) => {
        #[unsafe(naked)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name() -> ! {
            ::core::arch::naked_asm!(
                ".option push",
                ".option norelax",
                "la gp, __global_pointer$",
                ".option pop",
                "mv fp, zero",
                "mv ra, zero",
                "call {body}",
                "li a7, {exit}",
                "ecall",
                body = sym $body,
                exit = const $crate::abi::syscall::EXIT,
            )
        }
    };
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let _ = io::write_fmt(format_args!("\n!! user panic: {}\n", info.message()));
    if let Some(loc) = info.location() {
        let _ = io::write_fmt(format_args!("   at {}:{}\n", loc.file(), loc.line()));
    }
    sys::exit()
}
