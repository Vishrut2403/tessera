//! Printing, over the ambient `PUTC` syscall.
//!
//! `PUTC` names no capability, which makes it the last piece of ambient
//! authority a user program has. A console capability replaces it, and then
//! this file changes and nothing else does (D-032).

use core::fmt::{self, Write};

pub struct Console;

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            crate::sys::putc(b);
        }
        Ok(())
    }
}

pub fn write_fmt(args: fmt::Arguments) -> fmt::Result {
    Console.write_fmt(args)
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => { let _ = $crate::io::write_fmt(format_args!($($arg)*)); };
}

#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => { $crate::print!("{}\n", format_args!($($arg)*)) };
}
