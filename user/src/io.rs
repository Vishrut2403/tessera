//! Printing, over the ambient `PUTC` syscall.

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
    // A block, so the macro is an expression and can sit in a match arm.
    ($($arg:tt)*) => {{ let _ = $crate::io::write_fmt(format_args!($($arg)*)); }};
}

#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => { $crate::print!("{}\n", format_args!($($arg)*)) };
}
