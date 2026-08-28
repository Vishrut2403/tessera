//! NS16550A UART driver, MMIO at 0x1000_0000 on QEMU virt (D-004).
//!
//! We talk to the hardware directly rather than calling OpenSBI's console
//! (`sbi_console_putchar` / the DBCN extension). The SBI console is a crutch
//! that vanishes the moment the UART belongs to a userspace driver holding an
//! MMIO capability (M7), whereas the register-level knowledge below is exactly
//! what that driver will need.
//!
//! ## The register map
//!
//! Eight byte-wide registers at consecutive addresses. Three of them are two
//! registers wearing a trench coat: which one you get depends on DLAB, bit 7 of
//! the line control register.
//!
//! | Offset | DLAB=0 read | DLAB=0 write | DLAB=1 |
//! |--------|-------------|--------------|--------|
//! | 0 | RBR: received byte | THR: byte to transmit | DLL: divisor low |
//! | 1 | IER: interrupt enable | IER | DLM: divisor high |
//! | 2 | IIR: interrupt id | FCR: FIFO control | — |
//! | 3 | LCR: line control | LCR | LCR |
//! | 4 | MCR: modem control | MCR | MCR |
//! | 5 | LSR: line status | — | — |
//!
//! On QEMU virt the registers are one byte apart (`reg-shift = 0` in the device
//! tree). Real 16550s behind a wider bus often use `reg-shift = 2`; that is a
//! per-board constant to read out of the DTB from M2 onward, not something to
//! bake in.

use core::fmt;

use crate::sync::SpinLock;

/// QEMU virt's UART0. Hardcoded in M1; from M2 this comes out of the device tree.
pub const UART0_BASE: usize = 0x1000_0000;

// Register offsets.
const RBR: usize = 0; // read:  receive buffer
const THR: usize = 0; // write: transmit holding
const DLL: usize = 0; // DLAB=1: divisor latch low
const IER: usize = 1; // interrupt enable
const DLM: usize = 1; // DLAB=1: divisor latch high
const FCR: usize = 2; // write: FIFO control
const LCR: usize = 3; // line control
const MCR: usize = 4; // modem control
const LSR: usize = 5; // line status

// Line status bits.
const LSR_DATA_READY: u8 = 1 << 0;
/// Transmit Holding Register Empty — the THR can accept another byte.
const LSR_THR_EMPTY: u8 = 1 << 5;

// Line control bits.
const LCR_8BIT: u8 = 0b11;
const LCR_DLAB: u8 = 1 << 7;

// FIFO control bits.
const FCR_ENABLE: u8 = 1 << 0;
const FCR_CLEAR_RX: u8 = 1 << 1;
const FCR_CLEAR_TX: u8 = 1 << 2;

// Modem control bits.
const MCR_DTR: u8 = 1 << 0;
const MCR_RTS: u8 = 1 << 1;

pub struct Uart {
    base: *mut u8,
}

// SAFETY: `base` points at MMIO, not at memory anyone else owns. Sending a Uart
// between harts is fine; *sharing* it is not, which is why the global below is
// wrapped in a SpinLock rather than being Sync itself.
unsafe impl Send for Uart {}

impl Uart {
    /// # Safety
    /// `base` must be the address of an NS16550A with byte-spaced registers,
    /// mapped and owned exclusively by this object.
    pub const unsafe fn new(base: usize) -> Self {
        Self { base: base as *mut u8 }
    }

    #[inline]
    fn read(&self, off: usize) -> u8 {
        // SAFETY: `off` is one of the constants above, all within the 8-byte
        // register window promised by `new`. Volatile because MMIO reads have
        // side effects (reading RBR pops the FIFO) and must not be cached,
        // duplicated, or elided.
        unsafe { core::ptr::read_volatile(self.base.add(off)) }
    }

    #[inline]
    fn write(&self, off: usize, val: u8) {
        // SAFETY: as `read`.
        unsafe { core::ptr::write_volatile(self.base.add(off), val) }
    }

    /// Bring the UART into a known state: 8N1, FIFOs on and empty, interrupts off.
    pub fn init(&mut self) {
        // Interrupts off. We poll in M1; the UART becomes interrupt-driven when
        // it belongs to a userspace driver (M7).
        self.write(IER, 0x00);

        // Baud rate. QEMU ignores the divisor entirely — its "serial line" is a
        // pipe — but a real 16550 clocked at 1.8432 MHz needs divisor 3 for
        // 38400 baud, and doing it here means the code is already correct on the
        // Milk-V. Setting DLAB remaps offsets 0 and 1 to the divisor latches.
        self.write(LCR, LCR_DLAB);
        self.write(DLL, 0x03);
        self.write(DLM, 0x00);

        // Clearing DLAB in the same write that sets the word length: 8 bits, no
        // parity, 1 stop bit.
        self.write(LCR, LCR_8BIT);

        // Enable the FIFOs and discard anything the firmware left in them —
        // OpenSBI has been printing on this device already.
        self.write(FCR, FCR_ENABLE | FCR_CLEAR_RX | FCR_CLEAR_TX);

        // Assert DTR/RTS. Meaningless to QEMU, required by real modems and by
        // some USB-serial bridges that will not transmit without them.
        self.write(MCR, MCR_DTR | MCR_RTS);
    }

    /// Transmit one byte, spinning until the transmitter can accept it.
    pub fn put(&mut self, byte: u8) {
        while self.read(LSR) & LSR_THR_EMPTY == 0 {
            core::hint::spin_loop();
        }
        self.write(THR, byte);
    }

    /// Non-blocking receive. `None` if nothing has arrived.
    pub fn get(&mut self) -> Option<u8> {
        if self.read(LSR) & LSR_DATA_READY != 0 { Some(self.read(RBR)) } else { None }
    }
}

impl fmt::Write for Uart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            // A terminal in raw mode moves down but not left on '\n'. Everything
            // that writes to this UART goes through here, so this is the one
            // place the translation belongs.
            if b == b'\n' {
                self.put(b'\r');
            }
            self.put(b);
        }
        Ok(())
    }
}

/// The kernel's debug console.
///
/// SAFETY of the initialiser: `UART0_BASE` is QEMU virt's UART0, and this static
/// is the only thing that ever constructs a `Uart` for it — apart from the panic
/// path, which deliberately bypasses the lock (D-009).
pub static UART: SpinLock<Uart> = SpinLock::new(unsafe { Uart::new(UART0_BASE) });

pub fn init() {
    UART.lock().init();
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use fmt::Write;
    // Unwrap-free: our write_str cannot fail.
    let _ = UART.lock().write_fmt(args);
}

#[doc(hidden)]
pub fn _print_unlocked(args: fmt::Arguments) {
    use fmt::Write;
    // SAFETY: the panic path only. Racing output is strictly better than a
    // panic handler that deadlocks on a lock the panicking code still holds.
    let uart = unsafe { UART.force_get() };
    let _ = uart.write_fmt(args);
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => { $crate::uart::_print(format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => { $crate::uart::_print(format_args!("{}\n", format_args!($($arg)*))) };
}

/// `println!` that does not take the UART lock. Panic path only.
#[macro_export]
macro_rules! println_unlocked {
    () => { $crate::uart::_print_unlocked(format_args!("\n")) };
    ($($arg:tt)*) => {
        $crate::uart::_print_unlocked(format_args!("{}\n", format_args!($($arg)*)))
    };
}
