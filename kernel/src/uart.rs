//! NS16550A UART driver, MMIO at 0x1000_0000 on QEMU virt (D-004).

use core::fmt;

use crate::mm::{PhysAddr, phys_to_virt};
use crate::sync::SpinLock;

/// QEMU virt's UART0, as a physical address.
pub const UART0_PHYS: usize = 0x1000_0000;

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
    /// Physical base; the pointer is recomputed per access (D-017).
    base: PhysAddr,
}

// SAFETY: `base` names MMIO, not memory anyone else owns.
unsafe impl Send for Uart {}

impl Uart {
    /// # Safety
    /// `base` must be an NS16550A's physical address, byte-spaced registers,
    /// exclusively owned.
    pub const unsafe fn new(base: usize) -> Self {
        Self { base: PhysAddr::new(base) }
    }

    #[inline]
    fn reg(&self, off: usize) -> *mut u8 {
        phys_to_virt(PhysAddr::new(self.base.as_usize() + off)).as_mut_ptr()
    }

    #[inline]
    fn read(&self, off: usize) -> u8 {
        // SAFETY: `off` is one of the constants above, inside the 8-byte window promised by `new`.
        unsafe { core::ptr::read_volatile(self.reg(off)) }
    }

    #[inline]
    fn write(&self, off: usize, val: u8) {
        // SAFETY: as `read`.
        unsafe { core::ptr::write_volatile(self.reg(off), val) }
    }

    /// Bring the UART into a known state: 8N1, FIFOs on and empty, interrupts off.
    pub fn init(&mut self) {
        // Interrupts off.
        self.write(IER, 0x00);

        // Baud divisor, behind DLAB.
        self.write(LCR, LCR_DLAB);
        self.write(DLL, 0x03);
        self.write(DLM, 0x00);

        // Clearing DLAB in the same write that sets the word length: 8 bits, no parity, 1 stop bit.
        self.write(LCR, LCR_8BIT);

        // Enable the FIFOs and discard what the firmware left in them.
        self.write(FCR, FCR_ENABLE | FCR_CLEAR_RX | FCR_CLEAR_TX);

        // Assert DTR/RTS.
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
            // A terminal in raw mode moves down but not left on '\n'.
            if b == b'\n' {
                self.put(b'\r');
            }
            self.put(b);
        }
        Ok(())
    }
}

/// The kernel's debug console.
pub static UART: SpinLock<Uart> = SpinLock::new(unsafe { Uart::new(UART0_PHYS) });

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
    // SAFETY: the panic path only.
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
