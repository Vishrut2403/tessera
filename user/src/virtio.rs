//! The virtio-mmio transport, version 2 (D-044). Unprivileged: every register
//! here is reached through a frame the holder was given a capability to.

/// Register offsets, from the virtio 1.2 specification, section 4.2.2.
pub mod reg {
    pub const MAGIC: usize = 0x000;
    pub const VERSION: usize = 0x004;
    pub const DEVICE_ID: usize = 0x008;
    pub const VENDOR_ID: usize = 0x00c;
    pub const DEVICE_FEATURES: usize = 0x010;
    pub const DEVICE_FEATURES_SEL: usize = 0x014;
    pub const DRIVER_FEATURES: usize = 0x020;
    pub const DRIVER_FEATURES_SEL: usize = 0x024;
    pub const QUEUE_SEL: usize = 0x030;
    pub const QUEUE_NUM_MAX: usize = 0x034;
    pub const QUEUE_NUM: usize = 0x038;
    pub const QUEUE_READY: usize = 0x044;
    pub const QUEUE_NOTIFY: usize = 0x050;
    pub const INTERRUPT_STATUS: usize = 0x060;
    pub const INTERRUPT_ACK: usize = 0x064;
    pub const STATUS: usize = 0x070;
    pub const QUEUE_DESC_LOW: usize = 0x080;
    pub const QUEUE_DESC_HIGH: usize = 0x084;
    pub const QUEUE_DRIVER_LOW: usize = 0x090;
    pub const QUEUE_DRIVER_HIGH: usize = 0x094;
    pub const QUEUE_DEVICE_LOW: usize = 0x0a0;
    pub const QUEUE_DEVICE_HIGH: usize = 0x0a4;
    pub const CONFIG: usize = 0x100;
}

/// The device status byte, written one bit at a time in a fixed order.
pub mod status {
    pub const ACKNOWLEDGE: u32 = 1;
    pub const DRIVER: u32 = 2;
    pub const DRIVER_OK: u32 = 4;
    pub const FEATURES_OK: u32 = 8;
    pub const FAILED: u32 = 128;
}

/// `"virt"` little-endian: the first thing a transport must say.
pub const MAGIC: u32 = 0x7472_6976;

/// Version 2 is the non-legacy transport. Version 1 puts the whole queue at a
/// single page-frame number, which does not suit memory that arrives as
/// separately retyped frames.
pub const VERSION: u32 = 2;

pub const DEVICE_BLOCK: u32 = 2;

/// Feature bit 32 — the device speaks the non-legacy interface — which is bit
/// 0 of the high feature word.
pub const F_VERSION_1: u32 = 1;

/// Queue slots. Eight is enough to have a queue at all and keeps the whole
/// virtqueue inside one 4 KiB frame.
pub const QUEUE_SIZE: u16 = 8;

/// Offsets of the three rings within that one frame. Each is at or above the
/// alignment the specification requires (16, 2 and 4 bytes).
pub const DESC_OFF: usize = 0;
pub const AVAIL_OFF: usize = 16 * QUEUE_SIZE as usize;
pub const USED_OFF: usize = 256;

/// Descriptor flags. `NEXT` chains, `WRITE` marks a buffer the *device* may
/// write -- which is how it learns which parts of a request are output.
pub mod desc_flags {
    pub const NEXT: u16 = 1;
    pub const WRITE: u16 = 2;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtioError {
    /// The register block did not start with the virtio magic.
    NotVirtio,
    /// A legacy transport, or one from a future the driver does not know.
    WrongVersion,
    /// The transport is there but no device is behind it.
    NoDevice,
    /// The device does not offer `VIRTIO_F_VERSION_1`.
    NotModern,
    /// The device rejected the feature set the driver asked for.
    FeaturesRefused,
    /// The queue is smaller than the driver needs, or already in use.
    BadQueue,
}

/// One virtio-mmio register block.
pub struct Transport {
    base: usize,
}

impl Transport {
    /// # Safety
    /// `base` must be a virtio-mmio register page mapped read-write, and no
    /// other `Transport` may be driving the same registers.
    pub const unsafe fn new(base: usize) -> Self {
        Self { base }
    }

    fn read(&self, off: usize) -> u32 {
        // SAFETY: `new`'s caller promised a mapped register page, and every
        // offset used here is inside the 4 KiB block. Volatile because a
        // repeated read of a register is not a repeated read of a value.
        unsafe { ((self.base + off) as *const u32).read_volatile() }
    }

    fn write(&self, off: usize, value: u32) {
        // SAFETY: as above.
        unsafe { ((self.base + off) as *mut u32).write_volatile(value) }
    }

    /// Which device is behind this transport, or why there is not one.
    /// Reading `DeviceID` is safe on an unbacked transport: the block exists
    /// whether or not QEMU attached anything to it, and answers zero.
    pub fn identify(&self) -> Result<u32, VirtioError> {
        if self.read(reg::MAGIC) != MAGIC {
            return Err(VirtioError::NotVirtio);
        }
        if self.read(reg::VERSION) != VERSION {
            return Err(VirtioError::WrongVersion);
        }
        match self.read(reg::DEVICE_ID) {
            0 => Err(VirtioError::NoDevice),
            id => Ok(id),
        }
    }

    pub fn vendor(&self) -> u32 {
        self.read(reg::VENDOR_ID)
    }

    pub fn status(&self) -> u32 {
        self.read(reg::STATUS)
    }

    /// Writing zero resets the device; the specification requires reading the
    /// register back until it is zero before anything else is done.
    pub fn reset(&self) {
        self.write(reg::STATUS, 0);
        while self.status() != 0 {}
    }

    /// Status bits are added, never replaced: the device watches the sequence.
    pub fn add_status(&self, bits: u32) {
        self.write(reg::STATUS, self.status() | bits);
    }

    fn device_features(&self, word: u32) -> u32 {
        self.write(reg::DEVICE_FEATURES_SEL, word);
        self.read(reg::DEVICE_FEATURES)
    }

    fn set_driver_features(&self, word: u32, bits: u32) {
        self.write(reg::DRIVER_FEATURES_SEL, word);
        self.write(reg::DRIVER_FEATURES, bits);
    }

    /// Reset, acknowledge, and agree on features. Nothing is offered back but
    /// `VIRTIO_F_VERSION_1`: every optional feature is one more thing the
    /// driver would have to implement correctly.
    pub fn negotiate(&self) -> Result<(), VirtioError> {
        self.reset();
        self.add_status(status::ACKNOWLEDGE);
        self.add_status(status::DRIVER);

        if self.device_features(1) & F_VERSION_1 == 0 {
            self.add_status(status::FAILED);
            return Err(VirtioError::NotModern);
        }
        self.set_driver_features(0, 0);
        self.set_driver_features(1, F_VERSION_1);

        self.add_status(status::FEATURES_OK);
        // The one handshake step the device can refuse: if the bit does not
        // read back, the feature set is unacceptable and nothing may proceed.
        if self.status() & status::FEATURES_OK == 0 {
            self.add_status(status::FAILED);
            return Err(VirtioError::FeaturesRefused);
        }
        Ok(())
    }

    /// Point queue `q` at rings that are already zeroed, and mark it ready.
    /// The addresses are physical because the device does not walk page
    /// tables -- which is why `GetAddress` needs `WRITE` on the frame (D-040).
    pub fn configure_queue(
        &self,
        q: u32,
        desc: u64,
        avail: u64,
        used: u64,
    ) -> Result<u16, VirtioError> {
        self.write(reg::QUEUE_SEL, q);
        let max = self.read(reg::QUEUE_NUM_MAX) as u16;
        if max == 0 || max < QUEUE_SIZE {
            return Err(VirtioError::BadQueue);
        }
        if self.read(reg::QUEUE_READY) != 0 {
            return Err(VirtioError::BadQueue);
        }

        self.write(reg::QUEUE_NUM, QUEUE_SIZE as u32);
        for (low, high, addr) in [
            (reg::QUEUE_DESC_LOW, reg::QUEUE_DESC_HIGH, desc),
            (reg::QUEUE_DRIVER_LOW, reg::QUEUE_DRIVER_HIGH, avail),
            (reg::QUEUE_DEVICE_LOW, reg::QUEUE_DEVICE_HIGH, used),
        ] {
            self.write(low, addr as u32);
            self.write(high, (addr >> 32) as u32);
        }
        self.write(reg::QUEUE_READY, 1);
        Ok(max)
    }

    /// The last step: the device may use the queue from here on.
    pub fn finish(&self) {
        self.add_status(status::DRIVER_OK);
    }

    /// Tell the device there is something new in queue `q`'s available ring.
    pub fn notify(&self, q: u32) {
        self.write(reg::QUEUE_NOTIFY, q);
    }

    /// Why the device raised its interrupt line. Bit 0 is a used-ring update.
    pub fn interrupt_status(&self) -> u32 {
        self.read(reg::INTERRUPT_STATUS)
    }

    /// Clear the reasons named in `bits`. The device keeps asserting until
    /// this is written, so it comes *before* the source is unmasked (D-041).
    pub fn ack_interrupt(&self, bits: u32) {
        self.write(reg::INTERRUPT_ACK, bits);
    }

    /// A 64-bit field of the device-specific configuration space.
    pub fn config_u64(&self, off: usize) -> u64 {
        let low = self.read(reg::CONFIG + off) as u64;
        let high = self.read(reg::CONFIG + off + 4) as u64;
        (high << 32) | low
    }
}

/// The three rings, in one frame the driver owns. `va` is where the driver has
/// it mapped; `pa` is what the device is told, because a bus master does not
/// walk page tables (D-040).
pub struct Queue {
    va: usize,
    pa: u64,
}

impl Queue {
    /// # Safety
    /// `va` must be a zeroed page mapped read-write whose physical address is
    /// `pa`, and nothing else may be using it.
    pub const unsafe fn new(va: usize, pa: u64) -> Self {
        Self { va, pa }
    }

    /// Where the driver has the frame mapped, for the buffers it puts in the
    /// same page.
    pub const fn va(&self) -> usize {
        self.va
    }
    /// Where the device sees it.
    pub const fn pa(&self) -> u64 {
        self.pa
    }

    pub const fn desc_pa(&self) -> u64 {
        self.pa + DESC_OFF as u64
    }
    pub const fn avail_pa(&self) -> u64 {
        self.pa + AVAIL_OFF as u64
    }
    pub const fn used_pa(&self) -> u64 {
        self.pa + USED_OFF as u64
    }

    /// One descriptor: a buffer, and what follows it in the chain.
    pub fn set_desc(&self, i: usize, addr: u64, len: u32, flags: u16, next: u16) {
        let at = self.va + DESC_OFF + i * 16;
        // SAFETY: `new`'s caller promised a mapped page, and `i` below
        // `QUEUE_SIZE` keeps the whole 16-byte entry inside the descriptor
        // table. Volatile because the device reads this memory too.
        unsafe {
            (at as *mut u64).write_volatile(addr);
            ((at + 8) as *mut u32).write_volatile(len);
            ((at + 12) as *mut u16).write_volatile(flags);
            ((at + 14) as *mut u16).write_volatile(next);
        }
    }

    /// Offer the chain starting at `head`. The fences are the protocol, not a
    /// precaution: the device may be reading while this runs, and it must never
    /// see a bumped index before the descriptors it points at.
    pub fn submit(&self, head: u16) {
        // SAFETY: as above; the available ring is 4 + 2 * QUEUE_SIZE bytes at
        // `AVAIL_OFF`, and the slot is masked to the ring size.
        unsafe {
            let idx = ((self.va + AVAIL_OFF + 2) as *const u16).read_volatile();
            let slot = self.va + AVAIL_OFF + 4 + (idx as usize % QUEUE_SIZE as usize) * 2;
            (slot as *mut u16).write_volatile(head);
            fence();
            ((self.va + AVAIL_OFF + 2) as *mut u16).write_volatile(idx.wrapping_add(1));
        }
        fence();
    }

    /// How many chains the device has finished, ever.
    pub fn used_idx(&self) -> u16 {
        // SAFETY: as above.
        let idx = unsafe { ((self.va + USED_OFF + 2) as *const u16).read_volatile() };
        fence();
        idx
    }

    /// The `id`, `len` pair the device wrote at ring position `i`.
    pub fn used(&self, i: usize) -> (u32, u32) {
        let at = self.va + USED_OFF + 4 + (i % QUEUE_SIZE as usize) * 8;
        // SAFETY: as above; the used ring is 4 + 8 * QUEUE_SIZE bytes.
        unsafe {
            (
                (at as *const u32).read_volatile(),
                ((at + 4) as *const u32).read_volatile(),
            )
        }
    }
}

/// A full barrier. On RISC-V this is `fence rw, rw`, which is what Linux's
/// `virtio_wmb` becomes on this target.
fn fence() {
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}
