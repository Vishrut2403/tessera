//! The filesystem service protocol (D-047). One definition, linked by the
//! server and by everything that asks it for a file.

use crate::abi::label;

/// "Here is the frame I want file bytes copied into." Carries a capability.
pub const CONNECT: u64 = label::APP_BASE + 0x20;
/// "Which file is this?" The name is 24 bytes, exactly three registers.
pub const OPEN: u64 = label::APP_BASE + 0x21;
/// "Copy `w1` bytes from offset `w2` of file `w0` into my frame."
pub const READ: u64 = label::APP_BASE + 0x22;
/// "Stop serving." The server passes it on to the driver below it.
pub const SHUTDOWN: u64 = label::APP_BASE + 0x23;

pub const OK: usize = 0;
pub const FAILED: usize = 1;
pub const NO_SUCH_FILE: usize = 2;
pub const NO_BUFFER: usize = 3;

/// Pack a name into the three registers an `OPEN` carries it in.
pub fn pack_name(name: &str) -> [usize; 4] {
    let mut buf = [0u8; 24];
    let bytes = name.as_bytes();
    let n = bytes.len().min(buf.len());
    buf[..n].copy_from_slice(&bytes[..n]);
    let word = |i: usize| usize::from_le_bytes(buf[i..i + 8].try_into().unwrap());
    [word(0), word(8), word(16), 0]
}

/// The inverse, on the server's side.
pub fn unpack_name(words: &[usize; 4]) -> [u8; 24] {
    let mut buf = [0u8; 24];
    for i in 0..3 {
        buf[i * 8..i * 8 + 8].copy_from_slice(&words[i].to_le_bytes());
    }
    buf
}
