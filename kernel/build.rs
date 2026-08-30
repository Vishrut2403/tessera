fn main() {
    // The linker script comes from rustflags, which cargo does not track.
    println!("cargo::rerun-if-changed=link.ld");
    println!("cargo::rerun-if-changed=build.rs");
}
