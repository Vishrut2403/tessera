fn main() {
    // The linker script is passed via rustflags in .cargo/config.toml, which
    // means cargo does not know it is an input. Tell it, or edits to link.ld
    // will not trigger a relink.
    println!("cargo::rerun-if-changed=link.ld");
    println!("cargo::rerun-if-changed=build.rs");
}
