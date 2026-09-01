fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    // Absolute, so linking does not depend on where cargo was invoked.
    println!("cargo::rustc-link-arg-bins=-T{dir}/link.ld");
    println!("cargo::rerun-if-changed=link.ld");
    println!("cargo::rerun-if-changed=build.rs");
}
