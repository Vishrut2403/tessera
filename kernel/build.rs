use std::path::PathBuf;
use std::process::Command;

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());

    // Per-crate, not in the workspace's rustflags: those apply to every crate
    // built for this target, and userspace has its own linker script (D-039).
    println!("cargo::rustc-link-arg=-T{}/link.ld", dir.display());
    println!("cargo::rustc-link-arg-bins=-Map={}/kernel.map", dir.join("../target").display());

    println!("cargo::rerun-if-changed=link.ld");
    println!("cargo::rerun-if-changed=build.rs");

    build_user(&dir);
}

/// The user binaries the kernel embeds: the root task it loads, and the boot
/// modules it only maps read-only for the root task to load itself (D-043).
const BINS: [(&str, &str); 2] = [("root", "ROOT_TASK_ELF"), ("blk", "BLK_ELF")];

/// Build every user binary and hand each ELF to the kernel to embed (D-039).
fn build_user(kernel_dir: &PathBuf) {
    let user = kernel_dir.join("..").join("user");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("user");
    let release = std::env::var("PROFILE").unwrap() == "release";
    const TARGET: &str = "riscv64gc-unknown-none-elf";

    for path in ["src", "link.ld", "build.rs", "Cargo.toml"] {
        println!("cargo::rerun-if-changed={}", user.join(path).display());
    }
    println!("cargo::rerun-if-changed={}", kernel_dir.join("../abi/src").display());

    let mut cmd = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    cmd.current_dir(&user).arg("build").args(["--target", TARGET]).arg("--target-dir").arg(&out);
    for (bin, _) in BINS {
        cmd.args(["--bin", bin]);
    }
    if release {
        cmd.arg("--release");
    }
    // The outer build's cargo state would be read as this build's own.
    for (key, _) in std::env::vars() {
        if key.starts_with("CARGO_") && key != "CARGO_HOME" {
            cmd.env_remove(key);
        }
    }
    cmd.env_remove("RUSTC").env_remove("RUSTC_WRAPPER").env_remove("RUSTC_WORKSPACE_WRAPPER");

    let status = cmd.status().expect("could not run cargo for the user binaries");
    assert!(status.success(), "building the user binaries failed");

    let built = out.join(TARGET).join(if release { "release" } else { "debug" });
    for (bin, var) in BINS {
        let elf = built.join(bin);
        assert!(elf.is_file(), "{bin} ELF missing at {}", elf.display());
        println!("cargo::rustc-env={var}={}", elf.display());
    }
}
