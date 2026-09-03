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
    make_disk(&dir);
}

/// The raw image the QEMU runner attaches as a virtio-blk device (D-044).
/// Created here rather than by hand so a fresh clone can `cargo test` with no
/// extra step: QEMU refuses to start at all if the file is missing.
fn make_disk(kernel_dir: &PathBuf) {
    const BLOCKS: usize = 2048;
    const BLOCK: usize = 512;

    let path = kernel_dir.join("../target/disk.img");
    println!("cargo::rerun-if-changed={}", path.display());
    if path.metadata().is_ok_and(|m| m.len() == (BLOCKS * BLOCK) as u64) {
        return;
    }

    // Each block holds its own number, so a driver that reads block N and gets
    // block M has a bug that says which block it actually fetched.
    let mut image = vec![0u8; BLOCKS * BLOCK];
    for (n, block) in image.chunks_mut(BLOCK).enumerate() {
        block[..8].copy_from_slice(&(0x7e55e7a_0000_0000u64 | n as u64).to_le_bytes());
        block[BLOCK - 8..].copy_from_slice(&(n as u64).to_le_bytes());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("could not make the target directory");
    }
    std::fs::write(&path, &image).expect("could not write the disk image");
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
