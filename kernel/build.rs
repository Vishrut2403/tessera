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

/// The on-disk layout, shared verbatim with the filesystem server that reads
/// it (D-047). Included rather than duplicated: a format the two sides could
/// describe differently is a format that will eventually disagree.
#[allow(dead_code)]
mod fsformat {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../user/src/fsformat.rs"));
}

const MOTD: &[u8] = b"tessera\n  the kernel does four things\n  userspace asked for the rest\n";

/// The files the image contains. `spans.bin` is deliberately larger than a
/// block, so a server that only ever follows the first direct pointer fails.
fn contents() -> Vec<(&'static str, Vec<u8>)> {
    let spans: Vec<u8> = (0..1500u32).map(|i| (i % 251) as u8).collect();
    vec![
        ("hello.txt", b"Hello from a filesystem the kernel knows nothing about.\n".to_vec()),
        ("motd", MOTD.to_vec()),
        ("spans.bin", spans),
    ]
}

/// The raw image the QEMU runner attaches as a virtio-blk device (D-044).
/// Created here rather than by hand so a fresh clone can `cargo test` with no
/// extra step: QEMU refuses to start at all if the file is missing.
fn make_disk(kernel_dir: &PathBuf) {
    const BLOCKS: usize = 2048;
    let block = fsformat::BLOCK_SIZE;

    let path = kernel_dir.join("../target/disk.img");
    println!("cargo::rerun-if-changed={}", path.display());
    println!("cargo::rerun-if-changed={}", kernel_dir.join("../user/src/fsformat.rs").display());

    let mut image = vec![0u8; BLOCKS * block];
    write_filesystem(&mut image);

    // Every block the filesystem does not use carries its own number at both
    // ends, so a read of the wrong block says which one it fetched (D-044).
    for n in (fsformat::FS_BLOCKS as usize)..BLOCKS {
        let b = &mut image[n * block..(n + 1) * block];
        b[..8].copy_from_slice(&(0x07e5_5e7a_0000_0000u64 | n as u64).to_le_bytes());
        b[block - 8..].copy_from_slice(&(n as u64).to_le_bytes());
    }

    // Compared rather than stat-ed: the contents change whenever the format or
    // the file list does, and a stale image would fail in the server instead.
    if std::fs::read(&path).is_ok_and(|old| old == image) {
        return;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("could not make the target directory");
    }
    std::fs::write(&path, &image).expect("could not write the disk image");
}

/// Lay the superblock, the inode table, the name table and the file data into
/// the first `FS_BLOCKS` blocks.
fn write_filesystem(image: &mut [u8]) {
    let block = fsformat::BLOCK_SIZE;
    let files = contents();
    assert!(files.len() <= fsformat::MAX_FILES, "too many files for one inode block");

    let mut inodes = vec![0u8; block];
    let mut names = vec![0u8; block];
    let mut next = fsformat::FIRST_DATA_BLOCK;

    for (i, (name, bytes)) in files.iter().enumerate() {
        assert!(bytes.len() <= fsformat::MAX_FILE_SIZE, "{name} needs more direct pointers");
        assert!(name.len() <= fsformat::NAME_LEN, "{name} is too long for the name table");

        let mut direct = Vec::new();
        for chunk in bytes.chunks(block) {
            let at = next as usize * block;
            image[at..at + chunk.len()].copy_from_slice(chunk);
            direct.push(next);
            next += 1;
        }
        fsformat::write_inode(&mut inodes, i, bytes.len() as u32, &direct);
        fsformat::write_name(&mut names, i, name, i as u32);
    }
    assert!(next <= fsformat::FS_BLOCKS, "the filesystem does not fit in FS_BLOCKS");

    let mut sb = vec![0u8; block];
    fsformat::write_super(&mut sb, files.len() as u32);

    for (n, source) in [(fsformat::SUPER_BLOCK, sb), (fsformat::INODE_BLOCK, inodes),
                        (fsformat::NAME_BLOCK, names)] {
        let at = n as usize * block;
        image[at..at + block].copy_from_slice(&source);
    }
}

/// The user binaries the kernel embeds: the root task it loads, and the boot
/// modules it only maps read-only for the root task to load itself (D-043).
const BINS: [(&str, &str); 4] = [
    ("root", "ROOT_TASK_ELF"),
    ("blk", "BLK_ELF"),
    ("fs", "FS_ELF"),
    ("client", "CLIENT_ELF"),
];

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
