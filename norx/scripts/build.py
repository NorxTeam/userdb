#!/usr/bin/env python3
"""Build and stage the Norx userdb persistence smoke ELF."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sys

SCRIPT_ROOT = Path(__file__).resolve().parent
USERDB_ROOT = SCRIPT_ROOT.parents[1]
REPO_ROOT = USERDB_ROOT.parent
TOOLCHAIN_SCRIPTS = REPO_ROOT / "toolchain" / "scripts"
sys.path.insert(0, str(TOOLCHAIN_SCRIPTS))

from build import (  # noqa: E402
    cargo_command,
    checked_output,
    copy_checked,
    load_toml,
    run,
    sha256,
    target_emulation,
    tool_path,
    validate_elf,
)


def git_output(*arguments: str) -> str:
    return checked_output(["git", "-C", str(USERDB_ROOT), *arguments]).strip()


def main() -> int:
    versions = load_toml(REPO_ROOT / "toolchain" / "versions.toml")
    abi = load_toml(REPO_ROOT / "toolchain" / "abi.toml")
    cargo = cargo_command(versions["rust_toolchain"])
    rustc_version = checked_output([*cargo[:-1], "rustc", "-Vv"])
    if versions["rustc_version"] not in rustc_version or versions["rustc_commit"] not in rustc_version:
        raise SystemExit(f"rustc does not match the pinned userspace toolchain:\n{rustc_version}")
    ld_lld = tool_path("ld.lld.exe" if os.name == "nt" else "ld.lld", "NORX_LD_LLD")
    readobj = tool_path(
        "llvm-readobj.exe" if os.name == "nt" else "llvm-readobj", "NORX_LLVM_READOBJ"
    )
    llvm_strip = tool_path(
        "llvm-strip.exe" if os.name == "nt" else "llvm-strip", "NORX_LLVM_STRIP"
    )
    if versions["llvm_version"] not in checked_output([str(ld_lld), "--version"]):
        raise SystemExit(f"{ld_lld} is not pinned to LLVM {versions['llvm_version']}")

    manifest = USERDB_ROOT / "norx" / "Cargo.toml"
    rootfs = Path(os.environ.get("NORX_ROOTFS", REPO_ROOT / "test-rootfs"))
    results: dict[str, str] = {}
    for target_name, target_info in (("x86_64", abi["targets"]["x86_64"]), ("aarch64", abi["targets"]["aarch64"])):
        target_dir = USERDB_ROOT / "build" / target_name
        target_dir.mkdir(parents=True, exist_ok=True)
        linker_script = REPO_ROOT / "toolchain" / target_info["linker_script"]
        target_spec = REPO_ROOT / "toolchain" / "targets" / f"{target_name}-unknown-norx.json"
        triple = target_info["triple"]
        runtime_archive = REPO_ROOT / "toolchain" / "build" / "runtime" / target_name / "libnorxrt.a"
        if not runtime_archive.is_file():
            raise SystemExit(f"missing target runtime archive: {runtime_archive}")
        linker_revision = sha256(linker_script)[:16]
        config = [
            "--config",
            f'target."{triple}".linker = "{ld_lld.as_posix()}"',
            "--config",
            f'target."{triple}".rustflags = ["-C", "debuginfo=2", "-L", "native={runtime_archive.parent.as_posix()}", "-l", "static=norxrt", "-C", "link-arg=-T{linker_script.as_posix()}", "-C", "link-arg=-m{target_emulation(target_name)}", "-C", "link-arg=--defsym=__linker_revision=0x{linker_revision}"]',
        ]
        run([
            *cargo,
            *config,
            "build",
            "-Z",
            "build-std=core,alloc",
            "-Z",
            "json-target-spec",
            "--offline",
            "--locked",
            "--manifest-path",
            str(manifest),
            "--target",
            str(target_spec),
            "--target-dir",
            str(target_dir / "cargo-target"),
            "--release",
            "--bin",
            "userdb-smoke",
        ])
        candidates = [
            path
            for path in (target_dir / "cargo-target").rglob("userdb-smoke*")
            if path.is_file() and path.parent.name == "release" and path.name in {"userdb-smoke", "userdb-smoke.exe"}
        ]
        if len(candidates) != 1:
            raise SystemExit(f"expected one userdb smoke ELF for {target_name}, found {candidates}")
        artifact = target_dir / "userdb-smoke.elf"
        copy_checked(candidates[0], artifact)
        run([str(llvm_strip), "--strip-debug", str(artifact)])
        report = validate_elf(readobj, artifact)
        (target_dir / "readobj.txt").write_text(report, encoding="utf-8")
        destination = rootfs / "tests" / "userdb" / triple / artifact.name
        copy_checked(artifact, destination)
        results[target_name] = sha256(artifact)

    manifest_dir = rootfs / "var" / "lib" / "userdb"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    lines = [
        'schema = "userdb-build"',
        "version = 1",
        'abi_version = 1',
        f'upstream_commit = "{git_output("rev-parse", "upstream/master")}"',
        f'fork_commit = "{git_output("rev-parse", "HEAD")}"',
        f'dirty = {str(bool(git_output("status", "--porcelain"))).lower()}',
        'record_format = "NORX-USERDB 1"',
        'password_policy = "argon2id m=65536,t=3,p=1"',
        'storage_path = "/cfg/userdb/users.db"',
        "",
    ]
    for target_name, digest in results.items():
        lines.extend([f"[targets.{target_name}]", f'userdb_smoke_sha256 = "{digest}"', ""])
    manifest_path = manifest_dir / "manifest.toml"
    manifest_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"userdb build passed; manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
