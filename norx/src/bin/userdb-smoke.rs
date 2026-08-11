#![feature(alloc_error_handler)]
#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::alloc::Layout;
use core::panic::PanicInfo;
use norx_userdb::{Database, MAX_DATABASE_BYTES};
use userspace::syscall;

const DATABASE_PATH: &[u8] = b"/cfg/userdb/users.db";
const TEMP_PATH: &[u8] = b"/cfg/userdb/users.db.tmp";
const SEED: &[u8] = b"NORX-USERDB 1\nu:alice:1000:1000:0:0:/users/alice:/bin/nsh:$argon2id$v=19$m=65536,t=3,p=1$c2FsdFNhbXBsZQ$ZGlnaWVzdFNhbXBsZQ\ng:users:1000:alice\n";

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    syscall::exit(101)
}

#[alloc_error_handler]
fn allocation_error(_layout: Layout) -> ! {
    syscall::exit(12)
}

fn write_all(fd: syscall::Word, bytes: &[u8]) -> bool {
    let mut offset = 0;
    while offset < bytes.len() {
        let Ok(written) = syscall::write(fd, bytes[offset..].as_ptr(), bytes.len() - offset) else {
            return false;
        };
        if written == 0 {
            return false;
        }
        offset += written;
    }
    true
}

fn run() -> bool {
    let mut stat = syscall::Stat::default();
    if syscall::stat(DATABASE_PATH.as_ptr(), DATABASE_PATH.len(), &mut stat).is_err() {
        let mut config_stat = syscall::Stat::default();
        if syscall::stat(b"/cfg".as_ptr(), b"/cfg".len(), &mut config_stat).is_err()
            && syscall::mkdir(b"/cfg".as_ptr(), b"/cfg".len(), 0o755).is_err()
        {
            return false;
        }
        let mut parent_stat = syscall::Stat::default();
        if syscall::stat(
            b"/cfg/userdb".as_ptr(),
            b"/cfg/userdb".len(),
            &mut parent_stat,
        )
        .is_err()
            && syscall::mkdir(b"/cfg/userdb".as_ptr(), b"/cfg/userdb".len(), 0o700).is_err()
        {
            return false;
        }
    }
    let Ok(fd) = syscall::open(
        TEMP_PATH.as_ptr(),
        TEMP_PATH.len(),
        syscall::OPEN_WRITE | syscall::OPEN_CREATE | syscall::OPEN_TRUNCATE,
        0o600,
    ) else {
        return false;
    };
    let written = write_all(fd, SEED);
    let closed = syscall::close(fd).is_ok();
    if !written
        || !closed
        || syscall::rename(
            TEMP_PATH.as_ptr(),
            TEMP_PATH.len(),
            DATABASE_PATH.as_ptr(),
            DATABASE_PATH.len(),
        )
        .is_err()
    {
        return false;
    }
    let Ok(fd) = syscall::open(
        DATABASE_PATH.as_ptr(),
        DATABASE_PATH.len(),
        syscall::OPEN_READ,
        0,
    ) else {
        return false;
    };
    let mut bytes = Vec::with_capacity(MAX_DATABASE_BYTES.min(1024));
    let mut chunk = [0u8; 256];
    loop {
        let Ok(read) = syscall::read(fd, chunk.as_mut_ptr(), chunk.len()) else {
            let _ = syscall::close(fd);
            return false;
        };
        if read == 0 {
            break;
        }
        if bytes.len().saturating_add(read) > MAX_DATABASE_BYTES {
            let _ = syscall::close(fd);
            return false;
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    if syscall::close(fd).is_err() {
        return false;
    }
    let Ok(database) = Database::parse(&bytes) else {
        return false;
    };
    if database.lookup_user(b"alice").is_none()
        || database.serialize_for_storage().as_deref() != Ok(SEED)
    {
        return false;
    }
    write_all(1, b"[   OK   ] userdb: atomic update and reload\n")
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let status = if run() { 0 } else { 1 };
    syscall::exit(status)
}
