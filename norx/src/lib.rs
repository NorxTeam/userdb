#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

pub const FORMAT_HEADER: &[u8] = b"NORX-USERDB 1";
pub const MAX_DATABASE_BYTES: usize = 64 * 1024;
pub const MAX_LINE_BYTES: usize = 512;
pub const MAX_USERS: usize = 128;
pub const MAX_GROUPS: usize = 128;
pub const MAX_NAME_BYTES: usize = 31;
pub const MAX_PATH_BYTES: usize = 255;
pub const MAX_HASH_BYTES: usize = 256;
pub const FLAG_DISABLED: u32 = 1 << 0;
pub const FLAG_LOCKED: u32 = 1 << 1;
pub const FLAG_EXPIRED: u32 = 1 << 2;
pub const KNOWN_FLAGS: u32 = FLAG_DISABLED | FLAG_LOCKED | FLAG_EXPIRED;
pub const CAP_ACCOUNT_ADMIN: u64 = 1 << 8;
pub const CAP_SESSION_ADMIN: u64 = 1 << 9;
pub const KNOWN_CAPABILITIES: u64 = CAP_ACCOUNT_ADMIN | CAP_SESSION_ADMIN;
pub const ARGON2ID_PREFIX: &[u8] = b"$argon2id$v=19$m=65536,t=3,p=1$";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    Empty,
    TooLarge,
    InvalidHeader,
    UnsupportedVersion,
    InvalidLine,
    InvalidNumber,
    InvalidName,
    InvalidPath,
    InvalidHash,
    UnknownFlags,
    UnknownCapabilities,
    Duplicate,
    Limit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SerializeError {
    TooLarge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthError {
    Denied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mutation {
    ChangeOwnPassword,
    ModifyAccount,
    ModifyGroup,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionCredentials {
    pub real_uid: u32,
    pub effective_uid: u32,
    pub saved_uid: u32,
    pub real_gid: u32,
    pub effective_gid: u32,
    pub saved_gid: u32,
    pub capabilities: u64,
}

impl SessionCredentials {
    pub const fn from_user(user: &UserEntry) -> Self {
        Self {
            real_uid: user.uid,
            effective_uid: user.uid,
            saved_uid: user.uid,
            real_gid: user.gid,
            effective_gid: user.gid,
            saved_gid: user.gid,
            capabilities: user.capabilities,
        }
    }

    pub const fn inherit(self) -> Self {
        self
    }

    pub const fn has_capability(self, capability: u64) -> bool {
        self.capabilities & capability == capability
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserEntry {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub flags: u32,
    pub capabilities: u64,
    pub home: String,
    pub shell: String,
}

impl UserEntry {
    pub fn is_enabled(&self) -> bool {
        self.flags & (FLAG_DISABLED | FLAG_LOCKED | FLAG_EXPIRED) == 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupEntry {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct Account {
    entry: UserEntry,
    password_hash: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Database {
    accounts: Vec<Account>,
    groups: Vec<GroupEntry>,
}

pub trait PasswordVerifier {
    fn verify(&self, password: &[u8], encoded_hash: &[u8]) -> bool;
}

impl Database {
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.is_empty() {
            return Err(ParseError::Empty);
        }
        if bytes.len() > MAX_DATABASE_BYTES {
            return Err(ParseError::TooLarge);
        }
        let mut lines = bytes.split(|byte| *byte == b'\n');
        match lines.next() {
            Some(FORMAT_HEADER) => {}
            Some(header) if header.starts_with(b"NORX-USERDB ") => {
                return Err(ParseError::UnsupportedVersion)
            }
            _ => return Err(ParseError::InvalidHeader),
        }
        let mut database = Self {
            accounts: Vec::new(),
            groups: Vec::new(),
        };
        for line in lines {
            if line.is_empty() {
                continue;
            }
            if line.len() > MAX_LINE_BYTES || line.last() == Some(&b'\r') {
                return Err(ParseError::InvalidLine);
            }
            let fields = split_fields(line)?;
            match fields.first().copied() {
                Some(b"u") if fields.len() == 9 => database.add_account(parse_account(&fields)?)?,
                Some(b"g") if fields.len() == 4 => database.add_group(parse_group(&fields)?)?,
                _ => return Err(ParseError::InvalidLine),
            }
        }
        Ok(database)
    }

    pub fn lookup_user(&self, name: &[u8]) -> Option<UserEntry> {
        self.accounts
            .iter()
            .find(|account| account.entry.name.as_bytes() == name)
            .map(|account| account.entry.clone())
    }

    pub fn lookup_group(&self, name: &[u8]) -> Option<GroupEntry> {
        self.groups
            .iter()
            .find(|group| group.name.as_bytes() == name)
            .cloned()
    }

    pub fn authenticate<V: PasswordVerifier>(
        &self,
        name: &[u8],
        password: &[u8],
        verifier: &V,
    ) -> Result<SessionCredentials, AuthError> {
        let Some(account) = self
            .accounts
            .iter()
            .find(|account| account.entry.name.as_bytes() == name)
        else {
            return Err(AuthError::Denied);
        };
        if !account.entry.is_enabled()
            || !verifier.verify(password, account.password_hash.as_bytes())
        {
            return Err(AuthError::Denied);
        }
        Ok(SessionCredentials::from_user(&account.entry))
    }

    pub fn authorize_mutation(
        &self,
        actor: SessionCredentials,
        target_uid: u32,
        mutation: Mutation,
    ) -> Result<(), AuthError> {
        if actor.has_capability(CAP_ACCOUNT_ADMIN) {
            return Ok(());
        }
        if mutation == Mutation::ChangeOwnPassword && actor.effective_uid == target_uid {
            return Ok(());
        }
        Err(AuthError::Denied)
    }

    pub fn serialize_for_storage(&self) -> Result<Vec<u8>, SerializeError> {
        let mut output = Vec::new();
        output.extend_from_slice(FORMAT_HEADER);
        output.push(b'\n');
        for account in &self.accounts {
            append_fields(
                &mut output,
                &[
                    b"u",
                    account.entry.name.as_bytes(),
                    decimal(account.entry.uid).as_slice(),
                    decimal(account.entry.gid).as_slice(),
                    decimal(account.entry.flags).as_slice(),
                    decimal(account.entry.capabilities).as_slice(),
                    account.entry.home.as_bytes(),
                    account.entry.shell.as_bytes(),
                    account.password_hash.as_bytes(),
                ],
            )?;
        }
        for group in &self.groups {
            let mut members = Vec::new();
            if group.members.is_empty() {
                members.extend_from_slice(b"-");
            } else {
                for (index, member) in group.members.iter().enumerate() {
                    if index != 0 {
                        members.push(b',');
                    }
                    members.extend_from_slice(member.as_bytes());
                }
            }
            append_fields(
                &mut output,
                &[
                    b"g",
                    group.name.as_bytes(),
                    decimal(group.gid).as_slice(),
                    members.as_slice(),
                ],
            )?;
        }
        if output.len() > MAX_DATABASE_BYTES {
            return Err(SerializeError::TooLarge);
        }
        Ok(output)
    }

    fn add_account(&mut self, account: Account) -> Result<(), ParseError> {
        if self.accounts.len() == MAX_USERS
            || self.accounts.iter().any(|existing| {
                existing.entry.name == account.entry.name || existing.entry.uid == account.entry.uid
            })
        {
            return Err(if self.accounts.len() == MAX_USERS {
                ParseError::Limit
            } else {
                ParseError::Duplicate
            });
        }
        self.accounts.push(account);
        Ok(())
    }

    fn add_group(&mut self, group: GroupEntry) -> Result<(), ParseError> {
        if self.groups.len() == MAX_GROUPS
            || self
                .groups
                .iter()
                .any(|existing| existing.name == group.name || existing.gid == group.gid)
        {
            return Err(if self.groups.len() == MAX_GROUPS {
                ParseError::Limit
            } else {
                ParseError::Duplicate
            });
        }
        self.groups.push(group);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageError {
    Missing,
    Unavailable,
    Corrupt,
    TooLarge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryState {
    Current,
    RecoveredTemp,
}

pub trait AtomicStorage {
    fn read(&mut self, path: &[u8], output: &mut Vec<u8>) -> Result<(), StorageError>;
    fn write_temp(&mut self, path: &[u8], contents: &[u8]) -> Result<(), StorageError>;
    fn replace(&mut self, temp_path: &[u8], committed_path: &[u8]) -> Result<(), StorageError>;
}

pub fn atomic_replace<S: AtomicStorage>(
    storage: &mut S,
    committed_path: &[u8],
    temp_path: &[u8],
    database: &Database,
) -> Result<(), StorageError> {
    let contents = database
        .serialize_for_storage()
        .map_err(|_| StorageError::TooLarge)?;
    storage.write_temp(temp_path, &contents)?;
    storage.replace(temp_path, committed_path)
}

pub fn load_with_recovery<S: AtomicStorage>(
    storage: &mut S,
    committed_path: &[u8],
    temp_path: &[u8],
) -> Result<(Database, RecoveryState), StorageError> {
    let mut committed = Vec::new();
    match storage.read(committed_path, &mut committed) {
        Ok(()) => match Database::parse(&committed) {
            Ok(database) => Ok((database, RecoveryState::Current)),
            Err(_) => recover_temp(storage, committed_path, temp_path),
        },
        Err(StorageError::Missing | StorageError::Corrupt) => {
            recover_temp(storage, committed_path, temp_path)
        }
        Err(error) => Err(error),
    }
}

fn recover_temp<S: AtomicStorage>(
    storage: &mut S,
    committed_path: &[u8],
    temp_path: &[u8],
) -> Result<(Database, RecoveryState), StorageError> {
    let mut temporary = Vec::new();
    match storage.read(temp_path, &mut temporary) {
        Ok(()) => {}
        Err(StorageError::Missing | StorageError::Corrupt) => return Err(StorageError::Corrupt),
        Err(error) => return Err(error),
    }
    let database = Database::parse(&temporary).map_err(|_| StorageError::Corrupt)?;
    storage.replace(temp_path, committed_path)?;
    Ok((database, RecoveryState::RecoveredTemp))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lockout {
    pub failures: u8,
    pub locked_until: u64,
}

impl Lockout {
    pub const fn new() -> Self {
        Self {
            failures: 0,
            locked_until: 0,
        }
    }

    pub const fn is_locked(self, now: u64) -> bool {
        self.locked_until > now
    }

    pub fn register_failure(&mut self, now: u64, max_failures: u8, duration: u64) {
        if self.is_locked(now) {
            return;
        }
        self.failures = self.failures.saturating_add(1);
        if self.failures >= max_failures {
            self.locked_until = now.saturating_add(duration);
        }
    }

    pub const fn register_success(&mut self) {
        self.failures = 0;
        self.locked_until = 0;
    }
}

fn parse_account(fields: &[&[u8]]) -> Result<Account, ParseError> {
    let name = parse_name(fields[1])?;
    let uid = parse_u32(fields[2])?;
    let gid = parse_u32(fields[3])?;
    let flags = parse_u32(fields[4])?;
    if flags & !KNOWN_FLAGS != 0 {
        return Err(ParseError::UnknownFlags);
    }
    let capabilities = parse_u64(fields[5])?;
    if capabilities & !KNOWN_CAPABILITIES != 0 {
        return Err(ParseError::UnknownCapabilities);
    }
    let home = parse_path(fields[6])?;
    let shell = parse_path(fields[7])?;
    validate_password_hash(fields[8])?;
    Ok(Account {
        entry: UserEntry {
            name,
            uid,
            gid,
            flags,
            capabilities,
            home,
            shell,
        },
        password_hash: to_string(fields[8])?,
    })
}

fn parse_group(fields: &[&[u8]]) -> Result<GroupEntry, ParseError> {
    let name = parse_name(fields[1])?;
    let gid = parse_u32(fields[2])?;
    let mut members = Vec::new();
    if fields[3] != b"-" {
        for member in fields[3].split(|byte| *byte == b',') {
            if members.len() == MAX_USERS {
                return Err(ParseError::Limit);
            }
            members.push(parse_name(member)?);
        }
    }
    Ok(GroupEntry { name, gid, members })
}

fn split_fields(line: &[u8]) -> Result<Vec<&[u8]>, ParseError> {
    let mut fields = Vec::new();
    for field in line.split(|byte| *byte == b':') {
        if fields.len() == 9 {
            return Err(ParseError::InvalidLine);
        }
        fields.push(field);
    }
    Ok(fields)
}

fn parse_name(value: &[u8]) -> Result<String, ParseError> {
    if value.is_empty() || value.len() > MAX_NAME_BYTES || value == b"." || value == b".." {
        return Err(ParseError::InvalidName);
    }
    if !value
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ParseError::InvalidName);
    }
    to_string(value)
}

fn parse_path(value: &[u8]) -> Result<String, ParseError> {
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || value[0] != b'/'
        || value
            .iter()
            .any(|byte| *byte < 0x20 || *byte == b':' || *byte == b'\n')
    {
        return Err(ParseError::InvalidPath);
    }
    to_string(value)
}

fn parse_u32(value: &[u8]) -> Result<u32, ParseError> {
    let mut result = 0u32;
    if value.is_empty() {
        return Err(ParseError::InvalidNumber);
    }
    for byte in value {
        if !byte.is_ascii_digit() {
            return Err(ParseError::InvalidNumber);
        }
        result = result
            .checked_mul(10)
            .and_then(|value| value.checked_add(u32::from(byte - b'0')))
            .ok_or(ParseError::InvalidNumber)?;
    }
    Ok(result)
}

fn parse_u64(value: &[u8]) -> Result<u64, ParseError> {
    let mut result = 0u64;
    if value.is_empty() {
        return Err(ParseError::InvalidNumber);
    }
    for byte in value {
        if !byte.is_ascii_digit() {
            return Err(ParseError::InvalidNumber);
        }
        result = result
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
            .ok_or(ParseError::InvalidNumber)?;
    }
    Ok(result)
}

fn validate_password_hash(value: &[u8]) -> Result<(), ParseError> {
    if value.len() < ARGON2ID_PREFIX.len() + 16 || value.len() > MAX_HASH_BYTES {
        return Err(ParseError::InvalidHash);
    }
    if !value.starts_with(ARGON2ID_PREFIX) {
        return Err(ParseError::InvalidHash);
    }
    let rest = &value[ARGON2ID_PREFIX.len()..];
    let mut parts = rest.split(|byte| *byte == b'$');
    let Some(salt) = parts.next() else {
        return Err(ParseError::InvalidHash);
    };
    let Some(digest) = parts.next() else {
        return Err(ParseError::InvalidHash);
    };
    if parts.next().is_some()
        || salt.len() < 8
        || digest.len() < 16
        || !salt.iter().all(|byte| is_base64(*byte))
        || !digest.iter().all(|byte| is_base64(*byte))
    {
        return Err(ParseError::InvalidHash);
    }
    Ok(())
}

const fn is_base64(byte: u8) -> bool {
    matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=')
}

fn to_string(value: &[u8]) -> Result<String, ParseError> {
    String::from_utf8(value.to_vec()).map_err(|_| ParseError::InvalidLine)
}

fn decimal(value: impl Into<u64>) -> Vec<u8> {
    let mut value = value.into();
    let mut buffer = [0u8; 20];
    let mut index = buffer.len();
    loop {
        index -= 1;
        buffer[index] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    buffer[index..].to_vec()
}

fn append_fields(output: &mut Vec<u8>, fields: &[&[u8]]) -> Result<(), SerializeError> {
    for (index, field) in fields.iter().enumerate() {
        if index != 0 {
            output.push(b':');
        }
        output.extend_from_slice(field);
    }
    output.push(b'\n');
    if output.len() > MAX_DATABASE_BYTES {
        return Err(SerializeError::TooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &[u8] = b"$argon2id$v=19$m=65536,t=3,p=1$c2FsdFNhbXBsZQ$ZGlnaWVzdFNhbXBsZQ";
    const DATABASE: &[u8] = b"NORX-USERDB 1\nu:alice:1000:1000:0:0:/users/alice:/bin/nsh:$argon2id$v=19$m=65536,t=3,p=1$c2FsdFNhbXBsZQ$ZGlnaWVzdFNhbXBsZQ\ng:users:1000:alice\n";

    struct Verifier;

    impl PasswordVerifier for Verifier {
        fn verify(&self, password: &[u8], encoded_hash: &[u8]) -> bool {
            password == b"correct" && encoded_hash == HASH
        }
    }

    #[test]
    fn parses_without_exposing_hash_and_authenticates() {
        let database = Database::parse(DATABASE).unwrap();
        let user = database.lookup_user(b"alice").unwrap();
        assert_eq!(user.uid, 1000);
        assert!(user.is_enabled());
        assert_eq!(
            database.lookup_group(b"users").unwrap().members[0].as_bytes(),
            b"alice"
        );
        assert_eq!(
            database.authenticate(b"alice", b"correct", &Verifier),
            Ok(SessionCredentials::from_user(&user))
        );
        assert_eq!(
            database.authenticate(b"alice", b"wrong", &Verifier),
            Err(AuthError::Denied)
        );
    }

    #[test]
    fn round_trip_is_deterministic() {
        let database = Database::parse(DATABASE).unwrap();
        assert_eq!(database.serialize_for_storage().unwrap(), DATABASE);
    }

    #[test]
    fn rejects_duplicates_overflow_and_bad_hashes() {
        let duplicate = b"NORX-USERDB 1\nu:alice:1000:1000:0:0:/users/a:/bin/nsh:$argon2id$v=19$m=65536,t=3,p=1$c2FsdFNhbXBsZQ$ZGlnaWVzdFNhbXBsZQ\nu:bob:1000:1001:0:0:/users/b:/bin/nsh:$argon2id$v=19$m=65536,t=3,p=1$c2FsdFNhbXBsZQ$ZGlnaWVzdFNhbXBsZQ\n";
        assert_eq!(Database::parse(duplicate), Err(ParseError::Duplicate));
        let bad_hash = b"NORX-USERDB 1\nu:alice:1000:1000:0:0:/users/a:/bin/nsh:$bcrypt$hash\n";
        assert_eq!(Database::parse(bad_hash), Err(ParseError::InvalidHash));
        let overflow = b"NORX-USERDB 1\nu:alice:42949672960:1000:0:0:/users/a:/bin/nsh:$argon2id$v=19$m=65536,t=3,p=1$c2FsdFNhbXBsZQ$ZGlnaWVzdFNhbXBsZQ\n";
        assert_eq!(Database::parse(overflow), Err(ParseError::InvalidNumber));
    }

    #[test]
    fn root_without_account_capability_cannot_mutate() {
        let database = Database::parse(DATABASE).unwrap();
        let root = SessionCredentials {
            real_uid: 0,
            effective_uid: 0,
            saved_uid: 0,
            real_gid: 0,
            effective_gid: 0,
            saved_gid: 0,
            capabilities: 0,
        };
        assert_eq!(
            database.authorize_mutation(root, 1000, Mutation::ModifyAccount),
            Err(AuthError::Denied)
        );
        assert!(database
            .authorize_mutation(root, 1000, Mutation::ChangeOwnPassword)
            .is_err());
    }

    #[test]
    fn lockout_is_bounded_and_resets_on_success() {
        let mut lockout = Lockout::new();
        lockout.register_failure(10, 3, 100);
        lockout.register_failure(10, 3, 100);
        assert!(!lockout.is_locked(10));
        lockout.register_failure(10, 3, 100);
        assert!(lockout.is_locked(10));
        lockout.register_success();
        assert!(!lockout.is_locked(10));
        assert_eq!(lockout.failures, 0);
    }

    #[derive(Default)]
    struct MemoryStorage {
        committed: Option<Vec<u8>>,
        temporary: Option<Vec<u8>>,
        unavailable: bool,
    }

    impl AtomicStorage for MemoryStorage {
        fn read(&mut self, path: &[u8], output: &mut Vec<u8>) -> Result<(), StorageError> {
            if self.unavailable {
                return Err(StorageError::Unavailable);
            }
            let source = if path == b"tmp" {
                self.temporary.as_ref()
            } else {
                self.committed.as_ref()
            }
            .ok_or(StorageError::Missing)?;
            output.extend_from_slice(source);
            Ok(())
        }

        fn write_temp(&mut self, _path: &[u8], contents: &[u8]) -> Result<(), StorageError> {
            if self.unavailable {
                return Err(StorageError::Unavailable);
            }
            self.temporary = Some(contents.to_vec());
            Ok(())
        }

        fn replace(
            &mut self,
            _temp_path: &[u8],
            _committed_path: &[u8],
        ) -> Result<(), StorageError> {
            if self.unavailable {
                return Err(StorageError::Unavailable);
            }
            self.committed = self.temporary.take();
            Ok(())
        }
    }

    #[test]
    fn atomic_storage_recovers_valid_temp_and_fails_closed() {
        let database = Database::parse(DATABASE).unwrap();
        let mut storage = MemoryStorage::default();
        atomic_replace(&mut storage, b"db", b"tmp", &database).unwrap();
        assert_eq!(
            load_with_recovery(&mut storage, b"db", b"tmp").unwrap().1,
            RecoveryState::Current
        );
        storage.committed = Some(b"NORX-USERDB 1\ninvalid\n".to_vec());
        storage.temporary = Some(DATABASE.to_vec());
        assert_eq!(
            load_with_recovery(&mut storage, b"db", b"tmp").unwrap().1,
            RecoveryState::RecoveredTemp
        );
        storage.committed = Some(b"corrupt".to_vec());
        storage.temporary = Some(b"also corrupt".to_vec());
        assert_eq!(
            load_with_recovery(&mut storage, b"db", b"tmp"),
            Err(StorageError::Corrupt)
        );
        storage.unavailable = true;
        storage.committed = Some(DATABASE.to_vec());
        storage.temporary = Some(DATABASE.to_vec());
        assert_eq!(
            load_with_recovery(&mut storage, b"db", b"tmp"),
            Err(StorageError::Unavailable)
        );
    }

    #[test]
    fn newer_schema_is_rejected_without_implicit_migration() {
        assert_eq!(
            Database::parse(b"NORX-USERDB 2\n"),
            Err(ParseError::UnsupportedVersion)
        );
    }
}
