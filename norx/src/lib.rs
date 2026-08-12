#![no_std]

extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

pub const FORMAT_HEADER: &[u8] = b"NORX-USERDB 1";
pub const MAX_DATABASE_BYTES: usize = 64 * 1024;
pub const MAX_LINE_BYTES: usize = 512;
pub const MAX_USERS: usize = 128;
pub const MAX_GROUPS: usize = 128;
pub const MAX_NAME_BYTES: usize = 31;
pub const MAX_PATH_BYTES: usize = 255;
pub const MAX_HASH_BYTES: usize = 256;
pub const MAX_PASSWORD_BYTES: usize = 128;
pub const FLAG_DISABLED: u32 = 1 << 0;
pub const FLAG_LOCKED: u32 = 1 << 1;
pub const FLAG_EXPIRED: u32 = 1 << 2;
pub const KNOWN_FLAGS: u32 = FLAG_DISABLED | FLAG_LOCKED | FLAG_EXPIRED;
pub const CAP_ACCOUNT_ADMIN: u64 = 1 << 8;
pub const CAP_SESSION_ADMIN: u64 = 1 << 9;
pub const KNOWN_CAPABILITIES: u64 = CAP_ACCOUNT_ADMIN | CAP_SESSION_ADMIN;
pub const ARGON2ID_PREFIX: &[u8] = b"$argon2id$v=19$m=65536,t=3,p=1$";
pub const LOCKED_PASSWORD_HASH: &str =
    "$argon2id$v=19$m=65536,t=3,p=1$bG9ja2VkLXNlbnRpbmVs$bm90LWEtcGFzc3dvcmQ=";

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

#[derive(Clone, PartialEq, Eq)]
struct Account {
    entry: UserEntry,
    password_hash: String,
}

impl fmt::Debug for Account {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Account")
            .field("entry", &self.entry)
            .field("password_hash", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Database {
    accounts: Vec<Account>,
    groups: Vec<GroupEntry>,
}

pub trait PasswordVerifier {
    fn verify(&self, password: &[u8], encoded_hash: &[u8]) -> bool;
}

pub trait PasswordHasher {
    fn hash(&self, password: &[u8]) -> Option<String>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PasswordPolicy {
    pub min_length: usize,
    pub max_length: usize,
}

impl PasswordPolicy {
    pub const DEFAULT: Self = Self {
        min_length: 8,
        max_length: MAX_PASSWORD_BYTES,
    };

    fn validate(self, password: &[u8], confirmation: &[u8]) -> Result<(), PasswordChangeError> {
        if self.min_length == 0
            || self.min_length > self.max_length
            || self.max_length > MAX_PASSWORD_BYTES
        {
            return Err(PasswordChangeError::InvalidPolicy);
        }
        if password.len() > self.max_length || confirmation.len() > self.max_length {
            return Err(PasswordChangeError::InvalidPassword);
        }
        if !constant_time_equal(password, confirmation) {
            return Err(PasswordChangeError::ConfirmationMismatch);
        }
        if password.len() < self.min_length
            || password.len() > self.max_length
            || password
                .iter()
                .any(|byte| *byte == 0 || *byte == b'\r' || *byte == b'\n')
        {
            return Err(PasswordChangeError::InvalidPassword);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordChangeError {
    NotFound,
    Denied,
    OldPasswordRejected,
    ConfirmationMismatch,
    PasswordReuse,
    InvalidPassword,
    InvalidPolicy,
    HashFailed,
    InvalidHash,
}

pub const FIRST_DYNAMIC_ID: u32 = 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminError {
    PermissionDenied,
    InvalidInput,
    InvalidId,
    InvalidHash,
    Duplicate,
    NotFound,
    Limit,
    Storage(StorageError),
    Serialization,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserSpec {
    pub name: String,
    pub uid: Option<u32>,
    pub primary_gid: Option<u32>,
    pub supplementary_groups: Vec<String>,
    pub home: Option<String>,
    pub shell: Option<String>,
    pub flags: u32,
    pub capabilities: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UserUpdate {
    pub name: Option<String>,
    pub primary_gid: Option<u32>,
    pub supplementary_groups: Option<Vec<String>>,
    pub home: Option<String>,
    pub shell: Option<String>,
    pub flags: Option<u32>,
    pub capabilities: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GroupUpdate {
    pub name: Option<String>,
    pub members: Option<Vec<String>>,
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

    pub fn change_password<V: PasswordVerifier, H: PasswordHasher>(
        &mut self,
        actor: SessionCredentials,
        target_uid: u32,
        old_password: Option<&[u8]>,
        new_password: &[u8],
        confirmation: &[u8],
        policy: PasswordPolicy,
        verifier: &V,
        hasher: &H,
    ) -> Result<(), PasswordChangeError> {
        self.authorize_mutation(actor, target_uid, Mutation::ChangeOwnPassword)
            .map_err(|_| PasswordChangeError::Denied)?;
        let index = self
            .accounts
            .iter()
            .position(|account| account.entry.uid == target_uid)
            .ok_or(PasswordChangeError::NotFound)?;
        let administrator = actor.has_capability(CAP_ACCOUNT_ADMIN);
        if !administrator {
            if self.accounts[index].entry.flags & (FLAG_DISABLED | FLAG_LOCKED) != 0 {
                return Err(PasswordChangeError::Denied);
            }
            let Some(old_password) = old_password else {
                return Err(PasswordChangeError::OldPasswordRejected);
            };
            if !verifier.verify(old_password, self.accounts[index].password_hash.as_bytes()) {
                return Err(PasswordChangeError::OldPasswordRejected);
            }
        }
        policy.validate(new_password, confirmation)?;
        if verifier.verify(new_password, self.accounts[index].password_hash.as_bytes()) {
            return Err(PasswordChangeError::PasswordReuse);
        }
        let encoded = hasher
            .hash(new_password)
            .ok_or(PasswordChangeError::HashFailed)?;
        validate_password_hash(encoded.as_bytes()).map_err(|_| PasswordChangeError::InvalidHash)?;
        self.accounts[index].password_hash = encoded;
        Ok(())
    }

    pub fn set_locked(
        &mut self,
        actor: SessionCredentials,
        target_uid: u32,
        locked: bool,
    ) -> Result<(), AuthError> {
        self.authorize_mutation(actor, target_uid, Mutation::ModifyAccount)?;
        let account = self
            .accounts
            .iter_mut()
            .find(|account| account.entry.uid == target_uid)
            .ok_or(AuthError::Denied)?;
        if locked {
            account.entry.flags |= FLAG_LOCKED;
        } else {
            account.entry.flags &= !FLAG_LOCKED;
        }
        Ok(())
    }

    pub fn list_users(&self) -> Vec<UserEntry> {
        self.accounts
            .iter()
            .map(|account| account.entry.clone())
            .collect()
    }

    pub fn list_groups(&self) -> Vec<GroupEntry> {
        self.groups.clone()
    }

    pub fn create_group(
        &mut self,
        actor: SessionCredentials,
        name: String,
        gid: Option<u32>,
        members: Vec<String>,
    ) -> Result<u32, AdminError> {
        require_admin(actor)?;
        validate_name_string(&name)?;
        if self.groups.iter().any(|group| group.name == name) {
            return Err(AdminError::Duplicate);
        }
        validate_group_members(self, &members)?;
        let gid = match gid {
            Some(gid) => gid,
            None => next_id(self.groups.iter().map(|group| group.gid)).ok_or(AdminError::Limit)?,
        };
        if self.groups.iter().any(|group| group.gid == gid) {
            return Err(AdminError::Duplicate);
        }
        if self.groups.len() == MAX_GROUPS {
            return Err(AdminError::Limit);
        }
        self.groups.push(GroupEntry { name, gid, members });
        Ok(gid)
    }

    pub fn modify_group(
        &mut self,
        actor: SessionCredentials,
        gid: u32,
        update: GroupUpdate,
    ) -> Result<(), AdminError> {
        require_admin(actor)?;
        let index = self
            .groups
            .iter()
            .position(|group| group.gid == gid)
            .ok_or(AdminError::NotFound)?;
        let name = update.name.as_ref().unwrap_or(&self.groups[index].name);
        validate_name_string(name)?;
        if self
            .groups
            .iter()
            .enumerate()
            .any(|(other, group)| other != index && group.name == *name)
        {
            return Err(AdminError::Duplicate);
        }
        let members = update
            .members
            .as_ref()
            .unwrap_or(&self.groups[index].members);
        validate_group_members(self, members)?;
        let name = name.clone();
        let members = members.clone();
        self.groups[index].name = name.clone();
        self.groups[index].members = members.clone();
        Ok(())
    }

    pub fn delete_group(&mut self, actor: SessionCredentials, gid: u32) -> Result<(), AdminError> {
        require_admin(actor)?;
        if self.accounts.iter().any(|account| account.entry.gid == gid) {
            return Err(AdminError::PermissionDenied);
        }
        let index = self
            .groups
            .iter()
            .position(|group| group.gid == gid)
            .ok_or(AdminError::NotFound)?;
        if !self.groups[index].members.is_empty() {
            return Err(AdminError::PermissionDenied);
        }
        self.groups.remove(index);
        Ok(())
    }

    pub fn create_user<H: PasswordHasher>(
        &mut self,
        actor: SessionCredentials,
        spec: UserSpec,
        password: &[u8],
        hasher: &H,
    ) -> Result<u32, AdminError> {
        require_admin(actor)?;
        if self.accounts.len() == MAX_USERS {
            return Err(AdminError::Limit);
        }
        validate_user_fields(
            &spec.name,
            spec.flags,
            spec.capabilities,
            spec.home.as_deref(),
            spec.shell.as_deref(),
        )?;
        if self
            .accounts
            .iter()
            .any(|account| account.entry.name == spec.name)
        {
            return Err(AdminError::Duplicate);
        }
        let uid = match spec.uid {
            Some(uid) => uid,
            None => next_id(self.accounts.iter().map(|account| account.entry.uid))
                .ok_or(AdminError::Limit)?,
        };
        if self.accounts.iter().any(|account| account.entry.uid == uid) {
            return Err(AdminError::Duplicate);
        }
        if uid == 0 && spec.capabilities & CAP_ACCOUNT_ADMIN == 0 {
            return Err(AdminError::InvalidInput);
        }
        let gid = spec.primary_gid.ok_or(AdminError::InvalidInput)?;
        if !self.groups.iter().any(|group| group.gid == gid) {
            return Err(AdminError::InvalidId);
        }
        validate_group_names(self, &spec.supplementary_groups)?;
        if uid == 0 && spec.capabilities & CAP_ACCOUNT_ADMIN == 0 {
            return Err(AdminError::InvalidInput);
        }
        let encoded = hasher.hash(password).ok_or(AdminError::InvalidHash)?;
        validate_password_hash(encoded.as_bytes()).map_err(|_| AdminError::InvalidHash)?;
        let mut candidate_groups = self.groups.clone();
        set_membership(
            &mut candidate_groups,
            &spec.name,
            &spec.supplementary_groups,
        )?;
        let account = Account {
            entry: UserEntry {
                name: spec.name,
                uid,
                gid,
                flags: spec.flags,
                capabilities: spec.capabilities,
                home: spec.home.ok_or(AdminError::InvalidInput)?,
                shell: spec.shell.ok_or(AdminError::InvalidInput)?,
            },
            password_hash: encoded,
        };
        self.accounts.push(account);
        self.groups = candidate_groups;
        Ok(uid)
    }

    pub fn create_locked_user(
        &mut self,
        actor: SessionCredentials,
        spec: UserSpec,
    ) -> Result<u32, AdminError> {
        require_admin(actor)?;
        let mut spec = spec;
        spec.flags |= FLAG_LOCKED;
        self.create_user_with_hash(actor, spec, LOCKED_PASSWORD_HASH)
    }

    fn create_user_with_hash(
        &mut self,
        actor: SessionCredentials,
        spec: UserSpec,
        encoded: &str,
    ) -> Result<u32, AdminError> {
        require_admin(actor)?;
        if self.accounts.len() == MAX_USERS {
            return Err(AdminError::Limit);
        }
        validate_user_fields(
            &spec.name,
            spec.flags,
            spec.capabilities,
            spec.home.as_deref(),
            spec.shell.as_deref(),
        )?;
        if self
            .accounts
            .iter()
            .any(|account| account.entry.name == spec.name)
        {
            return Err(AdminError::Duplicate);
        }
        let uid = match spec.uid {
            Some(uid) => uid,
            None => next_id(self.accounts.iter().map(|account| account.entry.uid))
                .ok_or(AdminError::Limit)?,
        };
        if self.accounts.iter().any(|account| account.entry.uid == uid) {
            return Err(AdminError::Duplicate);
        }
        let gid = spec.primary_gid.ok_or(AdminError::InvalidInput)?;
        if !self.groups.iter().any(|group| group.gid == gid) {
            return Err(AdminError::InvalidId);
        }
        validate_group_names(self, &spec.supplementary_groups)?;
        validate_password_hash(encoded.as_bytes()).map_err(|_| AdminError::InvalidHash)?;
        let name = spec.name.clone();
        let mut candidate_groups = self.groups.clone();
        set_membership(&mut candidate_groups, &name, &spec.supplementary_groups)?;
        let account = Account {
            entry: UserEntry {
                name: spec.name,
                uid,
                gid,
                flags: spec.flags,
                capabilities: spec.capabilities,
                home: spec.home.ok_or(AdminError::InvalidInput)?,
                shell: spec.shell.ok_or(AdminError::InvalidInput)?,
            },
            password_hash: encoded.into(),
        };
        self.accounts.push(account);
        self.groups = candidate_groups;
        Ok(uid)
    }

    pub fn modify_user(
        &mut self,
        actor: SessionCredentials,
        target_uid: u32,
        update: UserUpdate,
    ) -> Result<(), AdminError> {
        require_admin(actor)?;
        let index = self
            .accounts
            .iter()
            .position(|account| account.entry.uid == target_uid)
            .ok_or(AdminError::NotFound)?;
        let current = self.accounts[index].entry.clone();
        let name = update.name.as_ref().unwrap_or(&current.name);
        let home = update.home.as_deref().unwrap_or(current.home.as_str());
        let shell = update.shell.as_deref().unwrap_or(current.shell.as_str());
        validate_user_fields(
            name,
            update.flags.unwrap_or(current.flags),
            update.capabilities.unwrap_or(current.capabilities),
            Some(home),
            Some(shell),
        )?;
        if self
            .accounts
            .iter()
            .enumerate()
            .any(|(other, account)| other != index && account.entry.name == *name)
        {
            return Err(AdminError::Duplicate);
        }
        if let Some(gid) = update.primary_gid {
            if !self.groups.iter().any(|group| group.gid == gid) {
                return Err(AdminError::InvalidId);
            }
        }
        if let Some(groups) = &update.supplementary_groups {
            validate_group_names(self, groups)?;
        }
        let old_name = current.name.clone();
        let new_name = name.to_owned();
        let groups = update.supplementary_groups.clone();
        let mut candidate_groups = self.groups.clone();
        if let Some(groups) = &groups {
            set_membership(&mut candidate_groups, &old_name, &[])?;
            set_membership(&mut candidate_groups, &new_name, groups)?;
        } else if old_name != new_name {
            for group in &mut candidate_groups {
                for member in &mut group.members {
                    if *member == old_name {
                        *member = new_name.clone();
                    }
                }
            }
        }
        let entry = &mut self.accounts[index].entry;
        entry.name = new_name.clone();
        entry.gid = update.primary_gid.unwrap_or(entry.gid);
        entry.home = home.to_owned();
        entry.shell = shell.to_owned();
        if let Some(flags) = update.flags {
            entry.flags = flags;
        }
        if let Some(capabilities) = update.capabilities {
            entry.capabilities = capabilities;
        }
        self.groups = candidate_groups;
        Ok(())
    }

    pub fn delete_user(
        &mut self,
        actor: SessionCredentials,
        target_uid: u32,
    ) -> Result<(), AdminError> {
        require_admin(actor)?;
        let index = self
            .accounts
            .iter()
            .position(|account| account.entry.uid == target_uid)
            .ok_or(AdminError::NotFound)?;
        if target_uid == actor.effective_uid || target_uid == 0 {
            return Err(AdminError::PermissionDenied);
        }
        let name = self.accounts[index].entry.name.clone();
        self.accounts.remove(index);
        for group in &mut self.groups {
            group.members.retain(|member| member != &name);
        }
        Ok(())
    }

    pub fn transact_admin<S: AtomicStorage, F>(
        &mut self,
        actor: SessionCredentials,
        storage: &mut S,
        committed_path: &[u8],
        temp_path: &[u8],
        operation: F,
    ) -> Result<(), AdminError>
    where
        F: FnOnce(&mut Database) -> Result<(), AdminError>,
    {
        self.transact_admin_with(actor, storage, committed_path, temp_path, operation)
            .map(|_| ())
    }

    pub fn transact_admin_with<S: AtomicStorage, F, R>(
        &mut self,
        actor: SessionCredentials,
        storage: &mut S,
        committed_path: &[u8],
        temp_path: &[u8],
        operation: F,
    ) -> Result<R, AdminError>
    where
        F: FnOnce(&mut Database) -> Result<R, AdminError>,
    {
        require_admin(actor)?;
        let mut candidate = self.clone();
        let result = operation(&mut candidate)?;
        atomic_replace(storage, committed_path, temp_path, &candidate)
            .map_err(AdminError::Storage)?;
        *self = candidate;
        Ok(result)
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
    Busy,
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
    fn lock(&mut self) -> Result<(), StorageError>;
    fn write_temp(&mut self, path: &[u8], contents: &[u8]) -> Result<(), StorageError>;
    fn sync_file(&mut self, path: &[u8]) -> Result<(), StorageError>;
    fn replace(&mut self, temp_path: &[u8], committed_path: &[u8]) -> Result<(), StorageError>;
    fn sync_parent(&mut self, committed_path: &[u8]) -> Result<(), StorageError>;
    fn unlock(&mut self) -> Result<(), StorageError>;
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
    storage.lock()?;
    let result = (|| {
        storage.write_temp(temp_path, &contents)?;
        storage.sync_file(temp_path)?;
        storage.replace(temp_path, committed_path)?;
        storage.sync_parent(committed_path)
    })();
    let unlock = storage.unlock();
    match (result, unlock) {
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
    }
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
    storage.lock()?;
    let mut temporary = Vec::new();
    let result = (|| {
        match storage.read(temp_path, &mut temporary) {
            Ok(()) => {}
            Err(StorageError::Missing | StorageError::Corrupt) => {
                return Err(StorageError::Corrupt)
            }
            Err(error) => return Err(error),
        }
        let database = Database::parse(&temporary).map_err(|_| StorageError::Corrupt)?;
        storage.replace(temp_path, committed_path)?;
        storage.sync_parent(committed_path)?;
        Ok((database, RecoveryState::RecoveredTemp))
    })();
    let unlock = storage.unlock();
    match (result, unlock) {
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
    }
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

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(left.get(index).copied().unwrap_or(0))
            ^ usize::from(right.get(index).copied().unwrap_or(0));
    }
    difference == 0
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

fn require_admin(actor: SessionCredentials) -> Result<(), AdminError> {
    if actor.has_capability(CAP_ACCOUNT_ADMIN) {
        Ok(())
    } else {
        Err(AdminError::PermissionDenied)
    }
}

fn validate_name_string(value: &str) -> Result<(), AdminError> {
    parse_name(value.as_bytes())
        .map(|_| ())
        .map_err(|_| AdminError::InvalidInput)
}

fn validate_path_string(value: &str) -> Result<(), AdminError> {
    parse_path(value.as_bytes())
        .map(|_| ())
        .map_err(|_| AdminError::InvalidInput)
}

fn validate_user_fields(
    name: &str,
    flags: u32,
    capabilities: u64,
    home: Option<&str>,
    shell: Option<&str>,
) -> Result<(), AdminError> {
    validate_name_string(name)?;
    if flags & !KNOWN_FLAGS != 0 || capabilities & !KNOWN_CAPABILITIES != 0 {
        return Err(AdminError::InvalidInput);
    }
    validate_path_string(home.ok_or(AdminError::InvalidInput)?)?;
    validate_path_string(shell.ok_or(AdminError::InvalidInput)?)?;
    Ok(())
}

fn validate_group_members(database: &Database, members: &[String]) -> Result<(), AdminError> {
    if members.len() > MAX_USERS
        || members.iter().any(|member| {
            validate_name_string(member).is_err()
                || !database
                    .accounts
                    .iter()
                    .any(|account| account.entry.name == *member)
        })
        || members
            .iter()
            .enumerate()
            .any(|(index, member)| members[..index].iter().any(|other| other == member))
    {
        return Err(AdminError::InvalidInput);
    }
    Ok(())
}

fn validate_group_names(database: &Database, groups: &[String]) -> Result<(), AdminError> {
    if groups.len() > MAX_GROUPS
        || groups.iter().any(|name| {
            validate_name_string(name).is_err()
                || !database.groups.iter().any(|group| group.name == *name)
        })
        || groups
            .iter()
            .enumerate()
            .any(|(index, name)| groups[..index].iter().any(|other| other == name))
    {
        return Err(AdminError::InvalidInput);
    }
    Ok(())
}

fn set_membership(
    groups: &mut [GroupEntry],
    user: &str,
    supplementary: &[String],
) -> Result<(), AdminError> {
    for group in groups.iter() {
        if supplementary.iter().any(|name| name == &group.name)
            && group.members.len() == MAX_USERS
            && !group.members.iter().any(|member| member == user)
        {
            return Err(AdminError::Limit);
        }
    }
    for group in groups {
        group.members.retain(|member| member != user);
        if supplementary.iter().any(|name| name == &group.name) {
            group.members.push(user.to_owned());
        }
    }
    Ok(())
}

fn next_id<I: Iterator<Item = u32> + Clone>(values: I) -> Option<u32> {
    let mut candidate = FIRST_DYNAMIC_ID;
    loop {
        if !values.clone().any(|value| value == candidate) {
            return Some(candidate);
        }
        if candidate == u32::MAX {
            return None;
        }
        candidate += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const HASH: &[u8] = b"$argon2id$v=19$m=65536,t=3,p=1$c2FsdFNhbXBsZQ$ZGlnaWVzdFNhbXBsZQ";
    const DATABASE: &[u8] = b"NORX-USERDB 1\nu:alice:1000:1000:0:0:/users/alice:/bin/nsh:$argon2id$v=19$m=65536,t=3,p=1$c2FsdFNhbXBsZQ$ZGlnaWVzdFNhbXBsZQ\ng:users:1000:alice\n";

    struct Verifier;

    impl PasswordVerifier for Verifier {
        fn verify(&self, password: &[u8], encoded_hash: &[u8]) -> bool {
            password == b"correct" && encoded_hash == HASH
        }
    }

    struct Hasher;

    impl PasswordHasher for Hasher {
        fn hash(&self, password: &[u8]) -> Option<String> {
            (password == b"newpass!").then(|| {
                String::from(
                    "$argon2id$v=19$m=65536,t=3,p=1$bmV3c2FsdFNhbXBsZQ$bmV3ZGlnaWVzdFNhbXBsZQ",
                )
            })
        }
    }

    const NEW_HASH: &[u8] =
        b"$argon2id$v=19$m=65536,t=3,p=1$bmV3c2FsdFNhbXBsZQ$bmV3ZGlnaWVzdFNhbXBsZQ";

    #[test]
    fn parses_without_exposing_hash_and_authenticates() {
        let database = Database::parse(DATABASE).unwrap();
        let debug = alloc::format!("{database:?}");
        assert!(!debug.contains(core::str::from_utf8(HASH).unwrap()));
        assert!(debug.contains("<redacted>"));
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
    fn password_change_requires_old_password_and_confirmation() {
        let mut database = Database::parse(DATABASE).unwrap();
        let actor = SessionCredentials::from_user(&database.lookup_user(b"alice").unwrap());
        assert_eq!(
            database.change_password(
                actor,
                1000,
                Some(b"correct"),
                b"correct",
                b"correct",
                PasswordPolicy {
                    min_length: 7,
                    max_length: MAX_PASSWORD_BYTES,
                },
                &Verifier,
                &Hasher,
            ),
            Err(PasswordChangeError::PasswordReuse)
        );
        assert_eq!(
            database.change_password(
                actor,
                1000,
                Some(b"wrong"),
                b"newpass!",
                b"newpass!",
                PasswordPolicy::DEFAULT,
                &Verifier,
                &Hasher,
            ),
            Err(PasswordChangeError::OldPasswordRejected)
        );
        assert_eq!(
            database.change_password(
                actor,
                1000,
                Some(b"correct"),
                b"newpass!",
                b"different",
                PasswordPolicy::DEFAULT,
                &Verifier,
                &Hasher,
            ),
            Err(PasswordChangeError::ConfirmationMismatch)
        );
        database
            .change_password(
                actor,
                1000,
                Some(b"correct"),
                b"newpass!",
                b"newpass!",
                PasswordPolicy::DEFAULT,
                &Verifier,
                &Hasher,
            )
            .unwrap();
        let serialized = database.serialize_for_storage().unwrap();
        assert!(serialized
            .windows(NEW_HASH.len())
            .any(|window| window == NEW_HASH));
        assert!(!serialized
            .windows(b"newpass!".len())
            .any(|window| window == b"newpass!"));
    }

    #[test]
    fn administrator_can_reset_and_lock_but_users_cannot() {
        let database = Database::parse(DATABASE).unwrap();
        let root = SessionCredentials {
            real_uid: 0,
            effective_uid: 0,
            saved_uid: 0,
            real_gid: 0,
            effective_gid: 0,
            saved_gid: 0,
            capabilities: CAP_ACCOUNT_ADMIN,
        };
        let mut database = database;
        database
            .change_password(
                root,
                1000,
                None,
                b"newpass!",
                b"newpass!",
                PasswordPolicy::DEFAULT,
                &Verifier,
                &Hasher,
            )
            .unwrap();
        assert!(database.set_locked(root, 1000, true).is_ok());
        assert_eq!(database.lookup_user(b"alice").unwrap().flags, FLAG_LOCKED);
        assert!(database.set_locked(root, 1000, false).is_ok());
        let alice = SessionCredentials {
            real_uid: 1000,
            effective_uid: 1000,
            saved_uid: 1000,
            real_gid: 1000,
            effective_gid: 1000,
            saved_gid: 1000,
            capabilities: 0,
        };
        assert_eq!(
            database.set_locked(alice, 1000, true),
            Err(AuthError::Denied)
        );
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
        locked: bool,
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

        fn lock(&mut self) -> Result<(), StorageError> {
            if self.unavailable {
                return Err(StorageError::Unavailable);
            }
            if self.locked {
                return Err(StorageError::Busy);
            }
            self.locked = true;
            Ok(())
        }

        fn write_temp(&mut self, _path: &[u8], contents: &[u8]) -> Result<(), StorageError> {
            if self.unavailable {
                return Err(StorageError::Unavailable);
            }
            self.temporary = Some(contents.to_vec());
            Ok(())
        }

        fn sync_file(&mut self, _path: &[u8]) -> Result<(), StorageError> {
            if self.unavailable {
                Err(StorageError::Unavailable)
            } else {
                Ok(())
            }
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

        fn sync_parent(&mut self, _committed_path: &[u8]) -> Result<(), StorageError> {
            if self.unavailable {
                Err(StorageError::Unavailable)
            } else {
                Ok(())
            }
        }

        fn unlock(&mut self) -> Result<(), StorageError> {
            self.locked = false;
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
    fn atomic_storage_rejects_concurrent_writer_and_does_not_publish_partial_data() {
        let database = Database::parse(DATABASE).unwrap();
        let mut storage = MemoryStorage::default();
        storage.lock().unwrap();
        assert_eq!(
            atomic_replace(&mut storage, b"db", b"tmp", &database),
            Err(StorageError::Busy)
        );
        assert!(storage.committed.is_none());
        storage.unlock().unwrap();
        atomic_replace(&mut storage, b"db", b"tmp", &database).unwrap();
        assert!(storage.committed.is_some());
    }

    #[test]
    fn administrator_can_manage_users_groups_and_membership() {
        let mut database = Database::parse(DATABASE).unwrap();
        let root = SessionCredentials {
            real_uid: 0,
            effective_uid: 0,
            saved_uid: 0,
            real_gid: 0,
            effective_gid: 0,
            saved_gid: 0,
            capabilities: CAP_ACCOUNT_ADMIN,
        };
        let alice = SessionCredentials::from_user(&database.lookup_user(b"alice").unwrap());

        assert_eq!(
            database.create_group(alice, String::from("operators"), None, Vec::new()),
            Err(AdminError::PermissionDenied)
        );
        let operators = database
            .create_group(root, String::from("operators"), None, Vec::new())
            .unwrap();
        assert_eq!(operators, 1000 + 1);
        assert_eq!(
            database.create_group(root, String::from("operators"), Some(2000), Vec::new()),
            Err(AdminError::Duplicate)
        );
        assert_eq!(
            database.create_group(root, String::from("bad:name"), None, Vec::new()),
            Err(AdminError::InvalidInput)
        );

        let bob = database
            .create_user(
                root,
                UserSpec {
                    name: String::from("bob"),
                    uid: None,
                    primary_gid: Some(operators),
                    supplementary_groups: vec![String::from("users")],
                    home: Some(String::from("/users/bob")),
                    shell: Some(String::from("/bin/nsh")),
                    flags: 0,
                    capabilities: 0,
                },
                b"newpass!",
                &Hasher,
            )
            .unwrap();
        assert_eq!(bob, 1001);
        assert!(database
            .lookup_group(b"users")
            .unwrap()
            .members
            .iter()
            .any(|member| member == "bob"));
        assert_eq!(
            database.create_user(
                root,
                UserSpec {
                    name: String::from("bob"),
                    uid: Some(2000),
                    primary_gid: Some(operators),
                    supplementary_groups: Vec::new(),
                    home: Some(String::from("/users/bob2")),
                    shell: Some(String::from("/bin/nsh")),
                    flags: 0,
                    capabilities: 0,
                },
                b"newpass!",
                &Hasher,
            ),
            Err(AdminError::Duplicate)
        );
        database
            .modify_user(
                root,
                bob,
                UserUpdate {
                    name: Some(String::from("bobby")),
                    supplementary_groups: Some(vec![String::from("operators")]),
                    flags: Some(FLAG_DISABLED),
                    ..UserUpdate::default()
                },
            )
            .unwrap();
        assert!(database.lookup_user(b"bobby").unwrap().flags & FLAG_DISABLED != 0);
        assert!(database
            .lookup_group(b"operators")
            .unwrap()
            .members
            .iter()
            .any(|member| member == "bobby"));
        assert!(!database
            .lookup_group(b"users")
            .unwrap()
            .members
            .iter()
            .any(|member| member == "bobby"));
        assert_eq!(
            database.delete_group(root, operators),
            Err(AdminError::PermissionDenied)
        );
        database.delete_user(root, bob).unwrap();
        database.delete_group(root, operators).unwrap();
        assert!(database.lookup_user(b"bobby").is_none());
    }

    #[test]
    fn locked_creation_has_no_usable_password_and_validates_groups() {
        let mut database = Database::parse(DATABASE).unwrap();
        let root = SessionCredentials {
            capabilities: CAP_ACCOUNT_ADMIN,
            ..SessionCredentials::from_user(&database.lookup_user(b"alice").unwrap())
        };
        let uid = database
            .create_locked_user(
                root,
                UserSpec {
                    name: String::from("service"),
                    uid: None,
                    primary_gid: Some(1000),
                    supplementary_groups: vec![String::from("users")],
                    home: Some(String::from("/users/service")),
                    shell: Some(String::from("/bin/false")),
                    flags: 0,
                    capabilities: 0,
                },
            )
            .unwrap();
        let user = database.lookup_user(b"service").unwrap();
        assert_eq!(user.uid, uid);
        assert!(user.flags & FLAG_LOCKED != 0);
        assert_eq!(
            database.authenticate(b"service", b"anything", &Verifier),
            Err(AuthError::Denied)
        );
        assert_eq!(
            database.create_locked_user(
                root,
                UserSpec {
                    name: String::from("broken"),
                    uid: None,
                    primary_gid: Some(1000),
                    supplementary_groups: vec![String::from("missing")],
                    home: Some(String::from("/users/broken")),
                    shell: Some(String::from("/bin/false")),
                    flags: 0,
                    capabilities: 0,
                },
            ),
            Err(AdminError::InvalidInput)
        );
    }

    #[test]
    fn admin_transaction_rolls_back_memory_when_storage_fails() {
        let mut database = Database::parse(DATABASE).unwrap();
        let before = database.clone();
        let root = SessionCredentials {
            capabilities: CAP_ACCOUNT_ADMIN,
            ..SessionCredentials::from_user(&database.lookup_user(b"alice").unwrap())
        };
        let mut storage = MemoryStorage {
            unavailable: true,
            ..MemoryStorage::default()
        };
        assert_eq!(
            database.transact_admin(root, &mut storage, b"db", b"tmp", |candidate| {
                candidate.modify_user(
                    root,
                    1000,
                    UserUpdate {
                        shell: Some(String::from("/bin/true")),
                        ..UserUpdate::default()
                    },
                )
            },),
            Err(AdminError::Storage(StorageError::Unavailable))
        );
        assert_eq!(database, before);
    }

    #[test]
    fn newer_schema_is_rejected_without_implicit_migration() {
        assert_eq!(
            Database::parse(b"NORX-USERDB 2\n"),
            Err(ParseError::UnsupportedVersion)
        );
    }
}
