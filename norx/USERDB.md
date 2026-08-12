# Norx userdb contract

## Ownership and paths

The mutable database is owned by the userdb service and stored at
`/cfg/userdb/users.db`. A writer must use `atomic_replace`: acquire the
single-writer lock, write bounded contents to
`/cfg/userdb/users.db.tmp`, sync the temporary file, rename it over the old
file, sync the containing directory, and release the lock. Readers open the
committed path only. A storage backend that cannot provide these operations
must return `Unavailable` rather than silently claiming durability.

On load, a valid committed file wins. If it is missing or malformed, a valid
temporary file is promoted and reported as `RecoveredTemp`; if both copies are
missing or malformed, loading fails closed as `Corrupt`. Storage errors are
returned as `Unavailable` and never trigger a root or empty-database fallback.
Only format v1 is accepted today. A newer header is reported as
`UnsupportedVersion`; migration must be an explicit, reviewed operation rather
than an automatic downgrade.

`/users` contains homes and user data. It is not an account database and is
never treated as one. Password material is not placed in argv, the environment,
shell output, or serial diagnostics.

## Record format v1

The file is UTF-8-free byte data with ASCII structural fields and this header:

```text
NORX-USERDB 1
u:<name>:<uid>:<gid>:<flags>:<capabilities>:<home>:<shell>:<argon2id-phc>
g:<name>:<gid>:<comma-separated-members-or->
```

Records are newline terminated. Maximum file size is 64 KiB, maximum line size
is 512 bytes, and there may be at most 128 users and 128 groups. Names are
ASCII `[A-Za-z0-9._-]`, max 31 bytes; paths are absolute and max 255 bytes.
Fields cannot contain `:` or control bytes. Duplicate names and IDs are
rejected. Unknown record types, flags, capabilities, missing fields, overflow,
and trailing bytes after a line are errors.

Flags are a decimal bitset: `disabled=1`, `locked=2`, and `expired=4`.
Capabilities are an explicit decimal bitset. UID 0 does not grant a capability
implicitly. The current service policy reserves bit 8 for `account-admin` and
bit 9 for `session-admin`; the kernel credentials ABI must publish these bits
before a service can transfer them across a process boundary.

Password fields must be Argon2id PHC strings with fixed policy parameters:
`m=65536,t=3,p=1`, bounded salt/digest fields, and no alternate password
scheme. The parser validates the encoded policy; cryptographic verification is
performed only by an injected password-verifier implementation.

## API and security rules

- `Database::lookup_user` returns `UserEntry` without a password hash.
- `Database::authenticate` returns generic denial for unknown, disabled,
  locked, expired, malformed, or failed accounts to avoid account enumeration.
- `SessionCredentials::from_user` initializes real/effective/saved UID/GID
  from the account and copies only explicitly mapped capabilities.
- Child processes inherit the complete credential tuple; no ambient capability
  appears merely because the UID is zero.
- Account/group mutation requires `account-admin`, except a user changing its
  own password after the caller has authenticated it. Authorization is checked
  before hashing or any temporary file is written. Disabled and locked users
  cannot change their own password; an expired user may still change it so the
  account can recover.
- `Database::change_password` requires a matching confirmation and a bounded
  policy (`8..=128` bytes by default), rejects NUL/CR/LF, verifies the old
  password for non-administrators, rejects password reuse, and validates the
  hasher's resulting PHC string before mutating memory. `None` for the old
  password is accepted only for `account-admin` reset.
- `Database::set_locked` is a separate privileged operation. `Lockout` is a
  bounded in-memory decision state; callers must serialize it together with
  the account update through `atomic_replace` if lockout persistence is
  required.
- Administrative user/group operations are exposed as bounded methods:
  `create_user`, `modify_user`, `delete_user`, `create_group`,
  `modify_group`, `delete_group`, `list_users`, and `list_groups`. They require
  the explicit `account-admin` capability; UID 0 alone is insufficient.
  Automatic IDs start at 1000, explicit IDs are checked for duplicates, user
  names/paths/flags/capabilities are revalidated, supplementary memberships
  refer only to existing groups, and primary groups cannot be deleted while
  referenced. Deleting a user removes its supplementary memberships.
- `Database::transact_admin` applies an administrative closure to a clone and
  publishes it through `atomic_replace` only after the complete candidate is
  valid. A failed operation, serialization, lock, sync, or rename leaves both
  the in-memory database and committed storage unchanged.
- `AtomicStorage` makes writer locking and file/directory sync explicit. A
  failed write, sync, or rename never publishes a partial database; recovery
  promotes a valid temporary file only while holding the writer lock.

The exported ABI is the Rust API in `norx/src/lib.rs`; C-facing login and
administration wrappers are intentionally deferred until the stable Norx
credential-transfer ABI exists.
