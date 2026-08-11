# Norx userdb

This directory is the Norx adapter maintained in the `NorxTeam/userdb` fork
of [`shadow-maint/shadow`](https://github.com/shadow-maint/shadow). The
upstream tree remains the reference for Unix account and group semantics; the
Norx code is deliberately isolated under `norx/` and does not claim host libc,
host filesystem, or Linux binary compatibility.

The current adapter provides:

- a bounded, versioned account/group record format;
- a lookup API that never returns password hashes;
- Argon2id PHC-format policy validation and a verifier boundary;
- explicit disabled/locked state, credential inheritance, capability mapping,
  mutation authorization, and bounded lockout state;
- atomic-replacement storage hooks and a target smoke binary using the Norx
  VFS ABI.

Password verification is intentionally injected through a `PasswordVerifier`
trait. The database parser never receives or logs plaintext through an output
path, and the target smoke only exercises persistence and malformed-record
handling, not authentication with a test password.
