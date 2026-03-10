# Changelog

All notable changes to SecureLock are documented here.

---

## [2.0.0] - 2026-03-10

### Changed
- **New vault format:** Locking a folder now produces a single encrypted `.vault` file instead of encrypting files in-place. All folder contents are packed into one AES-256-GCM ciphertext with an unencrypted JSON header (version, salt, verify token, file count, optional recovery key).
- `commands.rs`: path tracking now updates between folder path and vault path on lock/unlock, and `add_folder` accepts either a directory or an existing `.vault` file.
- `crypto.rs`: `NONCE_LEN` is now public; added `generate_nonce()`, `encrypt_with_nonce()`, and `decrypt_with_nonce()` helpers.

### Added
- **Import .vault** button in the UI — open an existing vault file directly.
- **Legacy badge** displayed for folders still using the old `.securelock` format.
- `tempfile` dependency for atomic write operations (temp file → rename).
- Legacy unlock support: old `.securelock` format is auto-detected and routed to legacy unlock functions, so existing locked folders are not broken.

### Vault file format
```
[8 bytes]  Magic: SECRLK + version bytes
[4 bytes]  Header length (u32 LE)
[N bytes]  Header JSON (unencrypted)
[12 bytes] Nonce
[rest]     AES-256-GCM ciphertext (packed file payload)
```

### Migration note
Folders locked with v1.x remain unlockable. After unlocking, re-locking will produce the new `.vault` format.

---

## [1.0.0] - initial release

- Folder encryption with AES-256-GCM and Argon2id key derivation
- Per-file in-place encryption with `.locked` extension and `.securelock` manifest
- Master password with wrapped key recovery
- System tray with "Lock All" action
- Password strength meter
- Single-instance enforcement
