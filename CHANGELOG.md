# Changelog

All notable changes to SecureLock are documented here.

---

## [2.1.0] - 2026-03-10

### Security
- **Removed verify token from vault header** — the token was a known-plaintext oracle enabling offline brute-force without touching the ciphertext. Wrong-password detection now relies solely on the AES-GCM authentication tag.
- **Folder metadata encrypted** — original folder name, file count, and total size are now stored inside the encrypted payload rather than the unencrypted header.
- **Master password recovery is now opt-in per lock** — previously the recovery key was automatically written to the vault whenever a master session was active. Now the user explicitly enables it per lock operation via a checkbox.

### Added
- **Password hint** — optional plaintext hint stored in the vault header. Set when locking; displayed above the password field in the unlock dialog. Intentionally unencrypted so it is readable before decryption.
- **`get_vault_hint` command** — reads the vault header without a password and returns the hint string for display in the UI.
- Lock modal now shows a hint input field and a "Protect with master password" checkbox (checkbox is only visible when a master session is active).
- Unlock modal fetches and displays the hint if one was set.
- File count displays `?` for locked vaults (count is inside the ciphertext and unavailable without the password).

### Changed
- Vault header format updated to version 2: fields are now `v`, `salt`, `hint` (optional), `recovery_key` (optional). All metadata previously in the header is moved into the encrypted payload.
- `lock_folder` and `lock_all` commands accept `hint: Option<String>` and `use_master: bool` parameters.
- `ProtectedFolder` struct includes a `hint` field returned after locking and included in folder list responses.

### Fixed
- Modal hint input and master password checkbox now correctly hidden in the unlock dialog (missing per-element `.hidden` CSS rules added).

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
