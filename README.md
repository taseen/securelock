# SecureLock

A lightweight desktop app for encrypting and locking folders with AES-256-GCM encryption. Built with [Tauri](https://tauri.app/) (Rust backend, HTML/CSS/JS frontend).

## Features

- **Vault encryption** — Lock any folder into a single encrypted `.vault` file using AES-256-GCM with Argon2id key derivation. All contents are packed into one portable container.
- **Import .vault files** — Open an existing `.vault` file directly from the UI without re-adding it.
- **Master password recovery** — Optionally set a master password. When locking a folder, enable recovery with a checkbox — the folder key is then wrapped with the master key and stored in the vault. If you forget a folder's password, the master password can decrypt it.
- **Password hint** — Optionally attach a plaintext hint when locking. The hint is shown above the password field when unlocking so you can remind yourself without compromising security.
- **System tray** — Minimizes to tray. Lock all folders at once from the tray menu.
- **Password strength meter** — Visual feedback when choosing passwords.
- **Single instance** — Only one instance of the app can run at a time. Launching again focuses the existing window.
- **Legacy support** — Folders locked with v1.x (`.securelock` format) are still unlockable.

## How It Works

1. **Locking:** Derives an AES-256 key from your password using Argon2id. All folder contents — plus encrypted metadata (name, file count, size) — are packed into a single `.vault` file and encrypted with AES-256-GCM. The original folder is removed. Only the salt, an optional hint, and an optional recovery key live in the unencrypted header.
2. **Unlocking:** Re-derives the key from your password and decrypts the payload. A wrong password is detected by the AES-GCM authentication tag failing — there is no known-plaintext token in the header. The original folder is reconstructed atomically via a temp directory.
3. **Master password (optional, per-lock):** When enabled for a specific lock operation, the folder's AES key is wrapped with the master key and stored in the vault header. Recovery unwraps the folder key using the master password without needing the original folder password.

## Prerequisites

- [Node.js](https://nodejs.org/) (v16+)
- [Rust](https://www.rust-lang.org/tools/install) (stable toolchain)
- Platform-specific dependencies for Tauri:
  - **Windows:** Visual Studio Build Tools with "Desktop development with C++" workload
  - **macOS:** Xcode Command Line Tools
  - **Linux:** `build-essential`, `libwebkit2gtk-4.0-dev`, `libssl-dev`, `libgtk-3-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`

## Getting Started

```bash
# Clone the repo
git clone https://github.com/Taseen/securelock.git
cd securelock

# Install dependencies
npm install

# Run in development mode
npm run dev

# Build for production
npm run build
```

The production binary will be in `src-tauri/target/release/`.

## Project Structure

```
securelock/
├── src/                    # Frontend (HTML/CSS/JS)
│   ├── index.html
│   ├── app.js
│   └── styles.css
├── src-tauri/              # Rust backend
│   └── src/
│       ├── main.rs         # App entry point, tray, window management
│       ├── commands.rs     # Tauri commands, app state, config persistence
│       ├── crypto.rs       # AES-256-GCM encryption, Argon2id key derivation
│       └── folder.rs       # Lock/unlock/recover folder operations
├── package.json
└── README.md
```

## Security

- **AES-256-GCM** for authenticated encryption — the auth tag detects wrong passwords and tampering with no separate verify token
- **Argon2id** for password-based key derivation (64 MB memory, 3 iterations)
- Random 32-byte salts and 12-byte nonces per encryption operation
- **No plaintext metadata leakage** — folder name, file count, and size are inside the ciphertext
- **No known-plaintext oracle** — there is no verify token in the vault header; brute-force must attack the full AES-GCM ciphertext
- Master key is only held in memory for the current session — never written to disk
- Keys are zeroized from memory when no longer needed
- Recovery key is opt-in per lock — vaults without it cannot be recovered via master password

## License

MIT
