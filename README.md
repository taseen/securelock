# SecureLock

A lightweight desktop app for encrypting and locking folders with AES-256-GCM encryption. Built with [Tauri](https://tauri.app/) (Rust backend, HTML/CSS/JS frontend).

## Features

- **Vault encryption** — Lock any folder into a single encrypted `.vault` file using AES-256-GCM with Argon2id key derivation. All contents are packed into one portable container.
- **Import .vault files** — Open an existing `.vault` file directly from the UI without re-adding it.
- **Master password recovery** — Optionally set a master password that can recover any folder locked while it was active. If you forget a folder's password, the master password can decrypt it.
- **System tray** — Minimizes to tray. Lock all folders at once from the tray menu.
- **Password strength meter** — Visual feedback when choosing passwords.
- **Single instance** — Only one instance of the app can run at a time. Launching again focuses the existing window.
- **Legacy support** — Folders locked with v1.x (`.securelock` format) are still unlockable.

## How It Works

1. **Locking:** Derives an AES-256 key from your password using Argon2id. All folder contents are packed into a single `.vault` file and encrypted with AES-256-GCM. The original folder is removed.
2. **Unlocking:** Re-derives the key from your password, verifies it against a stored token in the vault header, decrypts the payload, and reconstructs the original folder.
3. **Master password (optional):** When configured, the folder's AES key is wrapped with the master key and stored in the vault header. Recovery unwraps the folder key using the master password without needing the original folder password.

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

- **AES-256-GCM** for authenticated encryption
- **Argon2id** for password-based key derivation (64 MB memory, 3 iterations)
- Random 32-byte salts and 12-byte nonces per encryption operation
- Master key is only held in memory for the current session — never written to disk
- Keys are zeroized from memory when no longer needed

## License

MIT
