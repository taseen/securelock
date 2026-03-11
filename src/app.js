const { invoke } = window.__TAURI__.tauri;
const { open } = window.__TAURI__.dialog;
const { listen } = window.__TAURI__.event;

// DOM elements
const folderListEl = document.getElementById("folder-list");
const emptyStateEl = document.getElementById("empty-state");
const btnAdd = document.getElementById("btn-add");
const btnImport = document.getElementById("btn-import");
const modalOverlay = document.getElementById("modal-overlay");
const modalTitle = document.getElementById("modal-title");
const modalDesc = document.getElementById("modal-desc");
const modalPassword = document.getElementById("modal-password");
const modalConfirm = document.getElementById("modal-confirm");
const modalHint = document.getElementById("modal-hint");
const masterOptionWrap = document.getElementById("master-option-wrap");
const modalUseMaster = document.getElementById("modal-use-master");
const vaultHintDisplay = document.getElementById("vault-hint-display");
const modalError = document.getElementById("modal-error");
const btnCancel = document.getElementById("btn-cancel");
const btnConfirm = document.getElementById("btn-confirm");
const btnTogglePw = document.getElementById("btn-toggle-pw");
const strengthWrap = document.getElementById("strength-wrap");
const strengthFill = document.getElementById("strength-fill");
const strengthLabel = document.getElementById("strength-label");
const setupBanner = document.getElementById("setup-banner");
const btnSetupMaster = document.getElementById("btn-setup-master");
const btnDismissBanner = document.getElementById("btn-dismiss-banner");
const btnSettings = document.getElementById("btn-settings");
const forgotPassword = document.getElementById("forgot-password");
const btnForgot = document.getElementById("btn-forgot");

let currentAction = null; // { type: 'lock'|'unlock'|'lock_all'|'setup_master'|'verify_master'|'recover', path?: string }
let masterPasswordConfigured = false;
let masterSessionUnlocked = false;
let busyPath = null; // path currently being processed (disables buttons)

// ── Load folders on startup ──
async function loadFolders() {
  try {
    const folders = await invoke("get_folders");
    renderFolders(folders);
  } catch (e) {
    console.error("Failed to load folders:", e);
  }
}

// ── Check master password state ──
async function checkMasterState() {
  try {
    masterPasswordConfigured = await invoke("has_master_password");
    masterSessionUnlocked = await invoke("is_master_unlocked");
    updateSettingsIcon();
    if (!masterPasswordConfigured) {
      setupBanner.classList.remove("hidden");
    } else {
      setupBanner.classList.add("hidden");
    }
  } catch (e) {
    console.error("Failed to check master state:", e);
  }
}

function updateSettingsIcon() {
  if (masterPasswordConfigured && masterSessionUnlocked) {
    btnSettings.classList.add("active");
    btnSettings.title = "Master password active";
  } else if (masterPasswordConfigured) {
    btnSettings.classList.remove("active");
    btnSettings.title = "Master password locked — click to unlock";
  } else {
    btnSettings.classList.remove("active");
    btnSettings.title = "Set up master password";
  }
}

// ── Inline action helper (spinner + disable) ──
function setCardBusy(btn, label) {
  busyPath = btn.closest(".folder-card")?.dataset.path || true;
  btn.disabled = true;
  btn.dataset.origLabel = btn.textContent;
  btn.innerHTML = '<span class="spinner"></span> ' + label;
  const card = btn.closest(".folder-card");
  if (card) {
    card.querySelectorAll(".folder-actions .btn").forEach((b) => {
      if (b !== btn) b.disabled = true;
    });
  }
}

function clearCardBusy(btn) {
  busyPath = null;
  if (btn) {
    btn.disabled = false;
    btn.textContent = btn.dataset.origLabel || "Done";
    const card = btn.closest(".folder-card");
    if (card) {
      card.querySelectorAll(".folder-actions .btn").forEach((b) => {
        b.disabled = false;
      });
    }
  }
}

// ── Render folder cards ──
function renderFolders(folders) {
  if (folders.length === 0) {
    emptyStateEl.style.display = "flex";
    folderListEl.style.display = "none";
    return;
  }

  emptyStateEl.style.display = "none";
  folderListEl.style.display = "flex";

  folderListEl.innerHTML = folders
    .map((f) => {
      // Strip .vault extension for display; flag legacy-locked folders
      const rawName = f.path.split(/[\\/]/).pop();
      const isVaultFormat = f.path.endsWith(".vault");
      const isLegacy = f.is_locked && !isVaultFormat;
      const name = isVaultFormat ? rawName.slice(0, -6) : rawName;

      // File count: new-format locked vaults store count in encrypted payload
      const countDisplay = (f.is_locked && isVaultFormat)
        ? "? files"
        : `${f.file_count} file${f.file_count !== 1 ? "s" : ""}`;

      const lockIcon = f.is_locked
        ? `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
             <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
           </svg>`
        : `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
             <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 5-5 5 5 0 0 1 5 5"/>
           </svg>`;

      const recoveryBadge =
        f.is_locked && f.has_recovery
          ? `<span class="recovery-badge" title="Recovery available">
               <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                 <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
               </svg>
             </span>`
          : "";

      const legacyBadge = isLegacy
        ? `<span class="legacy-badge" title="Legacy format — will convert on next lock/unlock">Legacy</span>`
        : "";

      let actionBtns;
      if (f.is_locked) {
        actionBtns = `<button class="btn btn-sm btn-primary" onclick="promptUnlock('${escPath(f.path)}')">Unlock</button>`;
      } else {
        if (f.has_relock) {
          actionBtns = `
            <button class="btn btn-sm btn-accent" onclick="relockFolder(this, '${escPath(f.path)}')">Re-lock</button>
            <button class="btn btn-sm btn-secondary" onclick="promptLock('${escPath(f.path)}')">New Password</button>`;
        } else {
          actionBtns = `<button class="btn btn-sm btn-secondary" onclick="promptLock('${escPath(f.path)}')">Lock</button>`;
        }
      }

      return `
        <div class="folder-card" data-path="${escHtml(f.path)}">
          <div class="folder-icon ${f.is_locked ? "locked" : "unlocked"}">${lockIcon}</div>
          <div class="folder-info">
            <div class="folder-path" title="${escHtml(f.path)}">${escHtml(name)}</div>
            <div class="folder-meta">
              <span class="status-badge ${f.is_locked ? "locked" : "unlocked"}">${f.is_locked ? "Locked" : "Unlocked"}</span>
              ${recoveryBadge}
              ${legacyBadge}
              <span>${countDisplay}</span>
            </div>
          </div>
          <div class="folder-actions">
            ${actionBtns}
            <button class="btn btn-sm btn-danger" onclick="removeFolder('${escPath(f.path)}')">Remove</button>
          </div>
        </div>`;
    })
    .join("");
}

// ── Add folder ──
btnAdd.addEventListener("click", async () => {
  const selected = await open({ directory: true, multiple: false });
  if (!selected) return;
  try {
    await invoke("add_folder", { path: selected });
    await loadFolders();
  } catch (e) {
    alert("Error: " + e);
  }
});

// ── Import existing .vault file ──
btnImport.addEventListener("click", async () => {
  const selected = await open({
    directory: false,
    multiple: false,
    filters: [{ name: "SecureLock Vault", extensions: ["vault"] }],
  });
  if (!selected) return;
  try {
    await invoke("add_folder", { path: selected });
    await loadFolders();
  } catch (e) {
    alert("Error: " + e);
  }
});

// ── Modal helpers ──
function showModal(title, desc, action, showConfirmField) {
  modalTitle.textContent = title;
  modalDesc.textContent = desc;
  modalPassword.value = "";
  modalConfirm.value = "";
  modalHint.value = "";
  modalUseMaster.checked = false;
  modalError.classList.add("hidden");
  modalError.textContent = "";
  forgotPassword.classList.add("hidden");
  vaultHintDisplay.classList.add("hidden");
  vaultHintDisplay.textContent = "";
  currentAction = action;

  if (showConfirmField) {
    modalConfirm.classList.remove("hidden");
    strengthWrap.classList.remove("hidden");
    updateStrength("");
  } else {
    modalConfirm.classList.add("hidden");
    strengthWrap.classList.add("hidden");
  }

  // Show hint input and master checkbox only for lock actions
  const isLockAction = action.type === "lock" || action.type === "lock_all";
  if (isLockAction) {
    modalHint.classList.remove("hidden");
    if (masterSessionUnlocked) {
      masterOptionWrap.classList.remove("hidden");
    } else {
      masterOptionWrap.classList.add("hidden");
    }
  } else {
    modalHint.classList.add("hidden");
    masterOptionWrap.classList.add("hidden");
  }

  modalOverlay.classList.remove("hidden");
  setTimeout(() => modalPassword.focus(), 50);
}

function hideModal() {
  modalOverlay.classList.add("hidden");
  currentAction = null;
  modalPassword.value = "";
  modalConfirm.value = "";
  modalHint.value = "";
  modalHint.classList.add("hidden");
  modalUseMaster.checked = false;
  masterOptionWrap.classList.add("hidden");
  forgotPassword.classList.add("hidden");
  vaultHintDisplay.classList.add("hidden");
}

// ── Lock / Unlock prompts ──
window.promptLock = function (path) {
  showModal(
    "Lock Folder",
    "Enter a password to encrypt this folder into a secure .vault container. The original folder will be removed.",
    { type: "lock", path },
    true
  );
};

window.promptUnlock = async function (path) {
  showModal(
    "Unlock Vault",
    "Enter your password to decrypt and restore the folder.",
    { type: "unlock", path },
    false
  );

  // Load hint and recovery availability in parallel
  try {
    const [hint, hasRecovery] = await Promise.all([
      invoke("get_vault_hint", { path }).catch(() => null),
      invoke("check_recovery_key", { path }).catch(() => false),
    ]);
    if (hint) {
      vaultHintDisplay.textContent = "Hint: " + hint;
      vaultHintDisplay.classList.remove("hidden");
    }
    if (hasRecovery && masterPasswordConfigured) {
      forgotPassword.classList.remove("hidden");
    }
  } catch (e) {
    // Ignore — UI degrades gracefully
  }
};

window.relockFolder = async function (btn, path) {
  if (busyPath) return;
  setCardBusy(btn, "Locking...");
  try {
    await invoke("relock_folder", { path });
    busyPath = null;
    await loadFolders();
  } catch (e) {
    clearCardBusy(btn);
    alert("Re-lock failed: " + e);
  }
};

window.removeFolder = async function (path) {
  try {
    await invoke("remove_folder", { path });
    await loadFolders();
  } catch (e) {
    alert("Error: " + e);
  }
};

// ── Forgot password ──
btnForgot.addEventListener("click", (e) => {
  e.preventDefault();
  if (!currentAction || !currentAction.path) return;
  const path = currentAction.path;

  if (masterSessionUnlocked) {
    doRecover(path);
  } else {
    showModal(
      "Master Password",
      "Enter your master password to recover this vault.",
      { type: "recover", path },
      false
    );
  }
});

async function doRecover(path) {
  btnConfirm.disabled = true;
  btnConfirm.innerHTML = '<span class="spinner"></span> Recovering...';
  try {
    await invoke("recover_folder", { path });
    hideModal();
    await loadFolders();
  } catch (e) {
    showError(e);
  } finally {
    btnConfirm.disabled = false;
    btnConfirm.textContent = "Confirm";
  }
}

// ── Settings button ──
btnSettings.addEventListener("click", () => {
  if (!masterPasswordConfigured) {
    showModal(
      "Set Up Master Password",
      "This password can recover any vault locked while it's active. Choose a strong, memorable password.",
      { type: "setup_master" },
      true
    );
  } else if (!masterSessionUnlocked) {
    showModal(
      "Unlock Master Password",
      "Enter your master password to enable recovery for this session.",
      { type: "verify_master" },
      false
    );
  } else {
    showModal(
      "Unlock Master Password",
      "Master password is already active for this session. Re-enter to verify.",
      { type: "verify_master" },
      false
    );
  }
});

// ── Setup banner ──
btnSetupMaster.addEventListener("click", () => {
  setupBanner.classList.add("hidden");
  showModal(
    "Set Up Master Password",
    "This password can recover any vault locked while it's active. Choose a strong, memorable password.",
    { type: "setup_master" },
    true
  );
});

btnDismissBanner.addEventListener("click", () => {
  setupBanner.classList.add("hidden");
});

// ── Confirm action ──
btnConfirm.addEventListener("click", async () => {
  if (!currentAction) return;

  const password = modalPassword.value;

  if (!password) {
    showError("Please enter a password");
    return;
  }

  if (
    currentAction.type === "lock" ||
    currentAction.type === "lock_all" ||
    currentAction.type === "setup_master"
  ) {
    if (password.length < 4) {
      showError("Password must be at least 4 characters");
      return;
    }
    if (modalConfirm.value !== password) {
      showError("Passwords do not match");
      return;
    }
  }

  btnConfirm.disabled = true;
  btnConfirm.innerHTML = '<span class="spinner"></span> Working...';

  try {
    if (currentAction.type === "lock") {
      const hint = modalHint.value.trim() || null;
      const useMaster = masterSessionUnlocked && modalUseMaster.checked;
      await invoke("lock_folder", { path: currentAction.path, password, hint, useMaster });
    } else if (currentAction.type === "unlock") {
      await invoke("unlock_folder", { path: currentAction.path, password });
    } else if (currentAction.type === "lock_all") {
      const hint = modalHint.value.trim() || null;
      const useMaster = masterSessionUnlocked && modalUseMaster.checked;
      await invoke("lock_all", { password, hint, useMaster });
    } else if (currentAction.type === "setup_master") {
      await invoke("setup_master_password", { password });
      masterPasswordConfigured = true;
      masterSessionUnlocked = true;
      updateSettingsIcon();
    } else if (currentAction.type === "verify_master") {
      await invoke("verify_master_password", { password });
      masterSessionUnlocked = true;
      updateSettingsIcon();
    } else if (currentAction.type === "recover") {
      await invoke("verify_master_password", { password });
      masterSessionUnlocked = true;
      updateSettingsIcon();
      await invoke("recover_folder", { path: currentAction.path });
    }

    hideModal();
    await loadFolders();
  } catch (e) {
    showError(e);
  } finally {
    btnConfirm.disabled = false;
    btnConfirm.textContent = "Confirm";
  }
});

btnCancel.addEventListener("click", hideModal);

modalOverlay.addEventListener("click", (e) => {
  if (e.target === modalOverlay) hideModal();
});

modalPassword.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    if (!modalConfirm.classList.contains("hidden")) {
      modalConfirm.focus();
    } else {
      btnConfirm.click();
    }
  }
});

modalConfirm.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    if (!modalHint.classList.contains("hidden")) {
      modalHint.focus();
    } else {
      btnConfirm.click();
    }
  }
});

modalHint.addEventListener("keydown", (e) => {
  if (e.key === "Enter") btnConfirm.click();
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") hideModal();
});

btnTogglePw.addEventListener("click", () => {
  const isPassword = modalPassword.type === "password";
  modalPassword.type = isPassword ? "text" : "password";
  modalConfirm.type = isPassword ? "text" : "password";
});

// ── Password strength meter ──
modalPassword.addEventListener("input", () => {
  if (!strengthWrap.classList.contains("hidden")) {
    updateStrength(modalPassword.value);
  }
});

function updateStrength(pw) {
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
  if (/\d/.test(pw)) score++;
  if (/[^a-zA-Z0-9]/.test(pw)) score++;

  const levels = [
    { label: "", color: "var(--border)", width: "0%" },
    { label: "Weak", color: "var(--danger)", width: "20%" },
    { label: "Fair", color: "var(--warning)", width: "40%" },
    { label: "Good", color: "var(--warning)", width: "60%" },
    { label: "Strong", color: "var(--success)", width: "80%" },
    { label: "Excellent", color: "var(--success)", width: "100%" },
  ];

  const level = levels[score];
  strengthFill.style.width = level.width;
  strengthFill.style.background = level.color;
  strengthLabel.textContent = level.label;
  strengthLabel.style.color = level.color;
}

function showError(msg) {
  modalError.textContent = msg;
  modalError.classList.remove("hidden");
}

// ── Tray "Lock All" event ──
listen("tray-lock-all", () => {
  showModal(
    "Lock All Folders",
    "Enter a password to lock all unlocked folders into .vault containers.",
    { type: "lock_all" },
    true
  );
});

// ── Helpers ──
function escHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function escPath(str) {
  return str.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

// ── Init ──
checkMasterState();
loadFolders();
