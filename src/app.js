const { invoke } = window.__TAURI__.tauri;
const { open } = window.__TAURI__.dialog;
const { listen } = window.__TAURI__.event;

// DOM elements
const folderListEl = document.getElementById("folder-list");
const emptyStateEl = document.getElementById("empty-state");
const btnAdd = document.getElementById("btn-add");
const modalOverlay = document.getElementById("modal-overlay");
const modalTitle = document.getElementById("modal-title");
const modalDesc = document.getElementById("modal-desc");
const modalPassword = document.getElementById("modal-password");
const modalConfirm = document.getElementById("modal-confirm");
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
      const name = f.path.split(/[\\/]/).pop();
      const lockIcon = f.is_locked
        ? `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
             <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
           </svg>`
        : `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
             <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 5-5 5 5 0 0 1 5 5"/>
           </svg>`;

      const recoveryBadge = f.is_locked && f.has_recovery
        ? `<span class="recovery-badge" title="Recovery available">
             <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
               <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
             </svg>
           </span>`
        : "";

      const actionBtn = f.is_locked
        ? `<button class="btn btn-sm btn-primary" onclick="promptUnlock('${escPath(f.path)}')">Unlock</button>`
        : `<button class="btn btn-sm btn-secondary" onclick="promptLock('${escPath(f.path)}')">Lock</button>`;

      return `
        <div class="folder-card">
          <div class="folder-icon ${f.is_locked ? "locked" : "unlocked"}">${lockIcon}</div>
          <div class="folder-info">
            <div class="folder-path" title="${escHtml(f.path)}">${escHtml(name)}</div>
            <div class="folder-meta">
              <span class="status-badge ${f.is_locked ? "locked" : "unlocked"}">${f.is_locked ? "Locked" : "Unlocked"}</span>
              ${recoveryBadge}
              <span>${f.file_count} file${f.file_count !== 1 ? "s" : ""}</span>
            </div>
          </div>
          <div class="folder-actions">
            ${actionBtn}
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

// ── Modal helpers ──
function showModal(title, desc, action, showConfirmField) {
  modalTitle.textContent = title;
  modalDesc.textContent = desc;
  modalPassword.value = "";
  modalConfirm.value = "";
  modalError.classList.add("hidden");
  modalError.textContent = "";
  forgotPassword.classList.add("hidden");
  currentAction = action;

  if (showConfirmField) {
    modalConfirm.classList.remove("hidden");
    strengthWrap.classList.remove("hidden");
    updateStrength("");
  } else {
    modalConfirm.classList.add("hidden");
    strengthWrap.classList.add("hidden");
  }

  modalOverlay.classList.remove("hidden");
  setTimeout(() => modalPassword.focus(), 50);
}

function hideModal() {
  modalOverlay.classList.add("hidden");
  currentAction = null;
  modalPassword.value = "";
  modalConfirm.value = "";
  forgotPassword.classList.add("hidden");
}

// ── Lock / Unlock prompts ──
window.promptLock = function (path) {
  showModal(
    "Lock Folder",
    "Enter a password to encrypt all files in this folder.",
    { type: "lock", path },
    true
  );
};

window.promptUnlock = async function (path) {
  showModal(
    "Unlock Folder",
    "Enter your password to decrypt files.",
    { type: "unlock", path },
    false
  );
  // Check if recovery is available for this folder
  try {
    const hasRecovery = await invoke("check_recovery_key", { path });
    if (hasRecovery && masterPasswordConfigured) {
      forgotPassword.classList.remove("hidden");
    }
  } catch (e) {
    // Ignore — just don't show the link
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
    // Already unlocked — go straight to recovery
    doRecover(path);
  } else {
    // Need to verify master password first
    showModal(
      "Master Password",
      "Enter your master password to recover this folder.",
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
      "This password can recover any folder locked while it's active. Choose a strong, memorable password.",
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
    "This password can recover any folder locked while it's active. Choose a strong, memorable password.",
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

  // Validation for actions requiring confirmation
  if (currentAction.type === "lock" || currentAction.type === "lock_all" || currentAction.type === "setup_master") {
    if (password.length < 4) {
      showError("Password must be at least 4 characters");
      return;
    }
    if (modalConfirm.value !== password) {
      showError("Passwords do not match");
      return;
    }
  }

  // Show loading state
  btnConfirm.disabled = true;
  btnConfirm.innerHTML = '<span class="spinner"></span> Working...';

  try {
    if (currentAction.type === "lock") {
      await invoke("lock_folder", { path: currentAction.path, password });
    } else if (currentAction.type === "unlock") {
      await invoke("unlock_folder", { path: currentAction.path, password });
    } else if (currentAction.type === "lock_all") {
      await invoke("lock_all", { password });
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

// Enter key to confirm
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
  if (e.key === "Enter") btnConfirm.click();
});

// Escape to close
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") hideModal();
});

// Toggle password visibility
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
    "Enter a password to lock all unlocked folders.",
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
