// popup.js

// Helpers: base64 <-> ArrayBuffer
const bufToBase64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const base64ToBuf = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0));

// Settings for key derivation & encryption
const PBKDF2_ITER = 150000; // iterations
const KEY_LENGTH = 256; // bits

let sessionKey = null; // in-memory only
let saltStored = null; // Uint8Array

// DOM
const masterInput = document.getElementById('master-input');
const unlockBtn = document.getElementById('unlock-btn');
const lockBtn = document.getElementById('lock-btn');
const vault = document.getElementById('vault');
const lockedSection = document.getElementById('locked-section');
const status = document.getElementById('status');
const addForm = document.getElementById('add-form');
const listEl = document.getElementById('list');

// Load stored salt
chrome.storage.local.get(['_vault_salt', '_vault_entries'], (res) => {
  if (res._vault_salt) {
    saltStored = base64ToBuf(res._vault_salt);
  }
  if (!res._vault_entries) {
    chrome.storage.local.set({_vault_entries: {}});
  }
});

async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const passKey = await window.crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  const key = await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: PBKDF2_ITER,
      hash: 'SHA-256'
    },
    passKey,
    { name: 'AES-GCM', length: KEY_LENGTH },
    false,
    ['encrypt','decrypt']
  );
  return key;
}

async function encryptData(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const cipher = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, enc.encode(plaintext));
  return {cipher: bufToBase64(cipher), iv: bufToBase64(iv)};
}

async function decryptData(key, cipherB64, ivB64) {
  const cipherBuf = base64ToBuf(cipherB64);
  const iv = base64ToBuf(ivB64);
  const plainBuf = await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, cipherBuf);
  const dec = new TextDecoder();
  return dec.decode(plainBuf);
}

function showStatus(msg, short = true) {
  status.textContent = msg;
  if (short) setTimeout(()=> status.textContent = '', 3000);
}

function showVault() {
  lockedSection.classList.add('hidden');
  vault.classList.remove('hidden');
  renderList();
}

function hideVault() {
  vault.classList.add('hidden');
  lockedSection.classList.remove('hidden');
  masterInput.value = '';
  sessionKey = null;
}

// Unlock flow
unlockBtn.addEventListener('click', async () => {
  const pwd = masterInput.value;
  if (!pwd) { showStatus('Enter master password', true); return; }

  if (!saltStored) {
    saltStored = crypto.getRandomValues(new Uint8Array(16));
    chrome.storage.local.set({'_vault_salt': bufToBase64(saltStored)});
  }

  sessionKey = await deriveKey(pwd, saltStored);
  chrome.storage.local.get(['_vault_entries'], async (res) => {
    const entries = res._vault_entries || {};
    const ids = Object.keys(entries);
    if (ids.length === 0) {
      showStatus('Unlocked (empty vault)');
      showVault();
      return;
    }
    try {
      await decryptData(sessionKey, entries[ids[0]].cipher, entries[ids[0]].iv);
      showStatus('Unlocked');
      showVault();
    } catch {
      sessionKey = null;
      showStatus('Wrong master password', true);
    }
  });
});

lockBtn?.addEventListener('click', () => {
  
let autoLockTimer;
function resetAutoLockTimer() {
  if (autoLockTimer) clearTimeout(autoLockTimer);
  autoLockTimer = setTimeout(() => {
    hideVault();
    showStatus('Auto-locked after inactivity');
  }, 2 * 60 * 1000);
}

// reset timer on any click or keypress
document.addEventListener('click', resetAutoLockTimer);
document.addEventListener('keypress', resetAutoLockTimer);


hideVault();
  showStatus('Locked');
});

// Add credential
addForm.addEventListener('submit', async (ev) => {
  ev.preventDefault();
  if (!sessionKey) { showStatus('Unlock first', true); return; }
  const site = document.getElementById('site').value.trim();
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;
  if (!site || !username || !password) { showStatus('Fill all fields', true); return; }

  const toStore = JSON.stringify({site,username,password});
  const enc = await encryptData(sessionKey, toStore);
  const id = Date.now().toString();

  chrome.storage.local.get(['_vault_entries'], (res) => {
    const entries = res._vault_entries || {};
    entries[id] = {label: site, username, cipher: enc.cipher, iv: enc.iv};
    chrome.storage.local.set({'_vault_entries': entries}, () => {
      document.getElementById('site').value = '';
      document.getElementById('username').value = '';
      document.getElementById('password').value = '';
      renderList();
      showStatus('Saved');
    });
  });
});

// Render list
function renderList() {
  listEl.innerHTML = '';
  chrome.storage.local.get(['_vault_entries'], (res) => {
    const entries = res._vault_entries || {};
    const ids = Object.keys(entries).sort((a,b)=>b-a);
    if (ids.length === 0) {
      listEl.innerHTML = '<li class="muted">No entries</li>';
      return;
    }

    for (const id of ids) {
      const e = entries[id];
      const li = document.createElement('li');
      li.className = 'list-item';
      li.innerHTML = `<strong>${e.label}</strong> <div>${e.username}</div>`;

      const showBtn = document.createElement('button');
      showBtn.textContent = 'Show';
      showBtn.addEventListener('click', async () => {
        if (!sessionKey) { showStatus('Unlock first', true); return; }
        const dec = await decryptData(sessionKey, e.cipher, e.iv);
        const obj = JSON.parse(dec);
        const reveal = document.createElement('div');
        reveal.textContent = 'Password: ' + obj.password;
        const copyBtn = document.createElement('button');
        copyBtn.textContent = 'Copy';
        copyBtn.addEventListener('click', () => {
          navigator.clipboard.writeText(obj.password);
          showStatus('Copied to clipboard');
        });
        li.appendChild(reveal);
        li.appendChild(copyBtn);
        showBtn.disabled = true;
      });

      const delBtn = document.createElement('button');
      delBtn.textContent = 'Delete';
      delBtn.addEventListener('click', () => {
        chrome.storage.local.get(['_vault_entries'], (res2) => {
          const entries2 = res2._vault_entries || {};
          delete entries2[id];
          chrome.storage.local.set({'_vault_entries': entries2}, () => {
            renderList();
            showStatus('Deleted');
          });
        });
      });

      li.appendChild(showBtn);
      li.appendChild(delBtn);
      listEl.appendChild(li);
    }
  });
}


let autoLockTimer;
function resetAutoLockTimer() {
  if (autoLockTimer) clearTimeout(autoLockTimer);
  autoLockTimer = setTimeout(() => {
    hideVault();
    showStatus('Auto-locked after inactivity');
  }, 2 * 60 * 1000);
}

// reset timer on any click or keypress
document.addEventListener('click', resetAutoLockTimer);
document.addEventListener('keypress', resetAutoLockTimer);


hideVault();