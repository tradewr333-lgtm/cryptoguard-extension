// ============================================================
// SHIELD CryptoGuard — popup.js (v2.0)
// Login, PRO verification, and UI logic
// ============================================================

const STRIPE_PAYMENT_LINK = 'https://buy.stripe.com/8x25kEcqicQg3bmdBY7N601';

const RISK_CLASSES = {
  SAFE: 'risk-safe',
  MEDIUM: 'risk-medium',
  HIGH: 'risk-high',
  CRITICAL: 'risk-critical',
};

// ─── Init ────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  await loadUserState();
  await loadCurrentTabAnalysis();
  setupContractChecker();
  setupLogin();
  setupUpgrade();
});

// ─── Load user state and update UI ───────────────────────────
async function loadUserState() {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ action: 'GET_STATUS' }, (response) => {
      if (response?.userStatus) {
        updatePlanUI(response.userStatus);
      }
      resolve();
    });
  });
}

function updatePlanUI(status) {
  const planBadge = document.getElementById('planBadge');
  const planEmail = document.getElementById('planEmail');
  const loginSection = document.getElementById('loginSection');
  const upgradeBtn = document.getElementById('upgradeBtn');
  const manageBtn = document.getElementById('manageBtn');
  const footerText = document.getElementById('footerText');

  if (status.email) {
    // Logged in
    loginSection.classList.add('hidden');
    planEmail.textContent = status.email;

    if (status.isSubscribed || status.plan === 'pro') {
      // PRO user
      planBadge.textContent = '⚡ PRO';
      planBadge.className = 'plan-badge plan-pro';
      upgradeBtn.classList.add('hidden');
      manageBtn.classList.remove('hidden');
      footerText.textContent = 'v1.0.1 — PRO PROTECTION ACTIVE';
    } else {
      // Free user (logged in but not subscribed)
      planBadge.textContent = 'FREE';
      planBadge.className = 'plan-badge plan-free';
      upgradeBtn.classList.remove('hidden');
      manageBtn.classList.add('hidden');
      footerText.textContent = 'v1.0.1 — BASIC PROTECTION';
    }
  } else {
    // Not logged in
    loginSection.classList.remove('hidden');
    planBadge.textContent = 'FREE';
    planBadge.className = 'plan-badge plan-free';
    planEmail.textContent = '';
    upgradeBtn.classList.remove('hidden');
    manageBtn.classList.add('hidden');
    footerText.textContent = 'v1.0.1 — BASIC PROTECTION';
  }

  // Update stats
  document.getElementById('scanCount').textContent = status.scanCount || 0;
  document.getElementById('blockedCount').textContent = status.blockedCount || 0;
}

// ─── Login ───────────────────────────────────────────────────
function setupLogin() {
  const loginBtn = document.getElementById('loginBtn');
  const loginInput = document.getElementById('loginEmail');
  const loginError = document.getElementById('loginError');

  loginBtn.addEventListener('click', () => doLogin());
  loginInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') doLogin();
  });

  function doLogin() {
    const email = loginInput.value.trim();
    if (!email || !email.includes('@')) {
      loginError.textContent = '❌ Please enter a valid email address.';
      loginError.style.display = 'block';
      return;
    }

    loginBtn.textContent = '...';
    loginBtn.disabled = true;
    loginError.style.display = 'none';

    chrome.runtime.sendMessage({ action: 'LOGIN', email }, (response) => {
      loginBtn.textContent = 'LOGIN';
      loginBtn.disabled = false;

      if (response?.success) {
        updatePlanUI(response.userStatus);
      } else {
        loginError.textContent = response?.error || '❌ Login failed. Try again.';
        loginError.style.display = 'block';
      }
    });
  }
}

// ─── Upgrade / Manage ────────────────────────────────────────
function setupUpgrade() {
  document.getElementById('upgradeBtn').addEventListener('click', () => {
    // Open Stripe Payment Link directly
    chrome.tabs.create({ url: STRIPE_PAYMENT_LINK });
  });

  document.getElementById('manageBtn').addEventListener('click', () => {
    // For now, open Stripe customer portal via the site
    chrome.tabs.create({ url: 'https://cryptoguard.site' });
  });
}

// ─── Current Tab Analysis ────────────────────────────────────
async function loadCurrentTabAnalysis() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) return;

  const urlEl = document.getElementById('currentUrl');
  const badgeEl = document.getElementById('riskBadge');
  const bodyEl = document.getElementById('siteAnalysis');

  try {
    const hostname = new URL(tab.url).hostname.replace('www.', '');
    urlEl.textContent = hostname || tab.url;
  } catch {
    urlEl.textContent = tab.url;
  }

  chrome.runtime.sendMessage({ action: 'ANALYZE_URL', url: tab.url }, (response) => {
    if (!response?.result) {
      bodyEl.innerHTML = renderError();
      return;
    }

    const { result, userStatus } = response;

    badgeEl.textContent = result.riskLevel;
    badgeEl.className = `risk-badge ${RISK_CLASSES[result.riskLevel] || 'risk-safe'}`;

    if (result.riskLevel === 'SAFE') {
      bodyEl.innerHTML = renderSafe();
    } else {
      bodyEl.innerHTML = renderThreats(result.threats);
    }

    if (userStatus) {
      document.getElementById('scanCount').textContent = userStatus.scanCount || 0;
      document.getElementById('blockedCount').textContent = userStatus.blockedCount || 0;
    }
  });
}

// ─── Contract Checker ────────────────────────────────────────
function setupContractChecker() {
  const input = document.getElementById('contractInput');
  const btn = document.getElementById('checkBtn');
  const result = document.getElementById('checkResult');

  btn.addEventListener('click', () => doCheck());
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') doCheck();
  });

  function doCheck() {
    const address = input.value.trim();
    if (!address || !address.startsWith('0x') || address.length !== 42) {
      result.className = 'check-result danger visible';
      result.textContent = '❌ Invalid address. Use 0x... format with 42 characters.';
      return;
    }

    btn.textContent = '...';
    btn.disabled = true;
    result.className = 'check-result visible';
    result.innerHTML = '<div style="display:flex;gap:8px;align-items:center;color:rgba(255,255,255,0.4)"><div class="spinner"></div> Scanning contract...</div>';

    chrome.runtime.sendMessage({
      action: 'ANALYZE_CONTRACT',
      address: address,
      chainId: '1',
    }, (response) => {
      btn.textContent = 'SCAN';
      btn.disabled = false;

      if (!response?.result) {
        result.className = 'check-result danger visible';
        result.textContent = '❌ Analysis error. Try again.';
        return;
      }

      const r = response.result;

      // Check if PRO required message
      const proRequired = r.threats.find(t => t.type === 'PRO_REQUIRED');
      if (proRequired) {
        result.className = 'check-result info visible';
        result.innerHTML = `
          <div style="margin-bottom:6px;">
            <strong>${proRequired.message}</strong><br>
            <span style="opacity:0.7;font-size:10px;">${proRequired.detail}</span>
          </div>
          <button onclick="document.getElementById('upgradeBtn').click()" style="
            background:#00ff88; color:#000; border:none; border-radius:4px;
            padding:5px 12px; font-size:10px; font-weight:800; cursor:pointer;
            margin-top:4px;
          ">⚡ UPGRADE TO PRO</button>
        `;
        return;
      }

      if (r.riskLevel === 'SAFE') {
        result.className = 'check-result safe visible';
        result.innerHTML = '✅ <strong>No threats found</strong> — Contract appears safe.';
      } else {
        result.className = 'check-result danger visible';
        result.innerHTML = r.threats.map(t =>
          `<div style="margin-bottom:6px;">
            <strong>${t.message}</strong><br>
            <span style="opacity:0.7;font-size:10px;">${t.detail}</span>
          </div>`
        ).join('');
      }
    });
  }
}

// ─── Render helpers ──────────────────────────────────────────
function renderSafe() {
  return `<div class="safe-message">
    <span class="safe-icon">🛡️</span>
    <div>
      <div class="safe-text">Site is Safe</div>
      <div class="safe-sub">No threats detected</div>
    </div>
  </div>`;
}

function renderThreats(threats) {
  return threats.map(t => `
    <div class="threat-item">
      <div class="threat-top">
        <span class="threat-sev sev-${(t.severity || 'medium').toLowerCase()}">${t.severity}</span>
        <span class="threat-msg">${t.message}</span>
      </div>
      <div class="threat-detail">${t.detail}</div>
    </div>
  `).join('');
}

function renderError() {
  return `<div class="safe-message">
    <span class="safe-icon">⚠️</span>
    <div>
      <div class="safe-text" style="color:#ffd700">Cannot analyze</div>
      <div class="safe-sub">Internal or unsupported URL</div>
    </div>
  </div>`;
}
