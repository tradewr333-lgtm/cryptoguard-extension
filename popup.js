// ============================================================
// CryptoGuard — popup.js
// Lógica do popup da extensão
// ============================================================

const RISK_CLASSES = {
  SAFE:     'risk-safe',
  MEDIUM:   'risk-medium',
  HIGH:     'risk-high',
  CRITICAL: 'risk-critical',
};

// ─── Inicializa o popup ──────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  await loadCurrentTabAnalysis();
  await loadStats();
  setupContractChecker();
});

// ─── Analisa a aba atual ─────────────────────────────────────
async function loadCurrentTabAnalysis() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) return;

  const urlEl    = document.getElementById('currentUrl');
  const badgeEl  = document.getElementById('riskBadge');
  const bodyEl   = document.getElementById('siteAnalysis');

  try {
    const hostname = new URL(tab.url).hostname.replace('www.', '');
    urlEl.textContent = hostname || tab.url;
  } catch {
    urlEl.textContent = tab.url;
  }

  // Pede análise para o background
  chrome.runtime.sendMessage({
    action: 'ANALYZE_URL',
    url: tab.url,
  }, (response) => {
    if (!response?.result) {
      bodyEl.innerHTML = renderError();
      return;
    }

    const { result, userStatus } = response;

    // Atualiza badge de risco
    badgeEl.textContent  = result.riskLevel;
    badgeEl.className    = `risk-badge ${RISK_CLASSES[result.riskLevel] || 'risk-safe'}`;

    // Renderiza body
    if (result.riskLevel === 'SAFE') {
      bodyEl.innerHTML = renderSafe();
    } else {
      bodyEl.innerHTML = renderThreats(result.threats);
    }

    // Atualiza stats
    if (userStatus) {
      document.getElementById('scanCount').textContent    = userStatus.scanCount || 0;
      document.getElementById('blockedCount').textContent = userStatus.blockedCount || 0;
    }
  });
}

// ─── Carrega estatísticas ────────────────────────────────────
async function loadStats() {
  chrome.runtime.sendMessage({ action: 'GET_STATUS' }, (response) => {
    if (response?.userStatus) {
      document.getElementById('scanCount').textContent    = response.userStatus.scanCount    || 0;
      document.getElementById('blockedCount').textContent = response.userStatus.blockedCount || 0;
    }
  });
}

// ─── Setup do verificador de contrato ───────────────────────
function setupContractChecker() {
  const input  = document.getElementById('contractInput');
  const btn    = document.getElementById('checkBtn');
  const result = document.getElementById('checkResult');

  btn.addEventListener('click', async () => {
    const address = input.value.trim();
    if (!address || !address.startsWith('0x') || address.length !== 42) {
      result.className    = 'check-result danger visible';
      result.textContent  = '❌ Endereço inválido. Use formato 0x... com 42 caracteres.';
      return;
    }

    btn.textContent  = '...';
    btn.disabled     = true;
    result.className = 'check-result visible';
    result.innerHTML = '<div style="display:flex;gap:8px;align-items:center;"><div style="width:12px;height:12px;border:2px solid rgba(0,255,136,0.3);border-top-color:#00ff88;border-radius:50%;animation:spin 0.8s linear infinite;"></div> Analisando contrato...</div>';

    chrome.runtime.sendMessage({
      action:  'ANALYZE_CONTRACT',
      address: address,
      chainId: '1',
    }, (response) => {
      btn.textContent = 'SCAN';
      btn.disabled    = false;

      if (!response?.result) {
        result.className   = 'check-result danger visible';
        result.textContent = '❌ Erro ao analisar. Tente novamente.';
        return;
      }

      const r = response.result;
      if (r.riskLevel === 'SAFE') {
        result.className   = 'check-result safe visible';
        result.innerHTML   = '✅ <strong>Nenhuma ameaça encontrada</strong> — Contrato parece seguro.';
      } else {
        result.className   = 'check-result danger visible';
        result.innerHTML   = r.threats.map(t =>
          `<div style="margin-bottom:6px;">
            <strong>${t.message}</strong><br>
            <span style="opacity:0.7;font-size:10px;">${t.detail}</span>
          </div>`
        ).join('');
      }
    });
  });

  // Enter key
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') btn.click();
  });
}

// ─── Render helpers ──────────────────────────────────────────
function renderSafe() {
  return `
    <div class="safe-message">
      <span class="safe-icon">🛡️</span>
      <div>
        <div class="safe-text">Site Seguro</div>
        <div class="safe-sub">Nenhuma ameaça detectada</div>
      </div>
    </div>
  `;
}

function renderThreats(threats) {
  return threats.map(t => `
    <div class="threat-item">
      <div class="threat-top">
        <span class="threat-sev sev-${t.severity.toLowerCase()}">${t.severity}</span>
        <span class="threat-msg">${t.message}</span>
      </div>
      <div class="threat-detail">${t.detail}</div>
    </div>
  `).join('');
}

function renderError() {
  return `
    <div class="safe-message">
      <span class="safe-icon">⚠️</span>
      <div>
        <div class="safe-text" style="color:#ffd700">Não foi possível analisar</div>
        <div class="safe-sub">URL interna ou sem suporte</div>
      </div>
    </div>
  `;
}
