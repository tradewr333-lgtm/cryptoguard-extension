// ============================================================
// CryptoGuard — content.js
// Injetado em todas as páginas
// Intercepta conexões MetaMask e mostra avisos visuais
// ============================================================

// ─── Overlay de aviso ────────────────────────────────────────
function createWarningOverlay(result, url) {
  const existing = document.getElementById('cryptoguard-overlay');
  if (existing) existing.remove();

  const isCritical = result.riskLevel === 'CRITICAL';
  const bgColor    = isCritical ? '#1a0000' : '#1a0a00';
  const borderColor= isCritical ? '#ff3366' : '#ff6b35';
  const badgeColor = isCritical ? '#ff3366' : '#ff6b35';

  const overlay = document.createElement('div');
  overlay.id = 'cryptoguard-overlay';
  overlay.style.cssText = `
    position: fixed;
    top: 0; left: 0; right: 0;
    z-index: 2147483647;
    background: ${bgColor};
    border-bottom: 3px solid ${borderColor};
    padding: 0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    box-shadow: 0 4px 40px rgba(255,51,102,0.4);
    animation: slideDown 0.3s ease;
  `;

  const threatsHTML = result.threats.map(t => `
    <div style="
      background: rgba(255,255,255,0.05);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 6px;
      padding: 10px 14px;
      margin-bottom: 8px;
    ">
      <div style="display:flex; align-items:center; gap:8px; margin-bottom:4px;">
        <span style="
          background: ${t.severity === 'CRITICAL' ? '#ff3366' : t.severity === 'HIGH' ? '#ff6b35' : '#ffd700'};
          color: #000;
          font-size: 10px;
          font-weight: 800;
          padding: 2px 8px;
          border-radius: 3px;
          letter-spacing: 1px;
        ">${t.severity}</span>
        <span style="color: #fff; font-size: 13px; font-weight: 600;">${t.message}</span>
      </div>
      <p style="color: rgba(255,255,255,0.6); font-size: 12px; margin: 0;">${t.detail}</p>
    </div>
  `).join('');

  overlay.innerHTML = `
    <style>
      @keyframes slideDown {
        from { transform: translateY(-100%); }
        to   { transform: translateY(0); }
      }
      #cryptoguard-overlay button:hover { opacity: 0.85 !important; }
    </style>
    <div style="max-width: 900px; margin: 0 auto; padding: 20px 24px;">
      <div style="display:flex; align-items:flex-start; gap:16px;">
        <div style="flex-shrink:0; margin-top:2px;">
          <svg width="36" height="36" viewBox="0 0 36 36" fill="none">
            <path d="M18 2L3 9v9c0 9 6.6 17.4 15 19.5C25.4 35.4 33 27 33 18V9L18 2z" fill="${borderColor}" opacity="0.2"/>
            <path d="M18 2L3 9v9c0 9 6.6 17.4 15 19.5C25.4 35.4 33 27 33 18V9L18 2z" stroke="${borderColor}" stroke-width="2" fill="none"/>
            <text x="18" y="24" text-anchor="middle" fill="${borderColor}" font-size="16" font-weight="bold">!</text>
          </svg>
        </div>
        <div style="flex:1;">
          <div style="display:flex; align-items:center; gap:10px; margin-bottom:4px;">
            <span style="
              background: ${badgeColor};
              color: #fff;
              font-size: 11px;
              font-weight: 800;
              padding: 3px 10px;
              border-radius: 4px;
              letter-spacing: 2px;
            ">🛡️ CRYPTOGUARD — ${result.riskLevel} RISK</span>
          </div>
          <h2 style="color:#fff; font-size:18px; font-weight:700; margin:0 0 4px;">
            ${isCritical ? '⛔ Site Bloqueado' : '⚠️ Atenção — Site Suspeito'}
          </h2>
          <p style="color:rgba(255,255,255,0.5); font-size:12px; margin:0 0 14px; word-break:break-all;">
            ${url}
          </p>
          <div style="margin-bottom:16px;">${threatsHTML}</div>
          <div style="display:flex; gap:10px; flex-wrap:wrap;">
            <button onclick="window.history.back()" style="
              background: ${borderColor};
              color: #fff;
              border: none;
              padding: 10px 22px;
              border-radius: 6px;
              font-size: 13px;
              font-weight: 700;
              cursor: pointer;
              letter-spacing: 0.5px;
            ">← Voltar (recomendado)</button>
            <button onclick="document.getElementById('cryptoguard-overlay').remove()" style="
              background: transparent;
              color: rgba(255,255,255,0.4);
              border: 1px solid rgba(255,255,255,0.15);
              padding: 10px 22px;
              border-radius: 6px;
              font-size: 13px;
              cursor: pointer;
            ">Ignorar aviso (por minha conta e risco)</button>
          </div>
        </div>
      </div>
    </div>
  `;

  document.body.insertBefore(overlay, document.body.firstChild);
}

// ─── Intercepta window.ethereum (MetaMask) ───────────────────
function injectEthereumInterceptor() {
  const script = document.createElement('script');
  script.textContent = `
    (function() {
      const MAX_WAIT = 3000;
      const start = Date.now();

      function tryIntercept() {
        if (window.ethereum) {
          const original = window.ethereum.request.bind(window.ethereum);
          window.ethereum.request = async function(args) {
            // Intercepta aprovações de token (ERC20 approve)
            if (args.method === 'eth_sendTransaction') {
              const tx = args.params?.[0];
              if (tx?.data?.startsWith('0x095ea7b3')) {
                // É uma aprovação ERC20 — extrai amount
                const amount = BigInt('0x' + tx.data.slice(74));
                const isInfinite = amount > BigInt('0xfffffffffffffffffffffffffffffff');
                if (isInfinite) {
                  window.postMessage({
                    type: 'CRYPTOGUARD_APPROVAL_WARNING',
                    spender: tx.to,
                    amount: amount.toString(),
                  }, '*');
                }
              }
            }
            // Intercepta eth_requestAccounts (conexão da wallet)
            if (args.method === 'eth_requestAccounts') {
              window.postMessage({
                type: 'CRYPTOGUARD_WALLET_CONNECT',
                site: window.location.hostname,
              }, '*');
            }
            return original(args);
          };
          console.log('🛡️ CryptoGuard: Ethereum interceptor ativo');
          return;
        }
        if (Date.now() - start < MAX_WAIT) {
          setTimeout(tryIntercept, 100);
        }
      }
      tryIntercept();
    })();
  `;
  (document.head || document.documentElement).appendChild(script);
  script.remove();
}

// ─── Recebe mensagens do interceptor ────────────────────────
window.addEventListener('message', (event) => {
  if (event.source !== window) return;

  if (event.data?.type === 'CRYPTOGUARD_APPROVAL_WARNING') {
    chrome.runtime.sendMessage({
      action: 'ANALYZE_APPROVAL',
      spender: event.data.spender,
      amount: event.data.amount,
      token: event.data.token || 'Token',
    }, (response) => {
      if (response?.result && !response.result.safe) {
        showApprovalWarning(response.result, event.data);
      }
    });
  }
});

// ─── Aviso de aprovação inline ───────────────────────────────
function showApprovalWarning(result, data) {
  const banner = document.createElement('div');
  banner.style.cssText = `
    position: fixed;
    bottom: 24px;
    right: 24px;
    z-index: 2147483647;
    background: #1a0a00;
    border: 2px solid #ff6b35;
    border-radius: 12px;
    padding: 18px 20px;
    max-width: 360px;
    box-shadow: 0 8px 40px rgba(255,107,53,0.3);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    animation: fadeIn 0.3s ease;
  `;
  banner.innerHTML = `
    <style>@keyframes fadeIn { from { opacity:0; transform:translateY(10px); } to { opacity:1; transform:translateY(0); } }</style>
    <div style="display:flex; align-items:center; gap:10px; margin-bottom:10px;">
      <span style="font-size:20px;">🛡️</span>
      <strong style="color:#ff6b35; font-size:13px; letter-spacing:1px;">CRYPTOGUARD</strong>
      <button onclick="this.closest('div[style]').remove()" style="
        margin-left:auto; background:none; border:none;
        color:rgba(255,255,255,0.3); cursor:pointer; font-size:18px;
      ">×</button>
    </div>
    <p style="color:#fff; font-size:14px; font-weight:700; margin:0 0 6px;">
      ⚠️ Aprovação Infinita Detectada
    </p>
    <p style="color:rgba(255,255,255,0.6); font-size:12px; margin:0 0 14px; line-height:1.5;">
      Você está prestes a dar permissão <strong style="color:#ff6b35">ilimitada</strong> 
      para este contrato gastar seus tokens. Se o protocolo for hackeado, 
      você perde tudo.
    </p>
    <p style="color:rgba(255,255,255,0.4); font-size:11px; margin:0;">
      💡 Dica: Procure a opção "Definir limite" na MetaMask antes de confirmar.
    </p>
  `;
  document.body.appendChild(banner);
  setTimeout(() => banner.remove(), 15000);
}

// ─── Recebe mensagens do background ──────────────────────────
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.action === 'SHOW_WARNING') {
    createWarningOverlay(msg.result, msg.url);
  }
});

// ─── Inicia interceptor ──────────────────────────────────────
injectEthereumInterceptor();

// ─── Analisa a página atual ao carregar ──────────────────────
chrome.runtime.sendMessage({
  action: 'ANALYZE_URL',
  url: window.location.href,
}, (response) => {
  if (response?.result && !response.result.safe) {
    createWarningOverlay(response.result, window.location.href);
  }
});
