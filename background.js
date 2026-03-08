// ============================================================
// SHIELD CryptoGuard — background.js (v2.0)
// Service Worker: segurança + verificação de subscrição PRO
// ============================================================

const API_URL = 'https://cryptoguard-backend-production.up.railway.app';

// ─── Phishing domains database ───────────────────────────────
let PHISHING_DOMAINS = new Set([
  'metamask-io.com', 'metamasks.io', 'meta-mask.io', 'metamask.com.co',
  'metamask-extension.com', 'metamaskwallet.io', 'rnetamask.io',
  'uniswap-app.com', 'uniswaps.org', 'uniswap.exchange.com',
  'uniswapv3.io', 'uniswapdex.com',
  'opensea.io.com', 'openseas.io', 'open-sea.io',
  'coinbase-wallet.com', 'coinbasepro.io', 'coinbase.app.com',
  'aave-app.com', 'aaves.finance',
  'compound-finance.app', 'compoundprotocol.com',
  'claimrewards.net', 'airdrop-claim.com', 'wallet-connect.app',
  'walletconnect.network.com', 'nft-claim.io', 'mint-nft.app',
]);

let MALICIOUS_CONTRACTS = new Set();
let SCAM_ADDRESSES = new Set();

// ─── User status ─────────────────────────────────────────────
let userStatus = {
  email: null,
  plan: 'free',       // 'free' ou 'pro'
  isSubscribed: false,
  scanCount: 0,
  blockedCount: 0,
  lastCheck: null,
};

// ─── Init ────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(async () => {
  console.log('🛡️ SHIELD CryptoGuard instalado!');
  await loadUserStatus();
  await updateBlacklists();
});

// Também carrega ao iniciar o service worker
loadUserStatus();

// ─── Storage helpers ─────────────────────────────────────────
async function loadUserStatus() {
  try {
    const data = await chrome.storage.local.get(['userStatus']);
    if (data.userStatus) {
      userStatus = { ...userStatus, ...data.userStatus };
    }
    // Se tem email, verifica subscrição com o backend
    if (userStatus.email) {
      await checkSubscriptionWithBackend(userStatus.email);
    }
  } catch (e) {
    console.log('Error loading status:', e);
  }
}

async function saveUserStatus() {
  try {
    await chrome.storage.local.set({ userStatus });
  } catch (e) {
    console.log('Error saving status:', e);
  }
}

// ─── Verifica subscrição com o backend ───────────────────────
async function checkSubscriptionWithBackend(email) {
  if (!email) return;
  
  try {
    const resp = await fetch(`${API_URL}/subscription/status?email=${encodeURIComponent(email)}`);
    if (resp.ok) {
      const data = await resp.json();
      userStatus.plan = data.plan || 'free';
      userStatus.isSubscribed = data.active === true;
      userStatus.lastCheck = new Date().toISOString();
      await saveUserStatus();
      console.log(`🔍 Subscription check: ${email} → ${userStatus.plan}`);
    }
  } catch (e) {
    console.log('Subscription check failed (offline?):', e.message);
    // Mantém status anterior se offline
  }
}

// Verifica subscrição a cada 30 minutos
setInterval(() => {
  if (userStatus.email) {
    checkSubscriptionWithBackend(userStatus.email);
  }
}, 30 * 60 * 1000);

// ─── Blacklist updates ───────────────────────────────────────
async function updateBlacklists() {
  try {
    const response = await fetch(
      'https://raw.githubusercontent.com/niclas-sky/cryptoscamdb/master/output/domains.json'
    );
    if (response.ok) {
      const data = await response.json();
      if (Array.isArray(data)) {
        data.forEach(d => PHISHING_DOMAINS.add(d.toLowerCase()));
      }
    }
  } catch (e) {
    console.log('Blacklist update failed, using local list');
  }
  setTimeout(updateBlacklists, 6 * 60 * 60 * 1000);
}

// ─── URL Analysis ────────────────────────────────────────────
function analyzeUrl(url) {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase().replace('www.', '');
    const result = { safe: true, threats: [], riskLevel: 'SAFE' };

    if (PHISHING_DOMAINS.has(hostname)) {
      result.safe = false;
      result.threats.push({
        type: 'PHISHING', severity: 'CRITICAL',
        message: `Site de phishing confirmado: ${hostname}`,
        detail: 'Este domínio está na blacklist de scams crypto conhecidos.'
      });
    }

    const LEGIT_SITES = [
      'metamask.io', 'uniswap.org', 'opensea.io', 'coinbase.com',
      'aave.com', 'compound.finance', 'curve.fi', 'sushiswap.org',
      'pancakeswap.finance', 'raydium.io', 'phantom.app',
    ];

    for (const legit of LEGIT_SITES) {
      if (hostname !== legit && isSimilar(hostname, legit)) {
        result.safe = false;
        result.threats.push({
          type: 'TYPOSQUATTING', severity: 'HIGH',
          message: `Possível imitação de ${legit}`,
          detail: `${hostname} é muito similar ao site legítimo ${legit}.`
        });
      }
    }

    const SUSPICIOUS_PATTERNS = [
      { pattern: /airdrop/i, msg: 'URLs com "airdrop" são frequentemente scams' },
      { pattern: /claim.*reward/i, msg: 'Páginas de "claim rewards" são frequentemente falsas' },
      { pattern: /wallet.*connect.*\./i, msg: 'Possível phishing de WalletConnect' },
      { pattern: /free.*crypto/i, msg: '"Free crypto" é quase sempre scam' },
      { pattern: /nft.*mint.*free/i, msg: 'Mint gratuito suspeito' },
    ];

    for (const { pattern, msg } of SUSPICIOUS_PATTERNS) {
      if (pattern.test(url)) {
        result.threats.push({
          type: 'SUSPICIOUS_URL', severity: 'MEDIUM',
          message: msg, detail: 'Padrão suspeito detectado na URL.'
        });
      }
    }

    const hasCritical = result.threats.some(t => t.severity === 'CRITICAL');
    const hasHigh = result.threats.some(t => t.severity === 'HIGH');
    const hasMedium = result.threats.some(t => t.severity === 'MEDIUM');
    result.riskLevel = hasCritical ? 'CRITICAL' : hasHigh ? 'HIGH' : hasMedium ? 'MEDIUM' : 'SAFE';

    if (!result.safe) {
      userStatus.blockedCount++;
      saveUserStatus();
    }

    return result;
  } catch {
    return { safe: true, threats: [], riskLevel: 'SAFE' };
  }
}

// ─── Contract Analysis ───────────────────────────────────────
async function analyzeContract(contractAddress, chainId = '1') {
  const addr = contractAddress.toLowerCase();
  const result = { safe: true, threats: [], riskLevel: 'SAFE' };

  if (MALICIOUS_CONTRACTS.has(addr)) {
    result.safe = false;
    result.threats.push({
      type: 'MALICIOUS_CONTRACT', severity: 'CRITICAL',
      message: 'Contrato malicioso confirmado',
      detail: 'Este endereço está na blacklist de contratos que drenam carteiras.'
    });
    return result;
  }

  // PRO feature: GoPlus deep scan
  if (!userStatus.isSubscribed) {
    result.threats.push({
      type: 'PRO_REQUIRED', severity: 'INFO',
      message: '🔒 Análise avançada requer PRO',
      detail: 'Upgrade para SHIELD PRO para scan completo de honeypots, taxes, e ownership.'
    });
    result.riskLevel = 'SAFE';
    return result;
  }

  try {
    const chain = chainId === '56' ? '56' : chainId === '137' ? '137' : '1';
    const resp = await fetch(
      `https://api.gopluslabs.io/api/v1/token_security/${chain}?contract_addresses=${addr}`
    );
    const data = await resp.json();
    const info = data?.result?.[addr];

    if (info) {
      if (info.is_honeypot === '1') {
        result.safe = false;
        result.threats.push({
          type: 'HONEYPOT', severity: 'CRITICAL',
          message: '🍯 HONEYPOT DETECTADO',
          detail: 'Você pode comprar mas NÃO conseguirá vender.'
        });
      }
      if (info.is_blacklisted === '1') {
        result.safe = false;
        result.threats.push({
          type: 'BLACKLISTED', severity: 'CRITICAL',
          message: 'Contrato na blacklist',
          detail: 'Este contrato foi reportado como malicioso.'
        });
      }
      if (info.can_take_back_ownership === '1') {
        result.threats.push({
          type: 'OWNERSHIP_RISK', severity: 'HIGH',
          message: 'Dono pode retomar controle',
          detail: 'O criador pode recuperar ownership e drenar a liquidez.'
        });
      }
      if (info.hidden_owner === '1') {
        result.threats.push({
          type: 'HIDDEN_OWNER', severity: 'HIGH',
          message: 'Dono oculto detectado',
          detail: 'Há um owner escondido com poderes especiais.'
        });
      }
      if (info.is_mintable === '1') {
        result.threats.push({
          type: 'MINTABLE', severity: 'MEDIUM',
          message: 'Token mintável (inflação possível)',
          detail: 'O criador pode criar novos tokens a qualquer momento.'
        });
      }
      const tax = parseFloat(info.sell_tax || 0);
      if (tax > 10) {
        result.threats.push({
          type: 'HIGH_TAX', severity: tax > 49 ? 'CRITICAL' : 'HIGH',
          message: `Taxa de venda alta: ${tax}%`,
          detail: tax > 49 ? 'Impossível vender com lucro.' : 'Taxa de venda muito alta.'
        });
      }
      if (parseInt(info.holder_count || 0) < 50) {
        result.threats.push({
          type: 'FEW_HOLDERS', severity: 'MEDIUM',
          message: `Poucos holders: ${info.holder_count}`,
          detail: 'Token muito concentrado.'
        });
      }
    }
  } catch (e) {
    console.log('GoPlus API error:', e.message);
  }

  const hasCritical = result.threats.some(t => t.severity === 'CRITICAL');
  const hasHigh = result.threats.some(t => t.severity === 'HIGH');
  const hasMedium = result.threats.some(t => t.severity === 'MEDIUM');
  result.riskLevel = hasCritical ? 'CRITICAL' : hasHigh ? 'HIGH' : hasMedium ? 'MEDIUM' : 'SAFE';
  result.safe = !hasCritical && !hasHigh;

  return result;
}

// ─── Approval Analysis ───────────────────────────────────────
function analyzeApproval(spenderAddress, amount, tokenSymbol) {
  const result = { safe: true, threats: [], riskLevel: 'SAFE' };
  const isInfinite = amount === '115792089237316195423570985008687907853269984665640564039457584007913129639935' || amount > 1e30;

  if (isInfinite) {
    result.safe = false;
    result.threats.push({
      type: 'INFINITE_APPROVAL', severity: 'HIGH',
      message: `Aprovação INFINITA de ${tokenSymbol || 'token'}`,
      detail: 'Permissão ilimitada. Se o protocolo for hackeado, perde tudo.'
    });
    result.riskLevel = 'HIGH';
  }

  if (SCAM_ADDRESSES.has(spenderAddress.toLowerCase())) {
    result.safe = false;
    result.threats.push({
      type: 'SCAM_SPENDER', severity: 'CRITICAL',
      message: 'Spender na blacklist de scams',
      detail: 'Este endereço drena carteiras após aprovação.'
    });
    result.riskLevel = 'CRITICAL';
  }

  return result;
}

// ─── String similarity ───────────────────────────────────────
function isSimilar(a, b) {
  if (Math.abs(a.length - b.length) > 3) return false;
  const distance = levenshtein(a, b);
  return distance > 0 && distance <= 2;
}

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0)
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

// ─── Message handler ─────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  if (msg.action === 'ANALYZE_URL') {
    userStatus.scanCount++;
    saveUserStatus();
    const result = analyzeUrl(msg.url);
    sendResponse({ result, userStatus });
    return true;
  }

  if (msg.action === 'ANALYZE_CONTRACT') {
    analyzeContract(msg.address, msg.chainId).then(result => {
      sendResponse({ result });
    });
    return true;
  }

  if (msg.action === 'ANALYZE_APPROVAL') {
    const result = analyzeApproval(msg.spender, msg.amount, msg.token);
    sendResponse({ result });
    return true;
  }

  if (msg.action === 'GET_STATUS') {
    sendResponse({ userStatus });
    return true;
  }

  // ─── Login: guardar email e verificar PRO ──────────────────
  if (msg.action === 'LOGIN') {
    const email = (msg.email || '').toLowerCase().trim();
    if (!email || !email.includes('@')) {
      sendResponse({ success: false, error: 'Email inválido' });
      return true;
    }
    userStatus.email = email;
    saveUserStatus();
    checkSubscriptionWithBackend(email).then(() => {
      sendResponse({ success: true, userStatus });
    });
    return true;
  }

  // ─── Logout ────────────────────────────────────────────────
  if (msg.action === 'LOGOUT') {
    userStatus.email = null;
    userStatus.plan = 'free';
    userStatus.isSubscribed = false;
    saveUserStatus();
    sendResponse({ success: true });
    return true;
  }

  // ─── Check subscription ────────────────────────────────────
  if (msg.action === 'CHECK_SUBSCRIPTION') {
    if (userStatus.email) {
      checkSubscriptionWithBackend(userStatus.email).then(() => {
        sendResponse({ userStatus });
      });
    } else {
      sendResponse({ userStatus });
    }
    return true;
  }

  // ─── Get checkout URL ──────────────────────────────────────
  if (msg.action === 'GET_CHECKOUT_URL') {
    const email = userStatus.email || msg.email;
    if (!email) {
      sendResponse({ error: 'Faça login primeiro' });
      return true;
    }
    fetch(`${API_URL}/subscription/checkout`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    })
      .then(r => r.json())
      .then(data => sendResponse(data))
      .catch(err => sendResponse({ error: err.message }));
    return true;
  }
});

// ─── Navigation monitor ──────────────────────────────────────
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  if (!details.url.startsWith('http')) return;

  const result = analyzeUrl(details.url);

  if (result.riskLevel === 'CRITICAL' || result.riskLevel === 'HIGH') {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: `🚨 CryptoGuard — ${result.riskLevel} RISK`,
      message: result.threats[0]?.message || 'Site perigoso detectado!',
      priority: 2,
    });

    chrome.tabs.sendMessage(details.tabId, {
      action: 'SHOW_WARNING',
      result,
      url: details.url,
    }).catch(() => {});
  }
});
