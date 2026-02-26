// ============================================================
// CryptoGuard — background.js
// Service Worker: motor de segurança principal
// Roda em background, analisa URLs e contratos
// ============================================================

// ─── Base de dados de phishing (atualizada via API) ──────────
// Fontes: PhishFort, CryptoScamDB, nossa própria lista
let PHISHING_DOMAINS = new Set([
  // MetaMask fakes
  'metamask-io.com', 'metamasks.io', 'meta-mask.io', 'metamask.com.co',
  'metamask-extension.com', 'metamaskwallet.io', 'rnetamask.io',
  // Uniswap fakes
  'uniswap-app.com', 'uniswaps.org', 'uniswap.exchange.com',
  'uniswapv3.io', 'uniswapdex.com',
  // OpenSea fakes
  'opensea.io.com', 'openseas.io', 'open-sea.io',
  // Coinbase fakes
  'coinbase-wallet.com', 'coinbasepro.io', 'coinbase.app.com',
  // Aave fakes
  'aave-app.com', 'aaves.finance',
  // Compound fakes
  'compound-finance.app', 'compoundprotocol.com',
  // Genéricos
  'claimrewards.net', 'airdrop-claim.com', 'wallet-connect.app',
  'walletconnect.network.com', 'nft-claim.io', 'mint-nft.app',
]);

// ─── Blacklist de endereços de contratos maliciosos ──────────
let MALICIOUS_CONTRACTS = new Set([
  // Conhecidos drain wallets
  '0x00000000219ab540356cbb839cbe05303d7705fa',
  // Adicionar mais via API
]);

// ─── Blacklist de endereços de scammers conhecidos ───────────
let SCAM_ADDRESSES = new Set([
  // Popular scam addresses — atualizado via API
]);

// ─── Status do usuário ───────────────────────────────────────
let userStatus = {
  isSubscribed: false,
  scanCount: 0,
  blockedCount: 0,
  lastCheck: null,
};

// ─── Carrega dados salvos ────────────────────────────────────
chrome.runtime.onInstalled.addListener(async () => {
  console.log('🛡️ CryptoGuard instalado!');
  await loadUserStatus();
  await updateBlacklists();
});

async function loadUserStatus() {
  const data = await chrome.storage.local.get(['userStatus']);
  if (data.userStatus) userStatus = data.userStatus;
}

async function saveUserStatus() {
  await chrome.storage.local.set({ userStatus });
}

// ─── Atualiza blacklists via API ─────────────────────────────
async function updateBlacklists() {
  try {
    // PhishFort — lista pública de phishing crypto
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

  // Atualiza a cada 6 horas
  setTimeout(updateBlacklists, 6 * 60 * 60 * 1000);
}

// ─── Analisa uma URL ─────────────────────────────────────────
function analyzeUrl(url) {
  try {
    const parsed   = new URL(url);
    const hostname = parsed.hostname.toLowerCase().replace('www.', '');
    const result   = { safe: true, threats: [], riskLevel: 'SAFE' };

    // 1. Checa blacklist direta
    if (PHISHING_DOMAINS.has(hostname)) {
      result.safe = false;
      result.threats.push({
        type: 'PHISHING',
        severity: 'CRITICAL',
        message: `Site de phishing confirmado: ${hostname}`,
        detail: 'Este domínio está na blacklist de scams crypto conhecidos.'
      });
    }

    // 2. Checa similaridade com sites legítimos (typosquatting)
    const LEGIT_SITES = [
      'metamask.io', 'uniswap.org', 'opensea.io', 'coinbase.com',
      'aave.com', 'compound.finance', 'curve.fi', 'sushiswap.org',
      'pancakeswap.finance', 'raydium.io', 'phantom.app',
    ];

    for (const legit of LEGIT_SITES) {
      if (hostname !== legit && isSimilar(hostname, legit)) {
        result.safe = false;
        result.threats.push({
          type: 'TYPOSQUATTING',
          severity: 'HIGH',
          message: `Possível imitação de ${legit}`,
          detail: `${hostname} é muito similar ao site legítimo ${legit}. Pode ser uma armadilha.`
        });
      }
    }

    // 3. Padrões suspeitos na URL
    const SUSPICIOUS_PATTERNS = [
      { pattern: /airdrop/i,      msg: 'URLs com "airdrop" são frequentemente scams' },
      { pattern: /claim.*reward/i, msg: 'Páginas de "claim rewards" são frequentemente falsas' },
      { pattern: /wallet.*connect.*\./i, msg: 'Possível phishing de WalletConnect' },
      { pattern: /free.*crypto/i, msg: '"Free crypto" é quase sempre scam' },
      { pattern: /nft.*mint.*free/i, msg: 'Mint gratuito suspeito' },
    ];

    for (const { pattern, msg } of SUSPICIOUS_PATTERNS) {
      if (pattern.test(url)) {
        result.threats.push({
          type: 'SUSPICIOUS_URL',
          severity: 'MEDIUM',
          message: msg,
          detail: 'Padrão suspeito detectado na URL.'
        });
      }
    }

    // Define risk level
    const hasCritical = result.threats.some(t => t.severity === 'CRITICAL');
    const hasHigh     = result.threats.some(t => t.severity === 'HIGH');
    const hasMedium   = result.threats.some(t => t.severity === 'MEDIUM');

    result.riskLevel = hasCritical ? 'CRITICAL' :
                       hasHigh     ? 'HIGH'      :
                       hasMedium   ? 'MEDIUM'    : 'SAFE';

    if (!result.safe) {
      userStatus.blockedCount++;
      saveUserStatus();
    }

    return result;
  } catch {
    return { safe: true, threats: [], riskLevel: 'SAFE' };
  }
}

// ─── Analisa um contrato Ethereum/EVM ────────────────────────
async function analyzeContract(contractAddress, chainId = '1') {
  const addr   = contractAddress.toLowerCase();
  const result = { safe: true, threats: [], riskLevel: 'SAFE' };

  // 1. Checa blacklist
  if (MALICIOUS_CONTRACTS.has(addr)) {
    result.safe = false;
    result.threats.push({
      type: 'MALICIOUS_CONTRACT',
      severity: 'CRITICAL',
      message: 'Contrato malicioso confirmado',
      detail: 'Este endereço está na blacklist de contratos que drenam carteiras.'
    });
    return result;
  }

  // 2. Checa via GoPlus Security API (gratuita)
  try {
    const chain = chainId === '1' ? '1' : chainId === '56' ? '56' : '1';
    const resp  = await fetch(
      `https://api.gopluslabs.io/api/v1/token_security/${chain}?contract_addresses=${addr}`
    );
    const data  = await resp.json();
    const info  = data?.result?.[addr];

    if (info) {
      if (info.is_honeypot === '1') {
        result.safe = false;
        result.threats.push({
          type: 'HONEYPOT',
          severity: 'CRITICAL',
          message: '🍯 HONEYPOT DETECTADO',
          detail: 'Você pode comprar mas NÃO conseguirá vender. Armadilha confirmada.'
        });
      }

      if (info.is_blacklisted === '1') {
        result.safe = false;
        result.threats.push({
          type: 'BLACKLISTED',
          severity: 'CRITICAL',
          message: 'Contrato na blacklist',
          detail: 'Este contrato foi reportado como malicioso.'
        });
      }

      if (info.can_take_back_ownership === '1') {
        result.threats.push({
          type: 'OWNERSHIP_RISK',
          severity: 'HIGH',
          message: 'Dono pode retomar controle',
          detail: 'O criador pode recuperar ownership e drenar a liquidez.'
        });
      }

      if (info.hidden_owner === '1') {
        result.threats.push({
          type: 'HIDDEN_OWNER',
          severity: 'HIGH',
          message: 'Dono oculto detectado',
          detail: 'Há um owner escondido que pode ter poderes especiais sobre o contrato.'
        });
      }

      if (info.is_mintable === '1') {
        result.threats.push({
          type: 'MINTABLE',
          severity: 'MEDIUM',
          message: 'Token mintável (inflação possível)',
          detail: 'O criador pode criar novos tokens a qualquer momento, diluindo seu valor.'
        });
      }

      const tax = parseFloat(info.sell_tax || 0);
      if (tax > 10) {
        result.threats.push({
          type: 'HIGH_TAX',
          severity: tax > 49 ? 'CRITICAL' : 'HIGH',
          message: `Taxa de venda alta: ${tax}%`,
          detail: tax > 49
            ? 'Taxa acima de 49% — impossível de vender com lucro. Possível honeypot.'
            : 'Taxa de venda muito alta. Risco de não conseguir sair com lucro.'
        });
      }

      if (parseInt(info.holder_count || 0) < 50) {
        result.threats.push({
          type: 'FEW_HOLDERS',
          severity: 'MEDIUM',
          message: `Poucos holders: ${info.holder_count}`,
          detail: 'Token muito concentrado. Fácil de manipular o preço.'
        });
      }
    }
  } catch (e) {
    console.log('GoPlus API error:', e.message);
  }

  const hasCritical = result.threats.some(t => t.severity === 'CRITICAL');
  const hasHigh     = result.threats.some(t => t.severity === 'HIGH');
  const hasMedium   = result.threats.some(t => t.severity === 'MEDIUM');

  result.riskLevel = hasCritical ? 'CRITICAL' :
                     hasHigh     ? 'HIGH'      :
                     hasMedium   ? 'MEDIUM'    : 'SAFE';
  result.safe = !hasCritical && !hasHigh;

  return result;
}

// ─── Analisa aprovação de token ──────────────────────────────
function analyzeApproval(spenderAddress, amount, tokenSymbol) {
  const result   = { safe: true, threats: [], riskLevel: 'SAFE' };
  const isInfinite = amount === '115792089237316195423570985008687907853269984665640564039457584007913129639935'
                  || amount > 1e30;

  if (isInfinite) {
    result.safe = false;
    result.threats.push({
      type: 'INFINITE_APPROVAL',
      severity: 'HIGH',
      message: `Aprovação INFINITA de ${tokenSymbol || 'token'}`,
      detail: 'Você está dando permissão ilimitada para este contrato gastar seus tokens. Se for comprometido, pode perder tudo. Recomendamos aprovar apenas o valor necessário.'
    });
    result.riskLevel = 'HIGH';
  }

  if (SCAM_ADDRESSES.has(spenderAddress.toLowerCase())) {
    result.safe = false;
    result.threats.push({
      type: 'SCAM_SPENDER',
      severity: 'CRITICAL',
      message: 'Spender na blacklist de scams',
      detail: 'Este endereço é conhecido por drenar carteiras após aprovação.'
    });
    result.riskLevel = 'CRITICAL';
  }

  return result;
}

// ─── Calcula similaridade entre strings (Levenshtein) ────────
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
      dp[i][j] = a[i-1] === b[j-1]
        ? dp[i-1][j-1]
        : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
    }
  }
  return dp[m][n];
}

// ─── Message handler (recebe pedidos do popup e content) ─────
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

  if (msg.action === 'CHECK_SUBSCRIPTION') {
    // TODO: verificar via API do seu backend
    // Por ora retorna status local
    sendResponse({ isSubscribed: userStatus.isSubscribed });
    return true;
  }
});

// ─── Monitora navegação para alertar em tempo real ───────────
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  if (!details.url.startsWith('http')) return;

  const result = analyzeUrl(details.url);

  if (result.riskLevel === 'CRITICAL' || result.riskLevel === 'HIGH') {
    // Notificação do sistema
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: `🚨 CryptoGuard — ${result.riskLevel} RISK`,
      message: result.threats[0]?.message || 'Site perigoso detectado!',
      priority: 2,
    });

    // Injeta overlay de aviso na página
    chrome.tabs.sendMessage(details.tabId, {
      action: 'SHOW_WARNING',
      result,
      url: details.url,
    }).catch(() => {});
  }
});
