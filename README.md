# 🛡 SHIELD CryptoGuard — Web3 Antivirus

> **Real-time AI-powered security for every Web3 interaction. Blocks phishing, detects honeypots, intercepts malicious approvals — before your wallet signs anything.**

[![Beta](https://img.shields.io/badge/status-public%20beta-00ff88?style=flat-square&labelColor=0a1a0a)](https://cryptoguard.site)
[![License](https://img.shields.io/badge/license-MIT-00ff88?style=flat-square&labelColor=0a1a0a)](LICENSE)
[![Chrome Extension](https://img.shields.io/badge/Chrome-Web%20Store-00ff88?style=flat-square&labelColor=0a1a0a)](https://cryptoguard.site)
[![Chains](https://img.shields.io/badge/chains-ETH%20%7C%20BNB%20%7C%20MATIC%20%7C%20ARB%20%7C%20BASE%20%7C%20AVAX-00ff88?style=flat-square&labelColor=0a1a0a)](https://cryptoguard.site)

---

## What Is SHIELD CryptoGuard?

SHIELD CryptoGuard is a browser extension that functions as an **AI-driven security layer between your browser and the Web3 ecosystem**. Every URL, smart contract address, token approval, and wallet connection request you encounter is analyzed in real time — before you interact with it.

The Web3 threat landscape moves faster than any static blocklist can track. Phishing frontends go live in under 6 minutes. Honeypot tokens are deployed, promoted, and drained within a single block. SHIELD was built to operate at the speed of this environment.

---

## How It Works

SHIELD runs a **5-layer detection pipeline** on every Web3 interaction:

| Layer | Function |
|-------|----------|
| `01` INGESTION | Extracts domains, contract addresses, and approval parameters locally in-browser |
| `02` CLASSIFICATION AI | Multi-vector threat scoring: domain age, SSL anomalies, bytecode heuristics, deployer history |
| `03` APPROVAL INTERCEPTION | Decodes and surfaces every token approval before your wallet signs — flags infinite spend |
| `04` BLACKLIST INTELLIGENCE | Dynamic threat database updated every 6 hours across 6 EVM chains |
| `05` VERDICT & ALERT | Plain-language alerts with severity classification and recommended action |

Full technical documentation: [cryptoguard.site/how-it-works.html](https://cryptoguard.site/how-it-works.html)

---

## Threat Coverage

```
[CRITICAL] Phishing & domain spoofing (IDN homograph, subdomain hijack, UI clones)
[CRITICAL] Honeypot contracts (hidden sell restrictions, owner-only whitelist, dynamic tax)
[HIGH]     Infinite approval drainers (ERC-20 unlimited spend, Permit2, EIP-712 abuse)
[HIGH]     Rugpull detection (liquidity lock expiry, admin key concentration, proxy upgrades)
[MEDIUM]   Malicious airdrop tokens (SetApprovalForAll lures, claim drainers)
[MEDIUM]   Address poisoning (vanity address contamination of transaction history)
[INFO]     Unverified contracts (unaudited bytecode requesting custody or approvals)
[INFO]     High-tax token mechanics (>10% buy/sell tax flagged before swap)
```

---

## Extension Files

```
cryptoguard-extension/
├── manifest.json       # Extension manifest (MV3)
├── background.js       # Service worker — threat query orchestration
├── content.js          # In-page script — DOM analysis & approval interception
├── popup.html          # Extension popup UI
├── popup.js            # Popup logic & threat status display
└── icons/
    ├── icon16.png
    ├── icon32.png
    ├── icon48.png
    └── icon128.png
```

---

## Why Open Source?

Security software that interacts with your wallet should be verifiable. We publish the extension source code so that:

- Any developer can audit exactly what data the extension reads and transmits
- The community can identify and report issues faster than a closed codebase allows
- Users can verify that SHIELD never requests, stores, or transmits private keys or seed phrases

> **Note:** The backend threat intelligence API and AI classification engine are proprietary and run server-side. This repository contains the client-side extension code only.

---

## Data & Privacy

SHIELD CryptoGuard operates on a **minimal data collection principle**:

- The extension reads URLs and contract addresses to perform threat analysis
- No wallet private keys or seed phrases are ever accessed or transmitted
- Public wallet addresses are queried against security APIs transiently — not stored
- No advertising tracking, no behavioral profiling, no data sold to third parties

Full privacy policy: [cryptoguard.site/privacy.html](https://cryptoguard.site/privacy.html)

---

## Chains Supported

| Chain | Status |
|-------|--------|
| Ethereum Mainnet | ✅ Active |
| BNB Chain | ✅ Active |
| Polygon | ✅ Active |
| Arbitrum One | ✅ Active |
| Base | ✅ Active |
| Avalanche C-Chain | ✅ Active |

---

## Disclaimer

SHIELD CryptoGuard is a **beta product** under active development. It reduces — but does not eliminate — the risks of interacting with Web3 protocols. Threat detection coverage is continuously expanding but cannot guarantee identification of all attack vectors.

Interacting with DeFi, NFT platforms, and smart contracts carries inherent financial risk beyond the scope of any security tool. Always conduct independent due diligence before signing any transaction.

Full terms: [cryptoguard.site/terms.html](https://cryptoguard.site/terms.html)

---

## Built By

**Edutech Wise FZCO** — United Arab Emirates  
Website: [cryptoguard.site](https://cryptoguard.site)

---

*SHIELD CryptoGuard — Because in Web3, you sign first and regret later.*
