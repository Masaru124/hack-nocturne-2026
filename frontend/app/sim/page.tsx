"use client";

import { useState, useEffect, useRef, useCallback } from "react";

// ─── Types ────────────────────────────────────────────────────────────────────

type AttackType = "phishing" | "drainer" | "prize" | "malware" | "unknown";
type SimPhase = "idle" | "running" | "intercepted";

interface AnalysisResult {
  attackType: AttackType;
  riskScore: number;
  confidence: number;
  indicators: string[];
  whatWouldHappen: string;
}

interface SimState {
  phase: SimPhase;
  progress: number;
  logLines: string[];
  drainAmount: number;
  drainTokens: number;
  prizeSeconds: number;
  typedPassword: string;
  typedSeed: string;
  showSeedField: boolean;
  showPasswordWrong: boolean;
  walletConnecting: boolean;
  statusText: string;
}

interface HoneytrapIntel {
  intelId: number;
  url: string;
  domain: string;
  pageTitle?: string;
  domainRisk: number;
  scamNetworkRisk: number;
  urlModelScore?: number;
  urlModelStatus?: string;
  connectedDomains: number;
  sharedWallets: number;
  activeCampaign: boolean;
  wallets: string[];
  telegramIds: string[];
  emails: string[];
  phones?: string[];
  paymentInstructions: string[];
  formIntel?: Array<{ action?: string; method?: string; suspicious?: boolean }>;
  chatExchanges?: Array<{ sent?: string; received?: string }>;
  chatWidgetsFound?: string[];
  redirectsDetected?: string[];
  evidence: string[];
  history?: {
    samples: number;
    wallets: string[];
    telegramIds: string[];
    emails: string[];
    paymentInstructions: string[];
    latestCapturedAt?: string | null;
  };
  crawlDiagnostics?: {
    method?: string;
    unreachable?: boolean;
    playwrightMissing?: boolean;
    dnsFailure?: boolean;
    timeout?: boolean;
    likelyCause?: string;
    recommendations?: string[];
  };
  walletBlockchainReport?: {
    attempted: boolean;
    submitted: boolean;
    alreadyReported: boolean;
    wallet: string | null;
    txHash: string | null;
    textHash: string | null;
    error?: string | null;
  };
}

interface HoneytrapIntelRow {
  id: number;
  domain: string;
  wallets: string[];
  telegramIds: string[];
  emails: string[];
  paymentInstructions: string[];
  evidence: string[];
  createdAt?: string;
}

const INITIAL_SIM: SimState = {
  phase: "idle",
  progress: 0,
  logLines: [],
  drainAmount: 0,
  drainTokens: 0,
  prizeSeconds: 299,
  typedPassword: "",
  typedSeed: "",
  showSeedField: false,
  showPasswordWrong: false,
  walletConnecting: false,
  statusText: "Ready",
};

// ─── URL Analyzer ─────────────────────────────────────────────────────────────

function analyzeURL(raw: string): AnalysisResult {
  let url = raw.trim().toLowerCase();
  if (!url.startsWith("http")) url = "https://" + url;

  let parsed: URL | null = null;
  try {
    parsed = new URL(url);
  } catch {
    parsed = null;
  }

  const hostname = parsed?.hostname || url;
  const pathAndQuery = `${parsed?.pathname || ""}${parsed?.search || ""}`;
  const fullTarget = `${hostname}${pathAndQuery}`;

  const indicators: string[] = [];
  const addSignal = (label: string, points: number) => {
    indicators.push(label);
    score += points;
  };

  const fingerprintBucket = (value: string, modulo: number) => {
    let hash = 0;
    for (let i = 0; i < value.length; i++) {
      hash = (hash * 31 + value.charCodeAt(i)) >>> 0;
    }
    return hash % modulo;
  };

  let score = 0;
  const attackVotes: Record<AttackType, number> = {
    phishing: 0,
    drainer: 0,
    prize: 0,
    malware: 0,
    unknown: 0,
  };

  const trustedDomains = [
    "google.com",
    "youtube.com",
    "github.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "openai.com",
  ];
  const isTrusted = trustedDomains.some(
    (domain) => hostname === domain || hostname.endsWith(`.${domain}`),
  );

  const TLDS = [
    ".tk",
    ".xyz",
    ".ru",
    ".top",
    ".click",
    ".gq",
    ".cf",
    ".ml",
    ".ga",
    ".pw",
    ".shop",
    ".vip",
  ];
  const tld = TLDS.find((t) => hostname.endsWith(t));
  if (tld) addSignal(`Suspicious TLD: ${tld}`, 24);

  const parts = hostname.split(".");
  if (parts.length > 4) addSignal("Excessive subdomain depth", 15);
  if (hostname.includes("xn--")) addSignal("Punycode domain obfuscation", 18);
  if ((hostname.match(/-/g) || []).length >= 3)
    addSignal("High hyphenated-domain entropy", 10);

  if (/^\d{1,3}\.\d{1,3}/.test(hostname))
    addSignal("IP address as hostname", 20);
  if (hostname.length > 30)
    addSignal(`Long hostname (${hostname.length} chars)`, 10);

  const hostKeywords = [
    "secure-",
    "login-",
    "verify-",
    "update-",
    "alert-",
    "claim-",
    "support-",
    "wallet-",
    "airdrop-",
    "bonus-",
  ];
  const hostKw = hostKeywords.find((k) => hostname.includes(k));
  if (hostKw) addSignal(`Suspicious keyword: "${hostKw}"`, 18);

  const shorteners = ["bit.ly", "tinyurl.com", "t.co", "cutt.ly"];
  if (shorteners.some((s) => hostname === s || hostname.endsWith(`.${s}`))) {
    addSignal("URL shortener used", 12);
  }

  const BRANDS = [
    "paypal",
    "apple",
    "google",
    "amazon",
    "microsoft",
    "metamask",
    "coinbase",
    "binance",
    "opensea",
  ];
  const brand = BRANDS.find(
    (b) =>
      hostname.includes(b) &&
      !hostname.endsWith(`${b}.com`) &&
      !hostname.endsWith(`${b}.io`) &&
      !hostname.endsWith(`${b}.org`),
  );
  if (brand) {
    addSignal(`Brand impersonation: "${brand}"`, 28);
    attackVotes.phishing += 2;
  }

  if (/login|signin|auth|password|verify|recover/.test(pathAndQuery)) {
    addSignal("Credential capture path pattern", 14);
    attackVotes.phishing += 2;
  }

  if (/wallet|seed.?phrase|mnemonic|private.?key|passphrase/.test(fullTarget)) {
    addSignal("Wallet credential phishing pattern", 26);
    attackVotes.phishing += 3;
  }

  if (
    /airdrop|claim|free.?token|setapproval|approve|connect.?wallet/.test(
      fullTarget,
    )
  ) {
    addSignal("Crypto drainer flow pattern", 24);
    attackVotes.drainer += 3;
  }

  if (
    /winner|prize|congratul|you.?won|lucky.?visitor|gift.?card/.test(fullTarget)
  ) {
    addSignal("Fake prize / giveaway pattern", 22);
    attackVotes.prize += 3;
  }

  if (
    /download|setup|update|patch|installer|\.exe(\?|$)|\.msi(\?|$)|\.zip(\?|$)/.test(
      fullTarget,
    )
  ) {
    addSignal("Malware delivery pattern", 24);
    attackVotes.malware += 3;
  }

  if (!isTrusted && score < 15) {
    addSignal("Low-trust external domain", 15);
  }

  score = Math.min(score, 100);

  const topAttack = (Object.entries(attackVotes)
    .filter(([k]) => k !== "unknown")
    .sort((a, b) => b[1] - a[1])[0] || ["unknown", 0]) as [AttackType, number];

  let attackType: AttackType = topAttack[1] > 0 ? topAttack[0] : "unknown";
  if (attackType === "unknown" && score >= 45) attackType = "phishing";

  if (attackType === "unknown") {
    const tokenFamilies: Array<{
      type: Exclude<AttackType, "unknown">;
      regex: RegExp;
      label: string;
    }> = [
      {
        type: "phishing",
        regex:
          /login|signin|auth|password|verify|recover|support|account|security/i,
        label: "Pattern family: credential phishing",
      },
      {
        type: "drainer",
        regex: /wallet|airdrop|claim|token|dex|swap|staking|bridge|mint|nft/i,
        label: "Pattern family: crypto drainer",
      },
      {
        type: "prize",
        regex: /winner|prize|bonus|reward|gift|lottery|jackpot|promo|coupon/i,
        label: "Pattern family: fake prize",
      },
      {
        type: "malware",
        regex:
          /download|setup|update|patch|installer|driver|antivirus|cleaner|optimi[sz]er/i,
        label: "Pattern family: malware delivery",
      },
    ];

    const matchedFamily = tokenFamilies.find((f) => f.regex.test(fullTarget));
    if (matchedFamily) {
      attackType = matchedFamily.type;
      score = Math.max(score, 28);
      indicators.push(matchedFamily.label);
    } else if (!isTrusted) {
      const families: Exclude<AttackType, "unknown">[] = [
        "phishing",
        "drainer",
        "prize",
        "malware",
      ];
      const chosen =
        families[fingerprintBucket(fullTarget || hostname, families.length)];
      attackType = chosen;
      score = Math.max(score, 22);
      indicators.push(`URL fingerprint mapped to ${chosen} simulation profile`);
    }
  }

  const confidence = Math.min(
    99,
    Math.max(6, Math.round(score * 0.82 + indicators.length * 4)),
  );

  const WHAT: Record<AttackType, string> = {
    phishing:
      "Your seed phrase / password POSTed to attacker server. Wallet emptied in <60s. Completely unrecoverable.",
    drainer:
      "setApprovalForAll() called silently. All ERC-20 tokens + NFTs swept in one tx. Average victim loss: $24,000.",
    prize:
      'Card details sold on dark web within hours. "Processing fee" is a hidden $89/month subscription. No prize exists.',
    malware:
      "AsyncRAT keylogger installed. Captures every keystroke, banking session, clipboard. Access sold to botnet for $15.",
    unknown:
      "URL-only analysis found suspicious traits, but the exact exploit path is uncertain. Run Honeytrap deep crawl for concrete artifacts (wallets, contacts, payment instructions).",
  };

  return {
    attackType,
    riskScore: score,
    confidence,
    indicators,
    whatWouldHappen: WHAT[attackType],
  };
}

// ─── Sub components ───────────────────────────────────────────────────────────

function BrowserFrame({
  url,
  children,
}: {
  url: string;
  children: React.ReactNode;
}) {
  const danger =
    /\.(tk|xyz|ru|pw|click|gq|cf|ml|ga)$/.test(url.split("/")[2] ?? "") ||
    /secure-|login-|claim-|verify-|alert-/.test(url);
  return (
    <div
      className="rounded-2xl overflow-hidden border border-[#1e2a38] bg-[#0d1117] flex flex-col"
      style={{ minHeight: 460 }}
    >
      <div className="bg-[#111820] border-b border-[#1e2a38] px-4 py-2.5 flex items-center gap-3">
        <div className="flex gap-1.5 shrink-0">
          <div className="w-3 h-3 rounded-full bg-[#ff5f57]" />
          <div className="w-3 h-3 rounded-full bg-[#febc2e]" />
          <div className="w-3 h-3 rounded-full bg-[#28c840]" />
        </div>
        <div className="flex-1 bg-black/40 border border-[#1e2a38] rounded-md px-3 py-1.5 flex items-center gap-2 min-w-0">
          <span
            className={`text-xs shrink-0 ${danger ? "text-red-400" : "text-[#5a7a99]"}`}
          >
            {danger ? "⚠" : "🔒"}
          </span>
          <span
            className={`font-mono text-xs truncate ${danger ? "text-red-400" : "text-[#5a7a99]"}`}
          >
            {url}
          </span>
        </div>
      </div>
      <div className="flex-1 relative">{children}</div>
    </div>
  );
}

function InterceptScreen({
  result,
  onReset,
}: {
  result: AnalysisResult;
  onReset: () => void;
}) {
  const isBlocked = result.riskScore >= 30;
  const attackLabel =
    result.attackType === "unknown" ? "under_investigation" : result.attackType;

  return (
    <div
      className="absolute inset-0 z-50 flex flex-col items-center justify-center p-8 text-center"
      style={{ background: "rgba(7,9,13,0.97)", backdropFilter: "blur(8px)" }}
    >
      <div
        className="w-20 h-20 rounded-full border-2 border-[#00e5ff] bg-[#00e5ff]/10 flex items-center justify-center text-4xl mb-5"
        style={{ animation: "shieldPop .5s cubic-bezier(.34,1.56,.64,1) both" }}
      >
        🛡️
      </div>
      <h2 className="text-[#00e5ff] font-extrabold text-3xl tracking-tight mb-1">
        {isBlocked ? "ScamShield Blocked This" : "ScamShield Flagged This"}
      </h2>
      <p className="text-[#5a7a99] font-mono text-xs mb-6">
        community-reported · {attackLabel} · risk {result.riskScore}/100
      </p>

      {!isBlocked && (
        <div className="bg-[#00e5ff]/8 border border-[#00e5ff]/25 rounded-xl p-3 mb-4 text-left max-w-lg w-full">
          <p className="text-[#00e5ff] font-bold text-xs uppercase tracking-wider mb-1">
            Preliminary URL heuristic result
          </p>
          <p className="text-[#9dd8ff] font-mono text-xs leading-relaxed">
            This verdict is based on URL traits only. Use Honeytrap for deeper
            content interaction and stronger evidence.
          </p>
        </div>
      )}

      <div className="flex gap-3 mb-5 flex-wrap justify-center">
        {[
          ["Risk", result.riskScore],
          ["Confidence", result.confidence + "%"],
          ["Signals", result.indicators.length],
        ].map(([lab, val]) => (
          <div
            key={lab as string}
            className="bg-[#00e5ff]/5 border border-[#00e5ff]/20 rounded-xl px-5 py-3 text-center min-w-[88px]"
          >
            <div className="text-[#00e5ff] font-mono font-bold text-2xl">
              {val}
            </div>
            <div className="text-[#5a7a99] text-[10px] uppercase tracking-widest mt-0.5">
              {lab}
            </div>
          </div>
        ))}
      </div>

      <div className="bg-red-500/8 border border-red-500/20 rounded-xl p-4 mb-4 text-left max-w-lg w-full">
        <p className="text-red-400 font-bold text-xs uppercase tracking-wider mb-1.5">
          What would have happened:
        </p>
        <p className="text-red-300 font-mono text-xs leading-relaxed">
          {result.whatWouldHappen}
        </p>
      </div>

      {result.indicators.length > 0 && (
        <div className="bg-white/3 border border-[#1e2a38] rounded-xl p-4 mb-5 text-left max-w-lg w-full">
          <p className="text-[#5a7a99] font-mono text-[10px] uppercase tracking-widest mb-2">
            Detected signals:
          </p>
          <div className="flex flex-wrap gap-1.5">
            {result.indicators.map((s, i) => (
              <span
                key={i}
                className="bg-[#ffb800]/10 border border-[#ffb800]/25 text-[#ffb800] font-mono text-[10px] px-2 py-0.5 rounded-md"
              >
                {s}
              </span>
            ))}
          </div>
        </div>
      )}

      <button
        onClick={onReset}
        className="border border-[#00e5ff] text-[#00e5ff] font-mono text-sm px-7 py-2.5 rounded-xl hover:bg-[#00e5ff] hover:text-[#07090d] transition-all"
      >
        ↩ Try another URL
      </button>

      <style>{`
        @keyframes shieldPop {
          0%{transform:scale(.4);opacity:0}
          100%{transform:scale(1);opacity:1}
        }
      `}</style>
    </div>
  );
}

// ─── Attack visuals ───────────────────────────────────────────────────────────

function PhishingView({ sim }: { sim: SimState }) {
  return (
    <div
      className="w-full h-full flex items-center justify-center p-8"
      style={{ background: "#f0f2f5" }}
    >
      <div
        style={{
          background: "#fff",
          borderRadius: 8,
          padding: 28,
          width: "100%",
          maxWidth: 340,
          boxShadow: "0 4px 24px rgba(0,0,0,0.15)",
          fontFamily: "Segoe UI,sans-serif",
          color: "#1a1a2e",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            marginBottom: 22,
          }}
        >
          <svg width="34" height="34" viewBox="0 0 120 120">
            <ellipse cx="60" cy="60" r="55" fill="#f6851b" />
            <path d="M60 20L85 45L75 70L60 80L45 70L35 45Z" fill="#e2761b" />
            <circle cx="47" cy="52" r="6" fill="white" />
            <circle cx="73" cy="52" r="6" fill="white" />
            <circle cx="47" cy="53" r="3" fill="#1a1a2e" />
            <circle cx="73" cy="53" r="3" fill="#1a1a2e" />
          </svg>
          <span style={{ fontSize: 17, fontWeight: 700 }}>MetaMask</span>
        </div>
        <h2 style={{ fontSize: 15, fontWeight: 600, marginBottom: 4 }}>
          Welcome Back
        </h2>
        <p style={{ fontSize: 11, color: "#777", marginBottom: 18 }}>
          Enter your password to unlock your wallet
        </p>
        <div style={{ marginBottom: 12 }}>
          <label
            style={{
              display: "block",
              fontSize: 11,
              color: "#555",
              fontWeight: 600,
              marginBottom: 4,
            }}
          >
            Password
          </label>
          <input
            type="password"
            value={sim.typedPassword}
            readOnly
            style={{
              width: "100%",
              border: "1.5px solid #ddd",
              borderRadius: 5,
              padding: "9px 11px",
              fontSize: 13,
            }}
          />
        </div>
        {sim.showSeedField && (
          <div style={{ marginBottom: 12 }}>
            <label
              style={{
                display: "block",
                fontSize: 11,
                color: "#c00",
                fontWeight: 600,
                marginBottom: 4,
              }}
            >
              ⚠ Verify with seed phrase
            </label>
            <input
              type="text"
              value={sim.typedSeed}
              readOnly
              style={{
                width: "100%",
                border: "1.5px solid #f44",
                borderRadius: 5,
                padding: "9px 11px",
                fontSize: 12,
                background: "#fff8f8",
              }}
            />
          </div>
        )}
        {sim.showPasswordWrong && (
          <div
            style={{
              padding: "9px 11px",
              background: "#fff3cd",
              borderLeft: "3px solid #ffc107",
              borderRadius: 4,
              fontSize: 11,
              color: "#856404",
              marginBottom: 10,
            }}
          >
            Incorrect password. Verify using your 12-word seed phrase.
          </div>
        )}
        <button
          style={{
            width: "100%",
            background: "#f6851b",
            color: "#fff",
            border: "none",
            borderRadius: 5,
            padding: "11px",
            fontSize: 13,
            fontWeight: 700,
            cursor: "pointer",
          }}
        >
          Unlock
        </button>
      </div>
    </div>
  );
}

function DrainerView({
  sim,
  onWalletClick,
}: {
  sim: SimState;
  onWalletClick: () => void;
}) {
  const stages = [
    "Scanning assets…",
    "Reading balances…",
    "Building approval tx…",
    "Calling setApprovalForAll()…",
    "Submitting to mempool…",
    "Transfer complete",
  ];
  const stageIdx = Math.floor(sim.progress / 18);
  return (
    <div
      className="w-full h-full flex items-center justify-center p-8"
      style={{ background: "#0a0a1a" }}
    >
      <div
        style={{
          background: "#12122a",
          border: "1px solid #2a2a5a",
          borderRadius: 12,
          padding: 26,
          width: "100%",
          maxWidth: 360,
          color: "#e0e0ff",
          textAlign: "center",
          fontFamily: "Segoe UI,sans-serif",
        }}
      >
        <div style={{ fontSize: 30, marginBottom: 6 }}>🌊</div>
        <h2 style={{ fontSize: 16, fontWeight: 700, marginBottom: 3 }}>
          WaveSwap Finance
        </h2>
        <p style={{ fontSize: 11, color: "#8888cc", marginBottom: 20 }}>
          Connect wallet to claim 2.5 ETH airdrop
        </p>
        {!sim.walletConnecting ? (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {[
              ["🦊", "MetaMask"],
              ["👛", "WalletConnect"],
              ["⬡", "Coinbase Wallet"],
            ].map(([ico, name]) => (
              <div
                key={name}
                onClick={onWalletClick}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 12,
                  background: "#1a1a3a",
                  border: "1px solid #2a2a5a",
                  borderRadius: 7,
                  padding: "11px 14px",
                  cursor: "pointer",
                  fontSize: 13,
                }}
              >
                <span style={{ fontSize: 20 }}>{ico}</span>
                {name}
              </div>
            ))}
          </div>
        ) : (
          <div>
            <p
              style={{
                fontSize: 11,
                color: "#8888cc",
                fontFamily: "monospace",
                marginBottom: 10,
              }}
            >
              Requesting approval… do not close
            </p>
            <div
              style={{
                background: "#1a1a3a",
                borderRadius: 3,
                height: 5,
                overflow: "hidden",
                marginBottom: 6,
              }}
            >
              <div
                style={{
                  height: "100%",
                  background: "linear-gradient(90deg,#ff3b3b,#ff8800)",
                  width: sim.progress + "%",
                  transition: "width .1s",
                }}
              />
            </div>
            <p
              style={{
                fontFamily: "monospace",
                fontSize: 10,
                color: "#ff6060",
                marginBottom: 10,
              }}
            >
              {stages[Math.min(stageIdx, stages.length - 1)]}
            </p>
            {sim.progress > 60 && (
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  marginTop: 12,
                }}
              >
                <div>
                  <div style={{ color: "#888", fontSize: 10 }}>DRAINED</div>
                  <div
                    style={{ color: "#ff4444", fontWeight: 700, fontSize: 22 }}
                  >
                    ${sim.drainAmount.toLocaleString()}
                  </div>
                </div>
                <div style={{ textAlign: "right" }}>
                  <div style={{ color: "#888", fontSize: 10 }}>TOKENS</div>
                  <div
                    style={{ color: "#ff4444", fontWeight: 700, fontSize: 22 }}
                  >
                    {sim.drainTokens}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function PrizeView({ sim, onClaim }: { sim: SimState; onClaim: () => void }) {
  const mm = String(Math.floor(sim.prizeSeconds / 60)).padStart(2, "0");
  const ss = String(sim.prizeSeconds % 60).padStart(2, "0");
  return (
    <div
      className="w-full h-full flex items-center justify-center p-8 overflow-hidden"
      style={{ background: "linear-gradient(160deg,#1a0533,#0d1a3a)" }}
    >
      <div
        style={{
          background: "linear-gradient(135deg,#2a0a5e,#1a3a6e)",
          border: "2px solid gold",
          borderRadius: 14,
          padding: 26,
          width: "100%",
          maxWidth: 340,
          textAlign: "center",
          fontFamily: "Segoe UI,sans-serif",
          color: "#fff",
          boxShadow: "0 0 40px rgba(255,215,0,0.25)",
        }}
      >
        <div style={{ fontSize: 44, marginBottom: 6 }}>👑</div>
        <h2
          style={{
            fontSize: 20,
            fontWeight: 800,
            color: "gold",
            marginBottom: 4,
          }}
        >
          🎉 CONGRATULATIONS! 🎉
        </h2>
        <div style={{ fontSize: 32, fontWeight: 800, margin: "10px 0" }}>
          $50,000
        </div>
        <p style={{ fontSize: 11, color: "#aac", marginBottom: 16 }}>
          You are visitor #1,000,000! Claim before it expires.
        </p>
        <div
          style={{
            background: "rgba(0,0,0,0.3)",
            borderRadius: 6,
            padding: "8px 12px",
            marginBottom: 16,
            fontFamily: "monospace",
            color: "#ffcc00",
          }}
        >
          Expires in:{" "}
          <span style={{ fontSize: 20, fontWeight: 700 }}>
            {mm}:{ss}
          </span>
        </div>
        <input
          placeholder="Full name"
          style={{
            width: "100%",
            background: "rgba(255,255,255,0.1)",
            border: "1px solid rgba(255,255,255,0.2)",
            borderRadius: 5,
            padding: "8px 11px",
            fontSize: 12,
            color: "#fff",
            outline: "none",
            marginBottom: 7,
          }}
        />
        <input
          placeholder="Card number"
          style={{
            width: "100%",
            background: "rgba(255,255,255,0.1)",
            border: "1px solid rgba(255,255,255,0.2)",
            borderRadius: 5,
            padding: "8px 11px",
            fontSize: 12,
            color: "#fff",
            outline: "none",
            marginBottom: 7,
          }}
        />
        <div style={{ display: "flex", gap: 7, marginBottom: 12 }}>
          <input
            placeholder="MM/YY"
            style={{
              flex: 1,
              background: "rgba(255,255,255,0.1)",
              border: "1px solid rgba(255,255,255,0.2)",
              borderRadius: 5,
              padding: "8px 11px",
              fontSize: 12,
              color: "#fff",
              outline: "none",
            }}
          />
          <input
            placeholder="CVV"
            style={{
              flex: 0.6,
              background: "rgba(255,255,255,0.1)",
              border: "1px solid rgba(255,255,255,0.2)",
              borderRadius: 5,
              padding: "8px 11px",
              fontSize: 12,
              color: "#fff",
              outline: "none",
            }}
          />
        </div>
        <button
          onClick={onClaim}
          style={{
            width: "100%",
            background: "linear-gradient(90deg,#f7c948,#e89c28)",
            color: "#1a0533",
            border: "none",
            borderRadius: 7,
            padding: 11,
            fontSize: 13,
            fontWeight: 800,
            cursor: "pointer",
          }}
        >
          CLAIM MY $50,000 NOW →
        </button>
        <p
          style={{
            fontSize: 8,
            color: "rgba(255,255,255,0.25)",
            marginTop: 8,
            lineHeight: 1.6,
          }}
        >
          By claiming you agree to a $4.99 processing fee charged monthly until
          cancelled.
        </p>
      </div>
    </div>
  );
}

function MalwareView({
  sim,
  onDownload,
}: {
  sim: SimState;
  onDownload: () => void;
}) {
  return (
    <div
      className="w-full h-full flex items-center justify-center p-8"
      style={{ background: "#0f0f0f" }}
    >
      <div
        style={{
          background: "#1a1a1a",
          border: "1px solid #333",
          borderRadius: 7,
          width: "100%",
          maxWidth: 390,
          fontFamily: "Segoe UI,sans-serif",
          color: "#fff",
          boxShadow: "0 8px 32px rgba(0,0,0,0.5)",
        }}
      >
        <div
          style={{
            background: "#2d2d2d",
            padding: "9px 14px",
            borderRadius: "7px 7px 0 0",
            display: "flex",
            alignItems: "center",
            gap: 7,
            fontSize: 11,
            color: "#aaa",
          }}
        >
          <span>🪟</span> Windows Security Alert
        </div>
        <div style={{ padding: 22, textAlign: "center" }}>
          <div style={{ fontSize: 44, marginBottom: 10 }}>⚠️</div>
          <h2 style={{ fontSize: 15, marginBottom: 7 }}>
            Critical Security Update Required
          </h2>
          <p
            style={{
              fontSize: 11,
              color: "#999",
              marginBottom: 18,
              lineHeight: 1.6,
            }}
          >
            Your system is vulnerable to CVE-2024-38112. Download the emergency
            patch to prevent data loss.
          </p>
          <div
            style={{
              background: "#333",
              borderRadius: 3,
              height: 7,
              overflow: "hidden",
              marginBottom: 6,
            }}
          >
            <div
              style={{
                height: "100%",
                background: "linear-gradient(90deg,#0078d4,#00b4ff)",
                width: sim.progress + "%",
                transition: "width .05s",
              }}
            />
          </div>
          <p
            style={{
              fontSize: 10,
              color: "#888",
              fontFamily: "monospace",
              marginBottom: 14,
            }}
          >
            {sim.statusText}
          </p>
          {sim.logLines.length > 0 && (
            <div
              style={{
                background: "#0a0a0a",
                borderRadius: 3,
                padding: 10,
                fontFamily: "monospace",
                fontSize: 9,
                textAlign: "left",
                lineHeight: 1.9,
                maxHeight: 88,
                overflow: "hidden",
                marginBottom: 12,
              }}
            >
              {sim.logLines.map((l, i) => (
                <div
                  key={i}
                  style={{
                    color:
                      l.includes("RAT") ||
                      l.includes("FORGED") ||
                      l.includes("Exfil")
                        ? "#ff4444"
                        : "#00ff41",
                  }}
                >
                  {l}
                </div>
              ))}
            </div>
          )}
          <div style={{ display: "flex", gap: 8 }}>
            <button
              style={{
                flex: 1,
                padding: "8px",
                borderRadius: 3,
                fontSize: 12,
                cursor: "pointer",
                border: "1px solid #444",
                background: "#2d2d2d",
                color: "#fff",
              }}
            >
              Remind me later
            </button>
            <button
              onClick={onDownload}
              style={{
                flex: 1,
                padding: "8px",
                borderRadius: 3,
                fontSize: 12,
                fontWeight: 600,
                cursor: "pointer",
                background: "#0078d4",
                border: "none",
                color: "#fff",
              }}
            >
              Download Now (3.2 MB)
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Main ─────────────────────────────────────────────────────────────────────

export default function AttackSimulator() {
  const API_BASE = "http://localhost:10000/api";
  const [urlInput, setUrlInput] = useState("");
  const [displayUrl, setDisplayUrl] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [sim, setSim] = useState<SimState>(INITIAL_SIM);
  const [honeytrapUrl, setHoneytrapUrl] = useState("");
  const [honeytrapLoading, setHoneytrapLoading] = useState(false);
  const [honeytrapError, setHoneytrapError] = useState("");
  const [honeytrapIntel, setHoneytrapIntel] = useState<HoneytrapIntel | null>(
    null,
  );
  const [honeytrapHistory, setHoneytrapHistory] = useState<HoneytrapIntelRow[]>(
    [],
  );
  const [honeytrapPreviewStep, setHoneytrapPreviewStep] = useState(0);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);
  const ticker = useRef<ReturnType<typeof setInterval> | null>(null);

  const clear = useCallback(() => {
    timers.current.forEach(clearTimeout);
    timers.current = [];
    if (ticker.current) {
      clearInterval(ticker.current);
      ticker.current = null;
    }
  }, []);

  useEffect(() => () => clear(), [clear]);

  useEffect(() => {
    if (!honeytrapLoading) return;
    setHoneytrapPreviewStep(0);
    const interval = setInterval(() => {
      setHoneytrapPreviewStep((current) => Math.min(current + 1, 5));
    }, 950);
    return () => clearInterval(interval);
  }, [honeytrapLoading]);

  const after = (ms: number, fn: () => void) => {
    const t = setTimeout(fn, ms);
    timers.current.push(t);
  };
  const patch = (p: Partial<SimState>) => setSim((s) => ({ ...s, ...p }));

  const analyze = (e: React.FormEvent) => {
    e.preventDefault();
    if (!urlInput.trim()) return;
    clear();
    setSim(INITIAL_SIM);
    const r = analyzeURL(urlInput);
    setResult(r);
    const full = urlInput.startsWith("http") ? urlInput : "https://" + urlInput;
    setDisplayUrl(full);
  };

  const run = useCallback(() => {
    if (!result) return;
    patch({ phase: "running" });

    if (result.attackType === "phishing") {
      const pw = "MyWallet2024!";
      let i = 0;
      ticker.current = setInterval(() => {
        if (i < pw.length) {
          patch({ typedPassword: pw.slice(0, ++i) });
        } else {
          clearInterval(ticker.current!);
          after(400, () =>
            patch({ showPasswordWrong: true, showSeedField: true }),
          );
          after(1000, () => {
            const seed = "witch collapse practice feed shame open";
            let j = 0;
            ticker.current = setInterval(() => {
              if (j < seed.length) {
                patch({ typedSeed: seed.slice(0, ++j) });
              } else {
                clearInterval(ticker.current!);
                after(900, () => patch({ phase: "intercepted" }));
              }
            }, 42);
          });
        }
      }, 80);
    } else if (result.attackType === "drainer") {
      patch({ walletConnecting: true });
      _drain();
    } else if (result.attackType === "prize") {
      ticker.current = setInterval(
        () =>
          setSim((s) => ({
            ...s,
            prizeSeconds: Math.max(0, s.prizeSeconds - 1),
          })),
        1000,
      );
      after(1400, () => patch({ phase: "intercepted" }));
    } else if (result.attackType === "malware") {
      _malware();
    } else {
      after(1200, () => patch({ phase: "intercepted" }));
    }
  }, [result]);

  const _drain = () => {
    const stages: [number, string][] = [
      [15, "Scanning assets…"],
      [30, "Reading token balances…"],
      [50, "Building approval tx…"],
      [65, "Calling setApprovalForAll()…"],
      [80, "Submitting to mempool…"],
      [95, "Transaction confirmed…"],
      [100, "Transfer complete"],
    ];
    let pct = 0;
    let si = 0;
    ticker.current = setInterval(() => {
      pct = Math.min(pct + 1, 100);
      if (si < stages.length && pct >= stages[si][0])
        patch({ statusText: stages[si++][1] });
      const drain = pct >= 65 ? Math.floor(((pct - 65) / 35) * 24350) : 0;
      const tok =
        pct >= 65 ? Math.min(7, Math.floor(((pct - 65) / 35) * 7)) : 0;
      patch({ progress: pct, drainAmount: drain, drainTokens: tok });
      if (pct >= 100) {
        clearInterval(ticker.current!);
        after(700, () => patch({ phase: "intercepted" }));
      }
    }, 40);
  };

  const _malware = () => {
    const LOG = [
      "> Downloading WindowsSecurityPatch.exe…",
      "> Verifying signature… [FORGED]",
      "> Extracting payload…",
      "> Installing AsyncRAT.dll",
      "> Adding registry autorun key…",
      "> Connecting to C2: 185.220.101.x",
      "> Keylogger active. Capturing input…",
      "> Scanning for crypto wallets…",
      "> Exfiltrating: credentials.db (2.1 MB)",
    ];
    let pct = 0;
    let li = 0;
    patch({ statusText: "Downloading…" });
    ticker.current = setInterval(() => {
      pct = Math.min(pct + 0.8, 100);
      const txt =
        pct < 40
          ? `${Math.floor(pct)}% — Downloading…`
          : pct < 70
            ? `${Math.floor(pct)}% — Installing…`
            : `${Math.floor(pct)}% — Configuring…`;
      if (li < LOG.length && pct >= (li + 1) * 10) {
        setSim((s) => ({
          ...s,
          progress: pct,
          statusText: txt,
          logLines: [...s.logLines, LOG[li++]],
        }));
      } else {
        patch({ progress: pct, statusText: txt });
      }
      if (pct >= 100) {
        clearInterval(ticker.current!);
        after(600, () => patch({ phase: "intercepted" }));
      }
    }, 30);
  };

  const reset = () => {
    clear();
    setSim(INITIAL_SIM);
    setResult(null);
    setDisplayUrl("");
    setUrlInput("");
  };

  const runHoneytrap = async () => {
    const target = honeytrapUrl.trim() || displayUrl.trim() || urlInput.trim();
    if (!target) {
      setHoneytrapError("Enter a URL first");
      return;
    }

    setHoneytrapError("");
    setHoneytrapHistory([]);
    setHoneytrapPreviewStep(0);
    setHoneytrapLoading(true);
    try {
      const res = await fetch(`${API_BASE}/honeytrap/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: target,
          persona: "I'm new to crypto and want to claim the airdrop",
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.detail || "Honeytrap request failed");
      setHoneytrapIntel(data);

      const domainForLookup = (data?.domain || "")
        .toString()
        .toLowerCase()
        .replace(/^www\./, "");
      if (domainForLookup) {
        const intelRes = await fetch(
          `${API_BASE}/honeytrap/intel?limit=12&domain=${encodeURIComponent(domainForLookup)}`,
        );
        if (intelRes.ok) {
          const intelData = await intelRes.json();
          if (Array.isArray(intelData)) {
            setHoneytrapHistory(intelData as HoneytrapIntelRow[]);
          }
        }
      }
    } catch (error) {
      setHoneytrapError(
        error instanceof Error ? error.message : "Honeytrap request failed",
      );
    } finally {
      setHoneytrapLoading(false);
    }
  };

  const EXAMPLES = [
    { label: "Phishing", url: "http://meta-mask-secure-login.tk/unlock" },
    {
      label: "Drainer",
      url: "http://waveswap-airdrop-claim.xyz/connect-wallet",
    },
    { label: "Prize", url: "http://winner-1000000-prize.ru/claim-now" },
    {
      label: "Malware",
      url: "http://windows-security-patch-2024.com/critical-update.exe",
    },
  ];

  const TYPE_META: Record<
    AttackType,
    { emoji: string; label: string; cls: string }
  > = {
    phishing: {
      emoji: "🎣",
      label: "Phishing",
      cls: "text-orange-400 border-orange-400/30 bg-orange-400/10",
    },
    drainer: {
      emoji: "💀",
      label: "Crypto Drainer",
      cls: "text-red-400 border-red-400/30 bg-red-400/10",
    },
    prize: {
      emoji: "🎰",
      label: "Fake Prize",
      cls: "text-yellow-400 border-yellow-400/30 bg-yellow-400/10",
    },
    malware: {
      emoji: "☣️",
      label: "Malware",
      cls: "text-blue-400 border-blue-400/30 bg-blue-400/10",
    },
    unknown: {
      emoji: "❓",
      label: "Suspicious",
      cls: "text-gray-400 border-gray-600/30 bg-white/5",
    },
  };

  const walletClick = () => {
    if (sim.phase === "idle") run();
  };
  const claimClick = () => {
    if (sim.phase === "idle") run();
  };
  const dlClick = () => {
    if (sim.phase === "idle") run();
  };

  const HONEYTRAP_STEPS = [
    "Queueing investigation",
    "Opening target URL",
    "Extracting wallets/contacts",
    "Scoring domain & network",
    "Persisting intel",
    "Preparing response",
  ];

  return (
    <div
      className="min-h-screen text-white"
      style={{ background: "#07090d", fontFamily: "'DM Sans',sans-serif" }}
    >
      {/* Subtle grid */}
      <div
        className="fixed inset-0 pointer-events-none"
        style={{
          backgroundImage:
            "linear-gradient(rgba(0,229,255,.022) 1px,transparent 1px),linear-gradient(90deg,rgba(0,229,255,.022) 1px,transparent 1px)",
          backgroundSize: "40px 40px",
        }}
      />

      <div className="relative z-10 max-w-2xl mx-auto px-5 py-12">
        {/* Header */}
        <div className="text-center mb-10">
          <div className="inline-flex items-center gap-2 font-mono text-xs text-[#00e5ff] tracking-[.15em] uppercase border border-[#00e5ff]/20 px-3 py-1.5 rounded mb-5">
            <span className="text-[9px]">▶</span> ScamShield Demo
          </div>
          <h1
            className="text-4xl sm:text-[48px] font-extrabold leading-[1.06]"
            style={{ letterSpacing: "-0.025em" }}
          >
            Paste any link.
            <br />
            <span className="text-[#ff3b3b]">Watch the attack.</span>
            <br />
            <span className="text-[#00e5ff]">See it blocked.</span>
          </h1>
          <p className="text-[#5a7a99] text-sm mt-4 max-w-sm mx-auto leading-relaxed">
            ScamShield detects the attack type from the URL and runs a contained
            live simulation.
          </p>
        </div>

        {/* Input */}
        <form onSubmit={analyze} className="mb-3">
          <div className="flex gap-2">
            <input
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="Paste any suspicious URL here…"
              className="flex-1 bg-[#111820] border border-[#1e2a38] rounded-xl px-4 py-3.5 font-mono text-sm text-white placeholder-[#3a5060] outline-none focus:border-[#00e5ff]/40 transition-colors"
            />
            <button
              type="submit"
              className="bg-[#ff3b3b] hover:bg-red-600 text-white font-bold px-6 rounded-xl transition-all text-sm shrink-0"
            >
              Analyze
            </button>
          </div>
        </form>

        {/* Example pills */}
        <div className="flex flex-wrap gap-2 mb-7 items-center">
          <span className="text-[#5a7a99] font-mono text-[10px]">try:</span>
          {EXAMPLES.map(({ label, url: u }) => (
            <button
              key={label}
              onClick={() => setUrlInput(u)}
              className="font-mono text-[10px] border border-[#1e2a38] text-[#5a7a99] hover:text-white hover:border-[#00e5ff]/30 px-2.5 py-1 rounded-lg transition-all"
            >
              {label}
            </button>
          ))}
        </div>

        {/* Result badge row */}
        {result && (
          <div className="flex flex-wrap items-center gap-3 mb-3">
            <span
              className={`inline-flex items-center gap-1.5 font-mono text-xs border px-2.5 py-1 rounded-lg ${TYPE_META[result.attackType].cls}`}
            >
              {TYPE_META[result.attackType].emoji}{" "}
              {TYPE_META[result.attackType].label}
            </span>
            <div className="flex items-center gap-2">
              <div className="h-1 rounded-full w-28 bg-[#1e2a38] overflow-hidden">
                <div
                  className="h-full bg-[#ff3b3b] rounded-full"
                  style={{ width: result.riskScore + "%" }}
                />
              </div>
              <span className="font-mono text-xs text-[#ff3b3b]">
                {result.riskScore}/100
              </span>
            </div>
            <span className="font-mono text-[10px] text-[#5a7a99]">
              {result.confidence}% confidence
            </span>
          </div>
        )}

        {/* Stage */}
        {result ? (
          <>
            <BrowserFrame url={displayUrl}>
              {result.attackType === "phishing" && <PhishingView sim={sim} />}
              {result.attackType === "drainer" && (
                <DrainerView sim={sim} onWalletClick={walletClick} />
              )}
              {result.attackType === "prize" && (
                <PrizeView sim={sim} onClaim={claimClick} />
              )}
              {result.attackType === "malware" && (
                <MalwareView sim={sim} onDownload={dlClick} />
              )}
              {result.attackType === "unknown" && (
                <div className="w-full h-full flex flex-col items-center justify-center text-center p-10">
                  <div className="text-5xl mb-3 opacity-25">🔍</div>
                  <p className="text-[#5a7a99] font-mono text-xs">
                    Suspicious URL · {result.indicators.length} signals detected
                  </p>
                </div>
              )}
              {sim.phase === "intercepted" && (
                <InterceptScreen result={result} onReset={reset} />
              )}
            </BrowserFrame>

            {sim.phase !== "intercepted" && (
              <div className="mt-4 flex items-center justify-center gap-3">
                {sim.phase === "idle" && (
                  <button
                    onClick={run}
                    className="bg-[#ff3b3b] hover:bg-red-600 text-white font-bold px-8 py-3 rounded-xl flex items-center gap-2 transition-all text-sm"
                  >
                    ▶ Run Attack Simulation
                  </button>
                )}
                {sim.phase === "running" && (
                  <div className="flex items-center gap-2 font-mono text-xs text-[#5a7a99]">
                    <div className="w-2 h-2 rounded-full bg-[#ff3b3b] animate-pulse" />
                    Simulation running…
                  </div>
                )}
                <button
                  onClick={reset}
                  className="border border-[#1e2a38] text-[#5a7a99] hover:text-white hover:border-[#00e5ff]/30 font-mono text-xs px-4 py-3 rounded-xl transition-all"
                >
                  Reset
                </button>
              </div>
            )}
          </>
        ) : (
          <div className="rounded-2xl border border-[#1e2a38] bg-[#0d1117] flex flex-col items-center justify-center text-center py-20">
            <div className="text-5xl mb-3 opacity-20">🛡️</div>
            <p className="text-[#5a7a99] font-mono text-xs">
              Enter a URL above to begin
            </p>
          </div>
        )}

        <p className="text-center font-mono text-[10px] text-[#5a7a99] opacity-40 mt-6">
          All simulations are fully contained — no real network requests, no
          actual harm. Demo only.
        </p>

        <div className="mt-8 rounded-2xl border border-[#1e2a38] bg-[#0d1117] p-5">
          <div className="flex items-center justify-between gap-4 flex-wrap mb-4">
            <div>
              <h3 className="text-[#00e5ff] font-bold text-lg">
                Honeytrap Scammer Interaction Bot
              </h3>
              <p className="text-[#5a7a99] text-xs">
                Visits scam page, extracts wallets / telegram / emails / payment
                instructions
              </p>
            </div>
            <div className="font-mono text-[10px] text-[#5a7a99]">
              FastAPI endpoint: /api/honeytrap/run
            </div>
          </div>

          <div className="flex gap-2 flex-wrap mb-4">
            <input
              value={honeytrapUrl}
              onChange={(e) => setHoneytrapUrl(e.target.value)}
              placeholder="Scam URL for honeytrap run"
              className="flex-1 min-w-[260px] bg-[#111820] border border-[#1e2a38] rounded-xl px-3 py-2 font-mono text-xs text-white placeholder-[#3a5060] outline-none focus:border-[#00e5ff]/40"
            />
            <button
              onClick={runHoneytrap}
              disabled={honeytrapLoading}
              className="bg-[#00e5ff] hover:bg-cyan-400 disabled:opacity-60 text-[#07090d] font-bold px-4 rounded-xl text-xs"
            >
              {honeytrapLoading ? "Running…" : "Run Honeytrap"}
            </button>
          </div>

          {(honeytrapLoading || honeytrapIntel) && (
            <div className="mb-4 rounded-lg border border-[#1e2a38] bg-white/5 p-3">
              <div className="flex items-center justify-between gap-2 mb-2">
                <div className="text-[#00e5ff] text-xs font-semibold">
                  Honeytrap Activity Preview
                </div>
                <div className="text-[#5a7a99] text-[10px] font-mono">
                  {honeytrapLoading ? "live" : "last run"}
                </div>
              </div>

              <div className="h-1.5 rounded-full bg-[#1e2a38] overflow-hidden mb-3">
                <div
                  className="h-full bg-[#00e5ff] transition-all duration-500"
                  style={{
                    width: `${honeytrapLoading ? ((honeytrapPreviewStep + 1) / HONEYTRAP_STEPS.length) * 100 : 100}%`,
                  }}
                />
              </div>

              <div className="space-y-1.5">
                {HONEYTRAP_STEPS.map((step, idx) => {
                  const done = honeytrapLoading
                    ? idx < honeytrapPreviewStep
                    : true;
                  const active =
                    honeytrapLoading && idx === honeytrapPreviewStep;
                  return (
                    <div
                      key={step}
                      className={`font-mono text-[11px] ${
                        active
                          ? "text-[#00e5ff]"
                          : done
                            ? "text-[#a7f3d0]"
                            : "text-[#5a7a99]"
                      }`}
                    >
                      {active ? "▸" : done ? "✓" : "•"} {step}
                    </div>
                  );
                })}
              </div>

              {!honeytrapLoading && honeytrapIntel?.evidence?.length ? (
                <div className="mt-3 border-t border-[#1e2a38] pt-2">
                  <div className="text-[#ffb800] text-[10px] uppercase mb-1">
                    Snapshot
                  </div>
                  <div className="font-mono text-[11px] text-[#5a7a99] break-all">
                    {(honeytrapIntel.evidence || [])[0]}
                  </div>
                </div>
              ) : null}
            </div>
          )}

          {honeytrapError && (
            <div className="mb-4 text-red-400 text-xs font-mono border border-red-500/30 bg-red-500/5 rounded-lg p-2">
              {honeytrapError}
            </div>
          )}

          {honeytrapIntel && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                <div className="rounded-lg border border-[#1e2a38] p-2">
                  <div className="text-[#5a7a99] text-[10px] uppercase">
                    URL Model
                  </div>
                  <div className="text-[#93c5fd] font-mono font-bold text-sm uppercase">
                    {honeytrapIntel.urlModelStatus || "unknown"}
                  </div>
                </div>
                <div className="rounded-lg border border-[#1e2a38] p-2">
                  <div className="text-[#5a7a99] text-[10px] uppercase">
                    URL Model Score
                  </div>
                  <div className="text-[#93c5fd] font-mono font-bold text-lg">
                    {honeytrapIntel.urlModelScore ?? 0}
                  </div>
                </div>
                <div className="rounded-lg border border-[#1e2a38] p-2">
                  <div className="text-[#5a7a99] text-[10px] uppercase">
                    Forms Seen
                  </div>
                  <div className="text-[#00e5ff] font-mono font-bold text-lg">
                    {honeytrapIntel.formIntel?.length ?? 0}
                  </div>
                </div>
                <div className="rounded-lg border border-[#1e2a38] p-2">
                  <div className="text-[#5a7a99] text-[10px] uppercase">
                    Chat Exchanges
                  </div>
                  <div className="text-[#00e5ff] font-mono font-bold text-lg">
                    {honeytrapIntel.chatExchanges?.length ?? 0}
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
                <div className="rounded-lg border border-[#1e2a38] p-2">
                  <div className="text-[#5a7a99] text-[10px] uppercase">
                    Domain Risk
                  </div>
                  <div className="text-red-400 font-mono font-bold text-lg">
                    {honeytrapIntel.domainRisk}
                  </div>
                </div>
                <div className="rounded-lg border border-[#1e2a38] p-2">
                  <div className="text-[#5a7a99] text-[10px] uppercase">
                    Network Risk
                  </div>
                  <div className="text-orange-400 font-mono font-bold text-lg">
                    {honeytrapIntel.scamNetworkRisk}
                  </div>
                </div>
                <div className="rounded-lg border border-[#1e2a38] p-2">
                  <div className="text-[#5a7a99] text-[10px] uppercase">
                    Connected Domains
                  </div>
                  <div className="text-[#00e5ff] font-mono font-bold text-lg">
                    {honeytrapIntel.connectedDomains}
                  </div>
                </div>
                <div className="rounded-lg border border-[#1e2a38] p-2">
                  <div className="text-[#5a7a99] text-[10px] uppercase">
                    Shared Wallets
                  </div>
                  <div className="text-[#00e5ff] font-mono font-bold text-lg">
                    {honeytrapIntel.sharedWallets}
                  </div>
                </div>
                <div className="rounded-lg border border-[#1e2a38] p-2">
                  <div className="text-[#5a7a99] text-[10px] uppercase">
                    Active Campaign
                  </div>
                  <div
                    className={`font-mono font-bold text-lg ${honeytrapIntel.activeCampaign ? "text-red-400" : "text-green-400"}`}
                  >
                    {honeytrapIntel.activeCampaign ? "YES" : "NO"}
                  </div>
                </div>
              </div>

              <div className="grid md:grid-cols-2 gap-3">
                <div className="rounded-lg border border-[#1e2a38] p-3">
                  <div className="text-[#ffb800] text-xs font-semibold mb-1">
                    Scam wallets captured
                  </div>
                  {honeytrapIntel.wallets.length ? (
                    honeytrapIntel.wallets.map((wallet) => (
                      <div
                        key={wallet}
                        className="font-mono text-[11px] text-[#fca5a5] break-all"
                      >
                        {wallet}
                      </div>
                    ))
                  ) : (
                    <div className="text-[#5a7a99] text-xs">None detected</div>
                  )}
                </div>
                <div className="rounded-lg border border-[#1e2a38] p-3">
                  <div className="text-[#ffb800] text-xs font-semibold mb-1">
                    Telegram IDs
                  </div>
                  {honeytrapIntel.telegramIds.length ? (
                    honeytrapIntel.telegramIds.map((id) => (
                      <div
                        key={id}
                        className="font-mono text-[11px] text-[#93c5fd]"
                      >
                        {id}
                      </div>
                    ))
                  ) : (
                    <div className="text-[#5a7a99] text-xs">None detected</div>
                  )}
                </div>
              </div>

              <div className="grid md:grid-cols-2 gap-3">
                <div className="rounded-lg border border-[#1e2a38] p-3">
                  <div className="text-[#ffb800] text-xs font-semibold mb-1">
                    Emails
                  </div>
                  {honeytrapIntel.emails.length ? (
                    honeytrapIntel.emails.map((email) => (
                      <div
                        key={email}
                        className="font-mono text-[11px] text-[#a7f3d0]"
                      >
                        {email}
                      </div>
                    ))
                  ) : (
                    <div className="text-[#5a7a99] text-xs">None detected</div>
                  )}
                </div>
                <div className="rounded-lg border border-[#1e2a38] p-3">
                  <div className="text-[#ffb800] text-xs font-semibold mb-1">
                    Payment instructions
                  </div>
                  {honeytrapIntel.paymentInstructions.length ? (
                    honeytrapIntel.paymentInstructions.map(
                      (instruction, idx) => (
                        <div
                          key={`${idx}-${instruction}`}
                          className="font-mono text-[11px] text-[#fde68a]"
                        >
                          {instruction}
                        </div>
                      ),
                    )
                  ) : (
                    <div className="text-[#5a7a99] text-xs">None detected</div>
                  )}
                </div>
              </div>

              <div className="grid md:grid-cols-2 gap-3">
                <div className="rounded-lg border border-[#1e2a38] p-3">
                  <div className="text-[#ffb800] text-xs font-semibold mb-1">
                    Phones / WhatsApp
                  </div>
                  {(honeytrapIntel.phones || []).length ? (
                    (honeytrapIntel.phones || []).map((phone) => (
                      <div
                        key={phone}
                        className="font-mono text-[11px] text-[#d8b4fe]"
                      >
                        {phone}
                      </div>
                    ))
                  ) : (
                    <div className="text-[#5a7a99] text-xs">None detected</div>
                  )}
                </div>
                <div className="rounded-lg border border-[#1e2a38] p-3">
                  <div className="text-[#ffb800] text-xs font-semibold mb-1">
                    Crawl Metadata
                  </div>
                  <div className="text-[#5a7a99] text-xs">
                    Domain: {honeytrapIntel.domain}
                  </div>
                  <div className="text-[#5a7a99] text-xs break-all">
                    URL: {honeytrapIntel.url}
                  </div>
                  {honeytrapIntel.pageTitle && (
                    <div className="text-[#5a7a99] text-xs">
                      Title: {honeytrapIntel.pageTitle}
                    </div>
                  )}
                  <div className="text-[#5a7a99] text-xs">
                    Method:{" "}
                    {honeytrapIntel.evidence
                      .find((line) => line.startsWith("Crawler:"))
                      ?.replace("Crawler:", "")
                      .trim() || "unknown"}
                  </div>
                </div>
              </div>

              {!!honeytrapHistory.length && (
                <div className="rounded-lg border border-[#1e2a38] p-3 bg-white/5">
                  <div className="text-[#00e5ff] text-xs font-semibold mb-2">
                    Historical Intel (same domain)
                  </div>
                  <div className="text-[#5a7a99] text-xs mb-2">
                    Samples: {honeytrapHistory.length}
                    {honeytrapIntel.history?.latestCapturedAt
                      ? ` · latest: ${honeytrapIntel.history.latestCapturedAt}`
                      : ""}
                  </div>
                  <div className="grid md:grid-cols-2 gap-3">
                    <div>
                      <div className="text-[#ffb800] text-xs mb-1">
                        Recovered wallets
                      </div>
                      {(honeytrapIntel.history?.wallets || []).length ? (
                        (honeytrapIntel.history?.wallets || []).map(
                          (wallet) => (
                            <div
                              key={wallet}
                              className="font-mono text-[11px] text-[#fca5a5] break-all"
                            >
                              {wallet}
                            </div>
                          ),
                        )
                      ) : (
                        <div className="text-[#5a7a99] text-xs">
                          None in history
                        </div>
                      )}
                    </div>
                    <div>
                      <div className="text-[#ffb800] text-xs mb-1">
                        Recovered contacts
                      </div>
                      {[
                        ...(honeytrapIntel.history?.telegramIds || []),
                        ...(honeytrapIntel.history?.emails || []),
                      ].length ? (
                        [
                          ...(honeytrapIntel.history?.telegramIds || []),
                          ...(honeytrapIntel.history?.emails || []),
                        ].map((item) => (
                          <div
                            key={item}
                            className="font-mono text-[11px] text-[#93c5fd] break-all"
                          >
                            {item}
                          </div>
                        ))
                      ) : (
                        <div className="text-[#5a7a99] text-xs">
                          None in history
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {honeytrapIntel.crawlDiagnostics && (
                <div className="rounded-lg border border-[#1e2a38] p-3 bg-white/5">
                  <div className="text-[#00e5ff] text-xs font-semibold mb-2">
                    Crawl Diagnostics
                  </div>
                  <div className="grid sm:grid-cols-2 gap-2 mb-2">
                    <div className="text-[#5a7a99] text-xs">
                      Method:{" "}
                      {honeytrapIntel.crawlDiagnostics.method || "unknown"}
                    </div>
                    <div className="text-[#5a7a99] text-xs break-all">
                      Cause:{" "}
                      {honeytrapIntel.crawlDiagnostics.likelyCause || "none"}
                    </div>
                    <div className="text-[#5a7a99] text-xs">
                      unreachable:{" "}
                      {String(
                        Boolean(honeytrapIntel.crawlDiagnostics.unreachable),
                      )}
                    </div>
                    <div className="text-[#5a7a99] text-xs">
                      playwrightMissing:{" "}
                      {String(
                        Boolean(
                          honeytrapIntel.crawlDiagnostics.playwrightMissing,
                        ),
                      )}
                    </div>
                    <div className="text-[#5a7a99] text-xs">
                      dnsFailure:{" "}
                      {String(
                        Boolean(honeytrapIntel.crawlDiagnostics.dnsFailure),
                      )}
                    </div>
                    <div className="text-[#5a7a99] text-xs">
                      timeout:{" "}
                      {String(Boolean(honeytrapIntel.crawlDiagnostics.timeout))}
                    </div>
                  </div>
                  {(honeytrapIntel.crawlDiagnostics.recommendations || [])
                    .length > 0 && (
                    <div className="space-y-1">
                      <div className="text-[#ffb800] text-xs font-semibold">
                        Recommendations
                      </div>
                      {(
                        honeytrapIntel.crawlDiagnostics.recommendations || []
                      ).map((tip, idx) => (
                        <div
                          key={`${idx}-${tip}`}
                          className="font-mono text-[11px] text-[#a7f3d0] break-all"
                        >
                          • {tip}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              <div className="rounded-lg border border-[#1e2a38] p-3">
                <div className="text-[#00e5ff] text-xs font-semibold mb-1">
                  Evidence Log
                </div>
                <div className="max-h-36 overflow-auto space-y-1">
                  {(honeytrapIntel.evidence || []).map((line, idx) => (
                    <div
                      key={`${idx}-${line}`}
                      className="font-mono text-[11px] text-[#5a7a99] break-all"
                    >
                      • {line}
                    </div>
                  ))}
                </div>
              </div>

              {honeytrapIntel.walletBlockchainReport && (
                <div className="rounded-lg border border-[#1e2a38] p-3 bg-white/5">
                  <div className="text-[#00e5ff] text-xs font-semibold mb-1">
                    Wallet Blockchain Report
                  </div>
                  <div className="text-[#5a7a99] text-xs">
                    attempted:{" "}
                    {String(honeytrapIntel.walletBlockchainReport.attempted)}
                  </div>
                  <div className="text-[#5a7a99] text-xs">
                    submitted:{" "}
                    {String(honeytrapIntel.walletBlockchainReport.submitted)}
                  </div>
                  <div className="text-[#5a7a99] text-xs">
                    alreadyReported:{" "}
                    {String(
                      honeytrapIntel.walletBlockchainReport.alreadyReported,
                    )}
                  </div>
                  {honeytrapIntel.walletBlockchainReport.txHash && (
                    <div className="font-mono text-[11px] text-[#93c5fd] break-all mt-1">
                      tx: {honeytrapIntel.walletBlockchainReport.txHash}
                    </div>
                  )}
                  {honeytrapIntel.walletBlockchainReport.error && (
                    <div className="font-mono text-[11px] text-red-400 break-all mt-1">
                      error: {honeytrapIntel.walletBlockchainReport.error}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
