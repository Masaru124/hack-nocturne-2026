"use client";
import Navbar from "@/components/Navbar";
import { useState, useEffect, useRef, useCallback } from "react";

// ─── Types ────────────────────────────────────────────────────────────────────

type AttackType = "phishing" | "drainer" | "prize" | "malware" | "unknown";
type SimPhase = "idle" | "running" | "intercepted";

interface AnalysisResult {
  ok: true;
  attackType: AttackType;
  riskScore: number;
  confidence: number;
  indicators: string[];
  source: "ai" | "heuristic" | "fallback";
  url: string;
  domain: string;
  analysedAt: string;
}

interface AnalyzeErrorResponse {
  ok: false;
  error: string;
  code:
    | "MISSING_URL"
    | "INVALID_URL"
    | "URL_TOO_LONG"
    | "ANALYSIS_FAILED"
    | "INTERNAL_ERROR";
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
  behaviorSignals?: string[];
  notablePageText?: string[];
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

// ─── Helpers ─────────────────────────────────────────────────────────────────

function isAnalysisResult(value: unknown): value is AnalysisResult {
  if (!value || typeof value !== "object") return false;
  const data = value as Partial<AnalysisResult>;
  return (
    data.ok === true &&
    typeof data.attackType === "string" &&
    typeof data.riskScore === "number" &&
    typeof data.confidence === "number" &&
    Array.isArray(data.indicators) &&
    typeof data.source === "string" &&
    typeof data.url === "string" &&
    typeof data.domain === "string" &&
    typeof data.analysedAt === "string"
  );
}

function getImpactNarrative(attackType: AttackType): string {
  const impact: Record<AttackType, string> = {
    phishing:
      "Credentials or seed phrase could be submitted to attacker infrastructure, followed by immediate account takeover.",
    drainer:
      "A malicious approval or connection flow can grant token spending rights, then rapidly sweep wallet assets.",
    prize:
      "Victims are pressured with urgency to submit payment or card details for a fake reward that never arrives.",
    malware:
      "A fake update or download can install remote-control malware, steal credentials, and monitor wallet activity.",
    unknown:
      "The URL has suspicious characteristics but requires deeper interaction analysis for definitive exploit behavior.",
  };
  return impact[attackType];
}

function getRiskBand(score: number): "low" | "medium" | "high" | "critical" {
  if (score >= 85) return "critical";
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  return "low";
}

function formatAnalysedAt(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString();
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
      className="rounded-2xl border border-[#1e2a38] bg-[#0d1117] flex flex-col"
      style={{ minHeight: 800 }}
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
        className="w-20 h-40 rounded-full border-2 border-[#00e5ff] bg-[#00e5ff]/10 flex items-center justify-center text-4xl mb-5"
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
        <div className="bg-[#00e5ff]/8 border border-[#00e5ff]/25 rounded-xl p-4 mb-4 text-left max-w-lg w-full space-y-3">
          <p className="text-[#00e5ff] font-bold text-xs uppercase tracking-wider">
            Detailed Flagged Insights
          </p>

          <div className="grid grid-cols-2 gap-2">
            <div className="rounded-lg border border-[#00e5ff]/20 bg-black/20 p-2">
              <div className="text-[#5a7a99] text-[10px] uppercase">
                Risk Band
              </div>
              <div className="text-[#9dd8ff] font-mono text-xs font-semibold uppercase">
                {getRiskBand(result.riskScore)} ({result.riskScore}/100)
              </div>
            </div>
            <div className="rounded-lg border border-[#00e5ff]/20 bg-black/20 p-2">
              <div className="text-[#5a7a99] text-[10px] uppercase">
                Confidence
              </div>
              <div className="text-[#9dd8ff] font-mono text-xs font-semibold">
                {result.confidence}%
              </div>
            </div>
            <div className="rounded-lg border border-[#00e5ff]/20 bg-black/20 p-2">
              <div className="text-[#5a7a99] text-[10px] uppercase">
                Detection Source
              </div>
              <div className="text-[#9dd8ff] font-mono text-xs font-semibold uppercase">
                {result.source}
              </div>
            </div>
            <div className="rounded-lg border border-[#00e5ff]/20 bg-black/20 p-2">
              <div className="text-[#5a7a99] text-[10px] uppercase">
                Analyzed At
              </div>
              <div className="text-[#9dd8ff] font-mono text-xs leading-relaxed">
                {formatAnalysedAt(result.analysedAt)}
              </div>
            </div>
          </div>

          <div className="rounded-lg border border-[#00e5ff]/20 bg-black/20 p-2.5">
            <div className="text-[#5a7a99] text-[10px] uppercase mb-1">
              Why It Was Flagged
            </div>
            {result.indicators.length > 0 ? (
              <div className="space-y-1">
                {result.indicators.slice(0, 4).map((signal, idx) => (
                  <div
                    key={`${signal}-${idx}`}
                    className="text-[#9dd8ff] font-mono text-[11px]"
                  >
                    {idx + 1}. {signal}
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-[#9dd8ff] font-mono text-[11px]">
                Suspicious URL traits detected without explicit indicator text.
              </div>
            )}
          </div>

          <div className="rounded-lg border border-[#00e5ff]/20 bg-black/20 p-2.5">
            <div className="text-[#5a7a99] text-[10px] uppercase mb-1">
              Recommended Next Actions
            </div>
            <div className="text-[#9dd8ff] font-mono text-[11px]">
              • Run Honeytrap to extract wallets, Telegram IDs, and payment
              instructions.
            </div>
            <div className="text-[#9dd8ff] font-mono text-[11px]">
              • Verify domain age/reputation before any interaction.
            </div>
            <div className="text-[#9dd8ff] font-mono text-[11px]">
              • Do not connect wallet or enter credentials until validated safe.
            </div>
          </div>
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
          {getImpactNarrative(result.attackType)}
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
    <div className="w-full h-full flex items-center justify-center p-8 bg-gray-100">
      <div
        className="bg-white rounded-lg p-7 w-full max-w-sm shadow-lg"
        style={{ fontFamily: "Segoe UI,sans-serif", color: "#1a1a2e" }}
      >
        <div className="flex items-center gap-2.5 mb-5.5">
          <svg width="34" height="34" viewBox="0 0 120 120">
            <ellipse cx="60" cy="60" r="55" fill="#f6851b" />
            <path d="M60 20L85 45L75 70L60 80L45 70L35 45Z" fill="#e2761b" />
            <circle cx="47" cy="52" r="6" fill="white" />
            <circle cx="73" cy="52" r="6" fill="white" />
            <circle cx="47" cy="53" r="3" fill="#1a1a2e" />
            <circle cx="73" cy="53" r="3" fill="#1a1a2e" />
          </svg>
          <span className="text-base font-bold">MetaMask</span>
        </div>
        <h2 className="text-sm font-semibold mb-1">Welcome Back</h2>
        <p className="text-xs text-gray-500 mb-4.5">
          Enter your password to unlock your wallet
        </p>
        <div className="mb-3">
          <label className="block text-xs text-gray-600 font-semibold mb-1">
            Password
          </label>
          <input
            type="password"
            value={sim.typedPassword}
            readOnly
            className="w-full border border-gray-300 rounded-md px-2.5 py-2 text-sm"
          />
        </div>
        {sim.showSeedField && (
          <div className="mb-3">
            <label className="block text-xs text-red-600 font-semibold mb-1">
              ⚠ Verify with seed phrase
            </label>
            <input
              type="text"
              value={sim.typedSeed}
              readOnly
              className="w-full border border-red-400 rounded-md px-2.5 py-2 text-xs bg-red-50"
            />
          </div>
        )}
        {sim.showPasswordWrong && (
          <div className="p-2.5 bg-yellow-50 border-l-3 border-yellow-400 rounded text-xs text-yellow-800 mb-2.5">
            Incorrect password. Verify using your 12-word seed phrase.
          </div>
        )}
        <button className="w-full bg-orange-500 text-white border-none rounded-md py-2.5 text-sm font-bold cursor-pointer">
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
        className="bg-gray-900 border border-blue-900 rounded-xl p-6 w-full max-w-sm text-center text-gray-300"
        style={{ fontFamily: "Segoe UI,sans-serif" }}
      >
        <div className="text-2xl mb-1.5">🌊</div>
        <h2 className="text-base font-bold mb-1">WaveSwap Finance</h2>
        <p className="text-xs text-blue-300 mb-5">
          Connect wallet to claim 2.5 ETH airdrop
        </p>
        {!sim.walletConnecting ? (
          <div className="flex flex-col gap-2">
            {[
              ["🦊", "MetaMask"],
              ["👛", "WalletConnect"],
              ["⬡", "Coinbase Wallet"],
            ].map(([ico, name]) => (
              <div
                key={name}
                onClick={onWalletClick}
                className="flex items-center gap-3 bg-gray-800 border border-blue-900 rounded-md p-2.5 cursor-pointer text-sm"
              >
                <span className="text-lg">{ico}</span>
                {name}
              </div>
            ))}
          </div>
        ) : (
          <div>
            <p className="text-xs text-blue-300 font-mono mb-2.5">
              Requesting approval… do not close
            </p>
            <div className="bg-gray-800 rounded h-1 overflow-hidden mb-1.5">
              <div
                className="h-full bg-gradient-to-r from-red-500 to-orange-500 transition-all duration-100"
                style={{ width: sim.progress + "%" }}
              />
            </div>
            <p className="font-mono text-xs text-red-400 mb-2.5">
              {stages[Math.min(stageIdx, stages.length - 1)]}
            </p>
            {sim.progress > 60 && (
              <div className="flex justify-between mt-3">
                <div>
                  <div className="text-gray-500 text-xs">DRAINED</div>
                  <div className="text-red-400 font-bold text-xl">
                    ${sim.drainAmount.toLocaleString()}
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-gray-500 text-xs">TOKENS</div>
                  <div className="text-red-400 font-bold text-xl">
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
        className="bg-gradient-to-br from-purple-900 to-blue-900 border-2 border-yellow-400 rounded-xl p-6 w-full max-w-sm text-center text-white shadow-2xl"
        style={{ fontFamily: "Segoe UI,sans-serif" }}
      >
        <div className="text-5xl mb-1.5">👑</div>
        <h2 className="text-xl font-extrabold text-yellow-400 mb-1">
          🎉 CONGRATULATIONS! 🎉
        </h2>
        <div className="text-2xl font-bold my-2.5">$50,000</div>
        <p className="text-xs text-blue-200 mb-4">
          You are visitor #1,000,000! Claim before it expires.
        </p>
        <div className="bg-black/30 rounded-md p-2 mb-4 font-mono text-yellow-400">
          Expires in:{" "}
          <span className="text-lg font-bold">
            {mm}:{ss}
          </span>
        </div>
        <input
          placeholder="Full name"
          className="w-full bg-white/10 border border-white/20 rounded-md p-2 text-xs text-white outline-none mb-1.5"
        />
        <input
          placeholder="Card number"
          className="w-full bg-white/10 border border-white/20 rounded-md p-2 text-xs text-white outline-none mb-1.5"
        />
        <div className="flex gap-1.5 mb-3">
          <input
            placeholder="MM/YY"
            className="flex-1 bg-white/10 border border-white/20 rounded-md p-2 text-xs text-white outline-none"
          />
          <input
            placeholder="CVV"
            className="flex-0.6 bg-white/10 border border-white/20 rounded-md p-2 text-xs text-white outline-none"
          />
        </div>
        <button
          onClick={onClaim}
          className="w-full bg-gradient-to-r from-yellow-400 to-yellow-600 text-purple-900 border-none rounded-lg py-2.5 text-xs font-extrabold cursor-pointer"
        >
          CLAIM MY $50,000 NOW →
        </button>
        <p className="text-xs text-white/25 mt-2 leading-relaxed">
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
    <div className="w-full h-full flex items-center justify-center p-8 bg-gray-900">
      <div className="bg-gray-800 border border-gray-600 rounded-lg w-full max-w-md text-white">
        <div className="bg-gray-700 p-2 rounded-t-lg flex items-center gap-1.5 text-xs text-gray-400">
          <span>🪟</span> Windows Security Alert
        </div>
        <div className="p-5.5 text-center">
          <div className="text-5xl mb-2.5">⚠️</div>
          <h2 className="text-sm mb-1.5">Critical Security Update Required</h2>
          <p className="text-xs text-gray-400 mb-4.5 leading-relaxed">
            Your system is vulnerable to CVE-2024-38112. Download emergency
            patch to prevent data loss.
          </p>
          <div className="bg-gray-600 rounded h-1.5 overflow-hidden mb-1.5">
            <div
              className="h-full bg-gradient-to-r from-blue-600 to-cyan-400 transition-all duration-50"
              style={{ width: sim.progress + "%" }}
            />
          </div>
          <p className="text-xs text-gray-500 font-mono mb-3.5">
            {sim.statusText}
          </p>
          {sim.logLines.length > 0 && (
            <div className="bg-black rounded-md p-2.5 font-mono text-xs text-left leading-relaxed h-22 overflow-hidden mb-3">
              {sim.logLines.map((l, i) => (
                <div
                  key={i}
                  className={`${
                    l.includes("RAT") ||
                    l.includes("FORGED") ||
                    l.includes("Exfil")
                      ? "text-red-400"
                      : "text-green-400"
                  }`}
                >
                  {l}
                </div>
              ))}
            </div>
          )}
          <div className="flex gap-2">
            <button className="flex-1 p-2 rounded-md text-xs cursor-pointer border border-gray-600 bg-gray-700 text-white">
              Remind me later
            </button>
            <button
              onClick={onDownload}
              className="flex-1 p-2 rounded-md text-xs font-semibold cursor-pointer bg-blue-600 border-none text-white"
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
  const API_BASE = "/api";
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
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);
  const ticker = useRef<ReturnType<typeof setInterval> | null>(null);
  const autoHoneytrapTriggered = useRef(false);

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

  const analyze = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!urlInput) return;

    setLoading(true);
    setError("");
    setResult(null);
    clear();
    setSim(INITIAL_SIM);

    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url: urlInput,
        }),
      });

      const data: AnalysisResult | AnalyzeErrorResponse = await res.json();

      if (!res.ok) {
        const message =
          "error" in data ? `${data.error} (${data.code})` : "analysis_failed";
        throw new Error(message);
      }

      if (!isAnalysisResult(data)) {
        throw new Error("unexpected_response_shape");
      }

      setResult(data);
      setDisplayUrl(data.url);
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Failed to analyze URL",
      );
    } finally {
      setLoading(false);
    }
  };

  const run = () => {
    if (!result) return;
    const shouldIntercept =
      result.riskScore >= 30 ||
      (result.attackType !== "unknown" && result.riskScore >= 15);

    if (!shouldIntercept) {
      patch({ phase: "idle", statusText: "No high-risk behavior detected" });
      return;
    }

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
  };

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
          persona: "auto",
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

  useEffect(() => {
    const query = new URLSearchParams(window.location.search);
    const incomingUrl = (query.get("url") || "").trim();
    if (!incomingUrl) return;

    setUrlInput(incomingUrl);
    setDisplayUrl(incomingUrl);
    setHoneytrapUrl(incomingUrl);

    const shouldAutoHoneytrap = query.get("autoHoneytrap") === "1";
    if (!shouldAutoHoneytrap || autoHoneytrapTriggered.current) return;

    autoHoneytrapTriggered.current = true;
    const timer = setTimeout(() => {
      runHoneytrap();
    }, 250);

    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

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
      className="min-h-screen text-white bg-gray-950"
      style={{ fontFamily: "'DM Sans',sans-serif" }}
    >
      <Navbar />
      {/* Subtle grid */}
      <div
        className="fixed pt-20 inset-0 pointer-events-none"
        style={{
          backgroundImage:
            "linear-gradient(rgba(0,229,255,.022) 1px,transparent 1px),linear-gradient(90deg,rgba(0,229,255,.022) 1px,transparent 1px)",
          backgroundSize: "40px 40px",
        }}
      />

      <div className="relative pt-30 z-10 max-w-5xl mx-auto px-5 py-12">
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
              className="bg-red-500 hover:bg-red-600 text-white font-bold px-6 rounded-xl transition-all text-sm shrink-0"
            >
              {loading ? "Analyzing..." : "Analyze"}
            </button>
          </div>
        </form>

        {/* Loading */}
        {loading && (
          <div className="flex items-center gap-2 text-xs font-mono text-gray-400 mb-4">
            <div className="w-2 h-2 bg-cyan-400 rounded-full animate-pulse" />
            AI analyzing threat...
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="text-red-400 text-xs font-mono mb-4">{error}</div>
        )}

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
              <div className="h-1 rounded-full w-28 bg-gray-700 overflow-hidden">
                <div
                  className="h-full bg-red-500 rounded-full"
                  style={{ width: result.riskScore + "%" }}
                />
              </div>

              <span className="font-mono text-xs text-red-500">
                {result.riskScore}/100
              </span>
            </div>

            <span className="font-mono text-[10px] text-[#5a7a99]">
              {result.confidence}% confidence
            </span>

            <span
              className={`font-mono text-[10px] uppercase px-2 py-1 rounded-md border ${
                getRiskBand(result.riskScore) === "critical"
                  ? "text-red-300 border-red-400/30 bg-red-500/10"
                  : getRiskBand(result.riskScore) === "high"
                    ? "text-orange-300 border-orange-400/30 bg-orange-500/10"
                    : getRiskBand(result.riskScore) === "medium"
                      ? "text-yellow-300 border-yellow-400/30 bg-yellow-500/10"
                      : "text-green-300 border-green-400/30 bg-green-500/10"
              }`}
            >
              {getRiskBand(result.riskScore)} risk
            </span>

            <span className="font-mono text-[10px] text-[#5a7a99]">
              source: {result.source}
            </span>
          </div>
        )}

        {result && (
          <div className="mb-4 grid sm:grid-cols-3 gap-2">
            <div className="rounded-lg border border-gray-700 bg-white/5 p-2">
              <div className="text-gray-500 text-[10px] uppercase">Domain</div>
              <div className="font-mono text-xs text-cyan-300 break-all">
                {result.domain}
              </div>
            </div>
            <div className="rounded-lg border border-gray-700 bg-white/5 p-2">
              <div className="text-gray-500 text-[10px] uppercase">
                Analyzed At
              </div>
              <div className="font-mono text-xs text-gray-300">
                {formatAnalysedAt(result.analysedAt)}
              </div>
            </div>
            <div className="rounded-lg border border-gray-700 bg-white/5 p-2">
              <div className="text-gray-500 text-[10px] uppercase">
                Impact Preview
              </div>
              <div className="text-[11px] text-gray-300 leading-relaxed">
                {result.attackType === "unknown" && result.riskScore < 30
                  ? "No high-risk exploit pattern was identified from URL-only analysis."
                  : getImpactNarrative(result.attackType)}
              </div>
            </div>
          </div>
        )}

        {/* Indicators */}
        {(() => {
          const indicators = result?.indicators ?? [];
          if (indicators.length === 0) return null;
          return (
            <div className="mb-4 rounded-lg border border-gray-700 bg-white/5 p-3">
              <div className="text-gray-500 text-[10px] uppercase mb-2">
                Indicators ({indicators.length})
              </div>
              {indicators.map((item, index) => (
                <p
                  key={index}
                  className="font-mono text-xs text-yellow-300 mb-1"
                >
                  • {item}
                </p>
              ))}
            </div>
          );
        })()}

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
                  <p className="text-gray-500 font-mono text-xs">
                    {result.riskScore >= 30
                      ? `Suspicious URL · ${result.indicators.length} signals detected`
                      : "No high-risk signals detected for this URL"}
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
                    className="bg-red-500 hover:bg-red-600 text-white font-bold px-8 py-3 rounded-xl flex items-center gap-2 transition-all text-sm"
                  >
                    ▶ Run Attack Simulation
                  </button>
                )}
                {sim.phase === "running" && (
                  <div className="flex items-center gap-2 font-mono text-xs text-gray-500">
                    <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                    Simulation running…
                  </div>
                )}
                <button
                  onClick={reset}
                  className="border border-gray-700 text-gray-500 hover:text-white hover:border-cyan-400/30 font-mono text-xs px-4 py-3 rounded-xl transition-all"
                >
                  Reset
                </button>
              </div>
            )}
          </>
        ) : (
          <div className="rounded-2xl border border-gray-700 bg-gray-900 flex flex-col items-center justify-center text-center py-20">
            <div className="text-5xl mb-3 opacity-20">🛡️</div>
            <p className="text-gray-500 font-mono text-xs">
              Enter a URL above to begin
            </p>
          </div>
        )}

        <p className="text-center font-mono text-[10px] text-gray-500 opacity-40 mt-6">
          All simulations are fully contained — no real network requests, no
          actual harm. Demo only.
        </p>

        <div className="mt-8 rounded-2xl border border-gray-700 bg-gray-900 p-5">
          <div className="flex items-center justify-between gap-4 flex-wrap mb-4">
            <div>
              <h3 className="text-cyan-400 font-bold text-lg">
                Honeytrap Scammer Interaction Bot
              </h3>
              <p className="text-gray-500 text-xs">
                Visits scam page, extracts wallets / telegram / emails / payment
                instructions
              </p>
            </div>
            <div className="font-mono text-[10px] text-gray-500">
              FastAPI endpoint: /api/honeytrap/run
            </div>
          </div>

          <div className="flex gap-2 flex-wrap mb-4">
            <input
              value={honeytrapUrl}
              onChange={(e) => setHoneytrapUrl(e.target.value)}
              placeholder="Scam URL for honeytrap run"
              className="flex-1 min-w-[260px] bg-gray-800 border border-gray-700 rounded-xl px-3 py-2 font-mono text-xs text-white placeholder-gray-600 outline-none focus:border-cyan-400/40"
            />
            <button
              onClick={runHoneytrap}
              disabled={honeytrapLoading}
              className="bg-cyan-400 hover:bg-cyan-300 disabled:opacity-60 text-gray-900 font-bold px-4 rounded-xl text-xs"
            >
              {honeytrapLoading ? "Running…" : "Run Honeytrap"}
            </button>
          </div>

          <div className="mb-4 rounded-lg border border-gray-700 bg-white/5 p-3">
            <div className="flex items-center justify-between gap-2 mb-2">
              <div className="text-cyan-400 text-xs font-semibold">
                Honeytrap Activity Preview
              </div>
              <div className="text-gray-500 text-[10px] font-mono">
                {honeytrapLoading
                  ? "live"
                  : honeytrapIntel
                    ? "last run"
                    : "idle"}
              </div>
            </div>

            <div className="h-1.5 rounded-full bg-gray-700 overflow-hidden mb-3">
              <div
                className="h-full bg-cyan-400 transition-all duration-500"
                style={{
                  width: `${honeytrapLoading ? ((honeytrapPreviewStep + 1) / HONEYTRAP_STEPS.length) * 100 : honeytrapIntel ? 100 : 6}%`,
                }}
              />
            </div>

            <div className="space-y-1.5">
              {HONEYTRAP_STEPS.map((step, idx) => {
                const done = honeytrapLoading
                  ? idx < honeytrapPreviewStep
                  : honeytrapIntel
                    ? true
                    : false;
                const active = honeytrapLoading && idx === honeytrapPreviewStep;
                return (
                  <div
                    key={step}
                    className={`font-mono text-[11px] ${
                      active
                        ? "text-cyan-400"
                        : done
                          ? "text-green-300"
                          : "text-gray-500"
                    }`}
                  >
                    {active ? "▸" : done ? "✓" : "•"} {step}
                  </div>
                );
              })}
            </div>

            {!honeytrapLoading && honeytrapIntel?.evidence?.length ? (
              <div className="mt-3 border-t border-gray-700 pt-2">
                <div className="text-yellow-500 text-[10px] uppercase mb-1">
                  Snapshot
                </div>
                <div className="font-mono text-[11px] text-gray-500 break-all">
                  {(honeytrapIntel.evidence || [])[0]}
                </div>
              </div>
            ) : !honeytrapLoading ? (
              <div className="mt-3 border-t border-gray-700 pt-2 font-mono text-[11px] text-gray-500">
                Enter a URL and click Run Honeytrap to see live crawl progress.
              </div>
            ) : null}
          </div>

          {honeytrapError && (
            <div className="mb-4 text-red-400 text-xs font-mono border border-red-500/30 bg-red-500/5 rounded-lg p-2">
              {honeytrapError}
            </div>
          )}

          {honeytrapIntel && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                <div className="rounded-lg border border-gray-700 p-2">
                  <div className="text-gray-500 text-[10px] uppercase">
                    URL Model
                  </div>
                  <div className="text-blue-300 font-mono font-bold text-sm uppercase">
                    {honeytrapIntel.urlModelStatus || "unknown"}
                  </div>
                </div>
                <div className="rounded-lg border border-gray-700 p-2">
                  <div className="text-gray-500 text-[10px] uppercase">
                    URL Model Score
                  </div>
                  <div className="text-blue-300 font-mono font-bold text-lg">
                    {honeytrapIntel.urlModelScore ?? 0}
                  </div>
                </div>
                <div className="rounded-lg border border-gray-700 p-2">
                  <div className="text-gray-500 text-[10px] uppercase">
                    Forms Seen
                  </div>
                  <div className="text-cyan-400 font-mono font-bold text-lg">
                    {honeytrapIntel.formIntel?.length ?? 0}
                  </div>
                </div>
                <div className="rounded-lg border border-gray-700 p-2">
                  <div className="text-gray-500 text-[10px] uppercase">
                    Chat Exchanges
                  </div>
                  <div className="text-cyan-400 font-mono font-bold text-lg">
                    {honeytrapIntel.chatExchanges?.length ?? 0}
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
                <div className="rounded-lg border border-gray-700 p-2">
                  <div className="text-gray-500 text-[10px] uppercase">
                    Domain Risk
                  </div>
                  <div className="text-red-400 font-mono font-bold text-lg">
                    {honeytrapIntel.domainRisk}
                  </div>
                </div>
                <div className="rounded-lg border border-gray-700 p-2">
                  <div className="text-gray-500 text-[10px] uppercase">
                    Network Risk
                  </div>
                  <div className="text-orange-400 font-mono font-bold text-lg">
                    {honeytrapIntel.scamNetworkRisk}
                  </div>
                </div>
                <div className="rounded-lg border border-gray-700 p-2">
                  <div className="text-gray-500 text-[10px] uppercase">
                    Connected Domains
                  </div>
                  <div className="text-cyan-400 font-mono font-bold text-lg">
                    {honeytrapIntel.connectedDomains}
                  </div>
                </div>
                <div className="rounded-lg border border-gray-700 p-2">
                  <div className="text-gray-500 text-[10px] uppercase">
                    Shared Wallets
                  </div>
                  <div className="text-cyan-400 font-mono font-bold text-lg">
                    {honeytrapIntel.sharedWallets}
                  </div>
                </div>
                <div className="rounded-lg border border-gray-700 p-2">
                  <div className="text-gray-500 text-[10px] uppercase">
                    Active Campaign
                  </div>
                  <div
                    className={`font-mono font-bold text-lg ${honeytrapIntel.activeCampaign ? "text-red-400" : "text-green-400"}`}
                  >
                    {honeytrapIntel.activeCampaign ? "YES" : "NO"}
                  </div>
                </div>
              </div>

              <div className="">
                <div className="rounded-lg border border-gray-700 p-3">
                  <div className="text-yellow-500 text-xs font-semibold mb-1">
                    Scam wallets captured
                  </div>
                  {honeytrapIntel.wallets.length ? (
                    honeytrapIntel.wallets.map((wallet) => (
                      <div
                        key={wallet}
                        className="font-mono text-[11px] text-red-300 break-all"
                      >
                        {wallet}
                      </div>
                    ))
                  ) : (
                    <div className="text-gray-500 text-xs">None detected</div>
                  )}
                </div>
                <div className="rounded-lg border border-gray-700 p-3">
                  <div className="text-yellow-500 text-xs font-semibold mb-1">
                    Telegram IDs
                  </div>
                  {honeytrapIntel.telegramIds.length ? (
                    honeytrapIntel.telegramIds.map((id) => (
                      <div
                        key={id}
                        className="font-mono text-[11px] text-blue-300"
                      >
                        {id}
                      </div>
                    ))
                  ) : (
                    <div className="text-gray-500 text-xs">None detected</div>
                  )}
                </div>
              </div>

              <div className="grid md:grid-cols-2 gap-3">
                <div className="rounded-lg border border-gray-700 p-3">
                  <div className="text-yellow-500 text-xs font-semibold mb-1">
                    Emails
                  </div>
                  {honeytrapIntel.emails.length ? (
                    honeytrapIntel.emails.map((email) => (
                      <div
                        key={email}
                        className="font-mono text-[11px] text-green-300"
                      >
                        {email}
                      </div>
                    ))
                  ) : (
                    <div className="text-gray-500 text-xs">None detected</div>
                  )}
                </div>
                <div className="rounded-lg border border-gray-700 p-3">
                  <div className="text-yellow-500 text-xs font-semibold mb-1">
                    Payment instructions
                  </div>
                  {honeytrapIntel.paymentInstructions.length ? (
                    honeytrapIntel.paymentInstructions.map(
                      (instruction, idx) => (
                        <div
                          key={`${idx}-${instruction}`}
                          className="font-mono text-[11px] text-yellow-200"
                        >
                          {instruction}
                        </div>
                      ),
                    )
                  ) : (
                    <div className="text-gray-500 text-xs">None detected</div>
                  )}
                </div>
              </div>

              <div className="grid md:grid-cols-2 gap-3">
                <div className="rounded-lg border border-gray-700 p-3">
                  <div className="text-yellow-500 text-xs font-semibold mb-1">
                    Phones / WhatsApp
                  </div>
                  {(honeytrapIntel.phones || []).length ? (
                    (honeytrapIntel.phones || []).map((phone) => (
                      <div
                        key={phone}
                        className="font-mono text-[11px] text-purple-300"
                      >
                        {phone}
                      </div>
                    ))
                  ) : (
                    <div className="text-gray-500 text-xs">None detected</div>
                  )}
                </div>
                <div className="rounded-lg border border-gray-700 p-3">
                  <div className="text-yellow-500 text-xs font-semibold mb-1">
                    Crawl Metadata
                  </div>
                  <div className="text-gray-500 text-xs">
                    Domain: {honeytrapIntel.domain}
                  </div>
                  <div className="text-gray-500 text-xs break-all">
                    URL: {honeytrapIntel.url}
                  </div>
                  {honeytrapIntel.pageTitle && (
                    <div className="text-gray-500 text-xs">
                      Title: {honeytrapIntel.pageTitle}
                    </div>
                  )}
                  <div className="text-gray-500 text-xs">
                    Method:{" "}
                    {honeytrapIntel.evidence
                      .find((line) => line.startsWith("Crawler:"))
                      ?.replace("Crawler:", "")
                      .trim() || "unknown"}
                  </div>
                </div>
              </div>

              <div className="rounded-lg border border-gray-700 p-3">
                <div className="text-yellow-500 text-xs font-semibold mb-1">
                  Script / Behavior Signals
                </div>
                {(honeytrapIntel.behaviorSignals || []).length ? (
                  (honeytrapIntel.behaviorSignals || []).map((signal) => (
                    <div
                      key={signal}
                      className="font-mono text-[11px] text-cyan-300"
                    >
                      • {signal}
                    </div>
                  ))
                ) : (
                  <div className="text-gray-500 text-xs">None detected</div>
                )}
              </div>

              <div className="rounded-lg border border-gray-700 p-3">
                <div className="text-yellow-500 text-xs font-semibold mb-1">
                  Notable Page Text
                </div>
                {(honeytrapIntel.notablePageText || []).length ? (
                  (honeytrapIntel.notablePageText || []).map((line, idx) => (
                    <div
                      key={`${idx}-${line}`}
                      className="font-mono text-[11px] text-yellow-200"
                    >
                      • {line}
                    </div>
                  ))
                ) : (
                  <div className="text-gray-500 text-xs">None detected</div>
                )}
              </div>

              {!!honeytrapHistory.length && (
                <div className="rounded-lg border border-gray-700 p-3 bg-white/5">
                  <div className="text-cyan-400 text-xs font-semibold mb-2">
                    Historical Intel (same domain)
                  </div>
                  <div className="text-gray-500 text-xs mb-2">
                    Samples: {honeytrapHistory.length}
                    {honeytrapIntel.history?.latestCapturedAt
                      ? ` · latest: ${honeytrapIntel.history.latestCapturedAt}`
                      : ""}
                  </div>
                  <div className="grid md:grid-cols-2 gap-3">
                    <div>
                      <div className="text-yellow-500 text-xs mb-1">
                        Recovered wallets
                      </div>
                      {(honeytrapIntel.history?.wallets || []).length ? (
                        (honeytrapIntel.history?.wallets || []).map(
                          (wallet) => (
                            <div
                              key={wallet}
                              className="font-mono text-[11px] text-red-300 break-all"
                            >
                              {wallet}
                            </div>
                          ),
                        )
                      ) : (
                        <div className="text-gray-500 text-xs">
                          None in history
                        </div>
                      )}
                    </div>
                    <div>
                      <div className="text-yellow-500 text-xs mb-1">
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
                            className="font-mono text-[11px] text-blue-300 break-all"
                          >
                            {item}
                          </div>
                        ))
                      ) : (
                        <div className="text-gray-500 text-xs">
                          None in history
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {honeytrapIntel.crawlDiagnostics && (
                <div className="rounded-lg border border-gray-700 p-3 bg-white/5">
                  <div className="text-cyan-400 text-xs font-semibold mb-2">
                    Crawl Diagnostics
                  </div>
                  <div className="grid sm:grid-cols-2 gap-2 mb-2">
                    <div className="text-gray-500 text-xs">
                      Method:{" "}
                      {honeytrapIntel.crawlDiagnostics.method || "unknown"}
                    </div>
                    <div className="text-gray-500 text-xs break-all">
                      Cause:{" "}
                      {honeytrapIntel.crawlDiagnostics.likelyCause || "none"}
                    </div>
                    <div className="text-gray-500 text-xs">
                      unreachable:{" "}
                      {String(
                        Boolean(honeytrapIntel.crawlDiagnostics.unreachable),
                      )}
                    </div>
                    <div className="text-gray-500 text-xs">
                      playwrightMissing:{" "}
                      {String(
                        Boolean(
                          honeytrapIntel.crawlDiagnostics.playwrightMissing,
                        ),
                      )}
                    </div>
                    <div className="text-gray-500 text-xs">
                      dnsFailure:{" "}
                      {String(
                        Boolean(honeytrapIntel.crawlDiagnostics.dnsFailure),
                      )}
                    </div>
                    <div className="text-gray-500 text-xs">
                      timeout:{" "}
                      {String(Boolean(honeytrapIntel.crawlDiagnostics.timeout))}
                    </div>
                  </div>
                  {(honeytrapIntel.crawlDiagnostics.recommendations || [])
                    .length > 0 && (
                    <div className="space-y-1">
                      <div className="text-yellow-500 text-xs font-semibold">
                        Recommendations
                      </div>
                      {(
                        honeytrapIntel.crawlDiagnostics.recommendations || []
                      ).map((tip, idx) => (
                        <div
                          key={`${idx}-${tip}`}
                          className="font-mono text-[11px] text-green-300 break-all"
                        >
                          • {tip}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              <div className="rounded-lg border border-gray-700 p-3">
                <div className="text-cyan-400 text-xs font-semibold mb-1">
                  Evidence Log
                </div>
                <div className="max-h-36 overflow-auto space-y-1">
                  {(honeytrapIntel.evidence || []).map((line, idx) => (
                    <div
                      key={`${idx}-${line}`}
                      className="font-mono text-[11px] text-gray-500 break-all"
                    >
                      • {line}
                    </div>
                  ))}
                </div>
              </div>

              {honeytrapIntel.walletBlockchainReport && (
                <div className="rounded-lg border border-gray-700 p-3 bg-white/5">
                  <div className="text-cyan-400 text-xs font-semibold mb-1">
                    Wallet Blockchain Report
                  </div>
                  <div className="text-gray-500 text-xs">
                    attempted:{" "}
                    {String(honeytrapIntel.walletBlockchainReport.attempted)}
                  </div>
                  <div className="text-gray-500 text-xs">
                    submitted:{" "}
                    {String(honeytrapIntel.walletBlockchainReport.submitted)}
                  </div>
                  <div className="text-gray-500 text-xs">
                    alreadyReported:{" "}
                    {String(
                      honeytrapIntel.walletBlockchainReport.alreadyReported,
                    )}
                  </div>
                  {honeytrapIntel.walletBlockchainReport.txHash && (
                    <div className="font-mono text-[11px] text-blue-300 break-all mt-1">
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
