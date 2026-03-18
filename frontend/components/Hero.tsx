import React from "react";
import { useState } from "react";
import { useRouter } from "next/navigation";

type LocalAnalyzeResponse = {
  ok: true;
  attackType: string;
  riskScore: number;
  confidence: number;
  indicators: string[];
  source: "ai" | "heuristic" | "fallback";
};

type LegacyScanResponse = {
  riskScore?: number;
  category?: string;
  indicators?: string[];
  summary?: string;
  isScam?: boolean;
};

function normalizeRiskScore(value: unknown): number {
  if (typeof value !== "number" || Number.isNaN(value)) return 0;
  if (value >= 0 && value <= 1) return Math.round(value * 100);
  return Math.round(Math.max(0, Math.min(100, value)));
}

function isLocalAnalyzeResponse(
  payload: unknown,
): payload is LocalAnalyzeResponse {
  if (!payload || typeof payload !== "object") return false;
  const candidate = payload as Record<string, unknown>;
  return (
    candidate.ok === true &&
    typeof candidate.riskScore === "number" &&
    typeof candidate.attackType === "string"
  );
}

function isLegacyScanResponse(payload: unknown): payload is LegacyScanResponse {
  if (!payload || typeof payload !== "object") return false;
  const candidate = payload as Record<string, unknown>;
  return (
    "riskScore" in candidate || "isScam" in candidate || "summary" in candidate
  );
}

const Hero = () => {
  const router = useRouter();
  const [url, setUrl] = useState("");
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const analyze = async () => {
    if (!text.trim() && !url.trim()) {
      setError("Please enter a URL or message to analyze");
      return;
    }
    setLoading(true);
    setError("");
    try {
      let payload: unknown;

      if (url.trim()) {
        const res = await fetch("/api/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: url.trim() }),
        });

        payload = await res.json();
        if (!res.ok) {
          const detail =
            payload && typeof payload === "object" && "error" in payload
              ? String((payload as Record<string, unknown>).error)
              : "Failed to analyze URL";
          throw new Error(detail);
        }
      } else {
        const res = await fetch(
          "https://hack-nocturne-2026-production.up.railway.app/api/scan",
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ text, url }),
          },
        );

        payload = await res.json();
        if (!res.ok) {
          throw new Error("Failed to analyze content");
        }
      }

      let normalizedResult: {
        riskScore: number;
        category: string;
        indicators: string[];
        summary: string;
        isScam: boolean;
      };

      if (isLocalAnalyzeResponse(payload)) {
        const riskScore = normalizeRiskScore(payload.riskScore);
        normalizedResult = {
          riskScore,
          category: payload.attackType,
          indicators: payload.indicators ?? [],
          summary:
            payload.indicators?.[0] ||
            `${payload.attackType.toUpperCase()} risk detected (${payload.source})`,
          isScam: riskScore >= 50,
        };
      } else if (isLegacyScanResponse(payload)) {
        const riskScore = normalizeRiskScore(payload.riskScore ?? 0);
        normalizedResult = {
          riskScore,
          category: payload.category || "unknown",
          indicators: payload.indicators ?? [],
          summary: payload.summary || "Analysis complete",
          isScam: payload.isScam ?? riskScore >= 50,
        };
      } else {
        throw new Error("Unexpected response from analyzer");
      }

      localStorage.setItem(
        "scanResult",
        JSON.stringify({ text, url, ...normalizedResult }),
      );
      router.push("/result");
    } catch (err) {
      console.log(err);
      setError("Failed to analyze content. Please try again.");
    }
    setLoading(false);
  };

  return (
    <section className="noise-overlay relative flex flex-1 flex-col items-center justify-center overflow-hidden px-4 pb-24 pt-32 text-center md:px-6">
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          backgroundImage:
            "linear-gradient(rgba(120,180,215,.05) 1px,transparent 1px),linear-gradient(90deg,rgba(120,180,215,.05) 1px,transparent 1px)",
          backgroundSize: "52px 52px",
        }}
      />

      <div className="pointer-events-none absolute inset-0 bg-gradient-to-b from-[rgba(4,16,26,0.66)] via-transparent to-[rgba(3,11,18,0.82)]" />

      <div className="pointer-events-none absolute left-1/2 top-[28%] h-[34rem] w-[34rem] -translate-x-1/2 -translate-y-1/2 rounded-full bg-[rgba(58,167,255,0.16)] blur-3xl" />
      <div className="pointer-events-none absolute bottom-0 right-[10%] h-72 w-72 rounded-full bg-[rgba(255,112,102,0.16)] blur-3xl" />

      <div className="animate-rise mono relative mb-6 inline-flex items-center gap-2 rounded-full border border-[var(--border-strong)] bg-[rgba(58,167,255,0.14)] px-4 py-2 text-sm text-[#a6ddff]">
        <span className="h-2 w-2 rounded-full bg-[#7de1cf] animate-pulse" />
        AI + Blockchain Powered Protection
      </div>

      <h1 className="animate-rise relative mb-6 text-5xl font-bold leading-tight tracking-tight text-white md:text-7xl">
        Detect Scams
        <br />
        <span className="bg-gradient-to-r from-[#ff8d84] via-[#ffd0b3] to-[#77c7ff] bg-clip-text text-transparent">
          Before They Strike
        </span>
      </h1>

      <p className="animate-rise relative mb-12 max-w-2xl text-lg leading-relaxed text-[var(--text-muted)] md:text-xl">
        Paste any suspicious message or link. Our AI analyzes it instantly and
        stores confirmed scams permanently on the blockchain — a tamper-proof
        registry nobody can delete.
      </p>

      <div className="glass-panel animate-rise relative w-full max-w-2xl rounded-3xl p-6 text-left shadow-[0_24px_80px_rgba(3,12,19,0.6)]">
        <label className="mb-2 block text-sm font-medium text-[var(--text-muted)]">
          Suspicious URL
        </label>
        <input
          type="text"
          placeholder="https://suspicious-link.com"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          className="mb-4 w-full rounded-2xl border border-[var(--border-soft)] bg-[var(--panel-strong)] p-3 text-white placeholder-[#53718a] transition focus:border-[var(--border-strong)] focus:outline-none"
        />

        <label className="mb-2 block text-sm font-medium text-[var(--text-muted)]">
          Suspicious Message
        </label>
        <textarea
          rows={4}
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Paste the suspicious message here..."
          className="mb-4 w-full resize-none rounded-2xl border border-[var(--border-soft)] bg-[var(--panel-strong)] p-3 text-white placeholder-[#53718a] transition focus:border-[var(--border-strong)] focus:outline-none"
        />

        <button
          onClick={analyze}
          disabled={loading}
          className="w-full rounded-2xl bg-gradient-to-r from-[var(--warn)] to-[#ff8e69] py-3 text-base font-semibold text-white shadow-[0_10px_30px_rgba(255,112,102,0.35)] transition-all hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {loading ? (
            <span className="flex items-center justify-center gap-2">
              <svg
                className="animate-spin h-4 w-4"
                viewBox="0 0 24 24"
                fill="none"
              >
                <circle
                  className="opacity-25"
                  cx="12"
                  cy="12"
                  r="10"
                  stroke="currentColor"
                  strokeWidth="4"
                />
                <path
                  className="opacity-75"
                  fill="currentColor"
                  d="M4 12a8 8 0 018-8v8z"
                />
              </svg>
              Analyzing...
            </span>
          ) : (
            "Scan Now →"
          )}
        </button>

        {error && <p className="mono mt-3 text-sm text-red-300">{error}</p>}
      </div>

      <div className="relative mt-12 grid w-full max-w-4xl grid-cols-2 gap-4 md:grid-cols-4">
        {[
          { value: "10K+", label: "Scams Detected" },
          { value: "100%", label: "On-Chain Storage" },
          { value: "3 sec", label: "Avg Analysis Time" },
          { value: "Free", label: "No Wallet Needed" },
        ].map(({ value, label }) => (
          <div
            key={label}
            className="glass-panel rounded-2xl px-4 py-4 text-center"
          >
            <p className="text-2xl md:text-3xl font-bold text-white">{value}</p>
            <p className="mt-1 text-xs text-[var(--text-muted)] md:text-sm">
              {label}
            </p>
          </div>
        ))}
      </div>
    </section>
  );
};

export default Hero;
