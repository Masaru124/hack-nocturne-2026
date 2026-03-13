import React from "react";
import { useState } from "react";
import { useRouter } from "next/navigation";
import axios from "axios";

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
      const res = await axios.post(
        "https://hack-nocturne-2026-production.up.railway.app/api/scan",
        { text, url },
      );
      localStorage.setItem(
        "scanResult",
        JSON.stringify({ text, url, ...res.data }),
      );
      router.push("/result");
    } catch (err) {
      console.log(err);
      setError("Failed to analyze content. Please try again.");
    }
    setLoading(false);
  };

  return (
    <section className="relative flex-1 flex flex-col items-center justify-center text-center px-4 pt-32 pb-24 overflow-hidden bg-[#07090d]">
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          backgroundImage:
            "linear-gradient(rgba(0,229,255,.02) 1px,transparent 1px),linear-gradient(90deg,rgba(0,229,255,.02) 1px,transparent 1px)",
          backgroundSize: "40px 40px",
        }}
      />

      <div className="absolute inset-0 bg-gradient-to-b from-[#0d1117] via-[#0a1220] to-[#07090d] pointer-events-none" />

      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[36rem] h-[36rem] bg-cyan-400/10 rounded-full blur-3xl pointer-events-none" />

      <div className="relative mb-6 inline-flex items-center gap-2 bg-cyan-400/10 border border-cyan-400/20 text-cyan-300 text-sm px-4 py-2 rounded-full font-mono">
        <span className="w-2 h-2 bg-cyan-300 rounded-full animate-pulse" />
        AI + Blockchain Powered Protection
      </div>

      <h1 className="relative text-5xl md:text-7xl font-bold tracking-tight mb-6 leading-tight text-white">
        Detect Scams
        <br />
        <span className="bg-gradient-to-r from-red-400 to-cyan-300 bg-clip-text text-transparent">
          Before They Strike
        </span>
      </h1>

      <p className="relative text-[#8aa1b8] text-lg md:text-xl max-w-2xl mb-12 leading-relaxed">
        Paste any suspicious message or link. Our AI analyzes it instantly and
        stores confirmed scams permanently on the blockchain — a tamper-proof
        registry nobody can delete.
      </p>

      <div className="relative w-full max-w-2xl bg-[#0d1117] border border-[#1e2a38] rounded-2xl p-6 shadow-2xl text-left">
        <label className="block text-sm font-medium text-[#8aa1b8] mb-2">
          Suspicious URL
        </label>
        <input
          type="text"
          placeholder="https://suspicious-link.com"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          className="w-full bg-[#111820] border border-[#1e2a38] text-white placeholder-[#4f657a] p-3 rounded-xl mb-4 focus:outline-none focus:border-cyan-400/50 transition"
        />

        <label className="block text-sm font-medium text-[#8aa1b8] mb-2">
          Suspicious Message
        </label>
        <textarea
          rows={4}
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Paste the suspicious message here..."
          className="w-full bg-[#111820] border border-[#1e2a38] text-white placeholder-[#4f657a] p-3 rounded-xl mb-4 focus:outline-none focus:border-cyan-400/50 transition resize-none"
        />

        <button
          onClick={analyze}
          disabled={loading}
          className="w-full bg-red-500 hover:bg-red-600 disabled:bg-red-900/60 disabled:cursor-not-allowed text-white py-3 rounded-xl font-semibold transition-colors text-base"
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

        {error && (
          <p className="text-red-400 text-sm mt-3 font-mono">{error}</p>
        )}
      </div>

      <div className="relative mt-12 grid grid-cols-2 md:grid-cols-4 gap-4 w-full max-w-4xl">
        {[
          { value: "10K+", label: "Scams Detected" },
          { value: "100%", label: "On-Chain Storage" },
          { value: "3 sec", label: "Avg Analysis Time" },
          { value: "Free", label: "No Wallet Needed" },
        ].map(({ value, label }) => (
          <div
            key={label}
            className="rounded-xl border border-[#1e2a38] bg-white/5 px-4 py-4 text-center"
          >
            <p className="text-2xl md:text-3xl font-bold text-white">{value}</p>
            <p className="text-xs md:text-sm text-[#8aa1b8] mt-1">{label}</p>
          </div>
        ))}
      </div>
    </section>
  );
};

export default Hero;
