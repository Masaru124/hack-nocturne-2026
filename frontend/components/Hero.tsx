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
        "https://z4g1rll3-10000.inc1.devtunnels.ms/api/scan",
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
    <section className="relative flex-1 flex flex-col items-center justify-center text-center px-4 pt-32 pb-24 overflow-hidden">
      {/* Background gradient */}
      <div className="absolute inset-0 bg-linear-to-br from-gray-950 via-blue-950/40 to-gray-950 pointer-events-none" />

      {/* Glow */}
      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-150 h-150 bg-blue-600/10 rounded-full blur-3xl pointer-events-none" />

      {/* Badge */}
      <div className="relative mb-6 inline-flex items-center gap-2 bg-blue-500/10 border border-blue-500/20 text-blue-400 text-sm px-4 py-2 rounded-full">
        <span className="w-2 h-2 bg-blue-400 rounded-full animate-pulse" />
        AI + Blockchain Powered Protection
      </div>

      {/* Headline */}
      <h1 className="relative text-5xl md:text-7xl font-bold tracking-tight mb-6 leading-tight">
        Detect Scams
        <br />
        <span className="bg-linear-to-r from-blue-400 to-blue-600 bg-clip-text text-transparent">
          Before They Strike
        </span>
      </h1>

      {/* Subheading */}
      <p className="relative text-gray-400 text-lg md:text-xl max-w-2xl mb-12 leading-relaxed">
        Paste any suspicious message or link. Our AI analyzes it instantly and
        stores confirmed scams permanently on the blockchain — a tamper-proof
        registry nobody can delete.
      </p>

      {/* SCAN CARD */}
      <div className="relative w-full max-w-2xl bg-gray-900 border border-gray-800  p-6 shadow-2xl text-left">
        <label className="block text-sm font-medium text-gray-400 mb-2">
          Suspicious URL
        </label>
        <input
          type="text"
          placeholder="https://suspicious-link.com"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          className="w-full bg-gray-800 border border-gray-700 text-white placeholder-gray-500 p-3  mb-4 focus:outline-none focus:ring-2 focus:ring-blue-500 transition"
        />

        <label className="block text-sm font-medium text-gray-400 mb-2">
          Suspicious Message
        </label>
        <textarea
          rows={4}
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Paste the suspicious message here..."
          className="w-full bg-gray-800 border border-gray-700 text-white placeholder-gray-500 p-3  mb-4 focus:outline-none focus:ring-2 focus:ring-blue-500 transition resize-none"
        />

        <button
          onClick={analyze}
          disabled={loading}
          className="w-full bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 disabled:cursor-not-allowed text-white py-3  font-semibold transition-colors text-base"
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

        {error && <p className="text-red-400 text-sm mt-3">{error}</p>}
      </div>

      {/* Stats row */}
      <div className="relative mt-12 flex flex-wrap justify-center gap-10 text-center">
        {[
          { value: "10K+", label: "Scams Detected" },
          { value: "100%", label: "On-Chain Storage" },
          { value: "3 sec", label: "Avg Analysis Time" },
          { value: "Free", label: "No Wallet Needed" },
        ].map(({ value, label }) => (
          <div key={label}>
            <p className="text-3xl font-bold text-white">{value}</p>
            <p className="text-sm text-gray-500 mt-1">{label}</p>
          </div>
        ))}
      </div>
    </section>
  );
};

export default Hero;
