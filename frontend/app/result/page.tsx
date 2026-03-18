"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import Navbar from "@/components/Navbar";

type ScanResult = {
  isScam: boolean;
  summary: string;
  riskScore: number;
  category: string;
  url?: string;
  text?: string;
  indicators?: string[];
};

function normalizeRiskScore(value: unknown): number {
  if (typeof value !== "number" || Number.isNaN(value)) return 0;
  if (value >= 0 && value <= 1) return Math.round(value * 100);
  return Math.round(Math.max(0, Math.min(100, value)));
}

export default function ResultPage() {
  const router = useRouter();
  const [result, setResult] = useState<ScanResult | null>(null);

  useEffect(() => {
    const stored = localStorage.getItem("scanResult");
    if (stored) {
      setTimeout(() => {
        const parsed = JSON.parse(stored) as ScanResult;
        setResult({
          ...parsed,
          riskScore: normalizeRiskScore(parsed.riskScore),
        });
      }, 0);
    }
  }, []);

  if (!result) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center flex-col gap-4">
        <p className="text-gray-400">No scan data found.</p>
        <Link href="/" className="text-blue-400 underline text-sm">
          Go back and scan first
        </Link>
      </div>
    );
  }

  const getRiskColor = (s: number) =>
    s <= 30 ? "text-green-400" : s <= 70 ? "text-yellow-400" : "text-red-400";
  const getRiskBar = (s: number) =>
    s <= 30 ? "bg-green-500" : s <= 70 ? "bg-yellow-500" : "bg-red-500";
  const getRiskLabel = (s: number) =>
    s <= 30 ? "Low Risk" : s <= 70 ? "Medium Risk" : "High Risk";

  return (
    <div className="min-h-screen bg-gray-950 text-white flex flex-col">
      <Navbar />
      <main className="flex-1 flex justify-center px-4 pt-28 pb-16">
        <div className="w-full max-w-2xl space-y-4">
          {/* HEADER */}
          <div className="flex items-center justify-between mb-2">
            <h1 className="text-2xl font-bold">Analysis Result</h1>
            <Link
              href="/"
              className="text-sm text-gray-400 hover:text-white transition-colors"
            >
              ← Scan Another
            </Link>
          </div>

          {/* BADGE */}
          <div
            className={`w-full p-4 rounded-xl border flex items-center gap-3 ${
              result.isScam
                ? "bg-red-500/10 border-red-500/30"
                : "bg-green-500/10 border-green-500/30"
            }`}
          >
            <span className="text-2xl">{result.isScam ? "⚠️" : "✅"}</span>
            <div>
              <p
                className={`font-bold text-lg ${result.isScam ? "text-red-400" : "text-green-400"}`}
              >
                {result.isScam ? "SCAM DETECTED" : "NOT A SCAM"}
              </p>
              <p className="text-gray-400 text-sm">{result.summary}</p>
            </div>
          </div>

          {/* RISK SCORE */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
            <div className="flex justify-between items-center mb-3">
              <span className="text-sm text-gray-400 font-medium">
                Risk Score
              </span>
              <span
                className={`font-bold text-xl ${getRiskColor(result.riskScore)}`}
              >
                {result.riskScore}/100
                <span className="text-sm font-normal ml-2 text-gray-500">
                  {getRiskLabel(result.riskScore)}
                </span>
              </span>
            </div>
            <div className="w-full bg-gray-800 rounded-full h-3">
              <div
                className={`${getRiskBar(result.riskScore)} h-3 rounded-full transition-all`}
                style={{ width: `${result.riskScore}%` }}
              />
            </div>
          </div>

          {/* CATEGORY + SCANNED CONTENT */}
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
              <p className="text-xs text-gray-500 mb-1">Category</p>
              <p className="font-semibold text-white">{result.category}</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
              <p className="text-xs text-gray-500 mb-1">Scanned</p>
              <p className="font-semibold text-white text-sm truncate">
                {result.url || result.text?.slice(0, 30) + "..."}
              </p>
            </div>
          </div>

          {/* RED FLAGS */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
            <p className="text-sm text-gray-400 font-medium mb-3">Red Flags</p>
            {result.indicators && result.indicators.length > 0 ? (
              <ul className="space-y-2">
                {result.indicators.map((item: string, idx: number) => (
                  <li
                    key={idx}
                    className="flex items-start gap-2 text-sm text-gray-300"
                  >
                    <span className="text-red-400 mt-0.5">•</span>
                    {item}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-gray-500 text-sm">No red flags found</p>
            )}
          </div>

          <button
            onClick={() => router.push("/report")}
            className="w-full bg-red-600 hover:bg-red-500 text-white py-3 rounded-xl font-semibold transition-colors"
          >
            Report This Scam to Blockchain
          </button>

          <Link
            href="/"
            className="block w-full text-center border border-gray-700 text-gray-400 hover:text-white hover:border-gray-500 py-3 rounded-xl font-medium transition-colors text-sm"
          >
            ← Back to Scanner
          </Link>
        </div>
      </main>
    </div>
  );
}
