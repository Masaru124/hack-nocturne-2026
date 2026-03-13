"use client";

import Navbar from "@/components/Navbar";
import Link from "next/link";
import { useState, useEffect } from "react";

type ScamData = {
  url?: string;
  text?: string;
  category?: string;
  riskScore?: number;
};

type ReportBody = {
  url: string;
  text: string;
  category: string;
  riskScore: number;
  reporterAddress?: string;
};

type ReportResponse = {
  txHash: string;
};

type EthereumRequestArgs = {
  method: string;
  params?: unknown[];
};

type EthereumProvider = {
  request: (args: EthereumRequestArgs) => Promise<unknown>;
};

type WindowWithEthereum = Window & {
  ethereum?: EthereumProvider;
};

type ChainSwitchError = {
  code?: number;
};

function getErrorMessage(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

export default function ReportPage() {
  const [scamData, setScamData] = useState<ScamData | null>(null);
  const [account, setAccount] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [tx, setTx] = useState<ReportResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const stored = localStorage.getItem("scanResult");
    if (stored) setScamData(JSON.parse(stored));
  }, []);

  const connectWallet = async () => {
    try {
      const ethereum = (window as WindowWithEthereum).ethereum;

      if (!ethereum) {
        alert("Please install MetaMask");
        return;
      }

      try {
        await ethereum.request({
          method: "wallet_switchEthereumChain",
          params: [{ chainId: "0x13882" }],
        });
      } catch (switchError: unknown) {
        const chainError = switchError as ChainSwitchError;

        if (chainError.code === 4902) {
          await ethereum.request({
            method: "wallet_addEthereumChain",
            params: [
              {
                chainId: "0x13882",
                chainName: "Polygon Amoy Testnet",
                nativeCurrency: {
                  name: "MATIC",
                  symbol: "MATIC",
                  decimals: 18,
                },
                rpcUrls: ["https://rpc-amoy.polygon.technology"],
                blockExplorerUrls: ["https://amoy.polygonscan.com"],
              },
            ],
          });
        }
      }

      const accounts = await ethereum.request({
        method: "eth_requestAccounts",
      });

      if (Array.isArray(accounts) && typeof accounts[0] === "string") {
        setAccount(accounts[0]);
      } else {
        throw new Error("No account returned by wallet");
      }
    } catch (err: unknown) {
      setError(getErrorMessage(err, "Failed to connect wallet"));
    }
  };

  const report = async (withWallet: boolean) => {
    setLoading(true);
    setError(null);
    try {
      const body: ReportBody = {
        url: scamData?.url || "",
        text: scamData?.text || "",
        category: scamData?.category || "",
        riskScore: scamData?.riskScore || 0,
      };
      if (withWallet && account) body.reporterAddress = account;

      const res = await fetch(
        "https://hack-nocturne-2026.onrender.com/api/report",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        },
      );

      if (!res.ok) {
        let errorDetail = "Report failed";

        try {
          const errorResponse = (await res.json()) as { detail?: unknown };
          if (typeof errorResponse.detail === "string") {
            errorDetail = errorResponse.detail;
          }
        } catch {
          // Keep fallback message when response body is not valid JSON.
        }

        throw new Error(errorDetail);
      }

      const data = (await res.json()) as ReportResponse;
      setTx(data);
      localStorage.removeItem("scanResult");
    } catch (err: unknown) {
      setError(getErrorMessage(err, "Report failed"));
    }
    setLoading(false);
  };

  if (!scamData) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center flex-col gap-4">
        <p className="text-gray-400">No scan result found.</p>
        <Link href="/" className="text-blue-400 underline text-sm">
          Go back and scan first
        </Link>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-950 text-white flex flex-col">
      <Navbar />

      <main className="flex-1 flex justify-center px-4 pt-28 pb-16">
        <div className="w-full max-w-xl space-y-4">
          {/* HEADER */}
          <div className="flex items-center justify-between mb-2">
            <h1 className="text-2xl font-bold">Report This Scam</h1>
            <Link
              href="/"
              className="text-sm text-gray-400 hover:text-white transition-colors"
            >
              ← Back
            </Link>
          </div>

          <p className="text-sm text-gray-400">
            This will permanently store the report on the Polygon blockchain.
          </p>

          {/* SCAM SUMMARY */}
          <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 space-y-2">
            <p className="text-red-400 font-semibold text-sm">
              ⚠ Scam Detected
            </p>
            {scamData.url && (
              <p className="text-sm text-gray-300">
                <span className="text-gray-500">URL: </span>
                {scamData.url}
              </p>
            )}
            {scamData.text && (
              <p className="text-sm text-gray-300">
                <span className="text-gray-500">Message: </span>
                {scamData.text.slice(0, 100)}
                {scamData.text.length > 100 ? "..." : ""}
              </p>
            )}
            <div className="flex gap-4 pt-1">
              <p className="text-sm">
                <span className="text-gray-500">Category: </span>
                <span className="text-white font-medium">
                  {scamData.category}
                </span>
              </p>
              <p className="text-sm">
                <span className="text-gray-500">Risk: </span>
                <span className="text-red-400 font-bold">
                  {scamData.riskScore}/100
                </span>
              </p>
            </div>
          </div>

          {/* WALLET + REPORT SECTION */}
          {!tx && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-3">
              <h2 className="font-semibold text-gray-200">
                How do you want to report?
              </h2>

              {/* Wallet connect or connected state */}
              {!account ? (
                <button
                  onClick={connectWallet}
                  className="w-full bg-green-600 hover:bg-green-500 text-white py-3 rounded-lg font-semibold transition-colors"
                >
                  Connect Wallet
                </button>
              ) : (
                <div className="p-3 bg-green-500/10 border border-green-500/20 rounded-lg">
                  <p className="text-green-400 text-sm font-medium">
                    ✓ Wallet Connected
                  </p>
                  <p className="text-gray-500 text-xs mt-1 break-all">
                    {account}
                  </p>
                </div>
              )}

              {/* Report with wallet */}
              {account && (
                <button
                  onClick={() => report(true)}
                  disabled={loading}
                  className="w-full bg-purple-600 hover:bg-purple-500 disabled:bg-purple-900 disabled:text-purple-400 text-white py-3 rounded-lg font-semibold transition-colors"
                >
                  {loading ? "Submitting..." : "Report with My Wallet"}
                </button>
              )}

              {/* Divider */}
              <div className="flex items-center gap-3">
                <div className="flex-1 border-t border-gray-700" />
                <span className="text-xs text-gray-500">or</span>
                <div className="flex-1 border-t border-gray-700" />
              </div>

              {/* No wallet */}
              <button
                onClick={() => report(false)}
                disabled={loading}
                className="w-full bg-gray-700 hover:bg-gray-600 disabled:bg-gray-800 disabled:text-gray-500 text-white py-3 rounded-lg font-semibold transition-colors"
              >
                {loading ? "Submitting..." : "Report Without Wallet"}
              </button>

              <p className="text-xs text-gray-500 text-center">
                No wallet? We submit on-chain on your behalf.
              </p>
            </div>
          )}

          {/* LOADING */}
          {loading && (
            <div className="flex items-center justify-center gap-2 text-gray-400 text-sm py-2">
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
              Submitting to blockchain...
            </div>
          )}

          {/* ERROR */}
          {error && (
            <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
              <p className="text-red-400 text-sm">{error}</p>
            </div>
          )}

          {/* SUCCESS */}
          {tx && (
            <div className="space-y-3">
              <div className="p-4 bg-green-500/10 border border-green-500/20 rounded-xl">
                <p className="text-green-400 font-semibold mb-2">
                  ✓ Report Submitted to Blockchain
                </p>
                <p className="text-xs text-gray-500 break-all">
                  TX: {tx.txHash}
                </p>
              </div>

              <a
                className="block w-full text-center bg-blue-600 hover:bg-blue-500 text-white py-3 rounded-xl font-semibold transition-colors"
                href={`https://amoy.polygonscan.com/tx/${tx.txHash}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                View on Polygonscan →
              </a>

              <Link
                href="/"
                className="block w-full text-center border border-gray-700 text-gray-400 hover:text-white hover:border-gray-500 py-3 rounded-xl font-medium transition-colors text-sm"
              >
                Scan Another
              </Link>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
