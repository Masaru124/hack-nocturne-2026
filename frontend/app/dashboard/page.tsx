"use client";

import { useEffect, useState } from "react";

const API = "https://hack-nocturne-2026.onrender.com/api";

type ReportItem = {
  id: number;
  reporter?: string;
  textHash?: string;
  category?: string;
  riskScore?: number;
  timestamp?: number;
  votes?: number;
  isVerified?: boolean;
};

type StatsResponse = {
  totalReports: number;
  verifiedReports: number;
  categoryBreakdown: Record<string, number>;
  averageRiskScore: number;
};

export default function Dashboard() {
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [selected, setSelected] = useState<ReportItem | null>(null);

  async function loadReports() {
    const res = await fetch(`${API}/reports`);
    const data = await res.json();
    setReports(data);
  }

  async function loadStats() {
    const res = await fetch(`${API}/stats`);
    const data = await res.json();
    setStats(data);
  }

  async function openReport(id: number) {
    const res = await fetch(`${API}/reports/${id}`);
    const data = await res.json();
    setSelected(data);
  }

  async function vote() {
    if (!selected) return;

    await fetch(`${API}/vote`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        reportId: selected.id,
      }),
    });

    setSelected(null);
    loadReports();
  }

  useEffect(() => {
    loadReports();
    loadStats();
  }, []);

  return (
    <div className="min-h-screen bg-slate-950 text-white p-10">
      <div className="max-w-7xl mx-auto">
        <h1 className="text-4xl font-bold mb-2">Scam Intelligence</h1>

        <p className="text-slate-400 mb-10">
          Community flagged malicious links
        </p>

        {/* Stats */}

        {stats && (
          <div className="grid grid-cols-3 gap-6 mb-12">
            <div className="bg-slate-900 p-6 rounded-xl">
              <p className="text-slate-400 text-sm">Total Reports</p>
              <p className="text-3xl font-semibold">{stats.totalReports}</p>
            </div>

            <div className="bg-slate-900 p-6 rounded-xl">
              <p className="text-slate-400 text-sm">Verified</p>
              <p className="text-3xl font-semibold">{stats.verifiedReports}</p>
            </div>

            <div className="bg-slate-900 p-6 rounded-xl">
              <p className="text-slate-400 text-sm">Avg Risk</p>
              <p className="text-3xl font-semibold">{stats.averageRiskScore}</p>
            </div>
          </div>
        )}

        {/* Reports */}

        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {reports.map((r) => (
            <div
              key={r.id}
              onClick={() => openReport(r.id)}
              className="bg-slate-900 p-6 rounded-xl cursor-pointer hover:bg-slate-800 transition"
            >
              <h2 className="font-semibold text-lg mb-2">#{r.id}</h2>

              <p className="text-slate-400 text-sm mb-3">
                {r.category || "uncategorized"}
              </p>

              <p className="text-xs text-slate-500 break-all">{r.textHash}</p>

              <p className="mt-4 text-red-400 text-sm">Votes: {r.votes || 0}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Modal */}

      {selected && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center">
          <div className="bg-slate-900 p-8 rounded-xl max-w-lg w-full">
            <h2 className="text-2xl font-semibold mb-4">
              Report #{selected.id}
            </h2>

            <p className="text-slate-300 mb-6">
              Category: {selected.category || "uncategorized"}
            </p>

            <p className="text-xs text-slate-500 break-all mb-6">
              Hash: {selected.textHash}
            </p>

            <div className="flex gap-4">
              <button
                onClick={vote}
                className="bg-red-500 hover:bg-red-600 px-4 py-2 rounded-lg"
              >
                Upvote
              </button>

              <button
                onClick={() => setSelected(null)}
                className="bg-slate-700 px-4 py-2 rounded-lg"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
