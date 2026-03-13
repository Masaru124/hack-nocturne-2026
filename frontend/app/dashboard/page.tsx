"use client";

import { useEffect, useState } from "react";
import {
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";

const API = "https://hack-nocturne-2026-production.up.railway.app/api";

type ReportItem = {
  id: number;
  reporter?: string;
  textHash?: string;
  category?: string;
  riskScore?: number;
  timestamp?: number;
  votes?: number;
  isVerified?: boolean;
  url?: string | null;
};

type StatsResponse = {
  totalReports: number;
  verifiedReports: number;
  categoryBreakdown: Record<string, number>;
  averageRiskScore: number;
};

const PIE_COLORS = ["#ef4444", "#f97316", "#eab308", "#3b82f6", "#8b5cf6", "#06b6d4"];

function getRiskLevel(score?: number) {
  if (!score) return { label: "Unknown", color: "#64748b" };
  if (score >= 90) return { label: "Critical", color: "#ef4444" };
  if (score >= 70) return { label: "High", color: "#f97316" };
  if (score >= 40) return { label: "Medium", color: "#eab308" };
  return { label: "Low", color: "#22c55e" };
}

function formatTimestamp(ts?: number) {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString("en-US", {
    month: "short", day: "numeric", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

function truncate(str?: string | null, n = 32) {
  if (!str) return "—";
  return str.length > n ? str.slice(0, n) + "…" : str;
}

export default function Dashboard() {
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [selected, setSelected] = useState<ReportItem | null>(null);
  const [sortKey, setSortKey] = useState<keyof ReportItem>("id");
  const [sortAsc, setSortAsc] = useState(false);
  const [filterCat, setFilterCat] = useState("all");

  async function loadReports() {
    const res = await fetch(`${API}/reports`);
    setReports(await res.json());
  }
  async function loadStats() {
    const res = await fetch(`${API}/stats`);
    setStats(await res.json());
  }
  async function openReport(id: number) {
    const res = await fetch(`${API}/reports/${id}`);
    setSelected(await res.json());
  }
  async function vote() {
    if (!selected) return;
    await fetch(`${API}/vote`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reportId: selected.id }),
    });
    setSelected(null);
    loadReports();
  }

  useEffect(() => { loadReports(); loadStats(); }, []);

  const categoryData = stats?.categoryBreakdown
    ? Object.entries(stats.categoryBreakdown).map(([name, value]) => ({ name, value }))
    : [];

  const categories = ["all", ...Array.from(new Set(reports.map((r) => r.category || "uncategorized")))];

  const filtered = reports
    .filter((r) => filterCat === "all" || (r.category || "uncategorized") === filterCat)
    .sort((a, b) => {
      const av = a[sortKey] ?? 0;
      const bv = b[sortKey] ?? 0;
      if (av < bv) return sortAsc ? -1 : 1;
      if (av > bv) return sortAsc ? 1 : -1;
      return 0;
    });

  function handleSort(key: keyof ReportItem) {
    if (key === sortKey) setSortAsc(!sortAsc);
    else { setSortKey(key); setSortAsc(false); }
  }

  const COLS: { label: string; key: keyof ReportItem }[] = [
    { label: "ID", key: "id" },
    { label: "Hash / URL", key: "textHash" },
    { label: "Category", key: "category" },
    { label: "Risk", key: "riskScore" },
    { label: "Votes", key: "votes" },
    { label: "Verified", key: "isVerified" },
    { label: "Timestamp", key: "timestamp" },
  ];

  return (
    <div className="min-h-screen text-white" style={{
      background: "radial-gradient(ellipse at 20% 0%, #1a0505 0%, #09090f 50%, #050911 100%)",
      
    }}>
      <style>{`
        
        .card { background: linear-gradient(135deg,#111827,#0f172a); border: 1px solid rgba(239,68,68,0.12); border-radius: 14px; }
        .card:hover { border-color: rgba(239,68,68,0.3); }
        .row-item:hover { background: rgba(239,68,68,0.04); }
        .chip { display:inline-flex;align-items:center;padding:2px 10px;border-radius:20px;font-size:11px;font-weight:500; }
        .pill-btn { padding:3px 12px;border-radius:20px;font-size:11px;transition:all 0.15s;cursor:pointer; }
      `}</style>

      <div className="max-w-7xl mx-auto px-8 py-10">

        {/* Header */}
        <div className="flex items-end justify-between mb-10">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse inline-block" />
              <span className="text-red-500 text-xs tracking-widest uppercase">Live</span>
            </div>
            <h1 style={{ fontFamily: "'Syne',sans-serif", fontSize: "2.8rem", fontWeight: 800, letterSpacing: "-0.03em", lineHeight: 1 }}>
              Scam<span className="text-red-500">Intel</span>
            </h1>
            <p className="text-slate-500 text-sm mt-1">Community-powered threat detection</p>
          </div>
          <p className="text-slate-600 text-xs pb-1">{new Date().toDateString()}</p>
        </div>

        {/* KPIs */}
        {stats && (
          <div className="grid grid-cols-4 gap-4 mb-8">
            {[
              { label: "Total Reports", value: stats.totalReports, color: "#ef4444" },
              { label: "Verified", value: stats.verifiedReports, color: "#22c55e" },
              { label: "Avg Risk Score", value: stats.averageRiskScore, color: "#f97316" },
              { label: "Threat Types", value: categoryData.length, color: "#3b82f6" },
            ].map((s) => (
              <div key={s.label} className="card p-5 transition-all">
                <p className="text-slate-500 text-xs uppercase tracking-widest mb-3">{s.label}</p>
                <p style={{ color: s.color, fontFamily: "'Syne',sans-serif", fontSize: "2.4rem", fontWeight: 800, lineHeight: 1 }}>
                  {s.value}
                </p>
              </div>
            ))}
          </div>
        )}

        {/* Charts */}
        <div className="grid grid-cols-3 gap-4 mb-8">

          {/* Bar chart */}
          <div className="card col-span-2 p-5">
            <p className="text-slate-400 text-xs uppercase tracking-widest mb-5">Risk Score per Report</p>
            <ResponsiveContainer width="100%" height={170}>
              <BarChart data={reports.map((r) => ({ id: `#${r.id}`, score: r.riskScore ?? 0 }))} barSize={18}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" vertical={false} />
                <XAxis dataKey="id" tick={{ fill: "#475569", fontSize: 10 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: "#475569", fontSize: 10 }} axisLine={false} tickLine={false} domain={[0, 100]} />
                <Tooltip
                  contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8, fontSize: 12 }}
                  labelStyle={{ color: "#94a3b8" }}
                  itemStyle={{ color: "#ef4444" }}
                />
                <Bar dataKey="score" radius={[4, 4, 0, 0]}>
                  {reports.map((r) => (
                    <Cell key={r.id} fill={getRiskLevel(r.riskScore).color} opacity={0.85} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Pie chart */}
          <div className="card p-5">
            <p className="text-slate-400 text-xs uppercase tracking-widest mb-3">By Category</p>
            {categoryData.length > 0 ? (
              <>
                <ResponsiveContainer width="100%" height={120}>
                  <PieChart>
                    <Pie data={categoryData} cx="50%" cy="50%" innerRadius={32} outerRadius={52} dataKey="value" paddingAngle={4}>
                      {categoryData.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
                    </Pie>
                    <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8, fontSize: 12 }} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="mt-3 space-y-1.5">
                  {categoryData.map((d, i) => (
                    <div key={d.name} className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <div className="w-2 h-2 rounded-sm" style={{ background: PIE_COLORS[i % PIE_COLORS.length] }} />
                        <span className="text-slate-400 text-xs capitalize">{d.name}</span>
                      </div>
                      <span className="text-slate-300 text-xs font-medium">{d.value}</span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="h-40 flex items-center justify-center text-slate-700 text-xs">No category data</div>
            )}
          </div>
        </div>

        {/* Table */}
        <div className="card overflow-hidden">

          {/* Table toolbar */}
          <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
            <p className="text-slate-200 text-sm font-medium">Threat Reports
              <span className="text-slate-600 ml-2 text-xs font-normal">({filtered.length})</span>
            </p>
            <div className="flex items-center gap-2 flex-wrap">
              {categories.map((c) => (
                <button
                  key={c}
                  onClick={() => setFilterCat(c)}
                  className="pill-btn"
                  style={{
                    background: filterCat === c ? "rgba(239,68,68,0.18)" : "transparent",
                    color: filterCat === c ? "#ef4444" : "#64748b",
                    border: `1px solid ${filterCat === c ? "rgba(239,68,68,0.4)" : "rgba(100,116,139,0.2)"}`,
                  }}
                >
                  {c}
                </button>
              ))}
            </div>
          </div>

          {/* Column headers */}
          <div
            className="grid text-xs text-slate-600 uppercase tracking-widest px-6 py-3 border-b border-slate-800/50"
            style={{ gridTemplateColumns: "52px 1fr 120px 130px 72px 80px 150px" }}
          >
            {COLS.map((col) => (
              <button
                key={col.key}
                onClick={() => handleSort(col.key)}
                className="text-left hover:text-slate-300 transition-colors flex items-center gap-1"
              >
                {col.label}
                {col.key === sortKey
                  ? <span className="text-orange-400">{sortAsc ? "↑" : "↓"}</span>
                  : <span className="opacity-20">↕</span>}
              </button>
            ))}
          </div>

          {/* Rows */}
          <div className="divide-y divide-slate-800/30">
            {filtered.length === 0 && (
              <div className="px-6 py-12 text-center text-slate-700 text-sm">No reports match filter</div>
            )}
            {filtered.map((r) => {
              const risk = getRiskLevel(r.riskScore);
              return (
                <div
                  key={r.id}
                  onClick={() => openReport(r.id)}
                  className="row-item grid items-center px-6 py-4 cursor-pointer transition-colors"
                  style={{ gridTemplateColumns: "52px 1fr 120px 130px 72px 80px 150px" }}
                >
                  <span className="text-slate-500 text-sm">#{r.id}</span>

                  <div className="pr-4 min-w-0">
                    <p className="text-slate-300 text-xs font-mono truncate">{truncate(r.textHash, 38)}</p>
                    {r.url ? (
                      <a
                        href={r.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        onClick={(e) => e.stopPropagation()}
                        className="text-red-400 text-xs hover:underline block mt-0.5 truncate"
                      >
                        {truncate(r.url, 44)}
                      </a>
                    ) : (
                      <span className="text-slate-700 text-xs mt-0.5 block">no url</span>
                    )}
                  </div>

                  <span className="chip capitalize" style={{ background: "rgba(59,130,246,0.1)", color: "#93c5fd", border: "1px solid rgba(59,130,246,0.2)" }}>
                    {r.category || "unknown"}
                  </span>

                  <div className="flex items-center gap-2">
                    <div className="w-14 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                      <div className="h-full rounded-full" style={{ width: `${r.riskScore ?? 0}%`, background: risk.color }} />
                    </div>
                    <span className="text-xs font-medium tabular-nums" style={{ color: risk.color }}>{r.riskScore ?? "—"}</span>
                    <span className="text-xs text-slate-600">({risk.label})</span>
                  </div>

                  <span className="text-red-400 text-sm">▲ {r.votes ?? 0}</span>

                  <span className={`text-xs ${r.isVerified ? "text-green-400" : "text-slate-700"}`}>
                    {r.isVerified ? "✓ Verified" : "Unverified"}
                  </span>

                  <span className="text-slate-500 text-xs">{formatTimestamp(r.timestamp)}</span>
                </div>
              );
            })}
          </div>

          <div className="px-6 py-3 border-t border-slate-800 flex justify-between">
            <span className="text-slate-700 text-xs">{filtered.length} of {reports.length} reports shown</span>
            <span className="text-slate-700 text-xs">Click any row to inspect</span>
          </div>
        </div>
      </div>

      {/* Detail Modal */}
      {selected && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center"
          style={{ background: "rgba(0,0,0,0.8)", backdropFilter: "blur(6px)" }}
          onClick={() => setSelected(null)}
        >
          <div
            className="w-full max-w-lg rounded-2xl p-8 relative"
            style={{
              background: "linear-gradient(135deg,#111827,#0f172a)",
              border: "1px solid rgba(239,68,68,0.3)",
              boxShadow: "0 0 80px rgba(239,68,68,0.08), 0 25px 60px rgba(0,0,0,0.6)",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="absolute top-6 right-6">
              <span className="chip" style={{ background: `${getRiskLevel(selected.riskScore).color}18`, color: getRiskLevel(selected.riskScore).color, border: `1px solid ${getRiskLevel(selected.riskScore).color}40` }}>
                {getRiskLevel(selected.riskScore).label} · {selected.riskScore ?? "—"}
              </span>
            </div>

            <div className="flex items-center gap-3 mb-6">
              <div className="w-1 h-10 rounded bg-red-500 flex-shrink-0" />
              <div>
                <h2 style={{ fontFamily: "'Syne',sans-serif", fontSize: "1.6rem", fontWeight: 800 }}>Report #{selected.id}</h2>
                <p className="text-slate-500 text-xs">{formatTimestamp(selected.timestamp)}</p>
              </div>
            </div>

            <div className="space-y-2 mb-5">
              {[
                { label: "Category", value: selected.category || "uncategorized" },
                { label: "Reporter", value: truncate(selected.reporter, 36) },
                { label: "Votes", value: `▲ ${selected.votes ?? 0}` },
                { label: "Verified", value: selected.isVerified ? "✓ Yes" : "No" },
              ].map((f) => (
                <div key={f.label} className="flex justify-between items-center py-2 border-b border-slate-800/70">
                  <span className="text-slate-600 text-xs uppercase tracking-wider">{f.label}</span>
                  <span className="text-slate-200 text-sm">{f.value}</span>
                </div>
              ))}
            </div>

            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 mb-3">
              <p className="text-slate-600 text-xs uppercase tracking-wider mb-1">Hash</p>
              <p className="text-slate-400 text-xs font-mono break-all">{selected.textHash}</p>
            </div>

            {selected.url && (
              <div className="p-3 rounded-lg mb-5" style={{ background: "rgba(239,68,68,0.06)", border: "1px solid rgba(239,68,68,0.2)" }}>
                <p className="text-red-500 text-xs uppercase tracking-wider mb-1">⚠ Malicious URL</p>
                <a href={selected.url} target="_blank" rel="noopener noreferrer" className="text-red-400 text-xs font-mono break-all hover:underline">
                  {selected.url}
                </a>
              </div>
            )}

            <div className="flex gap-3">
              <button
                onClick={vote}
                className="flex-1 py-3 rounded-xl text-sm font-semibold transition-all hover:scale-[1.02] active:scale-95"
                style={{ background: "linear-gradient(135deg,#ef4444,#dc2626)", boxShadow: "0 4px 24px rgba(239,68,68,0.3)" }}
              >
                ▲ Upvote Threat
              </button>
              <button
                onClick={() => setSelected(null)}
                className="px-6 py-3 rounded-xl text-sm transition-all hover:bg-slate-700"
                style={{ background: "#1e293b", color: "#94a3b8" }}
              >
                Dismiss
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}