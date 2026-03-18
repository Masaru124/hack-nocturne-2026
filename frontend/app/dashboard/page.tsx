"use client";

import { useEffect, useState } from "react";
import dynamic from "next/dynamic";
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
import Navbar from "@/components/Navbar";
import type { MapConnection, MapMarker } from "@/components/ScamMap";

// Load Leaflet map only on the client side (Leaflet requires window / document)
const ScamMap = dynamic(() => import("@/components/ScamMap"), { ssr: false });

const API = "https://hack-nocturne-2026-production.up.railway.app/api";

type ReportItem = {
  id?: number | null;
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

type AiHuntActivityItem = {
  time: string;
  stage: "signal_found" | "analysis_running" | "reported";
  message: string;
  domain: string;
  riskScore: number;
  category: string;
  status: string;
  discoveredBy: string;
};

type AiHuntCampaign = {
  campaign: string;
  domains: string[];
  connectedDomains: number;
  maxRisk: number;
  categories: string[];
  reusedWallets: number;
};

type AiHuntGlobalActivity = {
  country: string;
  reports: number;
  highRisk: number;
  suspicious: number;
  safe: number;
  level: "high" | "medium" | "low";
};

type AiHuntDiscovery = {
  id?: string | number | null;
  domain: string;
  url: string;
  riskScore: number;
  category: string;
  indicators: string[];
  source: string;
  discoveredBy: string;
  discoveredAt: string;
  timestamp: number;
  status: string;
  txHash: string | null;
  onChain: boolean;
};

type AiHuntResponse = {
  generatedAt: string;
  status: string;
  scannedSources: string[];
  discoveries: AiHuntDiscovery[];
  activity: AiHuntActivityItem[];
  campaigns: AiHuntCampaign[];
  globalActivity: AiHuntGlobalActivity[];
  summary: {
    totalDiscoveries: number;
    highRiskCount: number;
    reportedOnChain: number;
  };
};

type CountryStat = {
  country: string;
  total: number;
  high: number;
  medium: number;
  low: number;
};

type MapActivity = {
  markers: MapMarker[];
  connections: MapConnection[];
  countryStats: CountryStat[];
  total: number;
  generatedAt: string;
};

function buildHardcodedMapActivity(): MapActivity {
  const now = Date.now();
  const markers: MapMarker[] = [
    {
      id: "m-1",
      lat: 12.9716,
      lng: 77.5946,
      domain: "upi-verify-security.top",
      riskScore: 91,
      category: "UPI Phishing",
      country: "India",
      discoveredAt: new Date(now - 5 * 60_000).toISOString(),
      level: "high",
      source: "Demo Radar",
      onChain: true,
    },
    {
      id: "m-2",
      lat: 28.6139,
      lng: 77.209,
      domain: "claim-binance-airdrop.xyz",
      riskScore: 94,
      category: "Crypto Airdrop Scam",
      country: "India",
      discoveredAt: new Date(now - 12 * 60_000).toISOString(),
      level: "high",
      source: "Demo Radar",
      onChain: true,
    },
    {
      id: "m-3",
      lat: 37.0902,
      lng: -95.7129,
      domain: "coinbase-wallet-verify.online",
      riskScore: 86,
      category: "Wallet Phishing",
      country: "USA",
      discoveredAt: new Date(now - 18 * 60_000).toISOString(),
      level: "high",
      source: "Demo Radar",
      onChain: true,
    },
    {
      id: "m-4",
      lat: 51.5072,
      lng: -0.1276,
      domain: "nft-mint-fastpass.io",
      riskScore: 62,
      category: "NFT Suspicious",
      country: "UK",
      discoveredAt: new Date(now - 55 * 60_000).toISOString(),
      level: "medium",
      source: "Demo Radar",
      onChain: false,
    },
    {
      id: "m-5",
      lat: 1.3521,
      lng: 103.8198,
      domain: "secure-exchange-bonus.site",
      riskScore: 74,
      category: "Exchange Phishing",
      country: "Singapore",
      discoveredAt: new Date(now - 3 * 3600_000).toISOString(),
      level: "high",
      source: "Demo Radar",
      onChain: false,
    },
    {
      id: "m-6",
      lat: 9.082,
      lng: 8.6753,
      domain: "eth-reward-checker.click",
      riskScore: 58,
      category: "Suspicious Rewards",
      country: "Nigeria",
      discoveredAt: new Date(now - 7 * 3600_000).toISOString(),
      level: "medium",
      source: "Demo Radar",
      onChain: false,
    },
    {
      id: "m-7",
      lat: 35.6762,
      lng: 139.6503,
      domain: "free-token-airdrop-info.net",
      riskScore: 29,
      category: "Low Risk Report",
      country: "Japan",
      discoveredAt: new Date(now - 42 * 3600_000).toISOString(),
      level: "low",
      source: "Demo Radar",
      onChain: false,
    },
  ];

  const connections: MapConnection[] = [
    {
      id: "c-1",
      fromLat: 61.524,
      fromLng: 105.3188,
      toLat: 51.1657,
      toLng: 10.4515,
      label: "fake-airdrop campaign: Russia → Germany",
      level: "high",
    },
    {
      id: "c-2",
      fromLat: 51.1657,
      fromLng: 10.4515,
      toLat: 20.5937,
      toLng: 78.9629,
      label: "Victims route: Germany → India",
      level: "high",
    },
    {
      id: "c-3",
      fromLat: 20.5937,
      fromLng: 78.9629,
      toLat: 1.3521,
      toLng: 103.8198,
      label: "Cashout route: India → Singapore",
      level: "medium",
    },
  ];

  const countryMap: Record<string, CountryStat> = {};
  for (const marker of markers) {
    if (!countryMap[marker.country]) {
      countryMap[marker.country] = {
        country: marker.country,
        total: 0,
        high: 0,
        medium: 0,
        low: 0,
      };
    }
    countryMap[marker.country].total += 1;
    countryMap[marker.country][marker.level] += 1;
  }

  const countryStats = Object.values(countryMap).sort(
    (a, b) => b.total - a.total,
  );

  return {
    markers,
    connections,
    countryStats,
    total: markers.length,
    generatedAt: new Date(now).toISOString(),
  };
}

const PIE_COLORS = [
  "#ef4444",
  "#f97316",
  "#eab308",
  "#3b82f6",
  "#8b5cf6",
  "#06b6d4",
];

function getRiskLevel(score?: number) {
  if (!score)
    return {
      label: "Unknown",
      color: "#64748b",
      textClass: "text-slate-500",
      chipClass: "bg-slate-500/10 text-slate-400 border-slate-500/30",
    };
  if (score >= 90)
    return {
      label: "Critical",
      color: "#ef4444",
      textClass: "text-red-500",
      chipClass: "bg-red-500/10 text-red-400 border-red-500/30",
    };
  if (score >= 70)
    return {
      label: "High",
      color: "#f97316",
      textClass: "text-orange-500",
      chipClass: "bg-orange-500/10 text-orange-400 border-orange-500/30",
    };
  if (score >= 40)
    return {
      label: "Medium",
      color: "#eab308",
      textClass: "text-yellow-500",
      chipClass: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
    };
  return {
    label: "Low",
    color: "#22c55e",
    textClass: "text-green-500",
    chipClass: "bg-green-500/10 text-green-400 border-green-500/30",
  };
}

function formatTimestamp(ts?: number) {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function truncate(str?: string | null, n = 32) {
  if (!str) return "—";
  return str.length > n ? str.slice(0, n) + "…" : str;
}

function formatRelativeTime(iso?: string) {
  if (!iso) return "just now";
  const value = new Date(iso).getTime();
  if (Number.isNaN(value)) return "just now";
  const diffSec = Math.max(0, Math.floor((Date.now() - value) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  return `${Math.floor(diffSec / 86400)}d ago`;
}

export default function Dashboard() {
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [selected, setSelected] = useState<ReportItem | null>(null);
  const [aiHunt, setAiHunt] = useState<AiHuntResponse | null>(null);
  const [aiHuntLoading, setAiHuntLoading] = useState(false);
  const [mapActivity, setMapActivity] = useState<MapActivity | null>(null);
  const [mapWindow, setMapWindow] = useState<"1h" | "24h" | "7d">("24h");
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
  async function openReport(id: number | null | undefined) {
    if (typeof id !== "number" || !Number.isFinite(id)) return;
    const res = await fetch(`${API}/reports/${id}`);
    if (!res.ok) return;
    setSelected(await res.json());
  }

  async function loadAiHunt() {
    try {
      setAiHuntLoading(true);
      const res = await fetch(`${API}/ai-hunt/activity?limit=12`);
      const data = await res.json();
      if (!res.ok) throw new Error(data?.detail || "Failed to load AI Hunt");
      setAiHunt(data as AiHuntResponse);
    } catch {
      setAiHunt(null);
    } finally {
      setAiHuntLoading(false);
    }
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

  useEffect(() => {
    loadReports();
    loadStats();
    loadAiHunt();
    setMapActivity(buildHardcodedMapActivity());
    const t = setInterval(() => {
      loadAiHunt();
    }, 30000);
    return () => clearInterval(t);
  }, []);

  const mapWindowMs =
    mapWindow === "1h"
      ? 3600_000
      : mapWindow === "24h"
        ? 86_400_000
        : 604_800_000;
  const mapMarkers = (mapActivity?.markers || []).filter((marker) => {
    const ts = new Date(marker.discoveredAt).getTime();
    return Number.isNaN(ts) ? true : Date.now() - ts <= mapWindowMs;
  });
  const mapCountryStats = (mapActivity?.countryStats || []).filter((country) =>
    mapMarkers.some((marker) => marker.country === country.country),
  );
  const latestMapMarker = mapMarkers[0] || null;
  const liveConnections = mapActivity?.connections || [];
  const nearbyHotspot = mapCountryStats[0] || null;
  const nearbyCategory = nearbyHotspot
    ? mapMarkers.find((marker) => marker.country === nearbyHotspot.country)
        ?.category || "Unknown"
    : "Unknown";

  const categoryData = stats?.categoryBreakdown
    ? Object.entries(stats.categoryBreakdown).map(([name, value]) => ({
        name,
        value,
      }))
    : [];

  const categories = [
    "all",
    ...Array.from(new Set(reports.map((r) => r.category || "uncategorized"))),
  ];

  const filtered = reports
    .filter(
      (r) =>
        filterCat === "all" || (r.category || "uncategorized") === filterCat,
    )
    .sort((a, b) => {
      const av = a[sortKey] ?? 0;
      const bv = b[sortKey] ?? 0;
      if (av < bv) return sortAsc ? -1 : 1;
      if (av > bv) return sortAsc ? 1 : -1;
      return 0;
    });

  function handleSort(key: keyof ReportItem) {
    if (key === sortKey) setSortAsc(!sortAsc);
    else {
      setSortKey(key);
      setSortAsc(false);
    }
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
    <div className="min-h-screen text-white bg-[radial-gradient(ellipse_at_20%_0%,#1a0505_0%,#09090f_50%,#050911_100%)]">
      <div className="max-w-6xl mx-auto px-8 py-10">
        <Navbar />
        {/* Header */}
        <div className="flex mt-20 items-end justify-between mb-10">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse inline-block" />
              <span className="text-red-500 text-xs tracking-widest uppercase">
                Live
              </span>
            </div>
            <h1 className="[font-family:'Syne',sans-serif] text-[2.8rem] font-extrabold tracking-[-0.03em] leading-none">
              Scam<span className="text-red-500">Shield</span>
            </h1>
            <p className="text-slate-500 text-sm mt-1">
              Community-powered threat detection
            </p>
          </div>
          <p className="text-slate-600 text-xs pb-1">
            {new Date().toDateString()}
          </p>
        </div>

        {/* KPIs */}
        {stats && (
          <div className="grid grid-cols-3 gap-4 mb-8">
            {[
              {
                label: "Total Reports",
                value: stats.totalReports,
                color: "#ef4444",
              },

              {
                label: "Avg Risk Score",
                value: stats.averageRiskScore,
                color: "#f97316",
              },
              {
                label: "Threat Types",
                value: categoryData.length,
                color: "#3b82f6",
              },
            ].map((s) => (
              <div
                key={s.label}
                className="rounded-[14px] border border-red-500/15 bg-gradient-to-br from-gray-900 to-slate-900 p-5 transition-all hover:border-red-500/30"
              >
                <p className="text-slate-500 text-xs uppercase tracking-widest mb-3">
                  {s.label}
                </p>
                <p
                  className="[font-family:'Syne',sans-serif] text-[2.4rem] font-extrabold leading-none"
                  style={{ color: s.color }}
                >
                  {s.value}
                </p>
              </div>
            ))}
          </div>
        )}

        {/* Charts */}
        <div className="grid grid-cols-3 gap-4 mb-8">
          {/* Bar chart */}
          <div className="col-span-2 rounded-[14px] border border-red-500/15 bg-gradient-to-br from-gray-900 to-slate-900 p-5 hover:border-red-500/30 transition-all">
            <p className="text-slate-400 text-xs uppercase tracking-widest mb-5">
              Risk Score per Report
            </p>
            <ResponsiveContainer width="100%" height={170}>
              <BarChart
                data={reports.map((r) => ({
                  id: `#${r.id}`,
                  score: r.riskScore ?? 0,
                }))}
                barSize={18}
              >
                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke="rgba(255,255,255,0.03)"
                  vertical={false}
                />
                <XAxis
                  dataKey="id"
                  tick={{ fill: "#475569", fontSize: 10 }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: "#475569", fontSize: 10 }}
                  axisLine={false}
                  tickLine={false}
                  domain={[0, 100]}
                />
                <Tooltip
                  contentStyle={{
                    background: "#0f172a",
                    border: "1px solid #1e293b",
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                  labelStyle={{ color: "#94a3b8" }}
                  itemStyle={{ color: "#ef4444" }}
                />
                <Bar dataKey="score" radius={[4, 4, 0, 0]}>
                  {reports.map((r, idx) => (
                    <Cell
                      key={`bar-${r.id}-${r.textHash || "no-hash"}-${r.timestamp || 0}-${idx}`}
                      fill={getRiskLevel(r.riskScore).color}
                      opacity={0.85}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Pie chart */}
          <div className="rounded-[14px] border border-red-500/15 bg-gradient-to-br from-gray-900 to-slate-900 p-5 hover:border-red-500/30 transition-all">
            <p className="text-slate-400 text-xs uppercase tracking-widest mb-3">
              By Category
            </p>
            {categoryData.length > 0 ? (
              <>
                <ResponsiveContainer width="100%" height={120}>
                  <PieChart>
                    <Pie
                      data={categoryData}
                      cx="50%"
                      cy="50%"
                      innerRadius={32}
                      outerRadius={52}
                      dataKey="value"
                      paddingAngle={4}
                    >
                      {categoryData.map((_, i) => (
                        <Cell
                          key={i}
                          fill={PIE_COLORS[i % PIE_COLORS.length]}
                        />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        background: "#0f172a",
                        border: "1px solid #1e293b",
                        borderRadius: 8,
                        fontSize: 12,
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
                <div className="mt-3 space-y-1.5">
                  {categoryData.map((d, i) => (
                    <div
                      key={d.name}
                      className="flex items-center justify-between"
                    >
                      <div className="flex items-center gap-2">
                        <div
                          className="w-2 h-2 rounded-sm"
                          style={{
                            background: PIE_COLORS[i % PIE_COLORS.length],
                          }}
                        />
                        <span className="text-slate-400 text-xs capitalize">
                          {d.name}
                        </span>
                      </div>
                      <span className="text-slate-300 text-xs font-medium">
                        {d.value}
                      </span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="h-40 flex items-center justify-center text-slate-700 text-xs">
                No category data
              </div>
            )}
          </div>
        </div>

        {/* Scam Intelligence Map */}
        <div className="rounded-[14px] border border-red-500/20 bg-gradient-to-br from-slate-900 to-[#0a101e] p-5 mb-6">
          <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
            <div>
              <p className="text-red-300 text-xs uppercase tracking-widest">
                🌍 Global Scam Activity
              </p>
              <p className="text-slate-500 text-xs mt-1">
                OpenStreetMap live radar · red=high risk · yellow=suspicious ·
                green=low
              </p>
            </div>
            <div className="flex items-center gap-2">
              {[
                { key: "1h", label: "Last hour" },
                { key: "24h", label: "Last 24h" },
                { key: "7d", label: "Last week" },
              ].map((w) => (
                <button
                  key={w.key}
                  onClick={() => setMapWindow(w.key as "1h" | "24h" | "7d")}
                  className={`px-3 py-1 rounded-full text-[11px] border transition ${mapWindow === w.key ? "text-red-300 border-red-500/40 bg-red-500/10" : "text-slate-500 border-slate-600/30 bg-slate-800/40"}`}
                >
                  {w.label}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-4 gap-4">
            <div className="xl:col-span-3 rounded-xl border border-slate-800 overflow-hidden bg-[#050b16]">
              {mapMarkers.length > 0 ? (
                <ScamMap
                  markers={mapMarkers}
                  connections={liveConnections}
                  height={430}
                />
              ) : (
                <div className="h-[430px] flex items-center justify-center text-slate-600 text-sm">
                  No map activity for selected time window
                </div>
              )}
            </div>

            <div className="space-y-3">
              <div className="rounded-lg border border-red-500/20 bg-black/30 p-3">
                <p className="text-red-300 text-[11px] uppercase tracking-widest mb-2">
                  ⚡ Live Scam Radar
                </p>
                {latestMapMarker ? (
                  <div className="space-y-1 text-xs">
                    <p className="text-slate-200 font-mono break-all">
                      {latestMapMarker.domain}
                    </p>
                    <p className="text-slate-400">
                      Risk Score:{" "}
                      <span className="text-red-400">
                        {latestMapMarker.riskScore}
                      </span>
                    </p>
                    <p className="text-slate-400">
                      Category:{" "}
                      <span className="text-slate-300">
                        {latestMapMarker.category}
                      </span>
                    </p>
                    <p className="text-slate-400">
                      Location:{" "}
                      <span className="text-slate-300">
                        {latestMapMarker.country}
                      </span>
                    </p>
                    <p className="text-slate-500">
                      Reported:{" "}
                      {formatRelativeTime(latestMapMarker.discoveredAt)}
                    </p>
                  </div>
                ) : (
                  <p className="text-slate-600 text-xs">
                    Waiting for detections...
                  </p>
                )}
              </div>

              <div className="rounded-lg border border-orange-500/20 bg-black/30 p-3">
                <p className="text-orange-300 text-[11px] uppercase tracking-widest mb-2">
                  🧠 Heatmap Mode
                </p>
                <div className="space-y-1.5 max-h-40 overflow-auto pr-1">
                  {mapCountryStats.slice(0, 6).map((country) => (
                    <div
                      key={country.country}
                      className="flex items-center justify-between text-xs"
                    >
                      <span className="text-slate-300">{country.country}</span>
                      <span className="font-mono text-slate-400">
                        {country.total} reports
                      </span>
                    </div>
                  ))}
                  {!mapCountryStats.length && (
                    <p className="text-slate-600 text-xs">No density data</p>
                  )}
                </div>
              </div>

              <div className="rounded-lg border border-cyan-500/20 bg-black/30 p-3">
                <p className="text-cyan-300 text-[11px] uppercase tracking-widest mb-2">
                  🧭 Scam Near You
                </p>
                <p className="text-slate-500 text-xs">
                  Derived from live hotspot activity:
                </p>
                {nearbyHotspot ? (
                  <p className="text-slate-300 text-xs mt-2">
                    ⚠ Region: {nearbyHotspot.country} · Category:{" "}
                    {nearbyCategory} · Reports: {nearbyHotspot.total}
                  </p>
                ) : (
                  <p className="text-slate-600 text-xs mt-2">
                    No nearby data yet
                  </p>
                )}
              </div>

              <div className="rounded-lg border border-purple-500/20 bg-black/30 p-3">
                <p className="text-purple-300 text-[11px] uppercase tracking-widest mb-2">
                  🔎 Scam Campaign Tracking
                </p>
                {liveConnections.length ? (
                  <div className="space-y-1.5 text-xs max-h-36 overflow-auto pr-1">
                    {liveConnections.slice(0, 3).map((route) => (
                      <p
                        key={route.id}
                        className="text-slate-300 font-mono break-words"
                      >
                        {route.label}
                      </p>
                    ))}
                  </div>
                ) : (
                  <p className="text-slate-600 text-xs">
                    No campaign routes detected yet
                  </p>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Live AI Discovery Cards */}
        <div id="ai-hunt" className="mb-6 scroll-mt-28">
          <div className="flex items-center justify-between mb-3">
            <div>
              <p className="text-cyan-300 text-xs uppercase tracking-widest">
                Live AI Discoveries
              </p>
              <p className="text-slate-500 text-xs mt-0.5">
                Threats autonomously found by the AI Hunt engine
              </p>
            </div>
            <span
              className={`text-[10px] font-mono px-2 py-1 rounded-full border ${
                aiHuntLoading
                  ? "text-cyan-300 border-cyan-500/30 bg-cyan-500/10"
                  : aiHunt?.status === "active"
                    ? "text-green-300 border-green-500/30 bg-green-500/10"
                    : "text-slate-400 border-slate-600/30 bg-slate-600/10"
              }`}
            >
              {aiHuntLoading
                ? "scanning…"
                : aiHunt?.status === "active"
                  ? "● hunting"
                  : "idle"}
            </span>
          </div>

          {aiHunt?.discoveries?.length ? (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
              {aiHunt.discoveries.slice(0, 6).map((d, idx) => {
                const rl = getRiskLevel(d.riskScore);
                const discoveryKey =
                  d.id ??
                  d.url ??
                  `${d.domain || "unknown"}-${d.timestamp || 0}-${idx}`;
                return (
                  <div
                    key={String(discoveryKey)}
                    className="rounded-[12px] border border-slate-700/60 bg-gradient-to-br from-slate-900 to-[#0a0f1a] p-4 hover:border-cyan-500/30 transition-all"
                  >
                    {/* Header row */}
                    <div className="flex items-center justify-between gap-2 mb-2">
                      <p className="font-mono text-sm text-slate-100 truncate flex-1">
                        {d.domain}
                      </p>
                      <span
                        className="text-xs font-bold px-2 py-0.5 rounded-full border"
                        style={{
                          color: rl.color,
                          borderColor: rl.color + "44",
                          backgroundColor: rl.color + "18",
                        }}
                      >
                        {d.riskScore}
                      </span>
                    </div>

                    {/* Category + source */}
                    <p className="text-[11px] text-cyan-400/80 mb-1">
                      {d.category}
                    </p>
                    <p className="text-[10px] text-slate-500 mb-2">
                      via {d.source}
                    </p>

                    {/* Top indicator */}
                    {d.indicators?.[0] && (
                      <p className="text-[11px] text-slate-400 bg-slate-800/60 rounded px-2 py-1 mb-2 truncate">
                        {d.indicators?.[0]}
                      </p>
                    )}

                    {/* Footer */}
                    <div className="flex items-center justify-between gap-2 mt-auto pt-1 border-t border-slate-800">
                      <span className="text-[10px] text-slate-500">
                        {formatRelativeTime(d.discoveredAt)}
                      </span>
                      {d.onChain ? (
                        <a
                          href={`https://amoy.polygonscan.com/tx/${d.txHash}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-[10px] font-mono text-green-400 border border-green-500/30 bg-green-500/10 px-1.5 py-0.5 rounded hover:bg-green-500/20 transition"
                        >
                          on-chain ↗
                        </a>
                      ) : (
                        <span className="text-[10px] font-mono text-yellow-400 border border-yellow-500/30 bg-yellow-500/10 px-1.5 py-0.5 rounded">
                          flagged
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="rounded-[12px] border border-slate-700/40 bg-slate-900/40 h-32 flex flex-col items-center justify-center gap-2">
              <span className="text-slate-500 text-xs">
                {aiHuntLoading
                  ? "AI Hunt is scanning…"
                  : "Warming up — first discoveries appear within 60 seconds"}
              </span>
            </div>
          )}
        </div>

        {/* AI Hunt Activity + Global Activity */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-8">
          <div className="lg:col-span-2 rounded-[14px] border border-cyan-500/20 bg-gradient-to-br from-slate-900 to-[#0b1626] p-5">
            <div className="flex items-center justify-between mb-4">
              <div>
                <p className="text-cyan-300 text-xs uppercase tracking-widest">
                  AI Hunt Activity
                </p>
                <p className="text-slate-500 text-xs mt-1">
                  Autonomous scam hunter pipeline
                </p>
              </div>
              <span className="text-[10px] font-mono text-cyan-300 bg-cyan-400/10 border border-cyan-400/30 px-2 py-1 rounded-full">
                {aiHuntLoading ? "scanning..." : aiHunt?.status || "idle"}
              </span>
            </div>

            {aiHunt ? (
              <>
                <div className="grid grid-cols-3 gap-3 mb-4">
                  <div className="rounded-lg border border-cyan-500/20 bg-black/20 p-3">
                    <p className="text-slate-500 text-[10px] uppercase">
                      Discoveries
                    </p>
                    <p className="text-cyan-300 text-xl font-bold">
                      {aiHunt.summary.totalDiscoveries}
                    </p>
                  </div>
                  <div className="rounded-lg border border-red-500/20 bg-black/20 p-3">
                    <p className="text-slate-500 text-[10px] uppercase">
                      High Risk
                    </p>
                    <p className="text-red-400 text-xl font-bold">
                      {aiHunt.summary.highRiskCount}
                    </p>
                  </div>
                  <div className="rounded-lg border border-orange-500/20 bg-black/20 p-3">
                    <p className="text-slate-500 text-[10px] uppercase">
                      On-Chain Reports
                    </p>
                    <p className="text-orange-400 text-xl font-bold">
                      {aiHunt.summary.reportedOnChain}
                    </p>
                  </div>
                </div>

                <div className="space-y-2 max-h-56 overflow-auto pr-1">
                  {aiHunt.activity.slice(0, 8).map((item, idx) => (
                    <div
                      key={`${item.time}-${idx}`}
                      className="rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <span className="text-[10px] font-mono text-slate-500">
                          [{formatRelativeTime(item.time)}]
                        </span>
                        <span
                          className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${item.status.includes("reported") ? "text-green-300 border-green-500/30 bg-green-500/10" : item.status === "running" ? "text-cyan-300 border-cyan-500/30 bg-cyan-500/10" : "text-yellow-300 border-yellow-500/30 bg-yellow-500/10"}`}
                        >
                          {item.status}
                        </span>
                      </div>
                      <p className="text-slate-200 text-xs mt-1">
                        {item.message}
                      </p>
                      <p className="text-slate-500 text-[11px] mt-1">
                        {item.domain} · {item.category} · risk {item.riskScore}
                      </p>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="h-40 flex items-center justify-center text-slate-600 text-xs">
                AI Hunt feed unavailable
              </div>
            )}
          </div>

          <div className="rounded-[14px] border border-orange-500/20 bg-gradient-to-br from-slate-900 to-[#191308] p-5">
            <p className="text-orange-300 text-xs uppercase tracking-widest mb-1">
              Global Scam Activity
            </p>
            <p className="text-slate-500 text-xs mb-4">Live radar by region</p>

            {aiHunt?.globalActivity?.length ? (
              <div className="space-y-2">
                {aiHunt.globalActivity.slice(0, 6).map((row) => (
                  <div
                    key={row.country}
                    className="rounded-lg border border-slate-800 bg-black/25 p-2"
                  >
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-slate-300">{row.country}</span>
                      <span
                        className={`font-mono ${row.level === "high" ? "text-red-400" : row.level === "medium" ? "text-yellow-400" : "text-green-400"}`}
                      >
                        {row.reports} reports
                      </span>
                    </div>
                    <div className="h-1.5 mt-2 rounded-full bg-slate-800 overflow-hidden">
                      <div
                        className={`${row.level === "high" ? "bg-red-500" : row.level === "medium" ? "bg-yellow-500" : "bg-green-500"} h-full rounded-full`}
                        style={{ width: `${Math.min(100, row.reports * 18)}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="h-32 flex items-center justify-center text-slate-600 text-xs">
                No regional activity
              </div>
            )}
          </div>
        </div>

        {/* Scam Campaign Detection */}

        {/* Table */}
        <div className="rounded-[14px] border border-red-500/15 bg-gradient-to-br from-gray-900 to-slate-900 overflow-hidden hover:border-red-500/30 transition-all">
          {/* Table toolbar */}
          <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
            <p className="text-slate-200 text-sm font-medium">
              Threat Reports
              <span className="text-slate-600 ml-2 text-xs font-normal">
                ({filtered.length})
              </span>
            </p>
            <div className="flex items-center gap-2 flex-wrap">
              {categories.map((c) => (
                <button
                  key={c}
                  onClick={() => setFilterCat(c)}
                  className={`px-3 py-0.5 rounded-full text-[11px] transition-all cursor-pointer border ${
                    filterCat === c
                      ? "bg-red-500/20 text-red-500 border-red-500/40"
                      : "bg-transparent text-slate-500 border-slate-500/20"
                  }`}
                >
                  {c}
                </button>
              ))}
            </div>
          </div>

          {/* Column headers */}
          <div className="grid grid-cols-[52px_1fr_120px_130px_72px_80px_150px] text-xs text-slate-600 uppercase tracking-widest px-6 py-3 border-b border-slate-800/50">
            {COLS.map((col) => (
              <button
                key={col.key}
                onClick={() => handleSort(col.key)}
                className="text-left hover:text-slate-300 transition-colors flex items-center gap-1"
              >
                {col.label}
                {col.key === sortKey ? (
                  <span className="text-orange-400">{sortAsc ? "↑" : "↓"}</span>
                ) : (
                  <span className="opacity-20">↕</span>
                )}
              </button>
            ))}
          </div>

          {/* Rows */}
          <div className="divide-y divide-slate-800/30">
            {filtered.length === 0 && (
              <div className="px-6 py-12 text-center text-slate-700 text-sm">
                No reports match filter
              </div>
            )}
            {filtered.map((r, idx) => {
              const risk = getRiskLevel(r.riskScore);
              const hasValidId =
                typeof r.id === "number" && Number.isFinite(r.id);
              return (
                <div
                  key={`${r.id}-${r.textHash || "no-hash"}-${r.timestamp || 0}-${idx}`}
                  onClick={() => {
                    if (hasValidId) openReport(r.id);
                  }}
                  className="grid grid-cols-[52px_1fr_120px_130px_72px_80px_150px] items-center px-6 py-4 cursor-pointer transition-colors hover:bg-red-500/5"
                >
                  <span className="text-slate-500 text-sm">
                    #{hasValidId ? r.id : "—"}
                  </span>

                  <div className="pr-4 min-w-0">
                    <p className="text-slate-300 text-xs font-mono truncate">
                      {truncate(r.textHash, 38)}
                    </p>
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
                      <span className="text-slate-700 text-xs mt-0.5 block">
                        no url
                      </span>
                    )}
                  </div>

                  <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-[11px] font-medium capitalize bg-blue-500/10 text-blue-300 border border-blue-500/20">
                    {r.category || "unknown"}
                  </span>

                  <div className="flex items-center gap-2">
                    <div className="w-14 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                      <div
                        className="h-full rounded-full"
                        style={{
                          width: `${r.riskScore ?? 0}%`,
                          background: risk.color,
                        }}
                      />
                    </div>
                    <span
                      className={`text-xs font-medium tabular-nums ${risk.textClass}`}
                    >
                      {r.riskScore ?? "—"}
                    </span>
                    <span className="text-xs text-slate-600">
                      ({risk.label})
                    </span>
                  </div>

                  <span className="text-red-400 text-sm">▲ {r.votes ?? 0}</span>

                  <span
                    className={`text-xs ${r.isVerified ? "text-green-400" : "text-slate-700"}`}
                  >
                    {r.isVerified ? "✓ Verified" : "Unverified"}
                  </span>

                  <span className="text-slate-500 text-xs">
                    {formatTimestamp(r.timestamp)}
                  </span>
                </div>
              );
            })}
          </div>

          <div className="px-6 py-3 border-t border-slate-800 flex justify-between">
            <span className="text-slate-700 text-xs">
              {filtered.length} of {reports.length} reports shown
            </span>
            <span className="text-slate-700 text-xs">
              Click any row to inspect
            </span>
          </div>
        </div>
      </div>

      {/* Detail Modal */}
      {selected && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md"
          onClick={() => setSelected(null)}
        >
          <div
            className="w-full max-w-lg rounded-2xl p-8 relative bg-gradient-to-br from-gray-900 to-slate-900 border border-red-500/30 shadow-[0_0_80px_rgba(239,68,68,0.08),0_25px_60px_rgba(0,0,0,0.6)]"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="absolute top-6 right-6">
              <span
                className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-[11px] font-medium border ${getRiskLevel(selected.riskScore).chipClass}`}
              >
                {getRiskLevel(selected.riskScore).label} ·{" "}
                {selected.riskScore ?? "—"}
              </span>
            </div>

            <div className="flex items-center gap-3 mb-6">
              <div className="w-1 h-10 rounded bg-red-500 flex-shrink-0" />
              <div>
                <h2 className="[font-family:'Syne',sans-serif] text-[1.6rem] font-extrabold leading-none">
                  Report #{selected.id}
                </h2>
                <p className="text-slate-500 text-xs">
                  {formatTimestamp(selected.timestamp)}
                </p>
              </div>
            </div>

            <div className="space-y-2 mb-5">
              {[
                {
                  label: "Category",
                  value: selected.category || "uncategorized",
                },
                { label: "Reporter", value: truncate(selected.reporter, 36) },
                { label: "Votes", value: `▲ ${selected.votes ?? 0}` },
                {
                  label: "Verified",
                  value: selected.isVerified ? "✓ Yes" : "No",
                },
              ].map((f) => (
                <div
                  key={f.label}
                  className="flex justify-between items-center py-2 border-b border-slate-800/70"
                >
                  <span className="text-slate-600 text-xs uppercase tracking-wider">
                    {f.label}
                  </span>
                  <span className="text-slate-200 text-sm">{f.value}</span>
                </div>
              ))}
            </div>

            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 mb-3">
              <p className="text-slate-600 text-xs uppercase tracking-wider mb-1">
                Hash
              </p>
              <p className="text-slate-400 text-xs font-mono break-all">
                {selected.textHash}
              </p>
            </div>

            {selected.url && (
              <div className="p-3 rounded-lg mb-5 bg-red-500/10 border border-red-500/20">
                <p className="text-red-500 text-xs uppercase tracking-wider mb-1">
                  ⚠ Malicious URL
                </p>
                <a
                  href={selected.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-red-400 text-xs font-mono break-all hover:underline"
                >
                  {selected.url}
                </a>
              </div>
            )}

            <div className="flex gap-3">
              <button
                onClick={vote}
                className="flex-1 py-3 rounded-xl text-sm font-semibold transition-all hover:scale-[1.02] active:scale-95 bg-gradient-to-br from-red-500 to-red-600 shadow-[0_4px_24px_rgba(239,68,68,0.3)]"
              >
                ▲ Upvote Threat
              </button>
              <button
                onClick={() => setSelected(null)}
                className="px-6 py-3 rounded-xl text-sm transition-all hover:bg-slate-700 bg-slate-800 text-slate-400"
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
