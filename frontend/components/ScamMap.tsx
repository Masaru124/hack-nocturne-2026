"use client";

import { useEffect, useRef, useState } from "react";

export type MapMarker = {
  id: string;
  lat: number;
  lng: number;
  domain: string;
  riskScore: number;
  category: string;
  country: string;
  discoveredAt: string;
  level: "high" | "medium" | "low";
  source: string;
  onChain: boolean;
};

export type MapConnection = {
  id: string;
  fromLat: number;
  fromLng: number;
  toLat: number;
  toLng: number;
  label: string;
  level: "high" | "medium" | "low";
};

type Props = {
  markers: MapMarker[];
  connections?: MapConnection[];
  height?: number;
};

const LEVEL_COLOR: Record<string, string> = {
  high: "#ef4444",
  medium: "#eab308",
  low: "#22c55e",
};

export default function ScamMap({
  markers,
  connections = [],
  height = 440,
}: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const mapRef = useRef<any>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const groupRef = useRef<any>(null);
  const [ready, setReady] = useState(false);

  // ── Initialise map once ──────────────────────────────────────────────────
  useEffect(() => {
    if (
      typeof window === "undefined" ||
      !containerRef.current ||
      mapRef.current
    )
      return;

    let destroyed = false;

    import("leaflet").then((L) => {
      if (destroyed || !containerRef.current || mapRef.current) return;

      // Inject Leaflet CSS directly from the npm package
      if (!document.querySelector("link[data-scam-leaflet]")) {
        const cssLink = document.createElement("link");
        cssLink.rel = "stylesheet";
        cssLink.setAttribute("data-scam-leaflet", "1");
        // next.js copies node_modules assets to _next/static only on build;
        // during dev we import it via a side-effect import instead
        cssLink.href = "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css";
        document.head.appendChild(cssLink);
      }

      const map = L.map(containerRef.current!, {
        center: [20, 10],
        zoom: 2,
        minZoom: 1,
        maxZoom: 12,
        zoomControl: true,
        attributionControl: true,
        preferCanvas: true,
      });

      // Dark CartoDB tiles (OpenStreetMap data, CartoDB styling)
      L.tileLayer(
        "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
        {
          attribution:
            '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>' +
            ' contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
          subdomains: "abcd",
          maxZoom: 19,
        },
      ).addTo(map);

      const group = L.layerGroup().addTo(map);
      mapRef.current = { map, L };
      groupRef.current = group;
      setReady(true);
    });

    return () => {
      destroyed = true;
      if (mapRef.current?.map) {
        mapRef.current.map.remove();
        mapRef.current = null;
        groupRef.current = null;
      }
    };
  }, []);

  // ── Sync markers whenever data or map readiness changes ──────────────────
  useEffect(() => {
    if (!ready || !mapRef.current || !groupRef.current) return;
    const { map, L } = mapRef.current;
    const group = groupRef.current;
    group.clearLayers();

    const now = Date.now();

    markers.forEach((m) => {
      if (typeof m.lat !== "number" || typeof m.lng !== "number") return;

      const color = LEVEL_COLOR[m.level] ?? LEVEL_COLOR.medium;
      const isNew = now - new Date(m.discoveredAt).getTime() < 5 * 60 * 1000;
      const radius = m.level === "high" ? 11 : m.level === "medium" ? 7 : 5;

      const circle = L.circleMarker([m.lat, m.lng], {
        radius,
        fillColor: color,
        color: isNew ? "#ffffff" : color,
        weight: isNew ? 2.5 : 1,
        opacity: isNew ? 1 : 0.85,
        fillOpacity: 0.72,
        className: isNew ? "scam-pulse-marker" : "",
      });

      circle.bindPopup(
        `<div class="scam-popup-inner">
          <div class="popup-domain">${escHtml(m.domain)}</div>
          <div class="popup-row">
            <span class="popup-label">Risk</span>
            <span style="color:${color};font-weight:700">${m.riskScore}</span>
          </div>
          <div class="popup-row">
            <span class="popup-label">Category</span>
            <span class="popup-value">${escHtml(m.category)}</span>
          </div>
          <div class="popup-row">
            <span class="popup-label">Country</span>
            <span class="popup-value">${escHtml(m.country)}</span>
          </div>
          <div class="popup-row">
            <span class="popup-label">Source</span>
            <span class="popup-value">${escHtml(m.source)}</span>
          </div>
          <div class="popup-row">
            <span class="popup-label">Reported</span>
            <span class="popup-value">${relTime(m.discoveredAt)}</span>
          </div>
          ${
            m.onChain
              ? '<div class="popup-chain">✓ Reported on-chain</div>'
              : '<div class="popup-flagged">⚑ Flagged by AI</div>'
          }
        </div>`,
        { className: "scam-map-popup", maxWidth: 270 },
      );

      group.addLayer(circle);
    });

    connections.forEach((connection) => {
      const color = LEVEL_COLOR[connection.level] ?? LEVEL_COLOR.medium;
      const line = L.polyline(
        [
          [connection.fromLat, connection.fromLng],
          [connection.toLat, connection.toLng],
        ],
        {
          color,
          weight: connection.level === "high" ? 2.8 : 2,
          opacity: 0.7,
          dashArray: connection.level === "high" ? "8 8" : "4 8",
          className: "scam-link-line",
        },
      );
      line.bindTooltip(connection.label, {
        sticky: true,
        className: "scam-link-tooltip",
      });
      group.addLayer(line);
    });

    // Fit bounds if we have markers and bounds are valid
    if (markers.length > 1) {
      try {
        const latlngs = markers
          .filter((m) => typeof m.lat === "number" && typeof m.lng === "number")
          .map((m) => [m.lat, m.lng] as [number, number]);
        if (latlngs.length >= 2) {
          map.fitBounds(L.latLngBounds(latlngs), {
            padding: [40, 40],
            maxZoom: 5,
          });
        }
      } catch {
        // ignore fitBounds errors
      }
    }
  }, [connections, markers, ready]);

  return (
    <>
      <style>{`
        /* ── Leaflet popup dark theme ── */
        .scam-map-popup .leaflet-popup-content-wrapper {
          background: #0f172a;
          border: 1px solid rgba(239,68,68,0.28);
          border-radius: 10px;
          box-shadow: 0 8px 40px rgba(0,0,0,0.7), 0 0 0 1px rgba(239,68,68,0.1);
          padding: 0;
          overflow: hidden;
        }
        .scam-map-popup .leaflet-popup-tip-container { display: none; }
        .scam-map-popup .leaflet-popup-content { margin: 0; }
        .scam-popup-inner {
          font-family: ui-monospace, 'Cascadia Code', monospace;
          font-size: 11px;
          color: #94a3b8;
          padding: 12px 14px;
          min-width: 210px;
        }
        .popup-domain {
          color: #f1f5f9;
          font-size: 12.5px;
          font-weight: 700;
          margin-bottom: 8px;
          word-break: break-all;
          line-height: 1.3;
        }
        .popup-row {
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 10px;
          margin-bottom: 3px;
        }
        .popup-label { color: #475569; white-space: nowrap; }
        .popup-value { color: #cbd5e1; text-align: right; font-size: 10.5px; }
        .popup-chain { color: #22c55e; margin-top: 8px; font-size: 11px; border-top: 1px solid rgba(34,197,94,0.2); padding-top: 6px; }
        .popup-flagged { color: #eab308; margin-top: 8px; font-size: 11px; border-top: 1px solid rgba(234,179,8,0.2); padding-top: 6px; }
        /* ── Leaflet control dark theme ── */
        .leaflet-control-zoom a {
          background: #1e293b !important;
          color: #94a3b8 !important;
          border-color: #334155 !important;
        }
        .leaflet-control-zoom a:hover {
          background: #334155 !important;
          color: #f1f5f9 !important;
        }
        .leaflet-control-attribution {
          background: rgba(15,23,42,0.85) !important;
          color: #475569 !important;
          font-size: 9px !important;
          backdrop-filter: blur(4px);
        }
        .leaflet-control-attribution a { color: #64748b !important; }
        /* ── Pulse animation for new markers ── */
        @keyframes scamPulse {
          0%   { stroke-width: 2.5; stroke-opacity: 1; }
          50%  { stroke-width: 8;   stroke-opacity: 0.4; }
          100% { stroke-width: 2.5; stroke-opacity: 1; }
        }
        .scam-pulse-marker {
          animation: scamPulse 1.4s ease-in-out infinite;
        }
        /* ── Map container ── */
        .scam-map-container .leaflet-container {
          background: #060c18;
        }
        .scam-link-line {
          animation: linkFlow 2.6s linear infinite;
        }
        .scam-link-tooltip {
          background: rgba(15,23,42,0.96);
          border: 1px solid rgba(168,85,247,0.35);
          color: #c4b5fd;
          font-size: 10px;
          font-family: ui-monospace, 'Cascadia Code', monospace;
          box-shadow: 0 8px 30px rgba(0,0,0,0.45);
        }
        @keyframes linkFlow {
          0% { stroke-dashoffset: 0; }
          100% { stroke-dashoffset: -24; }
        }
      `}</style>
      <div
        className="scam-map-container rounded-xl overflow-hidden"
        ref={containerRef}
        style={{ height, width: "100%" }}
      />
    </>
  );
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function escHtml(str: string): string {
  return (str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function relTime(iso: string): string {
  if (!iso) return "just now";
  const diff = Math.max(
    0,
    Math.floor((Date.now() - new Date(iso).getTime()) / 1000),
  );
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}
