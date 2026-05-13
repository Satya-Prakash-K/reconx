"use client";

import { motion } from "framer-motion";
import { Zap, ChevronRight, Flame } from "lucide-react";
import Link from "next/link";

const CATEGORIES = [
  { key: "sqli", label: "SQL Injection", critical: 3, high: 2, medium: 1, low: 0 },
  { key: "xss", label: "XSS", critical: 1, high: 4, medium: 3, low: 2 },
  { key: "ssrf", label: "SSRF", critical: 0, high: 2, medium: 1, low: 0 },
  { key: "idor", label: "IDOR", critical: 1, high: 3, medium: 2, low: 0 },
  { key: "auth_flaw", label: "Auth Flaws", critical: 2, high: 1, medium: 0, low: 0 },
  { key: "authz_bypass", label: "AuthZ Bypass", critical: 1, high: 2, medium: 1, low: 0 },
  { key: "jwt_weakness", label: "JWT Weakness", critical: 2, high: 0, medium: 1, low: 0 },
  { key: "graphql", label: "GraphQL", critical: 0, high: 1, medium: 2, low: 0 },
  { key: "file_upload", label: "File Upload", critical: 0, high: 2, medium: 0, low: 1 },
  { key: "open_redirect", label: "Open Redirect", critical: 0, high: 0, medium: 3, low: 2 },
  { key: "cors_misconfig", label: "CORS Misconfig", critical: 0, high: 3, medium: 1, low: 0 },
  { key: "api_security", label: "API Security", critical: 1, high: 2, medium: 3, low: 1 },
  { key: "data_exposure", label: "Data Exposure", critical: 2, high: 1, medium: 0, low: 2 },
  { key: "misconfiguration", label: "Misconfig", critical: 0, high: 0, medium: 4, low: 5 },
  { key: "cloud_exposure", label: "Cloud Exposure", critical: 2, high: 1, medium: 0, low: 0 },
];

function heatCell(value: number, maxVal: number) {
  if (value === 0) return "bg-white/[0.02]";
  const intensity = Math.min(1, value / Math.max(maxVal, 1));
  if (intensity > 0.7) return "bg-red-500/60";
  if (intensity > 0.4) return "bg-orange-500/40";
  if (intensity > 0.2) return "bg-yellow-500/30";
  return "bg-blue-500/20";
}

export default function HeatmapPage() {
  const maxVal = Math.max(...CATEGORIES.flatMap(c => [c.critical, c.high, c.medium, c.low]));

  return (
    <div className="min-h-screen">
      <header className="border-b border-white/5 bg-card/30 backdrop-blur-lg sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center gap-3">
          <Link href="/" className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-purple-500 to-indigo-600 flex items-center justify-center">
              <Zap className="w-5 h-5 text-white" />
            </div>
            <span className="text-xl font-bold gradient-text">ReconX</span>
          </Link>
          <ChevronRight className="w-4 h-4 text-muted-foreground" />
          <Flame className="w-5 h-5 text-orange-400" />
          <span className="text-lg font-semibold">Vulnerability Heatmap</span>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <h2 className="text-3xl font-bold gradient-text mb-2">Vulnerability Heatmap</h2>
          <p className="text-muted-foreground">
            Visual overview of vulnerability distribution across all 15 testing categories.
          </p>
        </motion.div>

        {/* Heatmap Grid */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.2 }}
          className="glass-card p-6 overflow-x-auto"
        >
          <table className="w-full">
            <thead>
              <tr>
                <th className="text-left text-sm font-medium text-muted-foreground pb-4 pr-6 min-w-[180px]">Category</th>
                <th className="text-center text-sm font-medium text-red-400 pb-4 px-4 w-24">Critical</th>
                <th className="text-center text-sm font-medium text-orange-400 pb-4 px-4 w-24">High</th>
                <th className="text-center text-sm font-medium text-yellow-400 pb-4 px-4 w-24">Medium</th>
                <th className="text-center text-sm font-medium text-blue-400 pb-4 px-4 w-24">Low</th>
                <th className="text-center text-sm font-medium text-muted-foreground pb-4 px-4 w-24">Total</th>
              </tr>
            </thead>
            <tbody>
              {CATEGORIES.map((cat, i) => {
                const total = cat.critical + cat.high + cat.medium + cat.low;
                return (
                  <motion.tr
                    key={cat.key}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.05 * i }}
                    className="border-t border-white/5"
                  >
                    <td className="py-3 pr-6 text-sm font-medium">{cat.label}</td>
                    {[cat.critical, cat.high, cat.medium, cat.low].map((val, j) => (
                      <td key={j} className="py-3 px-4">
                        <div className={`rounded-lg p-3 text-center font-bold text-lg transition-all hover:scale-105 ${heatCell(val, maxVal)}`}>
                          {val}
                        </div>
                      </td>
                    ))}
                    <td className="py-3 px-4 text-center font-bold text-lg">{total}</td>
                  </motion.tr>
                );
              })}
            </tbody>
          </table>
        </motion.div>

        {/* Legend */}
        <div className="mt-6 flex items-center gap-6 justify-center text-xs text-muted-foreground">
          <span>Intensity Scale:</span>
          <div className="flex items-center gap-2">
            <div className="w-6 h-4 rounded bg-white/[0.02] border border-white/5" />
            <span>None</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-6 h-4 rounded bg-blue-500/20" />
            <span>Low</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-6 h-4 rounded bg-yellow-500/30" />
            <span>Medium</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-6 h-4 rounded bg-orange-500/40" />
            <span>High</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-6 h-4 rounded bg-red-500/60" />
            <span>Critical</span>
          </div>
        </div>
      </main>
    </div>
  );
}
