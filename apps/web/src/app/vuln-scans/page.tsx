"use client";

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Shield, AlertTriangle, Activity, Bug, Zap, Target, Eye,
  Play, Pause, RefreshCw, ChevronRight, Terminal, Brain
} from "lucide-react";
import Link from "next/link";

interface ScanStatus {
  scan_id: string;
  status: string;
  current_phase: string | null;
  progress: number;
  endpoints_tested: number;
  endpoints_total: number;
  vulns_found: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  ai_reasoning: string[];
}

const PHASE_LABELS: Record<string, string> = {
  analysis: "🔍 Analyzing Attack Surface",
  classification: "🏷️ Classifying Endpoints",
  hypothesis: "🧠 Generating AI Hypotheses",
  passive: "📡 Passive Detection",
  fuzzing: "⚡ Intelligent Fuzzing",
  active: "🎯 Active Testing",
  validation: "✅ Validating Findings",
  reporting: "📝 Generating Report",
  completed: "✅ Completed",
};

const SEV_COLORS: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-blue-500",
  info: "bg-gray-500",
};

export default function VulnScansPage() {
  const [scans, setScans] = useState<ScanStatus[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanStatus | null>(null);
  const [isStarting, setIsStarting] = useState(false);

  // Mock data for demonstration
  useEffect(() => {
    const mockScan: ScanStatus = {
      scan_id: "demo-001",
      status: "running",
      current_phase: "fuzzing",
      progress: 62,
      endpoints_tested: 147,
      endpoints_total: 238,
      vulns_found: 23,
      critical: 2,
      high: 5,
      medium: 8,
      low: 6,
      info: 2,
      ai_reasoning: [
        "Identified 238 endpoints from recon data",
        "Classified 45 high-priority API endpoints",
        "Generated 89 vulnerability hypotheses",
        "Passive detection found 12 misconfigurations",
        "Fuzzing in progress — 62% complete",
      ],
    };
    setScans([mockScan]);
    setSelectedScan(mockScan);
  }, []);

  return (
    <div className="min-h-screen">
      {/* Header */}
      <header className="border-b border-white/5 bg-card/30 backdrop-blur-lg sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link href="/" className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-purple-500 to-indigo-600 flex items-center justify-center">
                <Zap className="w-5 h-5 text-white" />
              </div>
              <span className="text-xl font-bold gradient-text">ReconX</span>
            </Link>
            <ChevronRight className="w-4 h-4 text-muted-foreground" />
            <span className="text-lg font-semibold">Vulnerability Scans</span>
          </div>
          <button
            onClick={() => setIsStarting(true)}
            className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg font-medium transition-colors"
          >
            <Bug className="w-4 h-4" />
            New Vuln Scan
          </button>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        {/* Live Stats */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3 mb-8">
          {[
            { label: "Critical", value: selectedScan?.critical ?? 0, color: "text-red-400", bg: "bg-red-500/10" },
            { label: "High", value: selectedScan?.high ?? 0, color: "text-orange-400", bg: "bg-orange-500/10" },
            { label: "Medium", value: selectedScan?.medium ?? 0, color: "text-yellow-400", bg: "bg-yellow-500/10" },
            { label: "Low", value: selectedScan?.low ?? 0, color: "text-blue-400", bg: "bg-blue-500/10" },
            { label: "Info", value: selectedScan?.info ?? 0, color: "text-gray-400", bg: "bg-gray-500/10" },
            { label: "Total", value: selectedScan?.vulns_found ?? 0, color: "text-purple-400", bg: "bg-purple-500/10" },
          ].map((stat, i) => (
            <motion.div
              key={stat.label}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.05 }}
              className={`${stat.bg} border border-white/5 rounded-xl p-4 text-center`}
            >
              <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
              <p className="text-xs text-muted-foreground mt-1">{stat.label}</p>
            </motion.div>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Scan Progress */}
          <div className="lg:col-span-2 space-y-6">
            {selectedScan && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="glass-card p-6"
              >
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <h3 className="text-lg font-semibold">Scan Progress</h3>
                    <p className="text-sm text-muted-foreground">
                      {selectedScan.scan_id}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`px-3 py-1 rounded-full text-xs font-medium ${
                      selectedScan.status === "running"
                        ? "bg-green-500/10 text-green-400 border border-green-500/20"
                        : "bg-blue-500/10 text-blue-400 border border-blue-500/20"
                    }`}>
                      {selectedScan.status === "running" && (
                        <span className="inline-block w-2 h-2 rounded-full bg-green-400 mr-1.5 pulse-live" />
                      )}
                      {selectedScan.status.toUpperCase()}
                    </span>
                  </div>
                </div>

                {/* Progress bar */}
                <div className="w-full bg-secondary rounded-full h-3 mb-3 overflow-hidden">
                  <motion.div
                    className="h-full bg-gradient-to-r from-purple-500 to-indigo-500 rounded-full"
                    initial={{ width: 0 }}
                    animate={{ width: `${selectedScan.progress}%` }}
                    transition={{ duration: 1, ease: "easeOut" }}
                  />
                </div>
                <div className="flex justify-between text-sm text-muted-foreground">
                  <span>{PHASE_LABELS[selectedScan.current_phase || ""] || selectedScan.current_phase}</span>
                  <span>{selectedScan.progress.toFixed(0)}%</span>
                </div>

                {/* Phase pipeline */}
                <div className="mt-6 flex items-center gap-1 overflow-x-auto pb-2">
                  {Object.entries(PHASE_LABELS).filter(([k]) => k !== "completed").map(([key, label], i) => {
                    const phases = ["analysis", "classification", "hypothesis", "passive", "fuzzing", "active", "validation", "reporting"];
                    const currentIdx = phases.indexOf(selectedScan.current_phase || "");
                    const thisIdx = phases.indexOf(key);
                    const isDone = thisIdx < currentIdx;
                    const isCurrent = thisIdx === currentIdx;
                    return (
                      <div key={key} className="flex items-center">
                        <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold ${
                          isDone ? "bg-green-500 text-white" :
                          isCurrent ? "bg-purple-500 text-white pulse-live" :
                          "bg-secondary text-muted-foreground"
                        }`}>
                          {isDone ? "✓" : i + 1}
                        </div>
                        {i < 7 && <div className={`w-4 h-0.5 ${isDone ? "bg-green-500" : "bg-secondary"}`} />}
                      </div>
                    );
                  })}
                </div>

                {/* Stats row */}
                <div className="mt-6 grid grid-cols-3 gap-4 text-center">
                  <div>
                    <p className="text-2xl font-bold">{selectedScan.endpoints_tested}</p>
                    <p className="text-xs text-muted-foreground">Endpoints Tested</p>
                  </div>
                  <div>
                    <p className="text-2xl font-bold">{selectedScan.endpoints_total}</p>
                    <p className="text-xs text-muted-foreground">Total Endpoints</p>
                  </div>
                  <div>
                    <p className="text-2xl font-bold text-red-400">{selectedScan.vulns_found}</p>
                    <p className="text-xs text-muted-foreground">Vulns Found</p>
                  </div>
                </div>

                {/* Severity bar chart */}
                <div className="mt-6">
                  <h4 className="text-sm font-medium mb-3">Severity Distribution</h4>
                  <div className="flex h-6 rounded-lg overflow-hidden gap-0.5">
                    {(["critical", "high", "medium", "low", "info"] as const).map((sev) => {
                      const count = selectedScan[sev];
                      const pct = selectedScan.vulns_found > 0 ? (count / selectedScan.vulns_found) * 100 : 0;
                      return pct > 0 ? (
                        <div
                          key={sev}
                          className={`${SEV_COLORS[sev]} flex items-center justify-center text-xs text-white font-bold`}
                          style={{ width: `${Math.max(pct, 8)}%` }}
                          title={`${sev}: ${count}`}
                        >
                          {count}
                        </div>
                      ) : null;
                    })}
                  </div>
                </div>
              </motion.div>
            )}
          </div>

          {/* AI Reasoning Chain */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.2 }}
            className="glass-card p-6"
          >
            <div className="flex items-center gap-2 mb-4">
              <Brain className="w-5 h-5 text-purple-400" />
              <h3 className="text-lg font-semibold">AI Reasoning</h3>
            </div>
            <div className="space-y-3 max-h-96 overflow-y-auto">
              {selectedScan?.ai_reasoning.map((reason, i) => (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, x: 10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.1 * i }}
                  className="flex gap-3"
                >
                  <div className="flex-shrink-0 w-6 h-6 rounded-full bg-purple-500/20 flex items-center justify-center text-xs text-purple-400 font-bold mt-0.5">
                    {i + 1}
                  </div>
                  <p className="text-sm text-muted-foreground leading-relaxed">
                    {reason}
                  </p>
                </motion.div>
              ))}
            </div>
          </motion.div>
        </div>
      </main>
    </div>
  );
}
