"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import {
  Zap, ChevronRight, Crosshair, Filter, Search, Brain,
  AlertTriangle, CheckCircle, XCircle, ArrowUpDown, Copy
} from "lucide-react";
import Link from "next/link";

interface TriagedFinding {
  id: string;
  title: string;
  severity: string;
  category: string;
  affected_url: string;
  cwe_id: string;
  cwe_name: string;
  cvss_score: number;
  cvss_vector: string;
  owasp_category: string;
  exploitability_score: number;
  impact_score: number;
  priority_rank: number;
  is_duplicate: boolean;
  confidence: number;
  source_tool: string;
}

const MOCK_TRIAGED: TriagedFinding[] = [
  { id: "1", title: "SQL Injection (Error-based) via 'id'", severity: "critical", category: "sqli",
    affected_url: "https://target.com/api/users", cwe_id: "CWE-89", cwe_name: "SQL Injection",
    cvss_score: 9.8, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    owasp_category: "A03:2021-Injection", exploitability_score: 9.2, impact_score: 9.5,
    priority_rank: 1, is_duplicate: false, confidence: 0.95, source_tool: "sqlmap" },
  { id: "2", title: "JWT signed with weak secret", severity: "critical", category: "jwt_weakness",
    affected_url: "https://target.com/api/auth", cwe_id: "CWE-347", cwe_name: "Improper Crypto Verification",
    cvss_score: 9.1, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    owasp_category: "A02:2021-Cryptographic Failures", exploitability_score: 8.5, impact_score: 9.0,
    priority_rank: 2, is_duplicate: false, confidence: 0.95, source_tool: "jwt_weakness_scanner" },
  { id: "3", title: "Reflected XSS via 'search'", severity: "high", category: "xss",
    affected_url: "https://target.com/search", cwe_id: "CWE-79", cwe_name: "Cross-site Scripting",
    cvss_score: 6.1, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    owasp_category: "A03:2021-Injection", exploitability_score: 7.5, impact_score: 5.0,
    priority_rank: 3, is_duplicate: false, confidence: 0.87, source_tool: "dalfox" },
  { id: "4", title: "Public S3 bucket", severity: "critical", category: "cloud_exposure",
    affected_url: "https://target-assets.s3.amazonaws.com", cwe_id: "CWE-284", cwe_name: "Improper Access Control",
    cvss_score: 9.1, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    owasp_category: "A05:2021-Security Misconfiguration", exploitability_score: 9.0, impact_score: 8.5,
    priority_rank: 4, is_duplicate: false, confidence: 0.95, source_tool: "cloud_scanner" },
  { id: "5", title: "CORS reflects arbitrary origin", severity: "high", category: "cors_misconfig",
    affected_url: "https://target.com/api/data", cwe_id: "CWE-942", cwe_name: "Permissive CORS",
    cvss_score: 5.3, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    owasp_category: "A05:2021-Security Misconfiguration", exploitability_score: 7.0, impact_score: 5.0,
    priority_rank: 5, is_duplicate: false, confidence: 0.9, source_tool: "passive_detector" },
];

const SEV_COLORS: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/20",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  low: "text-blue-400 bg-blue-500/10 border-blue-500/20",
  info: "text-gray-400 bg-gray-500/10 border-gray-500/20",
};

function CvssBar({ score }: { score: number }) {
  const color = score >= 9 ? "bg-red-500" : score >= 7 ? "bg-orange-500" : score >= 4 ? "bg-yellow-500" : "bg-blue-500";
  return (
    <div className="flex items-center gap-2 min-w-[120px]">
      <div className="w-16 bg-secondary rounded-full h-2 overflow-hidden">
        <div className={`h-full ${color} rounded-full`} style={{ width: `${(score / 10) * 100}%` }} />
      </div>
      <span className="text-xs font-mono font-bold">{score.toFixed(1)}</span>
    </div>
  );
}

export default function TriagePage() {
  const [findings] = useState<TriagedFinding[]>(MOCK_TRIAGED);
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);

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
          <Crosshair className="w-5 h-5 text-red-400" />
          <span className="text-lg font-semibold">AI Triage</span>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="mb-6">
          <h2 className="text-3xl font-bold gradient-text mb-2">AI Triage Dashboard</h2>
          <p className="text-muted-foreground">
            Automated vulnerability analysis with CVSS, CWE, OWASP mapping, and AI prioritization.
          </p>
        </motion.div>

        {/* Summary stats */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-8">
          {[
            { label: "Critical", count: findings.filter(f => f.severity === "critical").length, color: "text-red-400" },
            { label: "High", count: findings.filter(f => f.severity === "high").length, color: "text-orange-400" },
            { label: "Medium", count: findings.filter(f => f.severity === "medium").length, color: "text-yellow-400" },
            { label: "Avg CVSS", count: (findings.reduce((a, f) => a + f.cvss_score, 0) / findings.length).toFixed(1), color: "text-purple-400" },
            { label: "Unique", count: findings.filter(f => !f.is_duplicate).length, color: "text-green-400" },
          ].map((s, i) => (
            <motion.div key={s.label} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.05 }} className="glass-card p-4 text-center">
              <p className={`text-2xl font-bold ${s.color}`}>{s.count}</p>
              <p className="text-xs text-muted-foreground mt-1">{s.label}</p>
            </motion.div>
          ))}
        </div>

        {/* Findings table */}
        <div className="glass-card overflow-hidden">
          <div className="p-4 border-b border-white/5">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <input type="text" placeholder="Search triaged findings..." value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full pl-10 pr-4 py-2.5 bg-secondary border border-white/5 rounded-lg text-sm focus:outline-none focus:ring-1 focus:ring-primary" />
            </div>
          </div>

          <table className="w-full">
            <thead>
              <tr className="border-b border-white/5 text-xs text-muted-foreground uppercase">
                <th className="p-3 text-left">#</th>
                <th className="p-3 text-left">Severity</th>
                <th className="p-3 text-left">Finding</th>
                <th className="p-3 text-left">CWE</th>
                <th className="p-3 text-left">CVSS</th>
                <th className="p-3 text-left">OWASP</th>
                <th className="p-3 text-left">Exploit</th>
                <th className="p-3 text-left">Impact</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f, i) => (
                <motion.tr key={f.id}
                  initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                  transition={{ delay: i * 0.03 }}
                  onClick={() => setExpanded(expanded === f.id ? null : f.id)}
                  className="border-b border-white/5 cursor-pointer hover:bg-white/[0.02] transition-colors">
                  <td className="p-3 text-sm font-bold text-muted-foreground">{f.priority_rank}</td>
                  <td className="p-3">
                    <span className={`px-2 py-1 rounded text-xs font-bold border ${SEV_COLORS[f.severity]}`}>
                      {f.severity.toUpperCase()}
                    </span>
                  </td>
                  <td className="p-3">
                    <p className="text-sm font-medium">{f.title}</p>
                    <p className="text-xs text-muted-foreground truncate max-w-xs">{f.affected_url}</p>
                  </td>
                  <td className="p-3 text-xs font-mono text-cyan-400">{f.cwe_id}</td>
                  <td className="p-3"><CvssBar score={f.cvss_score} /></td>
                  <td className="p-3 text-xs text-muted-foreground">{f.owasp_category.split("-")[0]}</td>
                  <td className="p-3"><CvssBar score={f.exploitability_score} /></td>
                  <td className="p-3"><CvssBar score={f.impact_score} /></td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </div>
      </main>
    </div>
  );
}
