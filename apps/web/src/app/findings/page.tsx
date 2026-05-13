"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import {
  Zap, ChevronRight, AlertTriangle, Filter, Search,
  ExternalLink, Copy, CheckCircle, XCircle, Eye
} from "lucide-react";
import Link from "next/link";

interface Finding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  affected_url: string;
  param?: string;
  confidence: number;
  status: string;
  source_tool: string;
  description: string;
}

const MOCK_FINDINGS: Finding[] = [
  { id: "1", title: "SQL Injection (Error-based) via 'id'", severity: "critical", category: "sqli",
    affected_url: "https://target.com/api/users", param: "id", confidence: 0.92, status: "confirmed",
    source_tool: "sqlmap", description: "SQL error triggered with single-quote payload" },
  { id: "2", title: "Reflected XSS via 'search'", severity: "high", category: "xss",
    affected_url: "https://target.com/search", param: "q", confidence: 0.87, status: "new",
    source_tool: "dalfox", description: "XSS payload reflected unencoded in response" },
  { id: "3", title: "CORS reflects arbitrary origin", severity: "high", category: "cors_misconfig",
    affected_url: "https://target.com/api/data", confidence: 0.9, status: "new",
    source_tool: "passive_detector", description: "CORS reflects evil.com in ACAO header" },
  { id: "4", title: "Public S3 bucket: target-assets", severity: "critical", category: "cloud_exposure",
    affected_url: "https://target-assets.s3.amazonaws.com", confidence: 0.95, status: "confirmed",
    source_tool: "cloud_exposure_scanner", description: "S3 bucket publicly listable" },
  { id: "5", title: "JWT signed with weak secret", severity: "critical", category: "jwt_weakness",
    affected_url: "https://target.com/api/auth", confidence: 0.95, status: "confirmed",
    source_tool: "jwt_weakness_scanner", description: "JWT secret is 'secret'" },
  { id: "6", title: "GraphQL introspection enabled", severity: "medium", category: "graphql",
    affected_url: "https://target.com/graphql", confidence: 0.95, status: "new",
    source_tool: "graphql_scanner", description: "Full schema exposed via introspection" },
  { id: "7", title: "Missing CSP header", severity: "medium", category: "misconfiguration",
    affected_url: "https://target.com", confidence: 0.95, status: "new",
    source_tool: "passive_detector", description: "No Content-Security-Policy header" },
  { id: "8", title: "Open Redirect via 'next' parameter", severity: "medium", category: "open_redirect",
    affected_url: "https://target.com/login", param: "next", confidence: 0.85, status: "new",
    source_tool: "fuzzing_engine", description: "Redirects to evil.com" },
];

const SEV_STYLES: Record<string, string> = {
  critical: "severity-critical",
  high: "severity-high",
  medium: "severity-medium",
  low: "severity-low",
  info: "severity-info",
};

export default function FindingsPage() {
  const [findings] = useState<Finding[]>(MOCK_FINDINGS);
  const [search, setSearch] = useState("");
  const [filterSev, setFilterSev] = useState<string>("all");
  const [expanded, setExpanded] = useState<string | null>(null);

  const filtered = findings.filter((f) => {
    if (filterSev !== "all" && f.severity !== filterSev) return false;
    if (search && !f.title.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

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
          <span className="text-lg font-semibold">Findings</span>
          <span className="ml-auto px-3 py-1 rounded-full bg-red-500/10 text-red-400 text-sm font-medium border border-red-500/20">
            {findings.length} Total
          </span>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        {/* Filters */}
        <div className="flex flex-wrap items-center gap-3 mb-6">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search findings..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-10 pr-4 py-2.5 bg-secondary border border-white/5 rounded-lg text-sm focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>
          <div className="flex gap-1.5">
            {["all", "critical", "high", "medium", "low", "info"].map((sev) => (
              <button
                key={sev}
                onClick={() => setFilterSev(sev)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                  filterSev === sev
                    ? "bg-primary text-primary-foreground"
                    : "bg-secondary text-muted-foreground hover:text-foreground"
                }`}
              >
                {sev === "all" ? "All" : sev.charAt(0).toUpperCase() + sev.slice(1)}
              </button>
            ))}
          </div>
        </div>

        {/* Findings table */}
        <div className="space-y-2">
          {filtered.map((finding, i) => (
            <motion.div
              key={finding.id}
              initial={{ opacity: 0, y: 5 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.03 }}
              className="glass-card overflow-hidden"
            >
              <div
                className="p-4 flex items-center gap-4 cursor-pointer hover:bg-white/[0.02] transition-colors"
                onClick={() => setExpanded(expanded === finding.id ? null : finding.id)}
              >
                <span className={`px-2.5 py-1 rounded text-xs font-bold uppercase border ${SEV_STYLES[finding.severity]}`}>
                  {finding.severity}
                </span>
                <div className="flex-1 min-w-0">
                  <h4 className="font-medium truncate">{finding.title}</h4>
                  <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                    <span className="font-mono">{finding.category}</span>
                    <span>•</span>
                    <span className="truncate max-w-xs">{finding.affected_url}</span>
                    {finding.param && (
                      <>
                        <span>•</span>
                        <span className="font-mono text-purple-400">?{finding.param}</span>
                      </>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-3 text-sm">
                  <span className="text-muted-foreground">{(finding.confidence * 100).toFixed(0)}%</span>
                  <span className={`px-2 py-0.5 rounded text-xs ${
                    finding.status === "confirmed" ? "bg-green-500/10 text-green-400" :
                    finding.status === "false_positive" ? "bg-gray-500/10 text-gray-400" :
                    "bg-yellow-500/10 text-yellow-400"
                  }`}>
                    {finding.status}
                  </span>
                  <span className="text-xs text-muted-foreground">{finding.source_tool}</span>
                </div>
              </div>

              {expanded === finding.id && (
                <motion.div
                  initial={{ height: 0 }}
                  animate={{ height: "auto" }}
                  className="border-t border-white/5 bg-card/50 p-4"
                >
                  <p className="text-sm text-muted-foreground mb-4">{finding.description}</p>
                  <div className="flex gap-2">
                    <button className="flex items-center gap-1.5 px-3 py-1.5 bg-primary/10 text-primary rounded-lg text-xs hover:bg-primary/20 transition-colors">
                      <Eye className="w-3.5 h-3.5" /> View Evidence
                    </button>
                    <button className="flex items-center gap-1.5 px-3 py-1.5 bg-green-500/10 text-green-400 rounded-lg text-xs hover:bg-green-500/20 transition-colors">
                      <CheckCircle className="w-3.5 h-3.5" /> Confirm
                    </button>
                    <button className="flex items-center gap-1.5 px-3 py-1.5 bg-red-500/10 text-red-400 rounded-lg text-xs hover:bg-red-500/20 transition-colors">
                      <XCircle className="w-3.5 h-3.5" /> False Positive
                    </button>
                    <button className="flex items-center gap-1.5 px-3 py-1.5 bg-secondary text-muted-foreground rounded-lg text-xs hover:text-foreground transition-colors">
                      <Copy className="w-3.5 h-3.5" /> Copy URL
                    </button>
                  </div>
                </motion.div>
              )}
            </motion.div>
          ))}
        </div>
      </main>
    </div>
  );
}
