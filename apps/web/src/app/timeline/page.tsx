"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { Zap, ChevronRight, Database, BarChart3 } from "lucide-react";
import Link from "next/link";

interface TimelineEvent {
  id: string;
  date: string;
  title: string;
  severity: string;
  category: string;
  url: string;
  status: string;
}

const MOCK_TIMELINE: TimelineEvent[] = [
  { id: "1", date: "2026-05-12 18:30", title: "SQL Injection confirmed", severity: "critical",
    category: "sqli", url: "/api/users", status: "confirmed" },
  { id: "2", date: "2026-05-12 18:25", title: "JWT weakness detected", severity: "critical",
    category: "jwt_weakness", url: "/api/auth", status: "confirmed" },
  { id: "3", date: "2026-05-12 18:20", title: "XSS reflected via search", severity: "high",
    category: "xss", url: "/search", status: "new" },
  { id: "4", date: "2026-05-12 18:15", title: "CORS misconfiguration", severity: "high",
    category: "cors_misconfig", url: "/api/data", status: "new" },
  { id: "5", date: "2026-05-12 18:10", title: "Scan started", severity: "info",
    category: "system", url: "—", status: "complete" },
  { id: "6", date: "2026-05-12 18:05", title: "Endpoints discovered", severity: "info",
    category: "system", url: "238 endpoints", status: "complete" },
  { id: "7", date: "2026-05-12 18:00", title: "Workspace created", severity: "info",
    category: "system", url: "target.com", status: "complete" },
];

const SEV_DOT: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-blue-500",
  info: "bg-gray-500",
};

export default function TimelinePage() {
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
          <BarChart3 className="w-5 h-5 text-cyan-400" />
          <span className="text-lg font-semibold">Timeline</span>
        </div>
      </header>

      <main className="max-w-3xl mx-auto px-6 py-8">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="mb-8">
          <h2 className="text-3xl font-bold gradient-text mb-2">Vulnerability Timeline</h2>
          <p className="text-muted-foreground">Chronological view of all discoveries and events.</p>
        </motion.div>

        <div className="relative">
          {/* Timeline line */}
          <div className="absolute left-6 top-0 bottom-0 w-0.5 bg-gradient-to-b from-purple-500 via-indigo-500 to-transparent" />

          <div className="space-y-6">
            {MOCK_TIMELINE.map((event, i) => (
              <motion.div key={event.id}
                initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.08 }}
                className="relative flex gap-4 pl-14">
                {/* Dot */}
                <div className={`absolute left-[18px] top-2 w-4 h-4 rounded-full border-2 border-background ${SEV_DOT[event.severity]}`} />

                <div className="glass-card p-4 flex-1">
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="font-medium text-sm">{event.title}</h4>
                    <span className={`px-2 py-0.5 rounded text-xs font-bold border ${
                      event.severity === "critical" ? "text-red-400 bg-red-500/10 border-red-500/20" :
                      event.severity === "high" ? "text-orange-400 bg-orange-500/10 border-orange-500/20" :
                      "text-gray-400 bg-gray-500/10 border-gray-500/20"
                    }`}>
                      {event.severity.toUpperCase()}
                    </span>
                  </div>
                  <div className="flex items-center gap-3 text-xs text-muted-foreground">
                    <span>{event.date}</span>
                    <span>•</span>
                    <span className="font-mono">{event.category}</span>
                    <span>•</span>
                    <span className="truncate">{event.url}</span>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </main>
    </div>
  );
}
