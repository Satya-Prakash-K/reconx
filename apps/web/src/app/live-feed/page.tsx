"use client";

import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Zap, ChevronRight, Radio, Globe, AlertTriangle, Shield, Search } from "lucide-react";
import Link from "next/link";

interface ReconEvent {
  id: string;
  timestamp: string;
  type: "endpoint" | "finding" | "change" | "asset" | "tech";
  title: string;
  detail: string;
  severity?: string;
}

const MOCK_FEED: ReconEvent[] = [
  { id: "1", timestamp: "00:42", type: "finding", title: "SQL Injection confirmed", detail: "/api/users?id=1' AND 1=1--", severity: "critical" },
  { id: "2", timestamp: "00:41", type: "change", title: "JS bundle changed", detail: "main.js — 3 new API endpoints detected", severity: "medium" },
  { id: "3", timestamp: "00:39", type: "finding", title: "JWT signed with 'secret'", detail: "/api/auth — weak HMAC key", severity: "critical" },
  { id: "4", timestamp: "00:37", type: "endpoint", title: "New endpoint discovered", detail: "POST /api/internal/admin/config" },
  { id: "5", timestamp: "00:35", type: "asset", title: "Subdomain found", detail: "staging.target.com — CNAME to AWS" },
  { id: "6", timestamp: "00:33", type: "tech", title: "Technology detected", detail: "Express.js 4.18.2, MongoDB 7.0" },
  { id: "7", timestamp: "00:30", type: "finding", title: "Public S3 bucket", detail: "target-assets.s3.amazonaws.com", severity: "high" },
  { id: "8", timestamp: "00:28", type: "endpoint", title: "GraphQL introspection enabled", detail: "POST /graphql — full schema exposed" },
  { id: "9", timestamp: "00:25", type: "change", title: "DNS drift detected", detail: "target.com A record changed: +1 new IP" },
  { id: "10", timestamp: "00:22", type: "finding", title: "CORS reflects origin", detail: "/api/data — Access-Control-Allow-Origin: *", severity: "high" },
];

const TYPE_COLORS: Record<string, string> = {
  finding: "border-l-red-500",
  change: "border-l-yellow-500",
  endpoint: "border-l-blue-500",
  asset: "border-l-green-500",
  tech: "border-l-purple-500",
};

const TYPE_ICONS: Record<string, typeof Globe> = {
  finding: AlertTriangle,
  change: Radio,
  endpoint: Search,
  asset: Globe,
  tech: Shield,
};

export default function LiveFeedPage() {
  const [events] = useState<ReconEvent[]>(MOCK_FEED);

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
          <Radio className="w-5 h-5 text-green-400" />
          <span className="text-lg font-semibold">Live Feed</span>
          <div className="ml-auto flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-green-500 pulse-live" />
            <span className="text-xs text-green-400">STREAMING</span>
          </div>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-6 py-8">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="mb-6">
          <h2 className="text-3xl font-bold gradient-text mb-2">Live Reconnaissance Feed</h2>
          <p className="text-muted-foreground">Real-time stream of discoveries, changes, and findings.</p>
        </motion.div>

        {/* Event counters */}
        <div className="flex gap-3 mb-6 flex-wrap">
          {[
            { type: "finding", count: events.filter(e => e.type === "finding").length, color: "text-red-400" },
            { type: "change", count: events.filter(e => e.type === "change").length, color: "text-yellow-400" },
            { type: "endpoint", count: events.filter(e => e.type === "endpoint").length, color: "text-blue-400" },
            { type: "asset", count: events.filter(e => e.type === "asset").length, color: "text-green-400" },
            { type: "tech", count: events.filter(e => e.type === "tech").length, color: "text-purple-400" },
          ].map(c => (
            <span key={c.type}
              className={`px-3 py-1 bg-card/50 border border-white/5 rounded-full text-xs ${c.color}`}>
              {c.type}: {c.count}
            </span>
          ))}
        </div>

        {/* Feed */}
        <div className="space-y-2">
          <AnimatePresence>
            {events.map((event, i) => {
              const Icon = TYPE_ICONS[event.type];
              return (
                <motion.div key={event.id}
                  initial={{ opacity: 0, x: -20, height: 0 }}
                  animate={{ opacity: 1, x: 0, height: "auto" }}
                  transition={{ delay: i * 0.06 }}
                  className={`glass-card p-4 border-l-4 ${TYPE_COLORS[event.type]}`}>
                  <div className="flex items-start gap-3">
                    <div className="w-8 h-8 rounded-lg bg-secondary flex items-center justify-center shrink-0 mt-0.5">
                      <Icon className="w-4 h-4 text-muted-foreground" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-medium text-sm">{event.title}</span>
                        {event.severity && (
                          <span className={`text-xs px-1.5 py-0.5 rounded border ${
                            event.severity === "critical" ? "text-red-400 bg-red-500/10 border-red-500/20" :
                            event.severity === "high" ? "text-orange-400 bg-orange-500/10 border-orange-500/20" :
                            "text-yellow-400 bg-yellow-500/10 border-yellow-500/20"
                          }`}>{event.severity.toUpperCase()}</span>
                        )}
                      </div>
                      <p className="text-xs text-muted-foreground font-mono truncate">{event.detail}</p>
                    </div>
                    <span className="text-xs text-muted-foreground font-mono shrink-0">{event.timestamp}</span>
                  </div>
                </motion.div>
              );
            })}
          </AnimatePresence>
        </div>
      </main>
    </div>
  );
}
