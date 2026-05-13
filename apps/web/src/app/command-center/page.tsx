"use client";

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Zap, ChevronRight, Brain, Activity, Shield, Target,
  Cpu, Network, AlertTriangle, CheckCircle, Clock, Radio
} from "lucide-react";
import Link from "next/link";

interface AgentState {
  name: string;
  status: "active" | "idle" | "completed";
  reasoning: string;
  progress: number;
}

const MOCK_AGENTS: AgentState[] = [
  { name: "Planner", status: "completed", reasoning: "Cycle 2: Deep scan strategy — focusing on confirmed SQLi endpoints", progress: 100 },
  { name: "Recon", status: "completed", reasoning: "Discovered 238 endpoints, 14 new since last cycle", progress: 100 },
  { name: "Analyzer", status: "completed", reasoning: "Attack surface: 42 high-priority, 12 auth endpoints", progress: 100 },
  { name: "Hypothesis", status: "completed", reasoning: "Generated 67 hypotheses — XSS (23), SQLi (18), SSRF (8), IDOR (11), Other (7)", progress: 100 },
  { name: "Tester", status: "active", reasoning: "Testing hypothesis 34/67 — blind SQLi via time-based on /api/users?id=", progress: 51 },
  { name: "Triager", status: "idle", reasoning: "Waiting for test results...", progress: 0 },
  { name: "Reporter", status: "idle", reasoning: "Will generate HackerOne reports for confirmed findings", progress: 0 },
  { name: "Memory", status: "idle", reasoning: "Ready to store findings in knowledge graph", progress: 0 },
];

const STATUS_COLORS: Record<string, string> = {
  active: "text-green-400 bg-green-500/10 border-green-500/30",
  idle: "text-gray-400 bg-gray-500/10 border-gray-500/20",
  completed: "text-cyan-400 bg-cyan-500/10 border-cyan-500/20",
};

const STATUS_ICONS: Record<string, typeof Activity> = {
  active: Radio,
  idle: Clock,
  completed: CheckCircle,
};

export default function CommandCenterPage() {
  const [agents] = useState<AgentState[]>(MOCK_AGENTS);
  const [cycle] = useState(2);
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => setElapsed(e => e + 1), 1000);
    return () => clearInterval(timer);
  }, []);

  const formatTime = (s: number) => `${Math.floor(s / 60)}:${(s % 60).toString().padStart(2, "0")}`;

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
          <Brain className="w-5 h-5 text-purple-400" />
          <span className="text-lg font-semibold">AI Command Center</span>
          <div className="ml-auto flex items-center gap-4">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-green-500 pulse-live" />
              <span className="text-xs text-green-400">AUTONOMOUS MODE</span>
            </div>
            <span className="text-xs text-muted-foreground font-mono">Cycle {cycle} • {formatTime(elapsed)}</span>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        {/* Stats row */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
          {[
            { label: "Active Agents", value: agents.filter(a => a.status === "active").length, icon: Cpu, color: "text-green-400" },
            { label: "Hypotheses", value: 67, icon: Brain, color: "text-purple-400" },
            { label: "Findings", value: 12, icon: AlertTriangle, color: "text-orange-400" },
            { label: "Endpoints", value: 238, icon: Network, color: "text-cyan-400" },
          ].map((s, i) => (
            <motion.div key={s.label} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.05 }} className="glass-card p-4">
              <div className="flex items-center gap-2 mb-2">
                <s.icon className={`w-4 h-4 ${s.color}`} />
                <span className="text-xs text-muted-foreground">{s.label}</span>
              </div>
              <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
            </motion.div>
          ))}
        </div>

        {/* Agent swarm */}
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Target className="w-5 h-5 text-purple-400" /> Agent Swarm Pipeline
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 mb-8">
          {agents.map((agent, i) => {
            const Icon = STATUS_ICONS[agent.status];
            return (
              <motion.div key={agent.name}
                initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: i * 0.06 }}
                className={`glass-card p-4 border ${
                  agent.status === "active" ? "border-green-500/30 glow-primary" : "border-white/5"
                }`}>
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${STATUS_COLORS[agent.status]}`}>
                      <Icon className="w-4 h-4" />
                    </div>
                    <span className="font-medium text-sm">{agent.name}</span>
                  </div>
                  <span className={`text-xs px-2 py-0.5 rounded border ${STATUS_COLORS[agent.status]}`}>
                    {agent.status.toUpperCase()}
                  </span>
                </div>
                {/* Progress bar */}
                <div className="w-full bg-secondary rounded-full h-1.5 mb-2">
                  <motion.div
                    className={`h-full rounded-full ${
                      agent.status === "active" ? "bg-green-500" : agent.status === "completed" ? "bg-cyan-500" : "bg-gray-600"
                    }`}
                    initial={{ width: 0 }}
                    animate={{ width: `${agent.progress}%` }}
                    transition={{ duration: 1, delay: i * 0.1 }}
                  />
                </div>
                <p className="text-xs text-muted-foreground leading-relaxed">{agent.reasoning}</p>
              </motion.div>
            );
          })}
        </div>

        {/* Reasoning chain */}
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Brain className="w-5 h-5 text-purple-400" /> AI Reasoning Chain
        </h3>
        <div className="glass-card p-4 max-h-96 overflow-y-auto">
          {[
            "[planner] Cycle 2: Planning strategy for 3 targets",
            "[planner] Previous cycle found 5 findings — focusing deeper",
            "[planner] Strategy: focused_scan",
            "[recon] Scanning 3 targets for endpoints and assets",
            "[recon] Discovered 238 endpoints (+14 new)",
            "[analysis] Classifying 238 endpoints",
            "[analysis] Attack surface: {total: 238, api: 142, auth: 12, high_priority: 42}",
            "[hypothesis] Generating hypotheses for 42 high-priority endpoints",
            "[hypothesis] Generated 67 hypotheses",
            "[testing] Executing test payloads against hypotheses (34/67)...",
          ].map((step, i) => (
            <motion.div key={i} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.04 }}
              className="flex items-start gap-3 py-2 border-b border-white/5 last:border-0">
              <span className="text-xs text-muted-foreground font-mono w-16 shrink-0">
                {`${Math.floor(i * 2.3)}:${(i * 7 % 60).toString().padStart(2, "0")}`}
              </span>
              <span className="text-sm text-muted-foreground">{step}</span>
            </motion.div>
          ))}
        </div>
      </main>
    </div>
  );
}
