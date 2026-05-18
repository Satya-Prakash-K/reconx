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
  const [agents, setAgents] = useState<AgentState[]>(MOCK_AGENTS);
  const [cycle, setCycle] = useState(0);
  const [elapsed, setElapsed] = useState(0);
  
  // Scan Form State
  const [targetUrl, setTargetUrl] = useState("");
  const [scanMode, setScanMode] = useState("autonomous");
  const [cycles, setCycles] = useState(3);
  const [isScanning, setIsScanning] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [reasoningChain, setReasoningChain] = useState<string[]>([
    "[system] Awaiting target configuration...",
    "[system] Ready to launch agent swarm."
  ]);

  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (isScanning) {
      timer = setInterval(() => setElapsed(e => e + 1), 1000);
    }
    return () => clearInterval(timer);
  }, [isScanning]);
  
  useEffect(() => {
    if (!scanId) return;
    
    // Connect to WebSocket for live updates
    const ws = new WebSocket(`ws://localhost:8000/api/v1/scans/ws/${scanId}`);
    
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.details && data.details.agents) {
           setAgents(data.details.agents);
        }
        if (data.details && data.details.reasoning) {
           setReasoningChain(prev => [...data.details.reasoning, ...prev].slice(0, 50));
        }
        if (data.details && data.details.cycle) {
           setCycle(data.details.cycle);
        }
        if (data.progress >= 100) {
           setIsScanning(false);
        }
      } catch (e) {}
    };
    
    return () => ws.close();
  }, [scanId]);

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl) return;
    
    setIsScanning(true);
    setElapsed(0);
    setCycle(1);
    setAgents(MOCK_AGENTS.map(a => ({ ...a, status: "idle", progress: 0, reasoning: "Pending start..." })));
    setReasoningChain(["[system] Initializing agent swarm..."]);
    
    try {
      const res = await fetch("http://localhost:8004/api/v1/agents/session/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          workspace_id: "default",
          targets: [targetUrl],
          max_cycles: cycles,
          mode: scanMode
        })
      });
      
      if (res.ok) {
        const data = await res.json();
        setScanId(data.session_id || data.id);
        setReasoningChain(prev => ["[planner] Session successfully established with backend.", ...prev]);
      } else {
        setReasoningChain(prev => [`[error] Failed to start scan: ${res.statusText}`, ...prev]);
        setIsScanning(false);
      }
    } catch (error) {
      setReasoningChain(prev => [`[error] Connection to Autonomous Engine failed. Is it running?`, ...prev]);
      setIsScanning(false);
    }
  };

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
        {/* Launchpad Form */}
        <div className="glass-card p-6 mb-8 border border-purple-500/30 glow-primary relative overflow-hidden">
          <div className="absolute top-0 right-0 w-64 h-64 bg-purple-500/10 rounded-full blur-3xl -mr-20 -mt-20 pointer-events-none" />
          
          <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
            <Target className="w-5 h-5 text-purple-400" /> Launch Autonomous Scan
          </h2>
          
          <form onSubmit={handleStartScan} className="flex flex-col md:flex-row gap-4 items-end relative z-10">
            <div className="flex-1 w-full">
              <label className="block text-xs text-muted-foreground mb-1">Target URL</label>
              <input 
                type="url" 
                required
                placeholder="https://juice-shop.herokuapp.com"
                value={targetUrl}
                onChange={e => setTargetUrl(e.target.value)}
                className="w-full bg-black/50 border border-white/10 rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:border-purple-500/50 transition-colors"
              />
            </div>
            
            <div className="w-full md:w-48">
              <label className="block text-xs text-muted-foreground mb-1">Mode</label>
              <select 
                value={scanMode}
                onChange={e => setScanMode(e.target.value)}
                className="w-full bg-black/50 border border-white/10 rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:border-purple-500/50 appearance-none"
              >
                <option value="autonomous">Autonomous (Full Swarm)</option>
                <option value="recon">Recon Only</option>
                <option value="vuln">Vuln Testing Only</option>
              </select>
            </div>
            
            <div className="w-full md:w-32">
              <label className="block text-xs text-muted-foreground mb-1">Max Cycles</label>
              <input 
                type="number" 
                min="1" max="10"
                value={cycles}
                onChange={e => setCycles(parseInt(e.target.value))}
                className="w-full bg-black/50 border border-white/10 rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:border-purple-500/50"
              />
            </div>
            
            <button 
              type="submit" 
              disabled={isScanning}
              className="w-full md:w-auto bg-purple-600 hover:bg-purple-500 text-white font-medium px-6 py-2.5 rounded-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              {isScanning ? (
                <><Radio className="w-4 h-4 animate-pulse" /> Scanning...</>
              ) : (
                <><Zap className="w-4 h-4" /> Start Scan</>
              )}
            </button>
          </form>
        </div>

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
          {reasoningChain.map((step, i) => (
            <motion.div key={i} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.04 }}
              className="flex items-start gap-3 py-2 border-b border-white/5 last:border-0">
              <span className="text-xs text-muted-foreground font-mono w-16 shrink-0">
                {formatTime(elapsed)}
              </span>
              <span className="text-sm text-gray-300">{step}</span>
            </motion.div>
          ))}
        </div>
      </main>
    </div>
  );
}
