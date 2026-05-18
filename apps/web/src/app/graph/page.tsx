"use client";

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Zap, ChevronRight, GitBranch, Shield, Globe, Server, Lock, AlertTriangle } from "lucide-react";
import Link from "next/link";

interface GraphNode {
  id: string;
  label: string;
  type: "domain" | "endpoint" | "vuln" | "param" | "service";
  x: number;
  y: number;
  severity?: string;
}

interface GraphEdge {
  from: string;
  to: string;
  label?: string;
}

const MOCK_NODES: GraphNode[] = [
  { id: "d1", label: "target.com", type: "domain", x: 400, y: 50 },
  { id: "e1", label: "/api/users", type: "endpoint", x: 200, y: 150 },
  { id: "e2", label: "/api/auth", type: "endpoint", x: 400, y: 150 },
  { id: "e3", label: "/graphql", type: "endpoint", x: 600, y: 150 },
  { id: "p1", label: "id", type: "param", x: 120, y: 250 },
  { id: "p2", label: "token", type: "param", x: 350, y: 250 },
  { id: "p3", label: "query", type: "param", x: 550, y: 250 },
  { id: "v1", label: "SQLi", type: "vuln", x: 120, y: 350, severity: "critical" },
  { id: "v2", label: "JWT Weak", type: "vuln", x: 350, y: 350, severity: "critical" },
  { id: "v3", label: "Introspection", type: "vuln", x: 550, y: 350, severity: "medium" },
  { id: "v4", label: "IDOR", type: "vuln", x: 220, y: 350, severity: "high" },
  { id: "s1", label: "DB Access", type: "service", x: 120, y: 450 },
  { id: "s2", label: "Auth Bypass", type: "service", x: 350, y: 450 },
];

const MOCK_EDGES: GraphEdge[] = [
  { from: "d1", to: "e1" }, { from: "d1", to: "e2" }, { from: "d1", to: "e3" },
  { from: "e1", to: "p1" }, { from: "e2", to: "p2" }, { from: "e3", to: "p3" },
  { from: "p1", to: "v1", label: "exploits" }, { from: "p1", to: "v4", label: "exploits" },
  { from: "p2", to: "v2", label: "exploits" }, { from: "p3", to: "v3", label: "exposes" },
  { from: "v1", to: "s1", label: "leads to" }, { from: "v2", to: "s2", label: "leads to" },
  { from: "v4", to: "s1", label: "leads to" },
];

const NODE_STYLES: Record<string, { bg: string; border: string; icon: any }> = {
  domain: { bg: "bg-blue-500/20", border: "border-blue-500/40", icon: Globe },
  endpoint: { bg: "bg-purple-500/20", border: "border-purple-500/40", icon: Server },
  vuln: { bg: "bg-red-500/20", border: "border-red-500/40", icon: AlertTriangle },
  param: { bg: "bg-yellow-500/20", border: "border-yellow-500/40", icon: Lock },
  service: { bg: "bg-green-500/20", border: "border-green-500/40", icon: Shield },
};

export default function AttackGraphPage() {
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);

  useEffect(() => {
    const fetchGraph = async () => {
      try {
        const res = await fetch("http://localhost:8000/api/v1/workspaces/default/graph?depth=3");
        if (res.ok) {
          const data = await res.json();
          
          if (!data.nodes || data.nodes.length === 0) {
             // Fallback to MOCK_NODES if Neo4j is empty so the dashboard isn't completely blank
             setNodes(MOCK_NODES);
             setEdges(MOCK_EDGES);
             return;
          }

          const newNodes = data.nodes.map((n: any, i: number) => {
            // Distribute nodes in a circle
            const angle = (i / data.nodes.length) * Math.PI * 2;
            const radius = 150 + Math.random() * 80;
            
            let type: GraphNode["type"] = "service";
            const ntype = n.type.toLowerCase();
            if (ntype === "domain" || ntype === "subdomain") type = "domain";
            else if (ntype === "ip" || ntype === "port") type = "endpoint";
            else if (ntype === "finding") type = "vuln";
            else if (ntype === "technology") type = "service";

            return {
              id: n.id,
              label: n.label,
              type: type,
              x: 400 + Math.cos(angle) * radius,
              y: 260 + Math.sin(angle) * radius,
              severity: n.properties?.severity
            };
          });
          
          const newEdges = data.edges.map((e: any) => ({
            from: e.from,
            to: e.to,
            label: e.type.replace(/_/g, " ")
          }));
          
          setNodes(newNodes);
          setEdges(newEdges);
        }
      } catch (e) {
        console.error("Failed to fetch graph", e);
        setNodes(MOCK_NODES);
        setEdges(MOCK_EDGES);
      }
    };
    
    fetchGraph();
  }, []);

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
          <GitBranch className="w-5 h-5 text-cyan-400" />
          <span className="text-lg font-semibold">Attack Graph</span>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="mb-6">
          <h2 className="text-3xl font-bold gradient-text mb-2">Attack Graph</h2>
          <p className="text-muted-foreground">
            Visual representation of vulnerability chains and exploitation paths.
          </p>
        </motion.div>

        {/* Graph SVG Canvas */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.2 }}
          className="glass-card p-2 overflow-hidden"
        >
          <svg viewBox="0 0 800 520" className="w-full h-auto" style={{ minHeight: 500 }}>
            <defs>
              <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">
                <polygon points="0 0, 10 3.5, 0 7" fill="hsl(262, 83%, 58%)" opacity="0.6" />
              </marker>
            </defs>

            {/* Edges */}
            {edges.map((edge, i) => {
              const from = nodes.find(n => n.id === edge.from);
              const to = nodes.find(n => n.id === edge.to);
              if (!from || !to) return null;
              return (
                <g key={`edge-${i}`}>
                  <line
                    x1={from.x} y1={from.y + 15} x2={to.x} y2={to.y - 15}
                    stroke="hsl(262, 83%, 58%)" strokeWidth="1.5" opacity="0.3"
                    markerEnd="url(#arrowhead)"
                  />
                  {edge.label && (
                    <text
                      x={(from.x + to.x) / 2 + 5} y={(from.y + to.y) / 2}
                      fill="hsl(215, 20%, 55%)" fontSize="9" textAnchor="start"
                    >
                      {edge.label}
                    </text>
                  )}
                </g>
              );
            })}

            {/* Nodes */}
            {nodes.map((node) => {
              const style = NODE_STYLES[node.type] || NODE_STYLES.service;
              const sevColor = node.severity === "critical" ? "#ef4444" :
                               node.severity === "high" ? "#f97316" :
                               node.severity === "medium" ? "#eab308" : "#8b5cf6";
              return (
                <g key={node.id} className="cursor-pointer">
                  <circle
                    cx={node.x} cy={node.y} r={22}
                    fill={node.type === "vuln" ? `${sevColor}33` : "hsl(217, 33%, 14%)"}
                    stroke={node.type === "vuln" ? sevColor : "hsl(262, 83%, 58%)"}
                    strokeWidth="1.5" opacity="0.9"
                  />
                  <text
                    x={node.x} y={node.y + 4} fill="hsl(210, 40%, 96%)"
                    textAnchor="middle" fontSize="10" fontWeight="600"
                  >
                    {node.label.length > 10 ? node.label.slice(0, 10) + "…" : node.label}
                  </text>
                  <text
                    x={node.x} y={node.y + 38} fill="hsl(215, 20%, 55%)"
                    textAnchor="middle" fontSize="8" opacity="0.7"
                  >
                    {node.type}
                  </text>
                </g>
              );
            })}
          </svg>
        </motion.div>

        {/* Legend */}
        <div className="mt-6 flex flex-wrap items-center gap-6 justify-center text-xs text-muted-foreground">
          {Object.entries(NODE_STYLES).map(([type, style]) => (
            <div key={type} className="flex items-center gap-2">
              <div className={`w-4 h-4 rounded-full ${style.bg} border ${style.border}`} />
              <span className="capitalize">{type}</span>
            </div>
          ))}
        </div>
      </main>
    </div>
  );
}
