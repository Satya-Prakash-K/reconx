"use client";

import { motion } from "framer-motion";
import {
  Shield, Search, Radar, Globe, Activity, AlertTriangle,
  ChevronRight, Zap, Brain, Target, Network, Bug, Flame, GitBranch,
  Crosshair, FileText, BarChart3, Database, Cpu, Radio
} from "lucide-react";
import Link from "next/link";

const stats = [
  { label: "Active Scans", value: "—", icon: Radar, color: "text-green-400" },
  { label: "Assets Found", value: "—", icon: Globe, color: "text-blue-400" },
  { label: "Findings", value: "—", icon: AlertTriangle, color: "text-orange-400" },
  { label: "Programs", value: "—", icon: Target, color: "text-purple-400" },
];

const features = [
  { title: "Command Center", desc: "Autonomous AI agent swarm control", icon: Cpu, href: "/command-center" },
  { title: "Live Feed", desc: "Real-time recon event stream", icon: Radio, href: "/live-feed" },
  { title: "Scans", desc: "Launch and monitor recon scans", icon: Search, href: "/scans" },
  { title: "Vuln Scans", desc: "Autonomous vulnerability testing", icon: Bug, href: "/vuln-scans" },
  { title: "AI Triage", desc: "CVSS/CWE/OWASP auto-classification", icon: Crosshair, href: "/triage" },
  { title: "Report Builder", desc: "Multi-platform report generator", icon: FileText, href: "/report-builder" },
  { title: "Findings", desc: "Browse and triage findings", icon: AlertTriangle, href: "/findings" },
  { title: "Heatmap", desc: "Vulnerability severity heatmap", icon: Flame, href: "/heatmap" },
  { title: "Attack Graph", desc: "Exploitation path visualization", icon: GitBranch, href: "/graph" },
  { title: "Timeline", desc: "Chronological vulnerability history", icon: BarChart3, href: "/timeline" },
  { title: "AI Insights", desc: "AI-powered analysis & summaries", icon: Brain, href: "/ai" },
  { title: "Programs", desc: "Manage bug bounty program scopes", icon: Shield, href: "/programs" },
];

export default function Dashboard() {
  return (
    <div className="min-h-screen">
      {/* Header */}
      <header className="border-b border-white/5 bg-card/30 backdrop-blur-lg sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-purple-500 to-indigo-600 flex items-center justify-center">
              <Zap className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold gradient-text">ReconX</h1>
              <p className="text-xs text-muted-foreground">Autonomous Recon Platform</p>
            </div>
          </div>
          <nav className="hidden md:flex items-center gap-6">
            {["Dashboard", "Command", "Live Feed", "Scans", "Triage", "Reports", "Graph"].map((item) => (
              <Link
                key={item}
                href={item === "Dashboard" ? "/" : item === "Command" ? "/command-center" : `/${item.toLowerCase().replace(" ", "-")}`}
                className="text-sm text-muted-foreground hover:text-foreground transition-colors"
              >
                {item}
              </Link>
            ))}
          </nav>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-green-500/10 border border-green-500/20">
              <span className="w-2 h-2 rounded-full bg-green-400 pulse-live" />
              <span className="text-xs text-green-400 font-medium">System Online</span>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        {/* Hero Section */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="mb-10"
        >
          <h2 className="text-4xl font-bold mb-2">
            <span className="gradient-text">Command Center</span>
          </h2>
          <p className="text-muted-foreground text-lg">
            AI-powered reconnaissance at your fingertips. Authorized testing only.
          </p>
        </motion.div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-10">
          {stats.map((stat, i) => (
            <motion.div
              key={stat.label}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4, delay: i * 0.1 }}
              className="stat-card"
            >
              <div className="flex items-center justify-between mb-4">
                <stat.icon className={`w-5 h-5 ${stat.color}`} />
                <span className="text-xs text-muted-foreground uppercase tracking-wider">{stat.label}</span>
              </div>
              <p className="text-3xl font-bold">{stat.value}</p>
            </motion.div>
          ))}
        </div>

        {/* Feature Cards */}
        <h3 className="text-xl font-semibold mb-6">Quick Actions</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-10">
          {features.map((feature, i) => (
            <motion.div
              key={feature.title}
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.3, delay: 0.3 + i * 0.08 }}
            >
              <Link href={feature.href} className="block group">
                <div className="glass-card p-6 hover:border-primary/30 hover:glow-primary transition-all duration-300 cursor-pointer">
                  <div className="flex items-start justify-between">
                    <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center mb-4 group-hover:bg-primary/20 transition-colors">
                      <feature.icon className="w-6 h-6 text-primary" />
                    </div>
                    <ChevronRight className="w-5 h-5 text-muted-foreground group-hover:text-primary group-hover:translate-x-1 transition-all" />
                  </div>
                  <h4 className="text-lg font-semibold mb-1">{feature.title}</h4>
                  <p className="text-sm text-muted-foreground">{feature.desc}</p>
                </div>
              </Link>
            </motion.div>
          ))}
        </div>

        {/* Recent Activity Placeholder */}
        <div className="glass-card p-8 text-center">
          <Radar className="w-12 h-12 text-primary mx-auto mb-4 opacity-50" />
          <h3 className="text-lg font-semibold mb-2">No Active Scans</h3>
          <p className="text-muted-foreground mb-6">
            Create a program, define your scope, and launch your first scan.
          </p>
          <Link
            href="/programs"
            className="inline-flex items-center gap-2 px-6 py-3 bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg font-medium transition-colors"
          >
            <Shield className="w-4 h-4" />
            Add Program
          </Link>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-white/5 mt-20 py-6">
        <div className="max-w-7xl mx-auto px-6 flex items-center justify-between text-xs text-muted-foreground">
          <span>ReconX v0.1.0 — Authorized Security Testing Only</span>
          <span>⚡ Powered by AI</span>
        </div>
      </footer>
    </div>
  );
}
