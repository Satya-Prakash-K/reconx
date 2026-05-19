"use client";
import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Plus, Shield, Globe, Trash2, ChevronDown, ChevronUp, Save, Target, AlertTriangle, Check } from "lucide-react";

const ENGINE = "http://localhost:8004/api/v1/agents";

const PLATFORMS = [
  { id: "hackerone", label: "HackerOne", color: "#00c13f" },
  { id: "bugcrowd", label: "Bugcrowd", color: "#f26522" },
  { id: "intigriti", label: "Intigriti", color: "#6c47ff" },
  { id: "yeswehack", label: "YesWeHack", color: "#00b4d8" },
  { id: "custom", label: "Private / Custom", color: "#64748b" },
];

const ALL_TESTS = [
  { id: "xss", label: "XSS", cat: "safe", desc: "Reflected / Stored Cross-Site Scripting" },
  { id: "sqli", label: "SQL Injection", cat: "safe", desc: "Error-based & Boolean blind" },
  { id: "lfi", label: "LFI / Path Traversal", cat: "safe", desc: "Local file read via path traversal" },
  { id: "ssrf", label: "SSRF", cat: "moderate", desc: "Server-side request forgery" },
  { id: "csrf", label: "CSRF", cat: "safe", desc: "Missing anti-CSRF token detection" },
  { id: "cors", label: "CORS", cat: "safe", desc: "Cross-origin resource sharing misconfig" },
  { id: "idor", label: "IDOR", cat: "moderate", desc: "Insecure direct object reference" },
  { id: "open_redirect", label: "Open Redirect", cat: "safe", desc: "Unvalidated redirect / forward" },
  { id: "ssti", label: "SSTI", cat: "safe", desc: "Server-side template injection" },
  { id: "misconfig", label: "Sensitive Files", cat: "safe", desc: "/.env, /.git/config, /phpinfo.php" },
  { id: "graphql", label: "GraphQL", cat: "moderate", desc: "Introspection + depth attacks" },
  { id: "jwt", label: "JWT", cat: "moderate", desc: "Algorithm confusion / weak secret" },
  { id: "cmdi", label: "Command Injection", cat: "aggressive", desc: "OS command injection via params" },
  { id: "xxe", label: "XXE", cat: "moderate", desc: "XML external entity injection" },
];

const PRESETS: Record<string, string[]> = {
  conservative: ["xss", "sqli", "lfi", "csrf", "cors", "open_redirect", "misconfig"],
  standard: ["xss", "sqli", "lfi", "ssrf", "csrf", "cors", "idor", "open_redirect", "ssti", "misconfig", "graphql", "jwt"],
  aggressive: ALL_TESTS.map(t => t.id),
};

const CAT_STYLES: Record<string, string> = {
  safe: "rgba(34,197,94,0.15)",
  moderate: "rgba(245,158,11,0.15)",
  aggressive: "rgba(239,68,68,0.15)",
};

interface Program {
  id: string; name: string; platform: string;
  in_scope: string[]; out_of_scope: string[];
  allowed_tests: string[]; rate_limit_rps: number;
  notes?: string; finding_count?: number; scan_count?: number;
}

export default function ProgramsPage() {
  const [programs, setPrograms] = useState<Program[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  // Form state
  const [name, setName] = useState("");
  const [platform, setPlatform] = useState("custom");
  const [scopeText, setScopeText] = useState("");
  const [inScope, setInScope] = useState<string[]>([]);
  const [outScope, setOutScope] = useState<string[]>([]);
  const [allowed, setAllowed] = useState<string[]>(PRESETS.standard);
  const [rateLimit, setRateLimit] = useState(2);
  const [notes, setNotes] = useState("");
  const [preset, setPreset] = useState("standard");

  useEffect(() => {
    fetch(`${ENGINE}/programs`).then(r => r.json()).then(setPrograms).catch(() => setPrograms([]));
  }, []);

  // Parse pasted scope text
  const parseScope = (text: string) => {
    const lines = text.split(/\n/).map(l => l.trim()).filter(Boolean);
    const inS: string[] = [], outS: string[] = [];
    for (const line of lines) {
      const lower = line.toLowerCase();
      if (lower.startsWith("out of scope") || lower.startsWith("excluded") || lower.includes("not in scope")) continue;
      const domain = line.match(/(\*\.)?([a-z0-9.-]+\.[a-z]{2,})/i)?.[0];
      if (!domain) continue;
      if (lower.includes("out") || lower.includes("exclu")) outS.push(domain);
      else inS.push(domain);
    }
    if (inS.length === 0 && lines.length > 0) {
      // Treat all as in-scope
      lines.forEach(l => {
        const d = l.match(/(\*\.)?([a-z0-9.-]+\.[a-z]{2,})/i)?.[0];
        if (d) inS.push(d);
      });
    }
    setInScope(inS); setOutScope(outS);
  };

  const toggleTest = (id: string) =>
    setAllowed(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);

  const applyPreset = (p: string) => { setPreset(p); setAllowed(PRESETS[p] || PRESETS.standard); };

  const handleSave = async () => {
    if (!name.trim()) return;
    setSaving(true);
    const body = { name, platform, in_scope: inScope, out_of_scope: outScope, allowed_tests: allowed, rate_limit_rps: rateLimit, notes };
    try {
      const res = await fetch(`${ENGINE}/programs`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      if (res.ok) {
        const p = await res.json();
        setPrograms(prev => [p, ...prev]);
        setShowForm(false); setSaved(true);
        setTimeout(() => setSaved(false), 2000);
        setName(""); setScopeText(""); setInScope([]); setOutScope([]); setAllowed(PRESETS.standard); setNotes("");
      }
    } catch {}
    setSaving(false);
  };

  const handleDelete = async (id: string) => {
    await fetch(`${ENGINE}/programs/${id}`, { method: "DELETE" }).catch(() => {});
    setPrograms(prev => prev.filter(p => p.id !== id));
  };

  const platformInfo = (id: string) => PLATFORMS.find(p => p.id === id) || PLATFORMS[4];

  return (
    <div style={{ padding: "2rem", maxWidth: 1100, margin: "0 auto" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "2rem" }}>
        <div>
          <h1 style={{ fontSize: "1.8rem", fontWeight: 700, margin: 0, color: "#f1f5f9" }}>
            <Shield style={{ display: "inline", marginRight: 10, color: "#6366f1" }} size={28} />
            Bug Bounty Programs
          </h1>
          <p style={{ color: "#64748b", marginTop: 6, fontSize: "0.9rem" }}>
            Define scope, policy, and allowed tests for each bug bounty program
          </p>
        </div>
        <motion.button whileHover={{ scale: 1.04 }} whileTap={{ scale: 0.97 }}
          onClick={() => setShowForm(true)}
          style={{ display: "flex", alignItems: "center", gap: 8, padding: "0.6rem 1.2rem", background: "linear-gradient(135deg,#6366f1,#8b5cf6)", border: "none", borderRadius: 10, color: "#fff", fontWeight: 600, cursor: "pointer" }}>
          <Plus size={16} /> New Program
        </motion.button>
      </div>

      {saved && (
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
          style={{ background: "rgba(34,197,94,0.15)", border: "1px solid rgba(34,197,94,0.3)", borderRadius: 10, padding: "0.75rem 1rem", marginBottom: "1rem", color: "#4ade80", display: "flex", alignItems: "center", gap: 8 }}>
          <Check size={16} /> Program saved successfully
        </motion.div>
      )}

      {/* Program List */}
      {programs.length === 0 && !showForm && (
        <div style={{ textAlign: "center", padding: "4rem", color: "#475569" }}>
          <Shield size={48} style={{ margin: "0 auto 1rem", opacity: 0.3, display: "block" }} />
          <p>No programs yet. Create your first bug bounty program to get started.</p>
        </div>
      )}

      <div style={{ display: "grid", gap: "1rem", marginBottom: "2rem" }}>
        {programs.map(prog => {
          const pf = platformInfo(prog.platform);
          return (
            <motion.div key={prog.id} layout initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
              style={{ background: "rgba(15,23,42,0.8)", border: "1px solid rgba(99,102,241,0.2)", borderRadius: 14, padding: "1.2rem 1.5rem" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <span style={{ background: pf.color + "25", color: pf.color, border: `1px solid ${pf.color}40`, borderRadius: 8, padding: "0.25rem 0.7rem", fontSize: "0.75rem", fontWeight: 700 }}>
                    {pf.label}
                  </span>
                  <span style={{ color: "#f1f5f9", fontWeight: 600, fontSize: "1.05rem" }}>{prog.name}</span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <span style={{ color: "#64748b", fontSize: "0.8rem" }}>
                    <Globe size={13} style={{ display: "inline", marginRight: 4 }} />
                    {(prog.in_scope || []).length} in-scope domains
                  </span>
                  <span style={{ color: "#64748b", fontSize: "0.8rem" }}>
                    <Target size={13} style={{ display: "inline", marginRight: 4 }} />
                    {(prog.allowed_tests || []).length} tests enabled
                  </span>
                  <button onClick={() => handleDelete(prog.id)}
                    style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.2)", borderRadius: 8, padding: "0.3rem 0.6rem", color: "#f87171", cursor: "pointer" }}>
                    <Trash2 size={14} />
                  </button>
                </div>
              </div>
              {(prog.in_scope || []).length > 0 && (
                <div style={{ marginTop: 10, display: "flex", flexWrap: "wrap", gap: 6 }}>
                  {(prog.in_scope || []).filter(Boolean).slice(0, 6).map(d => (
                    <span key={d} style={{ background: "rgba(99,102,241,0.1)", border: "1px solid rgba(99,102,241,0.2)", borderRadius: 6, padding: "0.15rem 0.5rem", fontSize: "0.75rem", color: "#a5b4fc" }}>
                      {d}
                    </span>
                  ))}
                  {(prog.in_scope || []).length > 6 && <span style={{ color: "#64748b", fontSize: "0.75rem", alignSelf: "center" }}>+{prog.in_scope.length - 6} more</span>}
                </div>
              )}
            </motion.div>
          );
        })}
      </div>

      {/* Create Program Form */}
      <AnimatePresence>
        {showForm && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", zIndex: 50, display: "flex", alignItems: "center", justifyContent: "center", padding: "1rem" }}
            onClick={e => { if (e.target === e.currentTarget) setShowForm(false); }}>
            <motion.div initial={{ scale: 0.95, y: 20 }} animate={{ scale: 1, y: 0 }} exit={{ scale: 0.95, y: 20 }}
              style={{ background: "#0f172a", border: "1px solid rgba(99,102,241,0.3)", borderRadius: 18, padding: "2rem", width: "100%", maxWidth: 700, maxHeight: "90vh", overflowY: "auto" }}>
              <h2 style={{ color: "#f1f5f9", fontWeight: 700, fontSize: "1.3rem", marginTop: 0 }}>Create Bug Bounty Program</h2>

              {/* Step 1: Basic */}
              <label style={lbl}>Program Name</label>
              <input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. HackerOne — Shopify" style={inp} />

              <label style={lbl}>Platform</label>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: "1.2rem" }}>
                {PLATFORMS.map(pf => (
                  <button key={pf.id} onClick={() => setPlatform(pf.id)}
                    style={{ padding: "0.4rem 0.9rem", borderRadius: 8, border: `1px solid ${platform === pf.id ? pf.color : "rgba(100,116,139,0.3)"}`, background: platform === pf.id ? pf.color + "25" : "transparent", color: platform === pf.id ? pf.color : "#94a3b8", cursor: "pointer", fontWeight: platform === pf.id ? 700 : 400, fontSize: "0.85rem" }}>
                    {pf.label}
                  </button>
                ))}
              </div>

              {/* Step 2: Scope */}
              <label style={lbl}>Paste Scope (from bug bounty page) — auto-parsed</label>
              <textarea value={scopeText} onChange={e => { setScopeText(e.target.value); parseScope(e.target.value); }}
                placeholder={"*.example.com\napi.example.com\nOut of scope: help.example.com"}
                rows={4} style={{ ...inp, resize: "vertical", fontFamily: "monospace", fontSize: "0.82rem" }} />
              {inScope.length > 0 && (
                <div style={{ marginBottom: "1rem" }}>
                  <p style={{ color: "#4ade80", fontSize: "0.8rem", margin: "0 0 6px" }}>✅ {inScope.length} in-scope domains detected:</p>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                    {inScope.map(d => <span key={d} style={{ background: "rgba(34,197,94,0.1)", border: "1px solid rgba(34,197,94,0.2)", borderRadius: 6, padding: "0.15rem 0.5rem", fontSize: "0.75rem", color: "#4ade80" }}>{d}</span>)}
                  </div>
                  {outScope.length > 0 && <p style={{ color: "#f87171", fontSize: "0.8rem", margin: "8px 0 0" }}>🚫 {outScope.length} out-of-scope: {outScope.join(", ")}</p>}
                </div>
              )}

              {/* Step 3: Policy preset */}
              <label style={lbl}>Policy Preset</label>
              <div style={{ display: "flex", gap: 8, marginBottom: "1rem" }}>
                {["conservative","standard","aggressive"].map(p => (
                  <button key={p} onClick={() => applyPreset(p)}
                    style={{ padding: "0.4rem 0.9rem", borderRadius: 8, border: `1px solid ${preset===p?"#6366f1":"rgba(100,116,139,0.3)"}`, background: preset===p?"rgba(99,102,241,0.15)":"transparent", color: preset===p?"#a5b4fc":"#94a3b8", cursor: "pointer", textTransform: "capitalize", fontSize: "0.85rem", fontWeight: preset===p?700:400 }}>
                    {p}
                  </button>
                ))}
              </div>

              {/* Step 4: Fine-tune tests */}
              <label style={lbl}>Test Coverage — toggle individual tests</label>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6, marginBottom: "1.2rem" }}>
                {ALL_TESTS.map(t => (
                  <button key={t.id} onClick={() => toggleTest(t.id)}
                    style={{ display: "flex", alignItems: "center", gap: 8, padding: "0.5rem 0.75rem", borderRadius: 9, border: `1px solid ${allowed.includes(t.id) ? "rgba(99,102,241,0.4)" : "rgba(100,116,139,0.2)"}`, background: allowed.includes(t.id) ? CAT_STYLES[t.cat] : "transparent", cursor: "pointer", textAlign: "left" }}>
                    <span style={{ width: 14, height: 14, borderRadius: 4, border: `2px solid ${allowed.includes(t.id) ? "#6366f1" : "#475569"}`, background: allowed.includes(t.id) ? "#6366f1" : "transparent", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                      {allowed.includes(t.id) && <Check size={10} color="#fff" />}
                    </span>
                    <div>
                      <div style={{ color: allowed.includes(t.id) ? "#e2e8f0" : "#64748b", fontSize: "0.8rem", fontWeight: 600 }}>{t.label}</div>
                      <div style={{ color: "#475569", fontSize: "0.7rem" }}>{t.desc}</div>
                    </div>
                  </button>
                ))}
              </div>

              {/* Step 5: Rate limit */}
              <label style={lbl}>Max Requests / Second: <strong style={{ color: "#a5b4fc" }}>{rateLimit}</strong></label>
              <input type="range" min={1} max={10} value={rateLimit} onChange={e => setRateLimit(+e.target.value)}
                style={{ width: "100%", marginBottom: "1.2rem", accentColor: "#6366f1" }} />

              {/* Step 6: Notes */}
              <label style={lbl}>Policy Notes (optional)</label>
              <textarea value={notes} onChange={e => setNotes(e.target.value)}
                placeholder="e.g. Do not test /admin. No rate limiting issues. Safe harbor confirmed."
                rows={2} style={{ ...inp, resize: "vertical" }} />

              {/* Never-allowed warning */}
              <div style={{ background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.2)", borderRadius: 10, padding: "0.75rem 1rem", marginBottom: "1.5rem" }}>
                <p style={{ color: "#f87171", fontSize: "0.78rem", margin: 0 }}>
                  <AlertTriangle size={12} style={{ display: "inline", marginRight: 6 }} />
                  <strong>Always disabled regardless of settings:</strong> Brute force · DoS/DDoS · SQLi with INSERT/DELETE · Cross-origin scanning · Data exfiltration
                </p>
              </div>

              <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
                <button onClick={() => setShowForm(false)}
                  style={{ padding: "0.6rem 1.2rem", borderRadius: 10, border: "1px solid rgba(100,116,139,0.3)", background: "transparent", color: "#94a3b8", cursor: "pointer" }}>
                  Cancel
                </button>
                <motion.button whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }} onClick={handleSave} disabled={saving || !name.trim()}
                  style={{ display: "flex", alignItems: "center", gap: 8, padding: "0.6rem 1.4rem", background: "linear-gradient(135deg,#6366f1,#8b5cf6)", border: "none", borderRadius: 10, color: "#fff", fontWeight: 600, cursor: saving ? "not-allowed" : "pointer", opacity: saving || !name.trim() ? 0.6 : 1 }}>
                  <Save size={15} /> {saving ? "Saving..." : "Save Program"}
                </motion.button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

const lbl: React.CSSProperties = { display: "block", color: "#94a3b8", fontSize: "0.82rem", fontWeight: 600, marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.05em" };
const inp: React.CSSProperties = { width: "100%", background: "rgba(30,41,59,0.8)", border: "1px solid rgba(99,102,241,0.2)", borderRadius: 10, padding: "0.65rem 0.9rem", color: "#e2e8f0", fontSize: "0.9rem", outline: "none", boxSizing: "border-box", marginBottom: "1.2rem" };
