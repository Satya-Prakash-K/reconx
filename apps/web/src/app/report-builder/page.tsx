"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import {
  Zap, ChevronRight, FileText, Copy, Download, Check
} from "lucide-react";
import Link from "next/link";

const FORMATS = [
  { id: "hackerone", name: "HackerOne", icon: "🏴‍☠️", desc: "Bug bounty submission format" },
  { id: "bugcrowd", name: "Bugcrowd", icon: "🐛", desc: "Bugcrowd submission format" },
  { id: "intigriti", name: "Intigriti", icon: "🛡️", desc: "Intigriti report format" },
  { id: "cve", name: "CVE Advisory", icon: "📋", desc: "CVE-style advisory" },
  { id: "executive", name: "Executive Summary", icon: "👔", desc: "Non-technical summary" },
  { id: "technical", name: "Technical Writeup", icon: "🔬", desc: "Full technical analysis" },
];

const SAMPLE_REPORT = `## Summary
SQL Injection (Error-based) via 'id' parameter

## Severity
**CRITICAL** (CVSS: 9.8)
CVSS Vector: \`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\`

## Description
The \`id\` parameter in the /api/users endpoint is vulnerable to error-based SQL injection.
User input is directly concatenated into the SQL query without parameterization.

## Steps to Reproduce
1. Navigate to \`https://target.com/api/users?id=1\`
2. Insert the following payload in the \`id\` field:
   \`\`\`
   1' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--
   \`\`\`
3. Submit the request and observe the error response
4. The database table name is leaked in the error message

## Supporting Material/References
- CWE: CWE-89 - SQL Injection
- OWASP: A03:2021-Injection

## Impact
An attacker could extract, modify, or delete all data in the database,
compromising user credentials, payment information, and business data.

## Remediation
Use parameterized queries (prepared statements). Never concatenate user input into SQL.
Implement an ORM layer with input validation.`;

export default function ReportBuilderPage() {
  const [selectedFormat, setSelectedFormat] = useState("hackerone");
  const [report, setReport] = useState(SAMPLE_REPORT);
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(report);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

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
          <FileText className="w-5 h-5 text-green-400" />
          <span className="text-lg font-semibold">Report Builder</span>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="mb-6">
          <h2 className="text-3xl font-bold gradient-text mb-2">Report Builder</h2>
          <p className="text-muted-foreground">
            AI-powered report generation for all major bug bounty platforms.
          </p>
        </motion.div>

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Format selector */}
          <div className="space-y-2">
            <h3 className="text-sm font-medium text-muted-foreground mb-3">Report Format</h3>
            {FORMATS.map((fmt, i) => (
              <motion.button key={fmt.id}
                initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.05 }}
                onClick={() => setSelectedFormat(fmt.id)}
                className={`w-full text-left p-3 rounded-xl border transition-all ${
                  selectedFormat === fmt.id
                    ? "bg-primary/10 border-primary/30 text-foreground"
                    : "bg-card/50 border-white/5 text-muted-foreground hover:border-white/10"
                }`}>
                <div className="flex items-center gap-3">
                  <span className="text-lg">{fmt.icon}</span>
                  <div>
                    <p className="text-sm font-medium">{fmt.name}</p>
                    <p className="text-xs text-muted-foreground">{fmt.desc}</p>
                  </div>
                </div>
              </motion.button>
            ))}
          </div>

          {/* Report preview */}
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
            transition={{ delay: 0.3 }} className="lg:col-span-3">
            <div className="glass-card overflow-hidden">
              <div className="flex items-center justify-between p-4 border-b border-white/5">
                <div className="flex items-center gap-2">
                  <FileText className="w-4 h-4 text-green-400" />
                  <span className="text-sm font-medium">Generated Report — {
                    FORMATS.find(f => f.id === selectedFormat)?.name
                  }</span>
                </div>
                <div className="flex gap-2">
                  <button onClick={handleCopy}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-secondary rounded-lg text-xs hover:text-foreground transition-colors">
                    {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                    {copied ? "Copied!" : "Copy"}
                  </button>
                  <button className="flex items-center gap-1.5 px-3 py-1.5 bg-primary/10 text-primary rounded-lg text-xs hover:bg-primary/20 transition-colors">
                    <Download className="w-3.5 h-3.5" /> Export PDF
                  </button>
                </div>
              </div>
              <div className="p-6 max-h-[70vh] overflow-y-auto">
                <pre className="whitespace-pre-wrap text-sm leading-relaxed font-sans text-muted-foreground">
                  {report}
                </pre>
              </div>
            </div>
          </motion.div>
        </div>
      </main>
    </div>
  );
}
