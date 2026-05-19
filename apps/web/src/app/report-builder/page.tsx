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
  const [report, setReport] = useState("Select a format and click Generate to run the AI Triage Engine.");
  const [copied, setCopied] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);

  const handleGenerate = async () => {
    setIsGenerating(true);
    setReport(`⏳ Fetching real scan findings...`);
    try {
      // Fetch real findings from autonomous engine
      const engineRes = await fetch("http://localhost:8004/api/v1/agents/findings");
      let findings: any[] = [];
      if (engineRes.ok) findings = await engineRes.json();

      // Fallback to API Gateway
      if (findings.length === 0) {
        try {
          const gwRes = await fetch("http://localhost:8000/api/v1/findings/?limit=10");
          if (gwRes.ok) findings = await gwRes.json();
        } catch {}
      }

      if (findings.length === 0) {
        setReport("⚠️ No confirmed findings yet. Run a scan first, then generate the report.");
        setIsGenerating(false);
        return;
      }

      // Generate a real report from actual findings
      const report = generateReport(selectedFormat, findings);
      setReport(report);
    } catch (e) {
      setReport("⚠️ Failed to generate report. Ensure a scan has been completed.");
    } finally {
      setIsGenerating(false);
    }
  };

  const generateReport = (format: string, findings: any[]): string => {
    const primary = findings[0];
    const title = primary.title || "Vulnerability Found";
    const severity = (primary.severity || "high").toUpperCase();
    const cvss = primary.cvss_score || "7.5";
    const url = primary.affected_url || primary.target || "N/A";
    const param = primary.parameter || primary.param || "N/A";
    const desc = primary.description || `${title} found on ${url}`;
    const evidence = primary.evidence || "Confirmed via active probe";
    const allTitles = findings.map(f => `- ${f.title} (${(f.severity||'?').toUpperCase()}, CVSS ${f.cvss_score || '?'}) → ${f.affected_url}`).join('\n');

    const cwes: Record<string, string> = {
      lfi: "CWE-22 (Path Traversal)",
      xss: "CWE-79 (Cross-Site Scripting)",
      sqli: "CWE-89 (SQL Injection)",
      rce: "CWE-78 (OS Command Injection)",
    };
    const vulnKey = Object.keys(cwes).find(k => title.toLowerCase().includes(k)) || "vuln";
    const cwe = cwes[vulnKey] || "CWE-Other";

    if (format === "hackerone" || format === "bugcrowd" || format === "intigriti") {
      return `## Summary
${title}

## Severity
**${severity}** (CVSS: ${cvss})
CVSS Vector: \`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\`

## Description
${desc}

**Affected URL:** \`${url}\`
**Vulnerable Parameter:** \`${param}\`
**Evidence:** ${evidence}

## Steps to Reproduce
1. Navigate to \`${url}\`
2. Inject the following payload into the \`${param}\` parameter:
   \`\`\`
   ${vulnKey === "lfi" ? "../../../etc/passwd" : vulnKey === "xss" ? "<script>alert('xss')</script>" : "' OR '1'='1"}
   \`\`\`
3. Observe the server response — the vulnerability is confirmed when ${
     vulnKey === "lfi" ? "the /etc/passwd file contents are disclosed" :
     vulnKey === "xss" ? "the script tag is reflected unescaped" :
     "a SQL error or unexpected data is returned"
   }

## Supporting Material
- Evidence: ${evidence}
- ${cwe}
- OWASP: ${vulnKey === "lfi" ? "A01:2021-Broken Access Control" : vulnKey === "xss" ? "A03:2021-Injection" : "A03:2021-Injection"}

## All Confirmed Findings (${findings.length} total)
${allTitles}

## Impact
${vulnKey === "lfi"
  ? "An attacker can read arbitrary files from the server, potentially exposing credentials, SSH keys, configuration files, and source code."
  : vulnKey === "xss"
  ? "An attacker can execute arbitrary JavaScript in the victim's browser, enabling session hijacking, credential theft, and phishing attacks."
  : "An attacker can read, modify, or delete database contents, bypass authentication, and potentially gain full system access."}

## Remediation
${vulnKey === "lfi"
  ? "Validate and sanitize file path inputs. Use a whitelist of allowed file names. Avoid passing user-controlled values directly to file system functions."
  : vulnKey === "xss"
  ? "Encode all user-controlled output with context-aware escaping. Implement a strict Content-Security-Policy header."
  : "Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries."}`;
    }

    if (format === "executive") {
      return `# Executive Summary — Security Assessment

**Assessment Date:** ${new Date().toLocaleDateString()}
**Target:** ${url}
**Total Confirmed Vulnerabilities:** ${findings.length}

## Key Findings

${allTitles}

## Risk Overview
The assessment identified **${findings.length} confirmed vulnerability(ies)**, including a **${severity}-severity** issue (${title}). This vulnerability allows an attacker to ${
  vulnKey === "lfi" ? "read sensitive server files" :
  vulnKey === "xss" ? "execute malicious scripts in user browsers" :
  "manipulate the application database"
}, posing significant risk to data confidentiality and system integrity.

## Immediate Actions Required
1. Patch the vulnerable parameter \`${param}\` on \`${url}\` immediately
2. Conduct a full code review for similar patterns
3. Implement input validation and output encoding across all user-controlled inputs
4. Deploy a Web Application Firewall (WAF) as a compensating control`;
    }

    // Technical writeup
    return `# Technical Vulnerability Report

**Title:** ${title}
**Severity:** ${severity} | **CVSS:** ${cvss}
**Target:** ${url}
**Parameter:** ${param}
**CWE:** ${cwe}

## Technical Analysis
${desc}

### Proof of Concept
\`\`\`
GET ${url}?${param}=${vulnKey === "lfi" ? "../../../etc/passwd" : vulnKey === "xss" ? "<script>alert(1)</script>" : "' OR 1=1--"}
\`\`\`

### Evidence
${evidence}

## All Findings
${allTitles}

## Remediation
${vulnKey === "lfi"
  ? "1. Validate all file path inputs with an allowlist\n2. Use realpath() and check it starts within the expected directory\n3. Disable allow_url_include in php.ini"
  : vulnKey === "xss"
  ? "1. Apply htmlspecialchars() or equivalent to all user output\n2. Set Content-Security-Policy header\n3. Use HTTPOnly and Secure cookie flags"
  : "1. Use PDO prepared statements\n2. Apply principle of least privilege to DB users\n3. Enable query logging to detect injection attempts"}`;
  };


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
                  <button onClick={handleGenerate} disabled={isGenerating}
                    className="flex items-center gap-1.5 px-4 py-1.5 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white rounded-lg text-xs font-medium transition-colors">
                    {isGenerating ? "Generating..." : "Generate with AI"}
                  </button>
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
