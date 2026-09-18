import type { TrustCard } from "../types/index.js";

export function generateMarkdownReport(card: TrustCard): string {
  const { subject, trustScore, security, permissions, provenance } = card;
  const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const ordered = [...security.findings].sort((a, b) => (rank[a.severity] ?? 5) - (rank[b.severity] ?? 5));
  const fixFirst = ordered.filter(f => f.severity === "critical" || f.severity === "high");

  return `# OpenTrustBench Evaluation Report

> **Capability:** \`${subject.name}\` (${subject.type})  
> **Trust Grade:** **${trustScore.grade}** (${trustScore.overall === null ? "not scored" : `${trustScore.overall}/100`})
> **Confidence:** ${trustScore.confidence.toUpperCase()}  
> **Date:** ${card.generatedAt}
>
> Static analysis only (8-rule suite, OWASP-mapped). Not a certification or penetration test.

---

## 🛡️ Trust Score Breakdown

| Category | Score | Status |
|---|---|---|
${trustScore.breakdown ? `| **Security** | ${trustScore.breakdown.security}/100 | Static findings only |
| **Permissions** | ${trustScore.breakdown.permissions}/100 | Scope: ${permissions.estimatedScope} |
| **Provenance** | ${trustScore.breakdown.provenance}/100 | ${provenance.isVerified ? "Signals present" : "Unverified origin"} |
| **Reliability** | ${trustScore.breakdown.reliability}/100 | Heuristic |
| **Stability** | ${trustScore.breakdown.stability}/100 | Lockfile: ${provenance.hasLockfile ? "Yes" : "No"} |` : "| All categories | Not scored | Insufficient coverage |"}

## Coverage

Status: **${card.coverage.status}** (static-heuristic; not runtime or dependency coverage).
${card.coverage.reasons.join("; ")}

- Discovered files: ${card.coverage.discoveredFiles}
- Successfully analyzed: ${card.coverage.analyzedFiles.length} (${card.coverage.analyzedFiles.filter(f => f.scope === "code").length} code)
${card.coverage.analyzedFiles.map(f => `  - ${f.path}: ${f.scope}, ${f.bytes} bytes, rules: ${f.ruleIds.join(", ")}`).join("\n")}
- Unsupported source: ${card.coverage.unsupportedSourceFiles.join(", ") || "none identified"}
- Read errors: ${card.coverage.readErrors.map(e => `${e.path} (${e.operation}: ${e.code})`).join(", ") || "none"}
- Truncation: ${card.coverage.truncation.map(e => `${e.path} (${e.reason})`).join(", ") || "none"}
- Excluded entries: ${card.coverage.excludedFiles.length}
${card.coverage.excludedFiles.map(f => `  - ${f.path}: ${f.reason}`).join("\n")}

${card.coverage.limitations.map(limit => `- ${limit}`).join("\n")}

${trustScore.status === "ungraded" ? "No passing assessment: missing findings do not establish safety. Permission signals below are incomplete observations, not guarantees." : "Grades reflect only the supported static rule scope, not proof of safety."}

**Rationale:** ${trustScore.rationale}

---

## 🎯 Fix this week (${fixFirst.length} critical/high)

${fixFirst.length === 0 ? "_No critical or high-severity findings in scope._" : fixFirst.map(f => `- **[${f.severity.toUpperCase()}] ${f.title}** — \`${f.file || "global"}:${f.line || 1}\` (${f.rule}, ${f.owaspCode}): ${f.remediation}`).join("\n")}

---

## 🚨 All Security Findings (${security.totalFindings} Total)

| Severity | Rule | Title | Location |
|---|---|---|---|
${ordered.map(f => `| **${f.severity.toUpperCase()}** | \`${f.rule}\` | ${f.title} | \`${f.file || "global"}:${f.line || 1}\` |`).join("\n")}

---

## 🔑 Permissions Declared & Detected

- **Shell Execution:** ${permissions.shell ? "Detected (" + permissions.shellCommands.join(", ") + ")" : "Not detected in analyzed content"}
- **Network Egress:** ${permissions.canMakeHTTPRequests ? "Outbound request signals detected" : "Not detected in analyzed content"}
- **Filesystem Modification:** ${permissions.canModifyFiles ? "Write signals detected" : "Not detected in analyzed content"}
- **Filesystem Deletion:** ${permissions.canDeleteFiles ? "Deletion signals detected" : "Not detected in analyzed content"}
- **Human In The Loop:** ${permissions.humanApprovalRequired.length > 0 ? "Approval signals detected, not verified (" + permissions.humanApprovalRequired.join(", ") + ")" : "Not detected in analyzed content"}

---

*Generated automatically by [OpenTrustBench](https://www.opentrustbench.com)*
`;
}
