import type { TrustCard, Finding, PermissionManifest, ProvenanceInfo, TrustScore, CapabilityType, Severity, DependencyInfo, ScanCoverage } from "../types/index.js";
import { inferCompatibility } from "./compatibility.js";
import { computeTrustScore } from "./scorer.js";
import { missingCoverage } from "../analysis/static-analyzer.js";

export function buildTrustCard(options: {
  capabilityType: CapabilityType;
  name: string;
  version?: string;
  description?: string;
  repository?: string;
  language?: string;
  findings: Finding[];
  permissions: PermissionManifest;
  provenance: ProvenanceInfo;
  trustScore: TrustScore;
  dependencies?: DependencyInfo[];
  coverage?: ScanCoverage;
}): TrustCard {
  const coverage = options.coverage ?? missingCoverage();
  const trustScore = computeTrustScore(options.findings, options.permissions, options.provenance, coverage);
  const findingsBySeverity: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };

  for (const f of options.findings) {
    findingsBySeverity[f.severity]++;
  }

  const tags: string[] = [options.capabilityType];
  if (options.permissions.shell) tags.push("shell-access");
  if (options.permissions.canMakeHTTPRequests) tags.push("network-egress");
  if (options.permissions.canAccessBrowser) tags.push("browser-automation");
  if (options.permissions.humanApprovalRequired.length > 0) tags.push("human-in-loop");
  if (trustScore.grade === "A") tags.push("grade-a");

  const depList = options.dependencies ?? [];
  const vulnerableDeps = depList.filter(d => d.vulnerabilities.length > 0);

  return {
    schema: "opentrustbench/trust-card/v2",
    generatedAt: new Date().toISOString(),
    opentrustbenchVersion: "0.1.3",
    subject: {
      type: options.capabilityType,
      name: options.name,
      version: options.version || "0.1.3",
      description: options.description || "",
      repository: options.repository,
      language: options.language
    },
    provenance: options.provenance,
    permissions: options.permissions,
    security: {
      findings: options.findings,
      findingsBySeverity,
      totalFindings: options.findings.length,
      criticalCount: findingsBySeverity.critical,
      highCount: findingsBySeverity.high
    },
    dependencies: {
      total: depList.length,
      vulnerable: vulnerableDeps.length,
      critical: vulnerableDeps.filter(d => d.vulnerabilities.some(v => v.severity === "critical")).length,
      list: depList
    },
    trustScore,
    coverage,
    compatibility: inferCompatibility(options.capabilityType),
    tags
  };
}
