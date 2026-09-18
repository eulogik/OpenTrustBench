import type { Finding, PermissionManifest, ProvenanceInfo, TrustScore, TrustGrade, TrustScoreBreakdown, ScanCoverage } from "../types/index.js";
import { missingCoverage } from "../analysis/static-analyzer.js";

export function computeTrustScore(
  findings: Finding[],
  permissions: PermissionManifest,
  provenance: ProvenanceInfo,
  coverage: ScanCoverage = missingCoverage()
): TrustScore {
  if (coverage.status !== "sufficient" || coverage.readErrors.length > 0 || coverage.truncation.length > 0 || coverage.unsupportedSourceFiles.length > 0 || coverage.excludedFiles.some(f => f.reason === "non-regular-file") || !coverage.analyzedFiles.some(f => f.scope === "code" && f.nonEmpty && f.ruleIds.length === 8)) {
    return {
      status: "ungraded", overall: null, grade: "U", breakdown: null, confidence: "low",
      rationale: `Insufficient static coverage: ${coverage.reasons.join("; ") || "incomplete analysis evidence"}. Findings remain actionable; absence of findings is not evidence of safety.`
    };
  }
  let security = 100;
  for (const f of findings) {
    if (f.severity === "critical") security -= 25;
    else if (f.severity === "high") security -= 15;
    else if (f.severity === "medium") security -= 8;
    else if (f.severity === "low") security -= 3;
  }
  security = Math.max(0, Math.min(100, security));

  let perm = 100;
  if (permissions.estimatedScope === "excessive") perm -= 45;
  else if (permissions.estimatedScope === "broad") perm -= 25;
  else if (permissions.estimatedScope === "moderate") perm -= 10;

  if (permissions.shell) perm -= 20;
  if (permissions.canDeleteFiles) perm -= 15;
  if (permissions.canSendEmail && permissions.humanApprovalRequired.length === 0) perm -= 10;
  if (permissions.humanApprovalRequired.length > 0) perm += 15;
  perm = Math.max(0, Math.min(100, perm));

  let prov = 50;
  if (provenance.hasLicense) prov += 15;
  if (provenance.hasLockfile) prov += 15;
  if (provenance.hasSecurityPolicy) prov += 10;
  if (provenance.hasChangelog) prov += 10;
  if (provenance.signed) prov += 20;
  prov = Math.max(0, Math.min(100, prov));

  let rel = 85;
  const relFindings = findings.filter(f => f.category === "reliability" || f.category === "compliance");
  rel -= relFindings.length * 10;
  if (permissions.humanApprovalRequired.length > 0) rel += 10;
  rel = Math.max(0, Math.min(100, rel));

  let stab = 75;
  if (provenance.hasLockfile) stab += 15;
  if (provenance.hasChangelog) stab += 10;
  stab = Math.max(0, Math.min(100, stab));

  const breakdown: TrustScoreBreakdown = {
    security,
    permissions: perm,
    provenance: prov,
    reliability: rel,
    stability: stab
  };

  const overall = Math.round(
    security * 0.35 +
    perm * 0.25 +
    prov * 0.15 +
    rel * 0.15 +
    stab * 0.10
  );

  const grade: TrustGrade = 
    overall >= 90 ? "A" :
    overall >= 75 ? "B" :
    overall >= 60 ? "C" :
    overall >= 40 ? "D" : "F";

  const criticals = findings.filter(f => f.severity === "critical").length;
  const highs = findings.filter(f => f.severity === "high").length;
  
  let rationale = "No critical or high-severity findings; grade reflects permissions and provenance signals.";
  if (criticals > 0 || highs > 0) {
    rationale = `Score constrained by ${criticals} critical and ${highs} high-severity findings.`;
  } else if (permissions.estimatedScope === "broad" || permissions.estimatedScope === "excessive") {
    rationale = `Score constrained by broad permissions (${permissions.estimatedScope} scope).`;
  }

  return {
    status: "graded",
    overall,
    grade,
    breakdown,
    confidence: provenance.isVerified ? "high" : "medium",
    rationale: `${rationale} Limited to the supported static rule scope; not proof of safety.`
  };
}
