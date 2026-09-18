
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type TrustGrade = "A" | "B" | "C" | "D" | "F" | "U";

export interface ScanCoverage {
  mode: "static-heuristic";
  status: "sufficient" | "limited" | "none";
  reasons: string[];
  limitations: string[];
  discoveredFiles: number;
  analyzedFiles: { path: string; scope: "code" | "data"; bytes: number; nonEmpty: boolean; ruleIds: string[] }[];
  unsupportedSourceFiles: string[];
  excludedFiles: { path: string; reason: string }[];
  readErrors: { path: string; operation: "read" | "walk"; code: string }[];
  truncation: { path: string; reason: "max-files" | "max-depth" | "max-file-bytes" }[];
  limits: { maxFiles: number; maxDepth: number; maxFileBytes: number };
}
export type CapabilityType = 
  | "mcp-server" 
  | "agent-skill" 
  | "claude-config" 
  | "openclaw-plugin" 
  | "generic-agent" 
  | "langgraph-agent" 
  | "unknown";

export interface ScanTarget {
  input: string;
  type: "local" | "github" | "npm";
  resolvedPath: string;
  name?: string;
  version?: string;
  url?: string;
}

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  category: "security" | "permissions" | "provenance" | "reliability" | "compliance";
  file?: string;
  line?: number;
  column?: number;
  rule: string;
  remediation: string;
  cwe?: string;
  owaspCode?: string;
  evidence?: string;
}

export interface NetworkPermission {
  type: "outbound" | "inbound";
  host?: string;
  protocol?: string;
}

export interface FilesystemPermission {
  type: "read" | "write" | "delete" | "execute";
  path: string;
}

export interface PermissionManifest {
  network: NetworkPermission[];
  filesystem: FilesystemPermission[];
  shell: boolean;
  shellCommands: string[];
  secrets: string[];
  envVars: string[];
  externalServices: string[];
  humanApprovalRequired: string[];
  canSpawnProcesses: boolean;
  canAccessDB: boolean;
  canSendEmail: boolean;
  canAccessBrowser: boolean;
  canModifyFiles: boolean;
  canDeleteFiles: boolean;
  canMakeHTTPRequests: boolean;
  estimatedScope: "minimal" | "moderate" | "broad" | "excessive";
}

export interface DependencyInfo {
  name: string;
  version: string;
  license?: string;
  vulnerabilities: {
    id: string;
    severity: Severity;
    title: string;
    url?: string;
  }[];
}

export interface ProvenanceInfo {
  signed: boolean;
  signer?: string;
  buildReproducible: boolean;
  hasLockfile: boolean;
  hasSBOM: boolean;
  hasLicense: boolean;
  license?: string;
  hasSecurityPolicy: boolean;
  hasChangelog: boolean;
  maintainersCount?: number;
  lastPublished?: string;
  repositoryUrl?: string;
  isVerified: boolean;
}

export interface TrustScoreBreakdown {
  security: number;      // 0-100
  permissions: number;   // 0-100
  provenance: number;    // 0-100
  reliability: number;   // 0-100
  stability: number;     // 0-100
}

export type TrustScore = {
  status: "graded";
  overall: number;
  grade: Exclude<TrustGrade, "U">;
  breakdown: TrustScoreBreakdown;
  confidence: "low" | "medium" | "high";
  rationale: string;
} | {
  status: "ungraded";
  overall: null;
  grade: "U";
  breakdown: null;
  confidence: "low";
  rationale: string;
};

export interface TrustCard {
  schema: "opentrustbench/trust-card/v2";
  generatedAt: string;
  opentrustbenchVersion: string;
  subject: {
    type: CapabilityType;
    name: string;
    version?: string;
    description?: string;
    repository?: string;
    language?: string;
  };
  provenance: ProvenanceInfo;
  permissions: PermissionManifest;
  security: {
    findings: Finding[];
    findingsBySeverity: Record<Severity, number>;
    totalFindings: number;
    criticalCount: number;
    highCount: number;
  };
  dependencies: {
    total: number;
    vulnerable: number;
    critical: number;
    list: DependencyInfo[];
  };
  trustScore: TrustScore;
  coverage: ScanCoverage;
  compatibility: string[];
  tags: string[];
}

export interface AttackTestResult {
  id: string;
  name: string;
  category: string;
  owaspCode: string;
  status: "pass" | "fail" | "warn";
  severity: Severity;
  details: string;
  evidence?: string;
  remediation?: string;
}

export interface AttackReport {
  targetName: string;
  timestamp: string;
  mode: "static-heuristic" | "dynamic";
  disclaimer?: string;
  testsRun: number;
  passed: number;
  failed: number;
  warn: number;
  resilienceScore: number;
  results: AttackTestResult[];
}

export interface WorkflowTestStep {
  name: string;
  input: string;
  expectedOutcome?: string;
  expectedTools?: string[];
  forbiddenTools?: string[];
  maxCostUsd?: number;
  maxDurationSec?: number;
  requiredPolicies?: string[];
}

export interface WorkflowTestCase {
  name: string;
  description?: string;
  steps: WorkflowTestStep[];
}

export interface WorkflowSuite {
  workflow: string;
  targetAgent: string;
  version?: string;
  tests: WorkflowTestCase[];
}

export interface WorkflowEvalResult {
  workflow: string;
  targetAgent: string;
  timestamp: string;
  mode: "simulated" | "executed";
  notice?: string;
  totalTests: number;
  passedTests: number;
  failedTests: number;
  successRate: number;
  totalCostUsd: number;
  avgDurationSec: number;
  regressions: string[];
  stepResults: {
    testName: string;
    stepName: string;
    status: "pass" | "fail" | "simulated";
    actualOutcome: string;
    durationSec: number;
    costUsd: number;
    policyViolations: string[];
  }[];
}

export interface ScanOptions {
  failOn?: Severity;
  output?: "terminal" | "json" | "sarif" | "markdown";
  outputFile?: string;
  verbose?: boolean;
}
