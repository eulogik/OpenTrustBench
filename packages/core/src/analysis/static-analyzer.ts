import fs from "node:fs";
import path from "node:path";
import type { Finding, Severity, ScanCoverage } from "../types/index.js";
import { inventoryFiles } from "../util/fs-walk.js";
import { stableFindingId } from "../util/finding-id.js";

interface RuleDef {
  rule: string;
  title: string;
  severity: Severity;
  category: Finding["category"];
  owaspCode: string;
  cwe: string;
  description: string;
  remediation: string;
  /** "code" (default) = source files only; "codeAndData" = also JSON/YAML. Markdown docs are never pattern-scanned. */
  scope?: "code" | "codeAndData";
  pattern?: RegExp | RegExp[];
  validator?: (content: string, filePath: string) => { match: boolean; line?: number; evidence?: string };
}

/** Source extensions eligible for code-pattern rules. */
const CODE_EXTS = new Set([".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs", ".py"]);
/** Secret scanning additionally covers structured data files (never prose docs). */
const SECRET_EXTS = new Set([...CODE_EXTS, ".json", ".yaml", ".yml"]);

/**
 * Lines shaped like the scanner's own rule DSL (`rule:`, `title:`, `pattern:`,
 * `remediation:`, … keys whose string values can mention e.g. `eval()`) are
 * meta, not target code — never flag them. Deliberately NOT based on rule-ID
 * substrings, so real findings in files that merely mention a rule ID in a
 * comment are still reported.
 */
const RULE_DSL_KEY = /^(?:rule|title|severity|category|owaspCode|cwe|description|remediation|pattern|scope)\s*:/;
function isRuleMetaLine(trimmed: string): boolean {
  return RULE_DSL_KEY.test(trimmed);
}

// owaspCode references the canonical OWASP lists:
// LLM Top 10 2025 (LLM01-LLM10) and Top 10 for Agentic Applications (ASI01-ASI10,
// published 2025-12-09). e.g. ASI05 = Unexpected Code Execution, ASI09 = Human-Agent
// Trust Exploitation, LLM02 = Sensitive Information Disclosure, LLM06 = Excessive Agency.

const RULES: RuleDef[] = [
  {
    rule: "AT-SEC-001",
    title: "Direct Prompt Concatenation (Injection Vulnerability)",
    severity: "critical",
    category: "security",
    owaspCode: "LLM01",
    cwe: "CWE-20",
    description: "User or tool input is directly concatenated into prompt templates without sanitization or boundary delimitation.",
    remediation: "Use parameterized messages, structured schema validation (Zod), and clear boundary delimiters.",
    pattern: [
      /(?:prompt|systemPrompt|userPrompt)\s*[+]=?\s*(?:req|request|input|userInput|query|params|args\.[a-zA-Z0-9_]+)/i,
      /(?:prompt|systemPrompt|userPrompt)\s*=\s*["'`][^"'`]*["'`]\s*\+\s*(?:args\.|req\.|request\.|input\b|userInput\b|params\b)/i
    ]
  },
  {
    rule: "AT-SEC-002",
    title: "Hardcoded Credential or API Secret",
    severity: "critical",
    category: "security",
    owaspCode: "LLM02",
    cwe: "CWE-798",
    description: "A hardcoded API key, private token, or secret was identified in source code.",
    remediation: "Move credentials to secure environment variables or a key vault. Never commit API keys.",
    scope: "codeAndData",
    pattern: /(?:api_?key|secret|password|bearer|auth_?token)[a-zA-Z0-9_]*\s*=\s*["'][a-zA-Z0-9_\-.]{20,}["']/i
  },
  {
    rule: "AT-SEC-003",
    title: "Unbounded Dynamic Shell Execution",
    severity: "critical",
    category: "security",
    owaspCode: "ASI02",
    cwe: "CWE-78",
    description: "The agent executes shell commands directly from dynamic parameters, allowing remote arbitrary command injection.",
    remediation: "Strictly restrict shell execution to an immutable allowlist of binary commands with explicit argument arrays, or execute inside microVM sandboxes.",
    pattern: /(?:exec|execSync|spawn|child_process\.exec|os\.system|subprocess\.Popen)\s*\(\s*[`"']?\s*(?:req|params|input|cmd|command|args)/i
  },
  {
    rule: "AT-SEC-004",
    title: "eval() / Function Constructor Invocation",
    severity: "critical",
    category: "security",
    owaspCode: "ASI05",
    cwe: "CWE-94",
    description: "Dangerous eval() or Function constructor used to dynamically execute code strings from LLM or external sources.",
    remediation: "Eliminate eval(). Use safe AST parsers or isolated sandboxes (e.g. E2B Firecracker microVMs).",
    pattern: /\beval\s*\(|new\s+Function\s*\(/
  },
  {
    rule: "AT-SEC-005",
    title: "Unrestricted Recursive File Deletion / Modification",
    severity: "high",
    category: "permissions",
    owaspCode: "ASI02",
    cwe: "CWE-732",
    description: "Capability can delete or overwrite arbitrary files on the host filesystem without path validation or human confirmation.",
    remediation: "Enforce strict jail/root directories and require explicit human-in-the-loop confirmation before file deletions.",
    pattern: /(?:fs\.rmdirSync|fs\.rmSync|fs\.unlinkSync|rmdir|unlink|shutil\.rmtree)\s*\([^)]*(?:req|input|path|target|args)/i
  },
  {
    rule: "AT-SEC-006",
    title: "Unfiltered SSRF / Arbitrary Network Egress",
    severity: "high",
    category: "permissions",
    owaspCode: "LLM06",
    cwe: "CWE-918",
    description: "Network requests accept arbitrary external URLs from agent or user input without host allowlisting.",
    remediation: "Define an explicit egress domain allowlist and block private IP ranges (127.0.0.1, 10.0.0.0/8, 169.254.169.254).",
    pattern: /(?:fetch|axios\.get|axios\.post|requests\.get|http\.request)\s*\(\s*(?:args\.[a-zA-Z0-9_]+|url|req\.body|input)/i
  },
  {
    rule: "AT-SEC-007",
    title: "Raw Secret Leakage in Debug Logging",
    severity: "medium",
    category: "security",
    owaspCode: "LLM02",
    cwe: "CWE-532",
    description: "Console or file logging dumps raw tokens, authorization headers, or environment objects.",
    remediation: "Implement PII/secret redaction masks before writing to log streams.",
    pattern: /console\.log\([^)]*(?:process\.env|authorization|password|apiKey|api_key|token)/i
  },
  {
    rule: "AT-COMP-001",
    title: "Missing Human-in-the-Loop Gate for Critical Actions",
    severity: "high",
    category: "compliance",
    owaspCode: "ASI09",
    cwe: "CWE-284",
    description: "Irreversible actions (e.g. database wipe, financial transaction, email dispatch) execute autonomously with no approval trigger.",
    remediation: "Mark high-impact tools with approval requirements and verify operator signature before dispatch.",
    validator: (content: string) => {
      // Require an actual call (identifier + paren) so type/field names such as
      // `canSendEmail` do not self-flag. Previously the bare-substring match
      // flagged the scanner's own PermissionManifest type as a finding.
      const call = /\b(transferFunds|sendEmail|dropTable|deleteUser|publishArticle|executeTrade)\s*\(/i.exec(content);
      if (!call) return { match: false };
      const hasApproval = /(?:requireApproval|humanInTheLoop|confirmAction|operatorConsent|humanApprovalRequired)/i.test(content);
      if (!hasApproval) {
        const line = content.slice(0, call.index).split("\n").length;
        return { match: true, line, evidence: `High-impact call ${call[1]}(...) detected without approval validation` };
      }
      return { match: false };
    }
  }
];

export interface AnalysisOptions {
  maxFiles?: number;
  maxDepth?: number;
  maxFileBytes?: number;
}

export function missingCoverage(): ScanCoverage {
  return {
    mode: "static-heuristic", status: "none", reasons: ["Coverage evidence not supplied"],
    limitations: [
      "Coverage describes the files read and regex rules applied, not semantic, runtime, or dependency coverage.",
      "Supported code is JavaScript, TypeScript, and Python; JSON/YAML receive only the credential rule.",
      "Skill instructions and other prose are not code-analyzed; declared controls are not verified enforcement.",
      "Ignored directories, declarations, and non-implementation assets are outside rule scope."
    ],
    discoveredFiles: 0, analyzedFiles: [], unsupportedSourceFiles: [], excludedFiles: [],
    readErrors: [], truncation: [], limits: { maxFiles: 4000, maxDepth: 12, maxFileBytes: 1024 * 1024 }
  };
}

export async function runStaticAnalysis(dirPath: string): Promise<Finding[]> {
  return (await analyzeStaticCoverage(dirPath)).findings;
}

export async function analyzeStaticCoverage(dirPath: string, options: AnalysisOptions = {}) {
  const limits = { maxFiles: options.maxFiles ?? 4000, maxDepth: options.maxDepth ?? 12, maxFileBytes: options.maxFileBytes ?? 1024 * 1024 };
  if (!Number.isSafeInteger(limits.maxFileBytes) || limits.maxFileBytes < 1) throw new Error("Invalid file byte limit");
  const inventory = inventoryFiles(dirPath, limits);
  const coverage: ScanCoverage = {
    ...missingCoverage(), limits, discoveredFiles: inventory.files.length,
    readErrors: inventory.readErrors, truncation: inventory.truncation, excludedFiles: inventory.excludedFiles
  };
  const contents = new Map<string, string>();
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const push = (f: Finding) => {
    if (seen.has(f.id)) return;
    seen.add(f.id);
    findings.push(f);
  };

  const assetExts = new Set([".md", ".txt", ".rst", ".adoc", ".toml", ".ini", ".cfg", ".lock", ".map", ".css", ".scss", ".sass", ".less", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".csv", ".snap", ".sarif"]);
  const metadataNames = new Set([".gitignore", ".gitattributes", ".npmignore", ".npmrc", ".editorconfig", ".dockerignore", ".prettierignore", ".prettierrc", ".nvmrc", ".node-version", ".python-version", ".ds_store"]);
  for (const file of inventory.files) {
    const relPath = path.relative(dirPath, file) || path.basename(file);
    const ext = path.extname(file).toLowerCase();
    const declaration = /\.d\.(?:ts|mts|cts)$/i.test(file);
    const isCode = CODE_EXTS.has(ext) && !declaration;
    if (!SECRET_EXTS.has(ext) || declaration) {
      const basename = path.basename(file).toLowerCase();
      const document = /^(license|licence|notice|authors|changelog|readme)(\.|$)/i.test(basename);
      const unsupported = !declaration && !assetExts.has(ext) && !metadataNames.has(basename) && !document;
      if (unsupported) coverage.unsupportedSourceFiles.push(relPath);
      coverage.excludedFiles.push({ path: relPath, reason: unsupported ? "unsupported-implementation" : declaration ? "type-declaration" : basename === "skill.md" ? "skill-instructions-not-code-analyzed" : "outside-rule-scope" });
      continue;
    }
    let content = "";
    try {
      const stat = fs.lstatSync(file);
      if (!stat.isFile()) {
        coverage.excludedFiles.push({ path: relPath, reason: "non-regular-file" });
        continue;
      }
      if (stat.size > limits.maxFileBytes) {
        coverage.truncation.push({ path: relPath, reason: "max-file-bytes" });
        continue;
      }
      content = fs.readFileSync(file, "utf8");
      const bytes = Buffer.byteLength(content);
      if (bytes > limits.maxFileBytes) {
        coverage.truncation.push({ path: relPath, reason: "max-file-bytes" });
        continue;
      }
      if (content.includes("\0")) {
        coverage.unsupportedSourceFiles.push(relPath);
        coverage.excludedFiles.push({ path: relPath, reason: "binary-content" });
        continue;
      }
      contents.set(file, content);
      coverage.analyzedFiles.push({
        path: relPath, scope: isCode ? "code" : "data", bytes, nonEmpty: content.trim().length > 0,
        ruleIds: RULES.filter(rule => isCode || rule.scope === "codeAndData").map(rule => rule.rule)
      });
    } catch (error) {
      coverage.readErrors.push({ path: relPath, operation: "read", code: (error as NodeJS.ErrnoException).code ?? "UNKNOWN" });
      continue;
    }

    const lines = content.split("\n");

    for (const rule of RULES) {
      const inScope = rule.scope === "codeAndData" ? true : isCode;
      if (!inScope) continue;
      const patterns = rule.pattern ? (Array.isArray(rule.pattern) ? rule.pattern : [rule.pattern]) : [];
      for (const pattern of patterns) {
        lines.forEach((line, index) => {
          const trimmed = line.trim();
          if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*")) return;
          if (isRuleMetaLine(trimmed)) return;

          pattern.lastIndex = 0;
          if (pattern.test(line)) {
            const evidence = trimmed.slice(0, 140);
            push({
              id: stableFindingId(rule.rule, relPath, index + 1, evidence),
              title: rule.title,
              description: rule.description,
              severity: rule.severity,
              category: rule.category,
              file: relPath,
              line: index + 1,
              rule: rule.rule,
              remediation: rule.remediation,
              cwe: rule.cwe,
              owaspCode: rule.owaspCode,
              evidence
            });
          }
        });
      }
      if (rule.validator && isCode) {
        const valRes = rule.validator(content, relPath);
        if (valRes.match) {
          push({
            id: stableFindingId(rule.rule, relPath, valRes.line, valRes.evidence),
            title: rule.title,
            description: rule.description,
            severity: rule.severity,
            category: rule.category,
            file: relPath,
            line: valRes.line,
            rule: rule.rule,
            remediation: rule.remediation,
            cwe: rule.cwe,
            owaspCode: rule.owaspCode,
            evidence: valRes.evidence
          });
        }
      }
    }
  }

  coverage.reasons = [];
  if (!coverage.analyzedFiles.some(f => f.scope === "code" && f.nonEmpty)) coverage.reasons.push("No non-empty supported source analyzed; documentation and data alone provide limited coverage");
  if (coverage.unsupportedSourceFiles.length) coverage.reasons.push("Unsupported source present");
  if (coverage.readErrors.length) coverage.reasons.push("File or directory reads failed");
  if (coverage.truncation.length) coverage.reasons.push("Scan limits reached");
  if (coverage.excludedFiles.some(f => f.reason === "non-regular-file")) coverage.reasons.push("Symlinks or special files were not examined");
  coverage.status = coverage.reasons.length === 0 ? "sufficient" : coverage.discoveredFiles > 0 ? "limited" : "none";
  return { findings, coverage, contents };
}
