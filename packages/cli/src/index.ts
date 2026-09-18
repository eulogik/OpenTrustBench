#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import {
  type TrustCard,
  type TrustScore,
  runScan,
  loadOpenTrustBenchConfig,
  runAttackSuite,
  evaluateWorkflow,
  generateSarif,
  generateMarkdownReport,
  resolveScanTarget,
  isSeverity,
  meetsSeverityThreshold
} from "@opentrustbench/core";

const args = process.argv.slice(2);
const command = args[0] || "help";

const USE_COLOR = !!process.stdout.isTTY && !process.env.NO_COLOR && !process.argv.includes("--no-color");
const wrap = (code: string) => (s: string) => USE_COLOR ? `\x1b[${code}m${s}\x1b[0m` : s;
const red = wrap("31");
const green = wrap("32");
const yellow = wrap("33");
const blue = wrap("34");
const magenta = wrap("35");
const cyan = wrap("36");
const bold = wrap("1");
const gray = wrap("90");

function printBanner() {
  if (process.argv.includes("--quiet") || process.argv.includes("--no-banner")) return;
  console.log(cyan(`
  ___               _____            _   ___              _
 / _ \\ _ __  ___ _ |_   _| _ _  _ __| |_| _ ) ___ _ _  __| |_
| (_) | '_ \\/ -_) ' \\| || '_| || (_-<  _| _ \\/ -_) ' \\/ _| ' \\
 \\___/| .__/\\___|_||_|_||_|  \\_,_/__/\\__|___/\\___|_||_\\__|_||_|
      |_|
`));
  console.log(bold(magenta("  The Trust, Reliability, and Evidence Layer for Autonomous AI Agents")) + gray(" (v0.1.3)\n"));
}

function parseArgs(argv: string[]): { target: string; flags: Record<string, string | boolean> } {
  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--fail-on") {
      flags["fail-on"] = argv[++i] ?? "high";
    } else if (argv[i] === "--format") {
      flags["format"] = argv[++i] ?? "terminal";
    } else if (argv[i] === "--output-dir") {
      flags["output-dir"] = argv[++i] ?? ".";
    } else if (argv[i] === "--github" || argv[i] === "--npm" || argv[i] === "--quiet" || argv[i] === "--no-banner" || argv[i] === "--no-color") {
      flags[argv[i].slice(2)] = true;
    } else {
      positional.push(argv[i]);
    }
  }
  return { target: positional[0] || ".", flags };
}

function shouldBanner(flags: Record<string, string | boolean>): boolean {
  return !flags["quiet"] && !flags["no-banner"];
}

async function main() {
  const { target, flags } = parseArgs(args.slice(1));
  switch (command) {
    case "scan":
      await handleScan(target, flags);
      break;
    case "attack":
      await handleAttack(target);
      break;
    case "eval":
      await handleEval(target);
      break;
    case "init":
      await handleInit();
      break;
    case "badge":
      await handleBadge(target, flags);
      break;
    case "registry":
      await handleRegistry();
      break;
    case "help":
    default:
      printBanner();
      printHelp();
      break;
  }
}

async function handleScan(targetPath: string, flags: Record<string, string | boolean> = {}) {
  // opentrustbench.yaml provides defaults; explicit CLI flags always win.
  const cfg = loadOpenTrustBenchConfig(process.cwd());
  const machineOutput = typeof flags["format"] === "string" && flags["format"] !== "terminal";
  if (shouldBanner(flags) && !machineOutput) printBanner();
  const quiet = !!flags["quiet"] || machineOutput;
  const log = (...parts: string[]) => { if (!quiet) console.log(parts.join("")); };

  let scanTarget;
  try {
    scanTarget = await resolveScanTarget(targetPath, flags);
  } catch (err) {
    console.error(red(`Error: ${(err as Error).message}`));
    process.exit(1);
  }
  const absPath = scanTarget.resolvedPath;

  if (!fs.existsSync(absPath)) {
    console.error(red(`Error: Target path does not exist: ${absPath}`));
    process.exit(1);
  }

  if (scanTarget.type === "github") {
    log(gray("[0/5] Cloned ") + bold(String(scanTarget.url)) + gray(branchSuffix(scanTarget.version)));
  } else if (scanTarget.type === "npm") {
    log(gray("[0/5] Fetched npm package ") + bold(String(scanTarget.name)) + gray(scanTarget.version ? `@${scanTarget.version}` : ""));
  }
  log(gray(`[1/5] Inspecting target capability at: `) + bold(absPath));

  const { detection, findings, permissions, provenance, trustScore, dependencies, trustCard } = await runScan(absPath);
  log(gray(`[2/5] Detected capability type: `) + cyan(bold(detection.type)) + gray(` (confidence: ${Math.round(detection.confidence * 100)}%)`));
  log(gray(`[3/5] Executed static security & OWASP rule suite (${findings.length} findings).`));
  log(gray(`[4/5] Extracted permissions and provenance.`));
  log(gray(`[5/5] Trust score: ${scoreLabel(trustScore)}.`));

  const format = typeof flags["format"] === "string" ? flags["format"] : "terminal";
  if (!["terminal", "json", "sarif", "md"].includes(format)) {
    console.error(red(`Error: invalid --format "${format}". Use one of: terminal, json, sarif, md.`));
    process.exit(2);
  }
  if (format === "json") {
    console.log(JSON.stringify(trustCard, null, 2));
  } else if (format === "sarif") {
    console.log(generateSarif(trustCard));
  } else if (format === "md") {
    console.log(generateMarkdownReport(trustCard));
  } else {
    renderTrustCardTerminal(trustCard, quiet);
  }

  const outDir = typeof flags["output-dir"] === "string" ? String(flags["output-dir"]) : (cfg.outputDir ?? ".");
  fs.mkdirSync(outDir, { recursive: true });
  const sarif = generateSarif(trustCard);
  const md = generateMarkdownReport(trustCard);
  const sarifPath = path.join(outDir, "opentrustbench-report.sarif");
  const mdPath = path.join(outDir, "opentrustbench-report.md");
  const cardPath = path.join(outDir, "trust-card.json");
  fs.writeFileSync(sarifPath, sarif, "utf8");
  fs.writeFileSync(mdPath, md, "utf8");
  fs.writeFileSync(cardPath, JSON.stringify(trustCard, null, 2), "utf8");

  log(gray("\nGenerated Artifacts:"));
  log(green(`  ✓ ${sarifPath}`) + gray(" (SARIF 2.1.0 for GitHub Code Scanning)"));
  log(green(`  ✓ ${mdPath}`) + gray(" (Findings grouped by OWASP code)"));
  log(green(`  ✓ ${cardPath}`) + gray(" (Machine-readable Trust Card v2)"));

  if (dependencies.length > 0) {
    log(gray(`\nDependencies: ${dependencies.length} declared | ${dependencies.filter(d => d.vulnerabilities.length > 0).length} with known vulnerabilities`));
  }
  if (!quiet) {
    console.log(gray("\nNext: enforce this in CI:"));
    console.log(cyan(`  opentrustbench scan ${targetPath} --fail-on high --quiet --output-dir ./trust`));
  }

  if (trustScore.status === "ungraded") {
    console.error(yellow(`CI gate incomplete: ${trustScore.rationale}`));
    process.exitCode = 2;
    return;
  }

  const rawFailOn = typeof flags["fail-on"] === "string" ? flags["fail-on"] : cfg.failOn;
  const failOn = rawFailOn;
  if (failOn) {
    if (!isSeverity(failOn)) {
      console.error(red(`Error: invalid --fail-on value "${failOn}". Use one of: info, low, medium, high, critical.`));
      process.exit(2);
    }
    const breaching = findings.filter(f => meetsSeverityThreshold(f.severity, failOn));
    if (breaching.length > 0) {
      console.error(red(`\n✗ CI gate failed: ${breaching.length} finding(s) at or above severity "${failOn}".`));
      process.exit(1);
    }
    console.error(green(`\nCI gate passed: no findings at or above severity "${failOn}" in the supported static rule scope only.`));
  }
}

function branchSuffix(branch?: string): string {
  return branch ? ` (branch: ${branch})` : "";
}

async function handleAttack(targetPath: string) {
  printBanner();
  const absPath = path.resolve(process.cwd(), targetPath);
  console.log(bold(red("⚡ Adversarial Attack Analysis (static-heuristic mode) ⚡")));
  console.log(gray(`Target: ${absPath}
`));

  const { detection, findings, permissions, trustScore } = await runScan(absPath);
  if (trustScore.status === "ungraded") {
    console.error(yellow(trustScore.rationale));
    process.exitCode = 2;
    return;
  }

  const report = await runAttackSuite({
    targetName: detection.name,
    permissions,
    findings
  });

  if (report.disclaimer) {
    console.log(yellow(`ℹ ${report.disclaimer}`));
    console.log("");
  }
  console.log(bold(`Heuristic Checks: ${report.testsRun} | Passed: ${green(String(report.passed))} | Failed: ${red(String(report.failed))} | Warnings: ${yellow(String(report.warn))}`));
  console.log(bold(`Resilience Score (heuristic): ${report.resilienceScore >= 80 ? green(report.resilienceScore + "/100") : red(report.resilienceScore + "/100")}
`));

  for (const res of report.results) {
    const badge = res.status === "pass" ? green("[PASS]") : res.status === "fail" ? red("[FAIL]") : yellow("[WARN]");
    console.log(`${badge} ${bold(res.name)} (${cyan(res.owaspCode)})`);
    console.log(gray(`       ${res.details}`));
    if (res.remediation && res.status !== "pass") {
      console.log(yellow(`       Fix: ${res.remediation}`));
    }
  }

  fs.writeFileSync("opentrustbench-attack-report.json", JSON.stringify(report, null, 2), "utf8");
  console.log(gray("\nSaved attack trace: ") + green("opentrustbench-attack-report.json"));
}
async function handleEval(suitePath: string) {
  printBanner();
  console.log(bold(cyan("🧪 Workflow Reliability & Regression Lab (simulation mode) 🧪\n")));
  const absPath = path.resolve(process.cwd(), suitePath);

  if (!fs.existsSync(absPath)) {
    console.error(red(`Error: Workflow suite file not found: ${absPath}`));
    process.exit(1);
  }

  const evalRes = await evaluateWorkflow(absPath);
  if (evalRes.notice) {
    console.log(yellow(`ℹ ${evalRes.notice}
`));
  }
  console.log(bold(`Workflow: ${cyan(evalRes.workflow)} | Agent: ${cyan(evalRes.targetAgent)}`));
  console.log(bold(`Tests Parsed: ${evalRes.totalTests} | Executed: 0 | Regressions: N/A (runtime execution not yet integrated)
`));

  for (const st of evalRes.stepResults) {
    console.log(`  ${yellow("○")} ${bold(st.testName)} → ${gray(st.stepName)} (${gray("simulated — not executed")})`);
  }

  if (evalRes.stepResults.length === 0) {
    console.log(yellow("\n⚠ No steps found in suite."));
  }
}

async function handleInit() {
  printBanner();
  // Only keys the scanner actually reads (see loadOpenTrustBenchConfig).
  const config = `# OpenTrustBench Configuration (read by \`opentrustbench scan\`; CLI flags override)
version: "1.0"
target: "."
failOn: "high"
outputDir: "."
writeFiles: true
`;
  fs.writeFileSync("opentrustbench.yaml", config, "utf8");
  console.log(green("✓ Initialized opentrustbench.yaml configuration file."));
}

async function handleBadge(targetPath: string, flags: Record<string, string | boolean> = {}) {
  const target = await resolveScanTarget(targetPath, flags);
  const { trustScore: score } = await runScan(target.resolvedPath);
  const color = score.status === "ungraded" ? "lightgrey" : score.grade === "A" ? "brightgreen" : score.grade === "B" ? "green" : score.grade === "C" ? "yellow" : "red";
  const label = score.status === "ungraded" ? "U%20(ungraded)" : `${score.grade}%20(${score.overall}%2F100)%20static%20only`;
  const badgeUrl = `https://img.shields.io/badge/OpenTrustBench-${label}-${color}`;
  if (score.status === "ungraded") {
    console.error(score.rationale);
    process.exitCode = 2;
  }

  console.log(bold("Embeddable Markdown Badge:"));
  console.log(gray("Tip: for a bound grade, embed the per-report badge: [![OpenTrustBench](<site>/r/<slug>.svg)](<site>/r/<slug>.html) — see https://www.opentrustbench.com/r/"));
  console.log(cyan(`[![OpenTrustBench Score](${badgeUrl})](https://www.opentrustbench.com)`));
}

async function handleRegistry() {
  printBanner();
  console.log(bold("🌐 OpenTrustBench Public Verified Capabilities Registry (Preview)\n"));
  console.log(yellow("ℹ Sample data for preview only — not live scan results. Registry backend is not yet deployed.\n"));
  const sampleRegistry = [
    { name: "github-mcp-server", type: "mcp-server", grade: "A", score: 94, downloads: "280K", author: "anthropic" },
    { name: "postgres-mcp-server", type: "mcp-server", grade: "A", score: 91, downloads: "145K", author: "modelcontextprotocol" },
    { name: "web-search-skill", type: "agent-skill", grade: "B", score: 82, downloads: "92K", author: "community" },
    { name: "openclaw-shell-exec", type: "openclaw-plugin", grade: "F", score: 32, downloads: "41K", author: "unverified" }
  ];

  console.log(bold("NAME".padEnd(28) + "TYPE".padEnd(18) + "GRADE".padEnd(10) + "SCORE".padEnd(10) + "PUBLISHER"));
  console.log(gray("─".repeat(78)));
  for (const item of sampleRegistry) {
    const gradeColor = item.grade === "A" ? green(item.grade) : item.grade === "B" ? cyan(item.grade) : red(item.grade);
    console.log(bold(item.name.padEnd(28)) + item.type.padEnd(18) + gradeColor.padEnd(19) + String(item.score).padEnd(10) + gray(item.author));
  }
}

function scoreLabel(score: TrustScore): string {
  return score.status === "ungraded" ? "U (ungraded; not scored)" : `${score.grade} (${score.overall}/100; static only)`;
}

function renderTrustCardTerminal(card: TrustCard, quiet = false) {
  const { subject, trustScore, security, permissions, provenance, coverage } = card;
  console.log(`Coverage: ${coverage.status} | ${coverage.analyzedFiles.filter(f => f.scope === "code").length} code files analyzed | ${coverage.unsupportedSourceFiles.length} unsupported implementation files`);
  console.log(coverage.limitations.join(" "));
  const gradeColor = trustScore.grade === "A" ? green : trustScore.grade === "B" ? cyan : trustScore.grade === "C" ? yellow : red;

  if (quiet) {
    console.log(`Trust Grade: ${scoreLabel(trustScore)} | Findings: ${security.totalFindings} (${security.criticalCount} critical, ${security.highCount} high) | Scope: ${permissions.estimatedScope}`);
    const top = [...security.findings]
      .sort((a: any, b: any) => (a.severity === b.severity ? 0 : a.severity === "critical" ? -1 : 1))
      .slice(0, 5);
    for (const f of top) {
      console.log(`  [${String(f.severity).toUpperCase()}] ${f.title} (${f.file || "global"}:${f.line || 1}) ${f.rule} ${f.owaspCode}`);
    }
    return;
  }

  console.log(bold("\n" + "═".repeat(60)));
  console.log(bold(`  OPENTRUSTBENCH CARD: ${subject.name} `) + gray(`(${subject.type})`));
  console.log("═".repeat(60));
  console.log(`  Trust Grade:       ${trustScore.status === "ungraded" ? gray(bold("U (ungraded)")) : gradeColor(bold(trustScore.grade))} ${trustScore.overall === null ? "" : `(${trustScore.overall}/100)`} `);
  console.log(`  Confidence:        ${bold(trustScore.confidence.toUpperCase())}`);
  if (trustScore.breakdown) {
    console.log(`  Security Score:    ${trustScore.breakdown.security}/100`);
  }
  console.log(`  Permission Scope:  ${bold(permissions.estimatedScope.toUpperCase())}`);
  console.log(`  Provenance:        ${provenance.isVerified ? green("Signals present (license+lockfile+policy)") : yellow("Unverified origin")}`);
  console.log(`  Shell Access:      ${permissions.shell ? red("ENABLED") : green("DISABLED")}`);
  console.log(`  Network Egress:    ${permissions.canMakeHTTPRequests ? yellow("HTTP/HTTPS Outbound") : green("NONE")}`);
  console.log(`  Human In The Loop: ${permissions.humanApprovalRequired.length > 0 ? green("ENFORCED") : gray("NONE")}`);
  if (trustScore.status === "ungraded") {
    console.log(yellow("  ⚠ Insufficient coverage — grade withheld. Findings are incomplete, not evidence of safety."));
  }
  console.log("─".repeat(60));
  console.log(`  Rationale: ${gray(trustScore.rationale)}`);
  console.log("═".repeat(60) + "\n");

  if (security.findings.length > 0) {
    console.log(bold(yellow(`⚠️  Security Findings (${security.totalFindings}) — fix criticals first:`)));
    const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const ordered = [...security.findings].sort((a, b) => (rank[a.severity] ?? 5) - (rank[b.severity] ?? 5));
    for (const f of ordered) {
      const sColor = f.severity === "critical" ? red : f.severity === "high" ? red : yellow;
      console.log(`  ${sColor("[" + f.severity.toUpperCase() + "]")} ${bold(f.title)} ` + gray(`(${f.file || "global"}:${f.line || 1})`));
      console.log(gray(`         Rule: ${f.rule} (${f.owaspCode}) | Remediation: ${f.remediation}`));
    }
  } else {
    console.log(green("  ✓ No security findings in scope of the 8-rule static suite."));
  }
}

function printHelp() {
  console.log(bold("USAGE:"));
  console.log("  opentrustbench scan <path|github-url|owner/repo>    Scan agent capability and generate Trust Card");
  console.log("      --github            Treat <owner/repo> as a GitHub repository (URLs are auto-detected)");
  console.log("      --npm               Treat target as an npm package name (scans the published tarball)");
  console.log("      --fail-on <sev>     Exit 1 when findings meet or exceed severity: info|low|medium|high|critical");
  console.log("      --format <fmt>      Stdout rendering: terminal|json|sarif|md (default: terminal)");
  console.log("      --output-dir <dir>  Where to write trust-card.json + reports (default: ., or opentrustbench.yaml outputDir)");
  console.log("      --quiet             Compact one-line summary, no banner/progress (CI-friendly)");
  console.log("      --no-banner         Suppress the ASCII banner");
  console.log("      --no-color          Disable ANSI colors (also auto-disabled when not a TTY)");
  console.log("  opentrustbench attack <path-or-repo>  Run OWASP-aligned adversarial attack analysis (static-heuristic mode)");
  console.log("  opentrustbench eval <workflow.yaml>   Parse & validate workflow suite (simulation mode)");
  console.log("  opentrustbench badge <path>           Generate embeddable markdown badge");
  console.log("  opentrustbench init                   Scaffold opentrustbench.yaml configuration");
  console.log("  opentrustbench registry               Browse public verified capability registry\n");
}

main().catch(err => {
  console.error(red("Fatal error: " + err.message));
  process.exit(1);
});
