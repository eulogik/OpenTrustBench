import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  detectCapability,
  runStaticAnalysis,
  extractPermissions,
  stableFindingId,
  inferCompatibility,
  parseOpenTrustBenchConfig,
  runScan
} from "../index.js";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { analyzeStaticCoverage, computeTrustScore, buildTrustCard, generateMarkdownReport, generateSarif } from "../index.js";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const VULNERABLE_FIXTURE = path.join(REPO_ROOT, "examples", "vulnerable-mcp-server");

function tmpDir(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "otb-integrity-"));
  for (const [name, content] of Object.entries(files)) {
    const full = path.join(dir, name);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content, "utf8");
  }
  return dir;
}

test("finding IDs are deterministic and distinct", () => {
  const a = stableFindingId("AT-SEC-004", "a.ts", 3, "eval(x)");
  const b = stableFindingId("AT-SEC-004", "a.ts", 3, "eval(x)");
  const c = stableFindingId("AT-SEC-004", "a.ts", 4, "eval(x)");
  assert.equal(a, b, "same rule+file+line+evidence must give the same id");
  assert.notEqual(a, c, "different line must give a different id");
  assert.match(a, /^AT-SEC-004-[0-9a-f]{12}$/);
});

test("static analysis IDs are stable across runs (SARIF-safe)", async () => {
  const first = await runStaticAnalysis(VULNERABLE_FIXTURE);
  const second = await runStaticAnalysis(VULNERABLE_FIXTURE);
  const ids = (list: typeof first) => [...new Set(list.map(f => f.id))].sort();
  assert.deepEqual(ids(first), ids(second), "repeat scans must produce identical finding IDs");
});

test("detector finds MCP servers nested in subdirectories", async () => {
  const dir = tmpDir({
    "package.json": JSON.stringify({ name: "nested", version: "1.0.0" }),
    "src/server.ts": `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\nserver.tool("x", {}, async () => ({}));\n`
  });
  try {
    const detection = await detectCapability(dir);
    assert.equal(detection.type, "mcp-server");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("detector reads uppercase SKILL.md (case-sensitive filesystems)", async () => {
  const dir = tmpDir({ "SKILL.md": "# My Cool Skill\n\nDoes things.\n" });
  try {
    const detection = await detectCapability(dir);
    assert.equal(detection.type, "agent-skill");
    assert.equal(detection.name, "My Cool Skill");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("compatibility is inferred per capability, never a universal allowlist", () => {
  assert.deepEqual(inferCompatibility("mcp-server"), ["mcp-host"]);
  assert.deepEqual(inferCompatibility("agent-skill"), ["claude-code", "cursor", "codex"]);
  assert.deepEqual(inferCompatibility("generic-agent"), []);
});

test("runScan cards carry inferred compatibility", async () => {
  const result = await runScan(VULNERABLE_FIXTURE);
  assert.equal(result.detection.type, "mcp-server");
  assert.deepEqual(result.trustCard.compatibility, ["mcp-host"]);
});

test("AT-COMP-001 requires a real call — field names do not self-flag", async () => {
  const dir = tmpDir({
    "flags.ts": "export const canSendEmail = false;\nexport const transferState = 1;\n"
  });
  try {
    const findings = await runStaticAnalysis(dir);
    assert.equal(
      findings.filter(f => f.rule === "AT-COMP-001").length, 0,
      "bare identifiers must not trigger the approval-gate rule"
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("AT-COMP-001 fires on unapproved high-impact calls with a line number", async () => {
  const dir = tmpDir({ "pay.ts": "export function run() {\n  transferFunds(5000);\n}\n" });
  try {
    const findings = await runStaticAnalysis(dir);
    const hit = findings.find(f => f.rule === "AT-COMP-001");
    assert.ok(hit, "transferFunds(...) without approval must fire AT-COMP-001");
    assert.equal(hit.line, 2);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("prose docs are out of scope for code-pattern rules", async () => {
  const dir = tmpDir({
    "notes.md": "# Design notes\n\nWe considered eval(userInput) but rejected it.\nExample key sk-proj-abc123456789012345678901234567890 (do not use).\n"
  });
  try {
    const findings = await runStaticAnalysis(dir);
    assert.equal(findings.length, 0, `docs must not produce code findings, got ${JSON.stringify(findings.map(f => f.rule))}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("scanner rule definitions do not flag themselves", async () => {
  const dir = tmpDir({
    "rules.ts": "pattern: /\\beval\\s*\\(|new\\s+Function\\s*\\(/\nremediation: \"Eliminate eval() fast\"\n"
  });
  try {
    const findings = await runStaticAnalysis(dir);
    assert.equal(findings.length, 0, `rule-definition lines must not self-flag, got ${JSON.stringify(findings.map(f => f.rule))}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("string literals do not confer capabilities", async () => {
  const dir = tmpDir({
    "sample.ts": [
      'const a = "openclaw-shell-exec";',
      'const b = "postgres-mcp-server";',
      "// please resend the report when ready",
      "const note = 'uses eval() for docs';"
    ].join("\n")
  });
  try {
    const perms = await extractPermissions(dir);
    assert.equal(perms.shell, false, "sample string must not flag shell");
    assert.equal(perms.canSpawnProcesses, false);
    assert.equal(perms.canAccessDB, false, "sample string must not flag database");
    assert.equal(perms.canSendEmail, false, "prose must not flag email");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("real calls and imports still confer capabilities", async () => {
  const dir = tmpDir({
    "srv.ts": [
      "import pg from 'pg';",
      "import { chromium } from 'playwright';",
      "export function run(cmd: string) { exec(cmd); }",
      "export function load(url: string) { return fetch(url); }",
      "const key = process.env.API_KEY;"
    ].join("\n")
  });
  try {
    const perms = await extractPermissions(dir);
    assert.equal(perms.shell, true, "exec(cmd) must flag shell");
    assert.equal(perms.canAccessDB, true, "import pg must flag database");
    assert.equal(perms.canAccessBrowser, true, "playwright import must flag browser");
    assert.equal(perms.canMakeHTTPRequests, true, "fetch(url) must flag network");
    assert.ok(perms.secrets.includes("API_KEY"), "process.env.API_KEY must register a secret");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("shipped CLI self-scan has no phantom shell/database flags", async () => {
  const cliDir = path.join(REPO_ROOT, "packages", "cli");
  const perms = await extractPermissions(cliDir);
  assert.equal(perms.shell, false, "CLI sample strings must not flag shell");
  assert.equal(perms.canAccessDB, false, "CLI sample strings must not flag database");
  assert.equal(perms.canSendEmail, false);
});

test("opentrustbench.yaml config parses the keys the scanner reads", () => {
  const cfg = parseOpenTrustBenchConfig([
    "# comment",
    'version: "1.0"',
    'target: "."',
    'failOn: "high"',
    'outputDir: "./trust"',
    "writeFiles: true"
  ].join("\n"));
  assert.equal(cfg.failOn, "high");
  assert.equal(cfg.outputDir, "./trust");
  assert.equal(cfg.writeFiles, true);
});

test("coverage records code and data rule scopes and keeps dist/build implementations", async () => {
  const files = {
    "package.json": JSON.stringify({ name: "dist-only", main: "dist/index.js" }),
    "dist/index.js": "export const ready = true;\n",
    "build/worker.cjs": "module.exports = 1;\n",
    "dist/module.mts": "export const ready: boolean = true;\n",
    "dist/module.cts": "export const ready: boolean = true;\n",
    "dist/index.d.ts": "export declare const ready: boolean;\n",
    "dist/index.d.mts": "export declare const ready: boolean;\n",
    "README.md": "# Package\n",
    ".gitignore": "node_modules\n"
  };
  const dir = tmpDir(files);
  try {
    const scan = await runScan(dir);
    assert.equal(scan.coverage.status, "sufficient");
    assert.equal(scan.trustScore.status, "graded");
    assert.equal(scan.coverage.discoveredFiles, Object.keys(files).length);
    assert.deepEqual(scan.coverage.unsupportedSourceFiles, []);
    assert.equal(scan.coverage.analyzedFiles.length, 5);
    for (const file of scan.coverage.analyzedFiles) {
      assert.equal(file.bytes, Buffer.byteLength(files[file.path as keyof typeof files]));
      assert.equal(file.nonEmpty, true);
      assert.equal(file.ruleIds.length, file.scope === "code" ? 8 : 1);
    }
    assert.deepEqual(scan.trustCard.coverage, scan.coverage);
    assert.equal(scan.trustCard.schema, "opentrustbench/trust-card/v2");
    assert.deepEqual(scan.trustCard.trustScore, scan.trustScore);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("empty, data-only, declaration-only, and unsupported implementations are ungraded", async () => {
  const cases: Record<string, string>[] = [
    {},
    { "README.md": "# Readme" },
    { "package.json": "{}" },
    { "index.js": " \n" },
    { "index.d.ts": "export declare const value: number;" },
    { "main.go": "package main" },
    { "index.js": "export const value = 1;", "main.rs": "fn main() {}" },
    { "index.js": "export const value = 1;", "plugin.unrecognized": "implementation" },
    { "index.js": "export const value = 1;", "plugin.node": "binary" },
    { "index.js": "export const value = 1;", "worker": "implementation" },
    { "index.js": "\0binary" }
  ];
  for (const files of cases) {
    const dir = tmpDir(files);
    try {
      const scan = await runScan(dir);
      assert.equal(scan.trustScore.status, "ungraded", JSON.stringify(files));
      assert.equal(scan.trustScore.grade, "U");
      assert.equal(scan.trustScore.overall, null);
      assert.equal(scan.trustScore.breakdown, null);
      assert.notEqual(scan.coverage.status, "sufficient");
      assert.ok(scan.coverage.reasons.length);
      assert.equal(scan.trustCard.tags.includes("grade-a"), false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("mixed-language coverage preserves actionable findings and incomplete SARIF", async () => {
  const dir = tmpDir({ "dist/index.js": "eval(input);\n", "src/main.go": "package main" });
  try {
    const scan = await runScan(dir);
    assert.equal(scan.trustScore.grade, "U");
    assert.deepEqual(scan.coverage.unsupportedSourceFiles, ["src/main.go"]);
    assert.ok(scan.findings.some(f => f.rule === "AT-SEC-004" && f.file === "dist/index.js"));
    const sarif = JSON.parse(generateSarif(scan.trustCard)).runs[0];
    assert.equal(sarif.invocations[0].executionSuccessful, false);
    assert.equal(sarif.invocations[0].toolExecutionNotifications[0].descriptor.id, "AT-COVERAGE");
    assert.equal(sarif.invocations[0].toolExecutionNotifications[0].level, "error");
    assert.ok(sarif.results.length > 0);
    assert.deepEqual(sarif.properties.coverage, scan.coverage);
    const markdown = generateMarkdownReport(scan.trustCard);
    assert.match(markdown, /\*\*U\*\* \(not scored\)/);
    assert.match(markdown, /src\/main.go/);
    assert.match(markdown, /dist\/index.js: code/);
    assert.match(markdown, /not semantic, runtime, or dependency coverage/);
    assert.doesNotMatch(markdown, /null\/100/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("scan limits withhold grades and report every kind of truncation", async () => {
  const dir = tmpDir({ "a.js": "export const value = 1;", "nested/b.js": "export const next = 2;" });
  try {
    for (const [options, reason] of [
      [{ maxFiles: 1 }, "max-files"],
      [{ maxDepth: 0 }, "max-depth"],
      [{ maxFileBytes: 1 }, "max-file-bytes"]
    ] as const) {
      const scan = await runScan(dir, options);
      assert.equal(scan.trustScore.grade, "U");
      assert.ok(scan.coverage.truncation.some(t => t.reason === reason));
    }
    const { coverage } = await analyzeStaticCoverage(dir, { maxFiles: 2 });
    assert.equal(coverage.status, "sufficient");
    assert.deepEqual(coverage.truncation, []);
    for (const options of [{ maxFiles: 0 }, { maxDepth: -1 }, { maxFileBytes: 0 }]) {
      await assert.rejects(() => analyzeStaticCoverage(dir, options), /Invalid/);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("symlink and missing target coverage cannot silently pass", async () => {
  const dir = tmpDir({ "a.js": "export const value = 1;" });
  try {
    fs.symlinkSync(path.join(dir, "a.js"), path.join(dir, "link.js"));
    const scan = await runScan(dir);
    assert.equal(scan.trustScore.grade, "U");
    assert.ok(scan.coverage.excludedFiles.some(f => f.path === "link.js" && f.reason === "non-regular-file"));
    const missing = await runScan(path.join(dir, "missing"));
    assert.equal(missing.trustScore.grade, "U");
    assert.equal(missing.coverage.status, "none");
    assert.equal(missing.coverage.readErrors[0].operation, "walk");
    assert.equal(missing.coverage.readErrors[0].code, "ENOENT");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("failed source reads are recorded and not counted as analyzed", async t => {
  const dir = tmpDir({ "index.js": "export const value = 1;" });
  const original = fs.readFileSync;
  t.mock.method(fs, "readFileSync", (...args: Parameters<typeof fs.readFileSync>) => {
    if (String(args[0]) === path.join(dir, "index.js")) {
      throw Object.assign(new Error("denied"), { code: "EACCES" });
    }
    return original(...args);
  });
  try {
    const scan = await runScan(dir);
    assert.equal(scan.trustScore.grade, "U");
    assert.deepEqual(scan.coverage.analyzedFiles, []);
    assert.deepEqual(scan.coverage.readErrors, [{ path: "index.js", operation: "read", code: "EACCES" }]);
  } finally {
    t.mock.restoreAll();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("direct scoring and card building fail closed without coverage evidence", async () => {
  const scan = await runScan(VULNERABLE_FIXTURE);
  const score = computeTrustScore([], scan.permissions, scan.provenance);
  assert.equal(score.grade, "U");
  const card = buildTrustCard({
    capabilityType: "mcp-server", name: "missing-coverage", findings: [],
    permissions: scan.permissions, provenance: scan.provenance, trustScore: scan.trustScore
  });
  assert.equal(card.trustScore.grade, "U");
  assert.equal(card.trustScore.overall, null);
  assert.equal(card.coverage.status, "none");
});

test("CLI scan gates and badges fail closed and machine output remains parseable", () => {
  const dir = tmpDir({
    "clean/dist/index.js": "export const value = 1;",
    "mixed/dist/index.js": "export const value = 1;",
    "mixed/main.go": "package main",
    "docs/SKILL.md": "# A Skill\nRead only instructions."
  });
  const cli = path.join(REPO_ROOT, "packages", "cli", "dist", "index.js");
  try {
    for (const [target, exitCode] of [["clean", 0], ["mixed", 2], ["docs", 2]] as const) {
      const result = spawnSync(process.execPath, [cli, "scan", path.join(dir, target), "--format", "json", "--fail-on", "high", "--output-dir", path.join(dir, "reports", target)], { cwd: dir, encoding: "utf8" });
      assert.equal(result.status, exitCode, result.stderr);
      const card = JSON.parse(result.stdout);
      assert.equal(card.trustScore.status, exitCode === 0 ? "graded" : "ungraded");
      if (exitCode !== 0) {
        assert.equal(card.trustScore.grade, "U");
        assert.doesNotMatch(result.stdout + result.stderr, /CI gate passed/);
      }
      const written = JSON.parse(fs.readFileSync(path.join(dir, "reports", target, "trust-card.json"), "utf8"));
      assert.deepEqual(written, card);
      const badge = spawnSync(process.execPath, [cli, "badge", path.join(dir, target)], { cwd: dir, encoding: "utf8" });
      assert.equal(badge.status, exitCode, badge.stderr);
      assert.match(badge.stdout, exitCode === 0 ? /static%20only/ : /U%20\(ungraded\)-lightgrey/);
    }
    const vulnerable = spawnSync(process.execPath, [cli, "scan", VULNERABLE_FIXTURE, "--quiet", "--format", "json", "--fail-on", "high", "--output-dir", path.join(dir, "reports", "vulnerable")], { cwd: dir, encoding: "utf8" });
    assert.equal(vulnerable.status, 1, vulnerable.stderr);
    assert.equal(JSON.parse(vulnerable.stdout).trustScore.grade, "F");
    const incomplete = spawnSync(process.execPath, [cli, "scan", path.join(dir, "mixed"), "--quiet", "--output-dir", path.join(dir, "reports", "no-gate")], { cwd: dir, encoding: "utf8" });
    assert.equal(incomplete.status, 2);
    assert.match(incomplete.stdout, /U \(ungraded; not scored\)/);
    assert.match(incomplete.stdout, /1 unsupported implementation files/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
