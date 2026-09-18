#!/usr/bin/env node
// CI smoke checks: run the demo commands end-to-end and assert the outputs that
// define correctness (vulnerable fixture must grade D/F; secure fixture must not).
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cli = path.join(root, "packages", "cli", "dist", "index.js");

function run(args) {
  try {
    execFileSync("node", [cli, ...args], { cwd: root, stdio: "pipe" });
  } catch (err) {
    if (err.status !== 2) throw err;
    // Exit code 2 = insufficient coverage (artifacts still written)
  }
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(path.join(root, file), "utf8"));
}

function fail(msg) {
  console.error(`FAIL: ${msg}`);
  process.exit(1);
}

run(["scan", "examples/vulnerable-mcp-server"]);
const vuln = readJson("trust-card.json");
if (!["D", "F"].includes(vuln.trustScore.grade)) {
  fail(`vulnerable fixture graded ${vuln.trustScore.grade}, expected D or F`);
}
if (vuln.security.criticalCount < 1) {
  fail("vulnerable fixture has no critical findings");
}
console.log(`ok: vulnerable fixture grade ${vuln.trustScore.grade} (${vuln.trustScore.overall}/100)`);

const sarif = readJson("opentrustbench-report.sarif");
if (sarif.version !== "2.1.0" || !sarif.runs?.[0]?.results?.length) {
  fail("SARIF report missing or malformed");
}
console.log(`ok: SARIF report valid (${sarif.runs[0].results.length} results)`);

run(["scan", "examples/secure-agent-skill"]);
const secure = readJson("trust-card.json");
if (secure.trustScore.grade !== "U") {
  fail(`secure fixture (docs-only) graded ${secure.trustScore.grade}, expected U (ungraded — no executable code)`);
}
if (secure.security.criticalCount !== 0) {
  fail(`secure fixture has ${secure.security.criticalCount} critical findings`);
}
if (secure.trustScore.status !== "ungraded") {
  fail(`secure fixture status ${secure.trustScore.status}, expected ungraded`);
}
if (secure.trustScore.overall !== null) {
  fail(`secure fixture overall score ${secure.trustScore.overall}, expected null for ungraded`);
}
console.log(`ok: secure fixture grade ${secure.trustScore.grade} (ungraded, docs-only skill — ${secure.coverage.analyzedFiles.length} analyzed / ${secure.coverage.discoveredFiles} discovered files)`);

run(["attack", "examples/vulnerable-mcp-server"]);
const attack = readJson("opentrustbench-attack-report.json");
if (attack.mode !== "static-heuristic") {
  fail("attack report must declare static-heuristic mode");
}
if (!attack.disclaimer) {
  fail("attack report must carry the static-heuristic disclaimer");
}
if (attack.failed < 2) {
  fail(`expected >=2 failed attack heuristics on vulnerable fixture, got ${attack.failed}`);
}
console.log(`ok: attack analysis mode=${attack.mode}, failed=${attack.failed}, resilience=${attack.resilienceScore}`);

run(["eval", "examples/sample-workflow.yaml"]);
console.log("ok: eval lab ran in simulation mode");

console.log("\nAll demo smoke checks passed.");
