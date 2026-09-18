#!/usr/bin/env node
// Seed-registry sweep: shallow-clone popular public MCP servers into /tmp,
// scan each with the local OpenTrustBench CLI, and record grade/score/counts.
// - Resumable: skips names already present in results.json
// - Never writes into the repo; all work happens under /tmp/at-sweep
// - Usage: node scripts/seed-registry.mjs [maxScans]
import { execFileSync, execSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { scanTarget as scanTargetCore, validateScanCard } from "./build-reports.mjs";
import fs from "node:fs";
import path from "node:path";

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const CLI = path.join(ROOT, "packages", "cli", "dist", "index.js");
const WORK = "/tmp/at-sweep";
const CLONES = path.join(WORK, "clones");
const OUT = path.join(WORK, "out");
const RESULTS = path.join(WORK, "results.json");
const MAX = Number(process.argv[2] || 50);

// Standalone repos (verified via `git ls-remote` before cloning; misses skipped).
const STANDALONE = [
  "github/github-mcp-server",
  "microsoft/playwright-mcp",
  "getsentry/sentry-mcp",
  "stripe/agent-toolkit",
  "mongodb-js/mongodb-mcp-server",
  "grafana/mcp-grafana",
  "elastic/mcp-server-elasticsearch",
  "supabase-community/supabase-mcp",
  "ClickHouse/mcp-clickhouse",
  "hashicorp/terraform-mcp-server",
  "JetBrains/mcp-proxy",
  "exa-labs/exa-mcp-server",
  "mendableai/firecrawl-mcp-server",
  "tavily-ai/tavily-mcp",
  "upstash/context7",
  "browserbase/mcp-server-browserbase",
  "e2b-dev/mcp-server",
  "qdrant/mcp-server-qdrant",
  "sooperset/mcp-atlassian",
  "korotovsky/slack-mcp-server",
  "ahujasid/blender-mcp",
  "Flux159/mcp-server-kubernetes",
  "framelink/figma-mcp-server",
  "makenotion/notion-mcp-server",
  "apify/actors-mcp-server",
  "neondatabase/mcp-server-neon",
  "jlowin/fastmcp",
  "modelcontextprotocol/typescript-sdk",
  "modelcontextprotocol/python-sdk",
  "Shopify/dev-mcp",
  "GongRzhe/Gmail-MCP-Server",
  "wong2/mcp-cli",
  "redis/mcp-redis",
  "cloudflare/mcp-server-cloudflare",
  "motherduckdb/mcp-server-motherduck",
  "vercel/mcp",
  "box/mcp-server-box",
  "pinecone-io/pinecone-mcp",
  "weaviate/mcp-server",
  "AirbyteHQ/mcp-server-airbyte",
  "PrefectHQ/prefect-mcp-server",
  "modelcontextprotocol/csharp-sdk",
  "modelcontextprotocol/java-sdk",
  "modelcontextprotocol/go-sdk",
  "modelcontextprotocol/kotlin-sdk",
  "modelcontextprotocol/registry",
  "modelcontextprotocol/inspector",
  "langchain-ai/langchain-mcp-adapters",
  "mcp-use/mcp-use",
  "idosal/gitmcp",
  "sparfenyuk/mcp-proxy",
  "figma/figma-developer-mcp",
  "manusa/kubernetes-mcp-server",
  "zereight/mcp-gitlab",
  "isaacphi/mcp-gdrive",
  "taazkareem/clickup-mcp-server",
  "StarRocks/mcp-server-starrocks",
  "cloudflare/workers-mcp",
  "anthropics/mcpb",
  "DataDog/datadog-mcp",
  "tursodatabase/mcp-server-turso",
  "meilisearch/mcp-server-meilisearch",
  "typesense/mcp-server-typesense",
  "milvus-io/mcp-server-milvus",
  "opensearch-project/mcp",
  "surrealdb/mcp-server-surrealdb",
  "questdb/mcp-server-questdb",
  "influxdata/mcp-server",
  "nspady/google-calendar-mcp",
  "PagerDuty/mcp-server",
  "tailscale/mcp",
  "docker/mcp-gateway",
  "Azure/mcp",
  "pulumi/mcp-server",
  "ansible/mcp",
  "hashicorp/vault-mcp-server",
  "tektoncd/mcp",
  "jenkinsci/mcp-server",
  "composiohq/composio",
  "sourcegraph/mcp-server-sourcegraph",
  "linear/linear-mcp-server"
];

// Subdirectories of the modelcontextprotocol/servers monorepo (checked post-clone).
const MONOREPO = "modelcontextprotocol/servers";
const MONO_SUBDIRS = [
  "filesystem", "fetch", "git", "github", "memory", "time",
  "brave-search", "google-maps", "slack", "postgres", "sqlite",
  "everart", "sequentialthinking", "puppeteer", "everything", "gdrive"
];

function sh(cmd, opts = {}) {
  return execSync(cmd, { stdio: "pipe", encoding: "utf8", timeout: 120000, ...opts }).trim();
}

function repoExists(repo) {
  try {
    sh(`git ls-remote https://github.com/${repo}.git HEAD`);
    return true;
  } catch {
    return false;
  }
}

function clone(repo, dest) {
  fs.rmSync(dest, { recursive: true, force: true });
  sh(`git clone --depth 1 --quiet https://github.com/${repo}.git "${dest}"`);
}

export function seedResult(name, card) {
  return {
    name,
    grade: card.trustScore.grade,
    overall: card.trustScore.overall,
    totalFindings: card.security.totalFindings,
    critical: card.security.criticalCount,
    high: card.security.highCount,
    scope: card.permissions.estimatedScope,
    type: card.subject.type
  };
}

export function scanTarget(name, targetPath) {
  const outDir = path.join(OUT, name.replace(/[^a-zA-Z0-9_-]/g, "_"));
  const card = scanTargetCore(targetPath, outDir);
  validateScanCard(card, card.trustScore.grade === "U" ? 2 : 0);
  return seedResult(name, card);
}

export function main() {
  fs.mkdirSync(CLONES, { recursive: true });
  fs.mkdirSync(OUT, { recursive: true });
  let results = [];
  try { results = JSON.parse(fs.readFileSync(RESULTS, "utf8")); } catch {}
  const done = new Set(results.map(r => r.name));
  const save = () => fs.writeFileSync(RESULTS, JSON.stringify(results, null, 2));

  const need = () => MAX - results.length;

  // 1. Monorepo subdirs (one clone).
  if (need() > 0) {
    const monoDir = path.join(CLONES, "monorepo-servers");
    try {
      if (!fs.existsSync(path.join(monoDir, ".git"))) {
        console.log("cloning " + MONOREPO + " ...");
        clone(MONOREPO, monoDir);
      }
      for (const sub of MONO_SUBDIRS) {
        if (need() <= 0) break;
        const name = `mcp-${sub}`;
        if (done.has(name)) continue;
        const target = path.join(monoDir, "src", sub);
        if (!fs.existsSync(target)) { console.log(`SKIP ${name} (no src/${sub})`); continue; }
        try {
          const r = scanTarget(name, target);
          results.push(r); done.add(name); save();
          console.log(`OK ${name}: ${r.grade} ${r.overall === null ? "ungraded" : r.overall} findings=${r.totalFindings} crit=${r.critical} scope=${r.scope}`);
        } catch (e) {
          console.log(`FAIL ${name}: ${String(e.message).split("\n")[0]}`);
        }
      }
    } catch (e) {
      console.log(`monorepo failed: ${String(e.message).split("\n")[0]}`);
    }
  }

  // 2. Standalone repos.
  for (const repo of STANDALONE) {
    if (need() <= 0) break;
    const name = repo.replace("/", "__");
    if (done.has(name)) continue;
    if (!repoExists(repo)) { console.log(`SKIP ${repo} (not found)`); continue; }
    const dest = path.join(CLONES, name.replace(/[^a-zA-Z0-9_-]/g, "_"));
    try {
      clone(repo, dest);
      const r = scanTarget(name, dest);
      results.push({ ...r, repo }); done.add(name); save();
      console.log(`OK ${repo}: ${r.grade} ${r.overall === null ? "ungraded" : r.overall} findings=${r.totalFindings} crit=${r.critical} scope=${r.scope}`);
    } catch (e) {
      console.log(`FAIL ${repo}: ${String(e.message).split("\n")[0]}`);
    } finally {
      fs.rmSync(dest, { recursive: true, force: true }); // keep /tmp small
    }
  }

  if (results.length < MAX) {
    console.error(`Seed sweep incomplete: ${results.length}/${MAX} (see FAIL/SKIP lines above)`);
    process.exitCode = 1;
  } else {
    console.log(`\nDone: ${results.length}/${MAX} servers scanned. Results: ${RESULTS}`);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
