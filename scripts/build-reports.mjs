#!/usr/bin/env node
// Build static per-repo Trust Card report pages + registry index.
// Input: /tmp/at-sweep/results.json (from scripts/seed-registry.mjs).
// Output: web/public/r/<slug>.html, web/public/r/index.html (+ 3 self scans).
// All pages are pure static HTML (no JS, no backend) for GitHub Pages.
// Re-run to refresh: results are a dated snapshot, never live data.
import { execFileSync, execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const THEME_TOGGLE = '<button class="theme-toggle" type="button" aria-label="Toggle theme"><svg class="icon-sun" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="5"/><path d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="icon-moon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg></button>';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const CLI = path.join(ROOT, "packages", "cli", "dist", "index.js");
const CORE_PKG = JSON.parse(fs.readFileSync(path.join(ROOT, "packages", "core", "package.json"), "utf8"));
const SITE = "https://www.opentrustbench.com";
const OUT_DIR = path.join(ROOT, "web", "public", "r");
const WORK = "/tmp/at-reports";
const CLONES = path.join(WORK, "clones");
const OUT = path.join(WORK, "out");
const RESULTS = "/tmp/at-sweep/results.json";
const MONOREPO = "modelcontextprotocol/servers";
const SCAN_DATE = new Date().toISOString().slice(0, 10);

function sh(cmd, opts = {}) {
  return execSync(cmd, { stdio: "pipe", encoding: "utf8", timeout: 180000, ...opts }).trim();
}

function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function slug(name) {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
}

const GRADE_COLOR = { A: "#34d399", B: "#22d3ee", C: "#fbbf24", D: "#fb923c", F: "#fb7185" };
const SEV_COLOR = { critical: "#fb7185", high: "#fb923c", medium: "#fbbf24", low: "#94a3b8", info: "#64748b" };

/**
 * Bound badge for one report: the image and the page ship together, so the
 * grade shown is always the grade evidenced. Embed form:
 * [![OpenTrustBench](<site>/r/<slug>.svg)](<site>/r/<slug>.html)
 */
function badgeSvg(grade, score) {
  const color = GRADE_COLOR[grade] || "#94a3b8";
  const right = `${grade} ${score}`;
  const leftW = 78, rightW = right.length * 7 + 14, W = leftW + rightW;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="20" role="img" aria-label="OpenTrustBench ${grade} ${score}/100"><title>OpenTrustBench ${grade} (${score}/100)</title><rect width="${leftW}" height="20" fill="#0f172a"/><rect x="${leftW}" width="${rightW}" height="20" fill="${color}"/><text x="${leftW / 2}" y="14" text-anchor="middle" fill="#a5f3fc" font-family="Verdana,system-ui,sans-serif" font-size="11" textLength="${leftW - 12}" lengthAdjust="spacingAndGlyphs">opentrustbench</text><text x="${leftW + rightW / 2}" y="14" text-anchor="middle" fill="#020617" font-family="Verdana,system-ui,sans-serif" font-size="11" font-weight="bold" textLength="${rightW - 10}" lengthAdjust="spacingAndGlyphs">${esc(right)}</text></svg>`;
}

function breakdownBars(b) {
  return Object.entries(b).map(([k, v]) => `
    <div style="display:flex;align-items:center;gap:12px;margin:10px 0"><span style="width:130px;color:var(--muted);font-size:14px">${esc(k)}</span>
    <span class="bar" style="flex:1"><span style="width:${Math.max(0, Math.min(100, v))}%"></span></span>
    <span class="mono" style="width:64px;text-align:right">${v}</span></div>`).join("");
}

function findingsTable(findings) {
  if (!findings.length) return "<p>No findings in scope of the 8-rule static suite.</p>";
  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sevColor = { critical: "var(--bad)", high: "var(--orange)", medium: "var(--warn)", low: "var(--muted)", info: "var(--faint)" };
  const rows = [...findings]
    .sort((a, b) => (rank[a.severity] ?? 5) - (rank[b.severity] ?? 5))
    .map(f => `<tr><td><strong style="color:${sevColor[f.severity] || "var(--muted)"}">${esc(String(f.severity).toUpperCase())}</strong></td><td><code>${esc(f.rule)}</code> (${esc(f.owaspCode || "")})</td><td>${esc(f.title)}<br><code class="muted">${esc(f.file || "global")}:${esc(f.line ?? 1)}</code><br><span class="muted">Evidence: </span><code>${esc(f.evidence || "")}</code></td><td>${esc(f.remediation || "")}</td></tr>`)
    .join("");
  return `<table class="data"><thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Remediation</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function reportPage({ slug: sl, title, repoUrl, upstream, card, rankLine }) {
  const g = card.trustScore.grade;
  const gc = { A: "gA", B: "gB", C: "gC", D: "gD", F: "gF" }[g] || "";
  const canon = `${SITE}/r/${sl}.html`;
  const fixN = card.security.findings.filter(f => f.severity === "critical" || f.severity === "high").length;
  const jsonLd = JSON.stringify({ "@context": "https://schema.org", "@graph": [
    { "@type": "Organization", "@id": `${SITE}/#org`, name: "OpenTrustBench", url: `${SITE}/`, sameAs: ["https://github.com/eulogik/OpenTrustBench"] },
    { "@type": "Article",
      headline: `${title} — OpenTrustBench Grade ${g} (${card.trustScore.overall}/100)`,
      description: `Static security scan of ${title}: ${card.security.totalFindings} findings (${card.security.criticalCount} critical), permission scope ${card.permissions.estimatedScope}.`,
      datePublished: SCAN_DATE, dateModified: SCAN_DATE,
      author: { "@id": `${SITE}/#org` }, publisher: { "@id": `${SITE}/#org` },
      mainEntityOfPage: canon }
  ]});
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(title)} — Trust Card (Grade ${esc(g)}) · OpenTrustBench</title>
<meta name="description" content="Static security scan of ${esc(title)}: grade ${esc(g)} (${card.trustScore.overall}/100), ${card.security.totalFindings} findings, scope ${esc(card.permissions.estimatedScope)}. ${esc(rankLine)}.">
<link rel="canonical" href="${canon}">
<meta property="og:type" content="article">
<meta property="og:title" content="${esc(title)} — OpenTrustBench Grade ${esc(g)}">
<meta property="og:url" content="${canon}">
<meta property="og:image" content="https://www.opentrustbench.com/og-image.png">
  <meta property="og:image:width" content="1280">
  <meta property="og:image:height" content="640">
<script type="application/ld+json">${jsonLd}</script>
<link rel="preload" href="../assets/fonts/inter-var-latin.woff2" as="font" type="font/woff2" crossorigin>
<link rel="stylesheet" href="../assets/site.css">
</head>
<body data-scan="${esc(SCAN_DATE)}">
<a class="skip" href="#main">Skip to content</a>
<nav class="nav" aria-label="Main"><div class="nav-inner">
<a class="brand" href="../"><span class="brand-mark">O</span>OpenTrustBench</a>
<div class="nav-links" id="nav-links"><a href="../#how">How it works</a><a href="./">Registry</a><a href="../methodology.html">Methodology</a></div>
<div class="nav-cta"><a class="btn btn-ghost btn-sm" href="https://github.com/eulogik/OpenTrustBench">GitHub</a>${THEME_TOGGLE}<button class="burger" aria-expanded="false" aria-controls="nav-links" aria-label="Menu">☰</button></div>
</div></nav>
<main id="main"><div class="report-wrap">
<p class="muted small"><a href="./">← All scanned servers</a></p>
<p id="stale" hidden class="callout warn">⚠️ This snapshot is over 30 days old — treat the grade as stale until the next refresh. Re-scan locally to verify.</p>
<script>try{var d=new Date(document.body.dataset.scan);if((Date.now()-d.getTime())/864e5>30){document.getElementById('stale').hidden=false;}}catch(_){}</script>
<p class="eyebrow">Trust Card · Static snapshot</p>
<h1>${esc(title)} <span class="grade ${gc}">${esc(g)}</span></h1>
<p class="lede"><strong style="color:var(--text)">${card.trustScore.overall}/100</strong> · ${card.security.totalFindings} findings (${card.security.criticalCount} critical) · scope ${esc(card.permissions.estimatedScope)} · ${esc(rankLine)}.</p>
<p class="muted">Scanned ${esc(SCAN_DATE)} · engine v${esc(CORE_PKG.version)} (8 regex rules, OWASP-mapped) · upstream ${esc(upstream)}</p>
<h2>Score breakdown</h2>
${breakdownBars(card.trustScore.breakdown)}
<p class="muted">${esc(card.trustScore.rationale || "")}</p>
<h2>Fix first (${fixN} critical/high)</h2>
${findingsTable(card.security.findings)}
<h2>Permissions</h2>
<p>Scope: <strong>${esc(card.permissions.estimatedScope)}</strong> · Shell: ${card.permissions.shell ? "enabled" : "disabled"} · Network egress: ${card.permissions.canMakeHTTPRequests ? "yes" : "no"} · File deletion: ${card.permissions.canDeleteFiles ? "enabled" : "none"} · Human approval: ${(card.permissions.humanApprovalRequired || []).length ? esc(card.permissions.humanApprovalRequired.join(", ")) : "none"}</p>
<h2>Provenance</h2>
<p>License: ${esc(card.provenance.license || "none detected")} · Lockfile: ${card.provenance.hasLockfile ? "yes" : "no"} · Security policy: ${card.provenance.hasSecurityPolicy ? "yes" : "no"} · Signals: ${card.provenance.isVerified ? "present (documentary, not a safety verdict)" : "unverified origin"}</p>
<div class="callout"><p><strong>Independently scanned by the OpenTrustBench registry</strong> (not self-reported by the project). Static analysis only — no code executed, findings need human triage, counts may include test/example code. <strong>Static snapshot; re-scan before relying on it:</strong> <code>npx @opentrustbench/cli scan ${esc(repoUrl)}</code>. Scores move with every upstream commit; pages refresh weekly. <a href="../methodology.html">How scoring works</a>.</p></div>
</div></main>
<footer><div class="wrap"><div class="foot-base" style="border-top:none;padding-top:0"><span>© 2026 OpenTrustBench · Apache-2.0 · Built by <a href="https://eulogik.com">Eulogik</a></span><span><a href="../">Home</a> · <a href="./">Registry</a></span></div></div></footer>
<script src="../assets/site.js" defer></script>
</body></html>
`;
}

function explorerJson(rows) {
  return rows.map(r => ({ title: r.title, grade: r.grade, overall: r.overall, total: r.total, crit: r.crit, scope: r.scope, url: "./" + r.slug + ".html", badge: "./" + r.slug + ".svg" }));
}

function adoptionLine() {
  try {
    const a = JSON.parse(fs.readFileSync(path.join(OUT_DIR, "adoption.json"), "utf8"));
    return `<p class="muted">Badge adoption: <strong style="color:var(--text)">${a.displaying} of ${a.checked}</strong> scanned repos display their grade (checked ${esc(a.date)}).</p>`;
  } catch { return ""; }
}

function indexPage(rows) {
  const sorted = [...rows].sort((a, b) => b.overall - a.overall);
  const counts = { all: rows.length, A: 0, B: 0, C: 0, D: 0, F: 0 };
  rows.forEach(r => { counts[r.grade] = (counts[r.grade] || 0) + 1; });
  const chips = ["all", "A", "B", "C", "D", "F"].map(g =>
    `<button class="chip" data-grade="${g}" aria-pressed="${g === "all" ? "true" : "false"}">${g === "all" ? "All" : "Grade " + g} (${counts[g] || 0})</button>`).join("");
  const trs = sorted.map(r =>
    `<tr><td><span class="grade g${r.grade}">${r.grade}</span></td><td><a href="./${r.slug}.html">${esc(r.title)}</a></td><td class="mono">${r.overall}</td><td>${r.total} (${r.crit} crit)</td><td>${esc(r.scope)}</td><td><a href="./${r.slug}.html"><img src="./${r.slug}.svg" alt="OpenTrustBench ${r.grade}" loading="lazy"></a></td></tr>`).join("");
  const items = sorted.map((r, i) => ({ "@type": "ListItem", position: i + 1, name: `${r.title} — OpenTrustBench Grade ${r.grade} (${r.overall}/100)`, url: `${SITE}/r/${r.slug}.html` }));
  const jsonLd = JSON.stringify({ "@context": "https://schema.org", "@graph": [
    { "@type": "Organization", "@id": `${SITE}/#org`, name: "OpenTrustBench", url: `${SITE}/`, sameAs: ["https://github.com/eulogik/OpenTrustBench"] },
    { "@type": "ItemList", name: "OpenTrustBench registry: Trust Cards for public MCP servers",
      description: `Static Trust Cards for ${rows.length} public MCP servers and SDKs, ranked by score.`,
      numberOfItems: rows.length, itemListElement: items }
  ]});
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Registry — Trust Cards for ${rows.length} MCP servers · OpenTrustBench</title>
<meta name="description" content="Searchable registry of static Trust Cards for ${rows.length} public MCP servers and SDKs: grades A–F, scores, findings, permission scope. Re-scanned weekly.">
<link rel="canonical" href="${SITE}/r/">
<meta property="og:type" content="website">
<meta property="og:title" content="OpenTrustBench registry — Trust Cards for ${rows.length} MCP servers">
<meta property="og:url" content="${SITE}/r/">
<meta property="og:image" content="https://www.opentrustbench.com/og-image.png">
  <meta property="og:image:width" content="1280">
  <meta property="og:image:height" content="640">
<script type="application/ld+json">${jsonLd}</script>
<link rel="preload" href="../assets/fonts/inter-var-latin.woff2" as="font" type="font/woff2" crossorigin>
<link rel="stylesheet" href="../assets/site.css">
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<nav class="nav" aria-label="Main"><div class="nav-inner">
<a class="brand" href="../"><span class="brand-mark">O</span>OpenTrustBench</a>
<div class="nav-links" id="nav-links"><a href="../#how">How it works</a><a href="./">Registry</a><a href="../methodology.html">Methodology</a></div>
<div class="nav-cta"><a class="btn btn-ghost btn-sm" href="https://github.com/eulogik/OpenTrustBench">GitHub</a>${THEME_TOGGLE}<button class="burger" aria-expanded="false" aria-controls="nav-links" aria-label="Menu">☰</button></div>
</div></nav>
<main id="main"><div class="wrap" style="padding-top:calc(68px + 64px)">
<p class="eyebrow">Registry · Re-scanned weekly</p>
<h1>Every grade, one page.</h1>
<p class="lede"><strong style="color:var(--text)">The registry is a set of static Trust Cards for public MCP servers</strong> — independently scanned snapshots, not self-reports. Search, filter, and open any card for file:line evidence.</p>
<div class="explorer-bar" role="group" aria-label="Filter by grade">${chips}
<input class="search" id="registry-search" type="search" placeholder="Search servers…" aria-label="Search servers">
<select class="sortsel" id="registry-sort" aria-label="Sort servers"><option value="score-desc">Top scored</option><option value="score-asc">Lowest scored</option><option value="findings-desc">Most findings</option><option value="grade">Grade A→F</option></select>
</div>
<div class="hist" id="grade-hist" aria-hidden="true"></div>
<p class="count-line" id="registry-count"></p>
<table class="data" id="registry-table"><thead><tr><th>Grade</th><th>Server</th><th>Score</th><th>Findings</th><th>Scope</th><th>Badge</th></tr></thead><tbody>${trs}</tbody></table>
<script type="application/json" id="registry-data">${JSON.stringify(explorerJson(rows)).replace(/</g, "\\u003c")}</script>
${adoptionLine()}
<div class="callout"><p>Dated snapshot (${esc(SCAN_DATE)}), engine v${esc(CORE_PKG.version)}. Static analysis only — findings need triage. <a href="../methodology.html">How scoring works</a> · <a href="https://github.com/eulogik/OpenTrustBench/blob/main/docs/STATE-OF-MCP-2026.md">State of MCP report</a>.</p></div>
</div></main>
<footer><div class="wrap"><div class="foot-base" style="border-top:none;padding-top:0"><span>© 2026 OpenTrustBench · Apache-2.0 · Built by <a href="https://eulogik.com">Eulogik</a></span><span><a href="../">Home</a> · <a href="../methodology.html">Methodology</a></span></div></div></footer>
<script src="../assets/site.js" defer></script>
</body></html>
`;
}

function scanTarget(targetPath, outDir) {
  fs.rmSync(outDir, { recursive: true, force: true });
  fs.mkdirSync(outDir, { recursive: true });
  execFileSync("node", [CLI, "scan", targetPath, "--quiet", "--format", "json", "--output-dir", outDir, "--no-color"], { stdio: "pipe", timeout: 180000 });
  return JSON.parse(fs.readFileSync(path.join(outDir, "trust-card.json"), "utf8"));
}

function clone(repo, dest) {
  fs.rmSync(dest, { recursive: true, force: true });
  sh(`git clone --depth 1 --quiet https://github.com/${repo}.git "${dest}"`);
}

function refreshOnePager(sweep) {
  const p = path.join(ROOT, "docs", "STATE-OF-MCP-2026.md");
  let doc;
  try { doc = fs.readFileSync(p, "utf8"); } catch { console.log("one-pager not found, skipping"); return; }
  const n = sweep.length;
  const avg = (sweep.reduce((a, r) => a + r.overall, 0) / n).toFixed(1);
  const grades = {};
  for (const r of sweep) grades[r.grade] = (grades[r.grade] || 0) + 1;
  const df = (grades.D || 0) + (grades.F || 0);
  const dfPct = Math.round((df / n) * 100);
  const scopes = {};
  for (const r of sweep) scopes[r.scope] = (scopes[r.scope] || 0) + 1;
  const findings = sweep.reduce((a, r) => a + r.total, 0);
  const crit = sweep.reduce((a, r) => a + r.crit, 0);
  const dist = ["A", "B", "C", "D", "F"].map(g => `${g} ${grades[g] || 0}`).join(" · ");
  const bottom = [...sweep].sort((a, b) => a.overall - b.overall).slice(0, 10)
    .map(r => `| ${r.overall} | ${r.title} | ${r.total} (${r.crit}) | ${r.scope} |`).join("\n");
  const top = [...sweep].sort((a, b) => b.overall - a.overall).slice(0, 10)
    .map(r => `| ${r.overall} | ${r.title} | ${r.total} | ${r.scope} |`).join("\n");
  const blockA = `## Headline numbers\n\n| Metric | Value |\n|---|---|\n| Servers scanned | ${n} |\n| Average Trust Score | **${avg} / 100** |\n| Graded D or F | **${df} / ${n} (${dfPct}%)** |\n| Total findings | ${findings} (${crit} critical) |\n| Excessive permission scope | **${scopes.excessive || 0} / ${n} (${Math.round(((scopes.excessive || 0) / n) * 100)}%)** |\n| Minimal scope | ${scopes.minimal || 0} / ${n} |\n\nGrade distribution: ${dist}.`;
  const setSection = (text, from, to, body) => {
    const a = text.indexOf(from);
    const b = to ? text.indexOf(to, a) : text.length;
    if (a < 0 || (to && b < 0)) throw new Error(`one-pager anchor missing: ${from}`);
    return text.slice(0, a) + body + "\n\n" + text.slice(to ? b : text.length);
  };
  doc = setSection(doc, "## Headline numbers", "This converges", blockA);
  doc = setSection(doc, "## Bottom 10 (by score)", "## Top 10",
    `## Bottom 10 (by score)\n\n| Score | Server | Findings (crit) | Scope |\n|---|---|---|---|\n${bottom}`);
  doc = setSection(doc, "## Top 10 (by score)", "## Limitations",
    `## Top 10 (by score)\n\n| Score | Server | Findings | Scope |\n|---|---|---|---|\n${top}`);
  doc = doc.replace(/re-scanned \d{4}-\d{2}-\d{2}/, `re-scanned ${SCAN_DATE}`);
  fs.writeFileSync(p, doc);
  console.log(`one-pager stats refreshed (${n} servers, avg ${avg})`);
}


function main() {
  if (!fs.existsSync(RESULTS)) {
    console.error(`Missing ${RESULTS} — run scripts/seed-registry.mjs first.`);
    process.exit(1);
  }
  const results = JSON.parse(fs.readFileSync(RESULTS, "utf8"));
  fs.mkdirSync(CLONES, { recursive: true });
  fs.mkdirSync(OUT, { recursive: true });
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const rows = [];
  const pending = [];
  let failed = 0;

  const monoDir = path.join(CLONES, "monorepo-servers");
  const isMono = (name) => name.startsWith("mcp-") && !name.includes("__");
  const needMono = results.some(r => isMono(r.name));
  if (needMono && !fs.existsSync(path.join(monoDir, ".git"))) {
    console.log("cloning " + MONOREPO + " ...");
    clone(MONOREPO, monoDir);
  }
  const monoSha = needMono ? sh(`git -C "${monoDir}" rev-parse --short HEAD`) : "";
  const monoDate = needMono ? sh(`git -C "${monoDir}" log -1 --format=%cs`) : "";

  for (const r of results) {
    const sl = slug(r.name);
    try {
      let target, repoUrl, upstream;
      if (isMono(r.name)) {
        const sub = r.name.slice(4);
        target = path.join(monoDir, "src", sub);
        repoUrl = `https://github.com/${MONOREPO}/tree/main/src/${sub}`;
        upstream = `${MONOREPO} @ ${monoSha} (${monoDate})`;
      } else {
        const repo = r.repo;
        const dest = path.join(CLONES, sl);
        clone(repo, dest);
        target = dest;
        const sha = sh(`git -C "${dest}" rev-parse --short HEAD`);
        const date = sh(`git -C "${dest}" log -1 --format=%cs`);
        repoUrl = `https://github.com/${repo}`;
        upstream = `${repo} @ ${sha} (${date})`;
      }
      const card = scanTarget(target, path.join(OUT, sl));
      pending.push({ sl, title: r.name, repoUrl, upstream, card, self: false });
      console.log(`OK ${r.name} (collected)`);
    } catch (e) {
      failed++;
      console.log(`FAIL ${r.name}: ${String(e.message || e).split("\n")[0]}`);
    }
  }

  // Self scans (local tree, bound to our own commit).
  const selfSha = sh(`git -C "${ROOT}" rev-parse --short HEAD`);
  const self = [
    ["self-packages-cli", "opentrustbench CLI (packages/cli)", path.join(ROOT, "packages", "cli")],
    ["self-examples-secure-agent-skill", "examples/secure-agent-skill", path.join(ROOT, "examples", "secure-agent-skill")],
    ["self-examples-vulnerable-mcp-server", "examples/vulnerable-mcp-server", path.join(ROOT, "examples", "vulnerable-mcp-server")]
  ];
  for (const [sl, title, target] of self) {
    try {
      const card = scanTarget(target, path.join(OUT, sl));
      const upstream = `eulogik/OpenTrustBench @ ${selfSha} (${SCAN_DATE})`;
      pending.push({ sl, title, repoUrl: "https://github.com/eulogik/OpenTrustBench", upstream, card, self: true });
      console.log(`OK ${title} (collected)`);
    } catch (e) {
      failed++;
      console.log(`FAIL ${title}: ${String(e.message || e).split("\n")[0]}`);
    }
  }

  // Emit with percentile rank computed across everything collected.
  const ranked = [...pending].sort((a, b) => b.card.trustScore.overall - a.card.trustScore.overall);
  for (const e of pending) {
    const rank = ranked.findIndex(x => x.sl === e.sl) + 1;
    const rankLine = `Ranked #${rank} of ${pending.length} scanned`;
    fs.writeFileSync(path.join(OUT_DIR, `${e.sl}.html`), reportPage({ slug: e.sl, title: e.title, repoUrl: e.repoUrl, upstream: e.upstream, card: e.card, rankLine }));
    fs.writeFileSync(path.join(OUT_DIR, `${e.sl}.svg`), badgeSvg(e.card.trustScore.grade, e.card.trustScore.overall));
    rows.push({ slug: e.sl, title: e.title, grade: e.card.trustScore.grade, overall: e.card.trustScore.overall, total: e.card.security.totalFindings, crit: e.card.security.criticalCount, scope: e.card.permissions.estimatedScope, upstreamShort: e.upstream.split(" (")[0], self: e.self });
    console.log(`OK ${e.title} -> r/${e.sl}.html`);
  }
  fs.writeFileSync(path.join(OUT_DIR, "index.html"), indexPage(rows));
  refreshOnePager(rows.filter(r => !r.self));
  const files = fs.readdirSync(OUT_DIR).filter(f => f.endsWith(".html"));
  const bytes = files.reduce((n, f) => n + fs.statSync(path.join(OUT_DIR, f)).size, 0);
  console.log(`\nWrote ${files.length} pages (${(bytes / 1024).toFixed(0)} KB) to web/public/r/. Failed: ${failed}.`);
}

main();
