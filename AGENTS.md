# AGENTS.md

## What this is

OpenTrustBench — trust/scanning layer for AI agent capabilities and MCP tools. npm workspaces monorepo, TypeScript, pure ESM (`"type": "module"`, NodeNext resolution, strict).

- `packages/core` — all engines: capability detectors, OWASP rule suite (8 regex rules: `AT-SEC-001`–`007` + `AT-COMP-001`), permission extraction, trust scoring/grades (A-F + U ungraded), attack heuristics, workflow eval parser, SARIF/markdown reporters. Public API re-exported from `src/index.ts`. Tests live in `src/tests/` (node:test), compiled into `dist/tests/`.
- `packages/cli` — `opentrustbench` binary; thin dispatcher over core (`import ... from "@opentrustbench/core"`).
- `packages/action` — GitHub Action wrapper; `action.yml` only, no code.
- `web/public` — site v4 (no frameworks): `index.html`, `methodology.html`, `r/` (generated report pages + registry explorer), `assets/` (`site.css` tokens, `site.js` vanilla, self-hosted Inter + JetBrains Mono woff2), `llms.txt`, `.well-known/ai.txt`, `feed.xml`, SEO files (`sitemap.xml`, `robots.txt`, `404.html`). Served via GitHub Pages at `https://opentrustbench.com` (`opentrustbench.dev` is a parked squatter domain — never point URLs at it). Internal links are relative (work at root locally and on the custom domain); only canonical/OG use absolute URLs. `404.html` must keep root-absolute `/assets/` paths (it serves at arbitrary depths).
- `badges/` — shareable grade badge SVGs (`a.svg` through `f.svg` + `u.svg`), shields.io-compatible, hosted at `https://opentrustbench.com/badge/`.
- `examples/` — scan fixtures: `vulnerable-mcp-server` (must grade F / fail attack heuristics), `secure-agent-skill` (docs-only, grades U), `sample-workflow.yaml`.
- `scripts/verify-demos.mjs` — end-to-end smoke checks used by CI and local verification.
- `scripts/seed-registry.mjs` — registry sweep (shallow clones, local scans, resumable).
- `scripts/build-reports.mjs` — report page generator (static HTML + badges).
- `docs/` + `walkthrough.md` — product strategy/research prose, not engineering docs (walkthrough has stale absolute paths).
- License: Apache-2.0.

## Honesty model (don't regress this)

- The **attack engine runs in static-heuristic mode**: results derive from static findings + permission manifest; no payloads execute. Reports carry `mode: "static-heuristic"` + a disclaimer. Do not reintroduce fabricated narratives ("payload triggered...") or invented durations/costs/success rates anywhere.
- **Workflow eval is simulation mode**: suites are parsed and validated (`parseSimpleYamlSuite`), steps are marked `"simulated"`/`not_executed`, costs/durations stay 0. Real execution requires eval lab v2.
- `registry` command shows sample data (labeled as such). Badges link to static per-repo report pages under `web/public/r/` (registry index at `r/index.html`); regenerate with `node scripts/build-reports.mjs` (re-clones + re-scans, ~10 min; needs `/tmp/at-sweep/results.json` from `seed-registry.mjs`). Bound badges live next to pages (`r/<slug>.svg`); embed as `[![OpenTrustBench](<site>/r/<slug>.svg)](<site>/r/<slug>.html)`. `.github/workflows/rescan.yml` refreshes weekly (Mon 06:00 UTC) and pushes with `GH_PAT`; deploys follow automatically.
- OWASP codes follow the canonical lists: LLM Top 10 2025 (LLM01–LLM10) and Agentic Top 10 published 2025-12-09 (ASI01 Goal Hijack … ASI10 Rogue Agents). Note LLM08 ≠ "secrets"; ASI03 ≠ file deletion. See comment block atop `RULES` in `packages/core/src/analysis/static-analyzer.ts`.
- **Marketing must match the engines**: site/README say **8 rules** (never 18), attack is static-heuristic, eval is simulated, Trust Cards are evidence input (never "certified"/"compliant"). The on-site demo is pre-rendered fixture output — never imply a live scan; badges link to the homepage until report pages exist.
- **Detection integrity**: finding IDs are deterministic hashes (`stableFindingId`) — never `Math.random()`; detector walks recursively (`walkFiles`) and reads `SKILL.md` case-insensitively; code-pattern rules skip prose docs and the scanner's own rule-DSL lines; `AT-COMP-001` requires a real call (paren), not a bare identifier; `compatibility` is inferred per capability type; `provenance.isVerified` means documentary signals present, never "safe".
- **Coverage integrity**: grades can be **U (ungraded)** when static coverage is insufficient (exit code 2, artifacts still written). Registry excludes U from rankings/averages; badge shows "U ungraded" (gray). Secure skill fixture correctly grades U (docs-only, 0 analyzed / 1 discovered files). Secure skill docs explain coverage limits, not safety.

## Build & test reality

- `npm i` triggers root `prepare` → builds core then cli (order pinned explicitly in root scripts; do NOT use `--workspaces` for build ordering — npm ran cli before core and broke resolution of `@opentrustbench/core`, which needs core's `dist/index.d.ts` to exist).
- `typescript` + `@types/node` are root devDependencies. `types: ["node"]` is set in `tsconfig.base.json`.
- `dist/` is gitignored and untracked. Fresh clone: `npm i` builds everything automatically.
- `npm test` = build + real node:test suite (`packages/core/dist/tests/*.test.js`). 36 tests. No silent fallbacks — failures fail loudly.
- Verification = `npm test` green + `node scripts/verify-demos.mjs` passing (asserts F-grade vulnerable fixture, U-grade secure fixture, non-empty SARIF, heuristic-mode attack report, simulated eval).
- Demo scans overwrite root artifacts: `trust-card.json`, `opentrustbench-report.sarif`, `opentrustbench-report.md`, `opentrustbench-attack-report.json` (committed samples get regenerated).
- Relative imports must use `.js` extensions in TS source (NodeNext requirement).

## Commands

```bash
npm i                                    # installs + auto-builds via prepare
npm test                                 # build + unit tests (36 tests)
node scripts/verify-demos.mjs            # end-to-end demo assertions (CI parity)
npm run scan:vulnerable                  # F-grade fixture scan
npm run scan:secure                      # U-grade fixture (docs-only)
npm run attack:demo                      # static-heuristic attack analysis
npm run eval:demo                        # simulation-mode workflow eval
node packages/cli/dist/index.js scan <path-or-dir>   # scan any target directly
node packages/cli/dist/index.js scan <t> --quiet --format json --output-dir ./trust   # CI-friendly: compact stdout, files to ./trust
npx serve web/public -p 3000             # static web UI (landing page)
# Badge URLs (after GitHub Pages deploy):
# https://opentrustbench.com/badge/a.svg  through  https://opentrustbench.com/badge/f.svg
# https://opentrustbench.com/badge/u.svg  (ungraded)
```

## Weekly registry refresh (automated)

- `.github/workflows/rescan.yml` runs Mon 06:00 UTC, uses `GH_PAT` secret for `actions/checkout@v4` and git push.
- Push with PAT triggers Pages deploy automatically.
- Scans 50 external targets + 3 self-scans (CLI, secure skill, vulnerable fixture).
- Updates `web/public/r/` report pages, badges, `docs/STATE-OF-MCP-2026.md`, `web/public/r/adoption.json`.

## Distribution (all v0.1.3)

- npm: `@opentrustbench/cli` (CLI, bin `opentrustbench`) + `@opentrustbench/core` (lib).
- PyPI: `opentrustbench` (requires Node 18+ for CLI engine).
- Homebrew: `brew tap eulogik/opentrustbench && brew install opentrustbench`.
- Docker: `docker run --rm -v $(pwd):/workspace eulogik/opentrustbench scan .` (`eulogik/opentrustbench` on Hub).
- VS Code: `code --install-extension eulogik.opentrustbench` (Marketplace).
- GitHub Action: `uses: eulogik/opentrustbench-action@v0.1.3` (requires `security-events: write` for SARIF).

## Known gaps (roadmap context)

- Dependency scanning runs `npm audit --package-lock-only` only when a lockfile exists; no pip-audit/Trivy yet. Rules remain regex-only, no AST.
- GitHub Action requires caller workflows to grant `security-events: write` for the SARIF upload step; scan targets must be local paths, full GitHub URLs, or flagged (`--github`, `--npm`) — bare `owner/repo` without a flag is treated as a local path by design.
- No lint/format config.
- npm packages published at 0.1.3: `@opentrustbench/cli` (CLI, bin `opentrustbench`) + `@opentrustbench/core` (lib). Unscoped `opentrustbench` is permanently blocked (typosquat guard vs real `agent-trust` package) — never reference it as installable.
- Repo is PUBLIC on GitHub: `eulogik/OpenTrustBench`.
- Custom domain `opentrustbench.com` (apex is canonical; `www` 301-redirects to apex) via GitHub Pages + `web/public/CNAME` (must stay `opentrustbench.com`; every deploy reasserts it). `opentrustbench.dev` is parked by a squatter — never use it. Canonical/OG/sitemap URLs use `https://opentrustbench.com` (no www). Contact is via GitHub issues (no project email exists).

## Implemented since last AGENTS.md update (2026-09-18)

### Coverage integrity v2 (trust-card v2 schema)
- **U grade** for insufficient static coverage: exit code 2, artifacts still written, `status: "ungraded"`, `overall: null`, `breakdown: null`, `confidence: "low"`.
- `TrustScore` gains `status: "graded" | "ungraded"`, `grade` adds `"U"`, optional `coverage` object with `mode`, `status`, `reasons`, `limitations`, `discoveredFiles`, `analyzedFiles[]`, `unsupportedSourceFiles[]`, `excludedFiles[]`, `readErrors[]`, `truncation[]`, `limits`.
- Secure skill fixture (docs-only) correctly grades **U** — 0 analyzed / 1 discovered files.
- Registry: U excluded from rankings/averages; gray badge "U ungraded"; explorer filter/sort/histogram includes U.
- Registry stats: 50 external targets (50 graded, 3 ungraded) + 3 self-scans; 36% D/F across graded externals.
- CLI: exit 2 for U; `--fail-on` gate fails on insufficient coverage (separate from severity gate).
- Reporters: markdown/SARIF surface coverage, nullable scores, gray U badge.

### Site/Readme (v2 schema, accurate claims)
- `trust-card/v2` in README, index.html FAQ, JSON-LD.
- "Local analysis, no OpenTrustBench telemetry; npm audit uses npm registry" (replaces "zero data leaving your machine").
- **50 external targets + 3 self-scans** (not "53 public servers").
- Footer, JSON-LD, FAQs updated with accurate numbers.
- Homepage: "50 external targets (50 graded, 3 ungraded); 3 self-scans".
- U badge at `opentrustbench.com/badge/u.svg` (gray).

### Weekly automation fixed
- `GH_PAT` secret configured for `actions/checkout@v4` + push.
- Weekly refresh Mon 06:00 UTC pushes with PAT → triggers Pages deploy automatically.
- Verified: Sep 18 10:05 UTC refresh → 10:08 UTC deploy both succeeded.

### Tests/demos
- 36 unit tests pass (was 14).
- All demo smoke checks pass: vulnerable F (33), secure U (0 analyzed / 1 discovered), attack static-heuristic (4 failed, resilience 20), eval simulation mode.

### Live site (verified 2026-09-18)
- Registry dated snapshot: **2026-09-18** (refreshed today via PAT).
- Secure skill page: **Grade U** with "Ungraded — insufficient static coverage".
- Registry shows "50 external targets (50 graded, 3 ungraded); 3 self-scans".
- U badge live at `opentrustbench.com/badge/u.svg` (gray).

## Future path (from ROADMAP.md)

### v0.2.0 — trust the grade (~2-3 weekends)
1. **Baseline diff CI mode** (Gitleaks-style): fingerprint findings, `--baseline` file, `--update-baseline`, `--fail-on fixed`.
2. **Version-pinned badges + validity window**: `subject.revision`, `validFrom`/`validUntil` (30d default), badge embeds pinned ref.
3. **Credential-exposure rules CRED-01/02/03**: CRED-01 long-lived handoff, CRED-02 hardcoded secret literal, CRED-03 secret + egress co-occurrence. Fixtures per rule, confidence decoupled from severity.
4. **Signed Trust Cards**: in-toto Statement v1 + Sigstore bundle, keyless via GHA OIDC, SLSA Build L2 target.
5. **Per-rule fixture harness + confidence + suppressions**: `opentrustbench.yaml` ignore section, inline `// opentrustbench-ignore`, `--explain <fingerprint>`.

### v0.3.0 — engine upgrade (~6-8 weekends)
6. **AST parsing for JS/TS** via TypeScript compiler API (parse-only), sink-finder interface, regex fallback.
7. **EU AI Act evidence pack**: Article-by-article mapping, deployer fields, Transparency Code of Practice, EN 18286 mapping, ISO 42001 pointers. Trust Cards = governance evidence INPUT, never certification.
8. **Dependency re-scan depth**: lockfile-aware recursive, reachability shading, document pip-audit/Trivy gap.

### Later (traction-dependent)
9. Runtime guidance profiles (least-privilege manifests).
10. Eval lab v2 (real container execution).
11. Registry expansion (top npm/PyPI agent packages).
12. Python AST (second parser after JS/TS proves).

## Open unknowns (re-verify before building)

- Sigstore offline-with-inclusion-proof behavior against live TUF/Rekor.
- Head-to-head parse benchmarks on agent/MCP corpus.
- EN 18286 OJ citation status and final watermark/C2PA references.
- No prior static classifier for long-lived vs brokered credentials; CRED-01/03 are heuristics with stated confidence.