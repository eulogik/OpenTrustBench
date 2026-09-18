# MEMORY.md

Session notes and durable context for future OpenCode sessions.

## User preferences

- **Always commit and push** after completing work (`git push` to `origin/main`). Confirmed 2026-08-24.

## 2026-08-24 — Repo setup + Phase 0 (honesty & engineering credibility)

**Setup:** Fetched repo from `https://github.com/eulogik/OpenTrustBench` (`main`, commit `7a1fb62`), remote `origin` configured.

**Deep research findings (drove the work):**
- Attack engine and eval lab were fully fabricated: attack results derived from static findings with invented "payload triggered" narratives; eval hardcoded `status = "pass"` + `Math.random()` costs/durations and ignored YAML content entirely.
- OWASP mappings were from a stale Feb-2025 draft taxonomy (e.g. file deletion labeled ASI03, SSRF labeled ASI07 — both wrong vs canonical Dec-2025 list).
- The CLI source NEVER compiled: 9 raw newlines inside double-quoted string literals; committed `dist/` was built from different source. Same for two regexes too narrow to fire on their own flagship fixture (AT-SEC-001 missed direct prompt concat; AT-SEC-002 missed `API_SECRET_TOKEN =`).
- npm name `opentrustbench` is unclaimed. Market check: static MCP scanning is commoditized (Cisco mcp-scanner, Snyk agent-scan, Akto, MCPShield, MCPhound); differentiation lives in real attack/eval execution + trust-card/badge/registry flywheel + EU AI Act compliance export.

**Phase 0 shipped (committed `50b1204`, pushed):**
1. Build fixed: root devDeps (`typescript@^7`, `@types/node`), `types:["node"]` in tsconfig.base, explicit core→cli build order in root scripts (workspace-ordering broke module resolution), all 9 broken string literals repaired in cli/src.
2. dist/ untracked + gitignored. Lockfile generated (`package-lock.json` — needs committing).
3. Real test suite: `packages/core/src/tests/core.test.ts` (9 node:test cases). Root `npm test` no longer falls back silently.
4. CI: `.github/workflows/ci.yml` (npm i → npm test → verify-demos) + `scripts/verify-demos.mjs`.
5. Honesty model enforced: attack reports carry `mode:"static-heuristic"` + disclaimer; eval rewritten as parser/validator with `"simulated"` steps and zero fabricated numbers; registry labeled sample data.
6. OWASP remapped to canonical lists (see comment block atop RULES in static-analyzer.ts).
7. Analyzer fixes: multi-pattern support; AT-SEC-001 catches string-template concat; AT-SEC-002 catches suffixed identifiers. Vulnerable fixture now grades **F (31)**, secure fixture **B (88)**.

**Verified:** clean-room `rm -rf node_modules && npm i` → build → 9/9 tests → all smoke checks pass.

**Open items:** make repo public; register npm name; attack engine v2 (real probing) + eval lab v2 (sandboxed execution) are the strategic unlock; EU AI Act compliance export timing-sensitive.

## 2026-08-24 — Phase 1 (scanner parity) — committed, pushed

- `--fail-on <sev>` CI gate in CLI (exit 1 on breach, exit 2 on invalid value); `action.yml` now passes `fail-on` through and uploads SARIF via `github/codeql-action/upload-sarif@v3` (callers must grant `security-events: write`).
- Scan targets: full GitHub URLs auto-detected; bare `owner/repo` needs `--github` (stays local otherwise by design); npm packages via `--npm` (`npm pack` + tar extract — scans what consumers install). GitHub refs support `.git` suffixes and `/tree/<branch>` (branch names with slashes handled).
- Dependency scanning: `npm audit --package-lock-only` when a lockfile exists (works without node_modules); audit JSON mapped into Trust Card `dependencies` block (moderate→medium normalized, advisory dedupe). No lockfile = no invented vulns.
- Tests: 14 total (added severity ranking, target classification, github-ref parsing incl. branch-with-slash case caught by tests, audit mapping, lockfile-less dep scan).
- Live-verified: cloned eulogik/OpenTrustBench itself and scanned it (9 criticals — repo contains its own vulnerable fixture; expected).

**Next up:** Phase 2 — attack engine v2 (real MCP probing over stdio/HTTP) + eval lab v2 (sandboxed execution). Also: register npm name, make repo public.

## 2026-09-10 — Phase 2-3 (registry + site + distribution) — committed, pushed

- Registry: 50 external MCP servers + 3 self-scans, bound badges, weekly refresh via GitHub Actions. `scripts/seed-registry.mjs` + `scripts/build-reports.mjs` generate static HTML + badges in `web/public/r/`.
- Site v4 (no frameworks): `index.html`, `methodology.html`, registry explorer at `r/`, self-hosted fonts, `llms.txt`, `ai.txt`, `feed.xml`, SEO files. Served via GitHub Pages at `opentrustbench.com` (apex canonical, www 301→apex).
- Distribution all at v0.1.3: npm (`@opentrustbench/cli`, `@opentrustbench/core`), PyPI (`opentrustbench`), Homebrew (`eulogik/opentrustbench`), Docker (`eulogik/opentrustbench`), VS Code Marketplace (`eulogik.opentrustbench`), GitHub Action (`eulogik/opentrustbench-action`).
- Badges: `a.svg`–`f.svg` at `opentrustbench.com/badge/`, shields.io-compatible.
- Tests: 28 unit + smoke (vulnerable F, secure B, attack static-heuristic, eval simulation). CI: `npm test` + `verify-demos`.
- Repo public: `eulogik/OpenTrustBench`. Custom domain `opentrustbench.com` (CNAME `opentrustbench.com`, apex canonical).

## 2026-09-11 — Roadmap v0.2.0/v0.3.0 drafted (docs/ROADMAP.md)

Researched, sequenced, buildable plan with non-negotiable constraints (local, honest, grades rot, no silent behavior). v0.2.0 (~2-3 weekends): baseline diff CI, pinned badges + validity window, CRED-01/02/03 credential rules, signed Trust Cards (Sigstore), fixture harness + confidence + suppressions. v0.3.0 (~6-8 weekends): TypeScript compiler API AST parsing, EU AI Act evidence pack, dependency re-scan depth. Later: runtime profiles, eval lab v2, registry expansion, Python AST. Open unknowns documented (Sigstore offline, parse benchmarks, EN 18286 status, credential classifier).

## 2026-09-18 — Coverage integrity v2 (trust-card v2) + site v2 + weekly automation fix — committed, pushed

**Core/CLI changes (packages/core, packages/cli):**
- TrustCard schema v2 (`opentrustbench/trust-card/v2`): U grade added, `status: "graded" | "ungraded"`, `overall/breakdown` nullable, `confidence: "low"` for ungraded.
- Coverage object required: `mode`, `status`, `reasons`, `limitations`, `discoveredFiles`, `analyzedFiles[]`, `unsupportedSourceFiles[]`, `excludedFiles[]`, `readErrors[]`, `truncation[]`, `limits`.
- Insufficient coverage → U grade, exit 2, artifacts still written, `status: "ungraded"`, `overall: null`, `breakdown: null`, `confidence: "low"`.
- Secure skill fixture (docs-only) correctly grades **U** — 0 analyzed / 1 discovered files.
- Registry excludes U from rankings/averages; badge shows "U ungraded" (gray).
- Registry explorer: U filter/sort/histogram; stats separate external/self/ungraded.
- CLI: exit 2 for U; `--fail-on` gate fails on insufficient coverage (separate from severity gate).
- Reporters: markdown/SARIF surface coverage, nullable scores, gray U badge.
- 36 unit tests pass (was 14); all demo smoke checks pass.

**Website/Readme (trust-card v2, accurate claims):**
- `trust-card/v2` in README, index.html FAQ, JSON-LD.
- "Local analysis, no OpenTrustBench telemetry; npm audit uses npm registry" (replaces "zero data leaving your machine").
- **50 external targets + 3 self-scans** (not "53 public servers").
- Footer, JSON-LD, FAQs updated with accurate numbers.
- Homepage: "50 external targets (50 graded, 3 ungraded); 3 self-scans".
- U badge at `opentrustbench.com/badge/u.svg` (gray).

**Weekly automation fixed:**
- `GH_PAT` secret configured for `actions/checkout@v4` + push.
- Weekly refresh Mon 06:00 UTC pushes with PAT → triggers Pages deploy automatically.
- Verified: Sep 18 10:05 UTC refresh → 10:08 UTC deploy both succeeded.

**Tests/demos:**
- 36 unit tests pass (was 14).
- All demo smoke checks pass (vulnerable F 33, secure U 0 analyzed/1 discovered, attack static-heuristic 4 failed/resilience 20, eval simulation mode).

**Live site verified (2026-09-18):**
- Registry dated snapshot: **2026-09-18** (refreshed today via PAT).
- Secure skill page: **Grade U** with "Ungraded — insufficient static coverage".
- Registry shows "50 external targets (50 graded, 3 ungraded); 3 self-scans".
- U badge live at `opentrustbench.com/badge/u.svg` (gray).

**Distribution (all v0.1.3):** npm, PyPI, Homebrew, Docker, VS Code, GitHub Action.

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

## Key files to know

| File | Purpose |
|------|---------|
| `packages/core/src/types/index.ts` | Core types (TrustCard v2, TrustScore, Coverage, Finding) |
| `packages/core/src/trust/scorer.ts` | Scoring logic, confidence, U-grade logic |
| `packages/core/src/trust/card-builder.ts` | TrustCard v2 assembly, grade-a tag |
| `packages/core/src/pipeline/scan.ts` | Scan orchestration, coverage collection |
| `packages/core/src/analysis/static-analyzer.ts` | 8 regex rules, OWASP mappings, file walking |
| `packages/core/src/util/fs-walk.ts` | File traversal with limits, diagnostics |
| `packages/cli/src/index.ts` | CLI entry, exit codes, CI gates, badge command |
| `scripts/seed-registry.mjs` | Registry sweep, resumable, validates scan cards |
| `scripts/build-reports.mjs` | Report page generator, U-grade handling, stats |
| `scripts/verify-demos.mjs` | Smoke checks (vulnerable F, secure U, attack, eval) |
| `.github/workflows/rescan.yml` | Weekly refresh (Mon 06:00 UTC, GH_PAT push) |
| `.github/workflows/deploy.yml` | Pages deploy (web/**, badges/**) |
| `web/public/assets/site.css/js` | Theme toggle, Spectral serif, responsive |
| `docs/ROADMAP.md` | v0.2.0/v0.3.0 sequenced plan |
| `docs/STATE-OF-MCP-2026.md` | Registry statistics, updated weekly |
| `AGENTS.md` | This file's parent — full context for agents |

## Secrets required (GitHub repo settings)

- `GH_PAT` — Personal Access Token with `repo` scope (for weekly refresh push → Pages deploy)
- npm 2FA enabled (manual publish: `npm publish -w @opentrustbench/core && npm publish -w @opentrustbench/cli`)
- PyPI token (stored in 1Password)
- Docker Hub token (stored in 1Password)
- VS Code Marketplace PAT (stored in 1Password)