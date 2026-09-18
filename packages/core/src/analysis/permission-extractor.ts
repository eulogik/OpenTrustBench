import { analyzeStaticCoverage } from "./static-analyzer.js";
import type { PermissionManifest } from "../types/index.js";

export async function extractPermissions(dirPath: string, contents?: ReadonlyMap<string, string>): Promise<PermissionManifest> {
  const manifest: PermissionManifest = {
    network: [],
    filesystem: [],
    shell: false,
    shellCommands: [],
    secrets: [],
    envVars: [],
    externalServices: [],
    humanApprovalRequired: [],
    canSpawnProcesses: false,
    canAccessDB: false,
    canSendEmail: false,
    canAccessBrowser: false,
    canModifyFiles: false,
    canDeleteFiles: false,
    canMakeHTTPRequests: false,
    estimatedScope: "minimal"
  };

  const analyzed = contents ?? (await analyzeStaticCoverage(dirPath)).contents;
  for (const content of analyzed.values()) {
    analyzeFileContent(content, manifest);
  }

  let riskPoints = 0;
  if (manifest.shell) riskPoints += 4;
  if (manifest.canDeleteFiles) riskPoints += 3;
  if (manifest.canModifyFiles) riskPoints += 1;
  if (manifest.canAccessBrowser) riskPoints += 2;
  if (manifest.canSendEmail) riskPoints += 2;
  if (manifest.canAccessDB) riskPoints += 2;
  if (manifest.canMakeHTTPRequests) riskPoints += 1;
  if (manifest.secrets.length > 3) riskPoints += 2;

  if (riskPoints >= 7) manifest.estimatedScope = "excessive";
  else if (riskPoints >= 4) manifest.estimatedScope = "broad";
  else if (riskPoints >= 2) manifest.estimatedScope = "moderate";
  else manifest.estimatedScope = "minimal";

  return manifest;
}

/**
 * Capability booleans are evaluated on de-stringed code, not raw text.
 * Rationale: string literals (sample data, docs, prose) must not confer
 * capabilities — e.g. the sample string "openclaw-shell-exec" used to flag
 * shell access, "postgres-mcp-server" flagged database access, and prose like
 * "please resend the report" flagged email. Import specifiers are extracted
 * from raw content first, since module names live inside quotes.
 */
function stripStringsAndComments(content: string): string {
  return content
    .replace(/`(?:\\.|[^`\\])*`/g, "``")
    .replace(/'(?:\\.|[^'\\])*'/g, "''")
    .replace(/"(?:\\.|[^"\\])*"/g, '""')
    .replace(/\/\/[^\n]*/g, "")
    .replace(/(^|[ \t])#[^\n]*/gm, "$1");
}

function importSpecifiers(content: string): string[] {
  const out: string[] = [];
  for (const m of content.matchAll(/(?:from\s+|require\(\s*|import\(\s*)["']([^"']+)["']/g)) {
    out.push(m[1].toLowerCase());
  }
  return out;
}

const DB_NAME_HINT = /^(pg|postgres|mysql2?|mariadb|sqlite3?|better-sqlite3|postgres\.js)$/;
const DB_SPEC_HINT = /(prisma|drizzle|mongoose|redis|typeorm|sequelize|knex|pg-promise|node-postgres)/;
const BROWSER_SPEC_HINT = /(playwright|puppeteer|selenium)/;
const EMAIL_SPEC_HINT = /(nodemailer|sendgrid|mailgun|postmark|resend|smtp|client-ses)/;
const NETWORK_SPEC_HINT = /(axios|node-fetch|undici|got|ky|superagent|requests|httpx|urllib3|aiohttp)/;

function analyzeFileContent(content: string, manifest: PermissionManifest): void {
  // Raw-content extractions (these live inside string literals by nature).
  const urlMatches = content.matchAll(/https?:\/\/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g);
  for (const m of urlMatches) {
    const host = m[1];
    if (!manifest.externalServices.includes(host)) {
      manifest.externalServices.push(host);
      manifest.network.push({ type: "outbound", host, protocol: "https" });
    }
  }
  const cmdMatches = content.matchAll(/(?:exec|spawn)\s*\(\s*["']([^"'\s]+)/g);
  for (const m of cmdMatches) {
    if (!manifest.shellCommands.includes(m[1])) {
      manifest.shellCommands.push(m[1]);
    }
  }
  const specs = importSpecifiers(content);
  const specHit = (re: RegExp) => specs.some(s => re.test(s.split("/").pop() ?? s) || re.test(s));

  const code = stripStringsAndComments(content);

  if (/\b(?:exec|execSync|spawn)\s*\(/.test(code) || specs.some(s => s === "child_process" || s === "node:child_process")) {
    manifest.shell = true;
    manifest.canSpawnProcesses = true;
  }

  if (/\b(?:fetch\s*\(|axios\s*\.|requests\s*\.|https?\s*\.\s*(?:get|request)\s*\()/.test(code) || specHit(NETWORK_SPEC_HINT)) {
    manifest.canMakeHTTPRequests = true;
  }

  if (/\b(?:writeFileSync|writeFile|appendFileSync|createWriteStream)\b/.test(code)) {
    manifest.canModifyFiles = true;
    manifest.filesystem.push({ type: "write", path: "host-workspace" });
  }
  if (/\b(?:unlinkSync|unlink|rmSync|rmdirSync|shutil\.rmtree)\b/.test(code)) {
    manifest.canDeleteFiles = true;
    manifest.filesystem.push({ type: "delete", path: "host-workspace" });
  }

  if (/\b(?:playwright|puppeteer|selenium|browser\.launch|page\.goto)\b/.test(code) || specHit(BROWSER_SPEC_HINT)) {
    manifest.canAccessBrowser = true;
  }

  if (/\b(?:nodemailer|sendgrid|resend|smtp)\b/.test(code) || specHit(EMAIL_SPEC_HINT)) {
    manifest.canSendEmail = true;
  }

  if (/\b(?:pg|postgres|mysql|sqlite3|prisma|drizzle|mongoose|redis)\b/.test(code) || specHit(DB_NAME_HINT) || specHit(DB_SPEC_HINT)) {
    manifest.canAccessDB = true;
  }

  const envMatches = code.matchAll(/process\.env\.([A-Z0-9_]+)/g);
  for (const m of envMatches) {
    const varName = m[1];
    if (!manifest.envVars.includes(varName)) manifest.envVars.push(varName);
    if (/KEY|TOKEN|SECRET|PASSWORD|AUTH|CREDENTIAL/i.test(varName)) {
      if (!manifest.secrets.includes(varName)) manifest.secrets.push(varName);
    }
  }

  if (/\b(?:requireApproval|confirmPrompt|askHumanConsent|operatorApproval)\b/.test(code)) {
    if (!manifest.humanApprovalRequired.includes("operator-confirmation-gate")) {
      manifest.humanApprovalRequired.push("operator-confirmation-gate");
    }
  }
}
