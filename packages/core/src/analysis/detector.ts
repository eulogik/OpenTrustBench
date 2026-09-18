import fs from "node:fs";
import path from "node:path";
import { walkFiles } from "../util/fs-walk.js";
import type { CapabilityType } from "../types/index.js";

export interface DetectionResult {
  type: CapabilityType;
  confidence: number;
  evidence: string[];
  name: string;
  version?: string;
  description?: string;
  language?: string;
}

export async function detectCapability(dirPath: string): Promise<DetectionResult> {
  const evidence: string[] = [];
  let files: string[] = [];
  
  try {
    files = fs.readdirSync(dirPath);
  } catch (err) {
    return {
      type: "unknown",
      confidence: 0,
      evidence: ["Unable to read directory: " + (err as Error).message],
      name: path.basename(dirPath)
    };
  }

  const fileSet = new Set(files.map(f => f.toLowerCase()));
  let name = path.basename(dirPath);
  let version = "0.1.3";
  let description = "";
  let language = "unknown";

  if (fileSet.has("package.json")) {
    language = fileSet.has("tsconfig.json") ? "TypeScript" : "JavaScript";
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(dirPath, "package.json"), "utf8"));
      if (pkg.name) name = pkg.name;
      if (pkg.version) version = pkg.version;
      if (pkg.description) description = pkg.description;
    } catch {}
  } else if (fileSet.has("pyproject.toml") || fileSet.has("requirements.txt") || fileSet.has("setup.py")) {
    language = "Python";
  }

  // Recursive file inventory (capped): detection must see past the top level
  // (e.g. MCP servers living in src/), not just root-level names.
  const allFiles = walkFiles(dirPath);
  const baseLower = new Set(allFiles.map(f => path.basename(f).toLowerCase()));
  const hasBase = (...names: string[]) => names.some(n => baseLower.has(n));

  if (hasBase("mcp.json", "mcp.yaml", "mcp.yml")) {
    evidence.push("Explicit mcp.json/yaml configuration found");
    return { type: "mcp-server", confidence: 0.98, evidence, name, version, description, language };
  }

  const isMcp = checkHasPattern(allFiles, [
    "@modelcontextprotocol",
    "McpServer",
    "ListToolsRequestSchema",
    "CallToolRequestSchema",
    "server.tool(",
    "server.resource("
  ]);
  if (isMcp) {
    evidence.push("Model Context Protocol (MCP) server signatures detected in source code");
    return { type: "mcp-server", confidence: 0.95, evidence, name, version, description, language };
  }

  const skillFile = allFiles.find(f => {
    const b = path.basename(f).toLowerCase();
    return b === "skill.md" || b === "skill.yaml" || b === "skill.yml";
  });
  if (skillFile) {
    evidence.push("Standard SKILL.md/yaml specification found");
    if (skillFile.toLowerCase().endsWith("skill.md")) {
      try {
        // Read via the discovered path (not a hardcoded lowercase name) so
        // SKILL.md works on case-sensitive filesystems.
        const content = fs.readFileSync(skillFile, "utf8");
        const match = content.match(/^#\s+(.+)$/m);
        if (match) name = match[1].trim();
      } catch {}
    }
    return { type: "agent-skill", confidence: 0.95, evidence, name, version, description, language };
  }

  if (hasBase("claude.md", "claude_desktop_config.json") || fileSet.has(".claude")) {
    evidence.push("Claude Desktop / Claude Code configuration detected");
    return { type: "claude-config", confidence: 0.90, evidence, name, version, description, language };
  }

  if (hasBase("openclaw.json", "claw.json", "clawhub.json")) {
    evidence.push("OpenClaw plugin metadata detected");
    return { type: "openclaw-plugin", confidence: 0.90, evidence, name, version, description, language };
  }

  const isLangGraph = checkHasPattern(allFiles, [
    "@langchain",
    "langgraph",
    "StateGraph",
    "createReactAgent",
    "from langchain"
  ]);
  if (isLangGraph) {
    evidence.push("LangGraph / LangChain orchestration patterns detected");
    return { type: "langgraph-agent", confidence: 0.85, evidence, name, version, description, language };
  }

  const isGeneric = checkHasPattern(allFiles, [
    "openai",
    "anthropic",
    "system_prompt",
    "tools",
    "agent"
  ]);
  if (isGeneric) {
    evidence.push("AI Agent prompt/tool interaction patterns detected");
    return { type: "generic-agent", confidence: 0.70, evidence, name, version, description, language };
  }

  return {
    type: "unknown",
    confidence: 0.30,
    evidence: ["Standard agent capability markers not detected"],
    name,
    version,
    description,
    language
  };
}

const CONTENT_SCAN_EXTS = new Set([".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs", ".py", ".json", ".md", ".yaml", ".yml"]);

function checkHasPattern(files: string[], patterns: string[]): boolean {
  for (const full of files) {
    if (!CONTENT_SCAN_EXTS.has(path.extname(full).toLowerCase())) continue;
    try {
      const st = fs.statSync(full);
      if (!st.isFile() || st.size > 512 * 1024) continue;
      const content = fs.readFileSync(full, "utf8");
      if (patterns.some(p => content.includes(p))) {
        return true;
      }
    } catch {}
  }
  return false;
}