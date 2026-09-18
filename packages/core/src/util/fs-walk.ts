import fs from "node:fs";
import path from "node:path";

export const IGNORE_DIRS = new Set([
  "node_modules",
  ".git",
  ".venv",
  "venv",
  "__pycache__",
  ".opentrustbench",
  "coverage",
  ".next",
  ".turbo"
]);

const DEFAULT_EXTS = new Set([
  ".ts",
  ".tsx",
  ".mts",
  ".cts",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".py",
  ".json",
  ".yaml",
  ".yml",
  ".md"
]);

export interface WalkOptions {
  extensions?: Set<string>;
  maxFiles?: number;
  maxDepth?: number;
}

export function inventoryFiles(dir: string, options: WalkOptions = {}) {
  const maxFiles = options.maxFiles ?? 4000;
  const maxDepth = options.maxDepth ?? 12;
  if (!Number.isInteger(maxFiles) || maxFiles < 1 || !Number.isInteger(maxDepth) || maxDepth < 0) {
    throw new Error("Invalid file inventory limits");
  }
  const files: string[] = [];
  const readErrors: { path: string; operation: "walk"; code: string }[] = [];
  const truncation: { path: string; reason: "max-files" | "max-depth" }[] = [];
  const excludedFiles: { path: string; reason: string }[] = [];
  let visited = 0;
  const relative = (file: string) => path.relative(dir, file) || ".";

  function walk(current: string, depth: number) {
    if (visited >= maxFiles) {
      truncation.push({ path: relative(current), reason: "max-files" });
      return;
    }
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(current);
    } catch (error) {
      readErrors.push({ path: relative(current), operation: "walk", code: (error as NodeJS.ErrnoException).code ?? "UNKNOWN" });
      return;
    }
    if (stat.isSymbolicLink() || (!stat.isFile() && !stat.isDirectory())) {
      visited++;
      excludedFiles.push({ path: relative(current), reason: "non-regular-file" });
      return;
    }
    if (stat.isFile()) {
      visited++;
      files.push(current);
      return;
    }
    if (depth > maxDepth) {
      truncation.push({ path: relative(current), reason: "max-depth" });
      return;
    }
    try {
      const entries = fs.readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
      for (const entry of entries) {
        const full = path.join(current, entry.name);
        if (entry.isDirectory() && IGNORE_DIRS.has(entry.name)) {
          excludedFiles.push({ path: relative(full), reason: "ignored-directory" });
          continue;
        }
        if (visited >= maxFiles) {
          truncation.push({ path: relative(full), reason: "max-files" });
          break;
        }
        walk(full, depth + 1);
      }
    } catch (error) {
      readErrors.push({ path: relative(current), operation: "walk", code: (error as NodeJS.ErrnoException).code ?? "UNKNOWN" });
    }
  }

  walk(dir, 0);
  return { files, readErrors, truncation, excludedFiles };
}

export function walkFiles(dir: string, options: WalkOptions = {}): string[] {
  const extensions = options.extensions ?? DEFAULT_EXTS;
  return inventoryFiles(dir, options).files.filter(file => extensions.size === 0 || extensions.has(path.extname(file).toLowerCase()));
}

export function listBasenamesLower(dir: string): string[] {
  try {
    return fs.readdirSync(dir).map(f => f.toLowerCase());
  } catch {
    return [];
  }
}
