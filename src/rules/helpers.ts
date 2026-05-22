import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';

export const INSTALL_LIFECYCLE_HOOKS = ['preinstall', 'install', 'postinstall'] as const;
export const ALL_LIFECYCLE_HOOKS = [
  'preinstall',
  'install',
  'postinstall',
  'prepublish',
  'prepare',
  'prepack',
  'postpack',
] as const;

export interface CodeSource {
  label: string;
  content: string;
}

export interface PackageJson {
  name?: string;
  version?: string;
  main?: string;
  bin?: string | Record<string, string>;
  scripts?: Record<string, string>;
  author?: string | { name?: string; email?: string; url?: string };
  repository?: string | { type?: string; url?: string; directory?: string };
  license?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

export function readPackageJson(pkgPath: string): PackageJson | null {
  const packageJsonPath = path.join(pkgPath, 'package.json');
  try {
    return JSON.parse(readFileSync(packageJsonPath, 'utf-8')) as PackageJson;
  } catch {
    return null;
  }
}

export function getMainEntry(pkgPath: string): string {
  const packageJson = readPackageJson(pkgPath);
  return packageJson?.main || 'index.js';
}

export function resolveScriptFile(pkgPath: string, scriptCommand: string): string | null {
  const nodeMatch = scriptCommand.match(/^node\s+["']?([^"'\s]+)["']?/);
  if (nodeMatch) {
    const candidate = path.join(pkgPath, nodeMatch[1]);
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

export function getInstallScriptSources(pkgPath: string): CodeSource[] {
  const packageJson = readPackageJson(pkgPath);
  if (!packageJson?.scripts) return [];

  const sources: CodeSource[] = [];
  for (const hook of INSTALL_LIFECYCLE_HOOKS) {
    const script = packageJson.scripts[hook];
    if (!script || typeof script !== 'string') continue;

    const scriptFile = resolveScriptFile(pkgPath, script);
    if (scriptFile) {
      try {
        sources.push({
          label: `scripts.${hook} -> ${path.basename(scriptFile)}`,
          content: readFileSync(scriptFile, 'utf-8'),
        });
      } catch {
        // unreadable script file
      }
    } else {
      sources.push({
        label: `scripts.${hook}`,
        content: script,
      });
    }
  }
  return sources;
}

export function getAllScannableSources(pkgPath: string): CodeSource[] {
  const sources: CodeSource[] = [];

  const mainEntry = getMainEntry(pkgPath);
  const mainPath = path.join(pkgPath, mainEntry);
  if (existsSync(mainPath)) {
    try {
      sources.push({
        label: mainEntry,
        content: readFileSync(mainPath, 'utf-8'),
      });
    } catch {
      // skip
    }
  }

  sources.push(...getInstallScriptSources(pkgPath));

  const packageJson = readPackageJson(pkgPath);
  if (packageJson?.bin) {
    const bins =
      typeof packageJson.bin === 'string'
        ? { [packageJson.name || 'bin']: packageJson.bin }
        : packageJson.bin;
    for (const [name, binPath] of Object.entries(bins)) {
      const fullPath = path.join(pkgPath, binPath);
      if (existsSync(fullPath)) {
        try {
          sources.push({
            label: `bin:${name}`,
            content: readFileSync(fullPath, 'utf-8'),
          });
        } catch {
          // skip
        }
      }
    }
  }

  return sources;
}

export function scanSources(
  sources: CodeSource[],
  matcher: (content: string, label: string) => RuleMatch | null
): RuleMatch | null {
  for (const source of sources) {
    const match = matcher(source.content, source.label);
    if (match) return match;
  }
  return null;
}

export interface RuleMatch {
  evidence?: string;
  message?: string;
}

export function extractRelevantCode(code: string, regex: RegExp): string {
  const lines = code.split('\n');
  const matches: string[] = [];
  const testRegex = new RegExp(regex.source, regex.flags.replace('g', ''));

  for (let i = 0; i < lines.length; i++) {
    if (testRegex.test(lines[i])) {
      matches.push(`Line ${i + 1}: ${lines[i].trim().substring(0, 100)}`);
      if (matches.length >= 3) break;
    }
  }

  return matches.join('\n');
}

export function findReadmePath(pkgPath: string): string | null {
  const readmePaths = ['README.md', 'README.txt', 'readme.md', 'Readme.md'];
  for (const readmePath of readmePaths) {
    const fullPath = path.join(pkgPath, readmePath);
    if (existsSync(fullPath)) return fullPath;
  }
  return null;
}

export function getSourceFileCount(pkgPath: string, maxDepth = 2): number {
  let count = 0;

  function walk(dir: string, depth: number) {
    if (depth > maxDepth) return;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry === 'node_modules' || entry.startsWith('.')) continue;
      const fullPath = path.join(dir, entry);
      try {
        const stat = statSync(fullPath);
        if (stat.isFile() && /\.(js|mjs|cjs|ts)$/.test(entry)) {
          count++;
        } else if (stat.isDirectory()) {
          walk(fullPath, depth + 1);
        }
      } catch {
        // skip
      }
    }
  }

  walk(pkgPath, 0);
  return count;
}
