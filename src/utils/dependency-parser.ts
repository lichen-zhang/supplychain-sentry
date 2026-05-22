import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

export type LockFileType = 'package-lock.json' | 'pnpm-lock.yaml' | 'yarn.lock';

export interface DependencyInfo {
  name: string;
  version: string;
  resolved?: string;
  integrity?: string;
  dev?: boolean;
  optional?: boolean;
  depth?: number;
}

export function findLockFile(projectPath: string): string | null {
  const lockFiles: LockFileType[] = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'];

  for (const lockFile of lockFiles) {
    const lockPath = join(projectPath, lockFile);
    if (existsSync(lockPath)) {
      return lockPath;
    }
  }

  return null;
}

export function parseDependencies(projectPath: string): DependencyInfo[] {
  const lockPath = findLockFile(projectPath);
  if (!lockPath) {
    throw new Error('No lock file found. Please run npm install, pnpm install, or yarn install first.');
  }

  let deps: DependencyInfo[];
  if (lockPath.endsWith('package-lock.json')) {
    deps = parsePackageLock(lockPath);
  } else if (lockPath.endsWith('pnpm-lock.yaml')) {
    deps = parsePnpmLock(lockPath);
  } else if (lockPath.endsWith('yarn.lock')) {
    deps = parseYarnLock(lockPath);
  } else {
    throw new Error(`Unsupported lock file format: ${lockPath}`);
  }

  return deduplicateDependencies(deps);
}

function deduplicateDependencies(deps: DependencyInfo[]): DependencyInfo[] {
  const byName = new Map<string, DependencyInfo>();
  for (const dep of deps) {
    const existing = byName.get(dep.name);
    if (!existing || compareVersions(dep.version, existing.version) > 0) {
      byName.set(dep.name, dep);
    }
  }
  return Array.from(byName.values());
}

function compareVersions(a: string, b: string): number {
  const pa = a.replace(/^[^\d]*/, '').split('.').map(Number);
  const pb = b.replace(/^[^\d]*/, '').split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const diff = (pa[i] || 0) - (pb[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

function normalizePackageName(lockPath: string): string {
  const parts = lockPath.split('node_modules/');
  return parts[parts.length - 1].replace(/\\/g, '/');
}

function depthFromLockPath(lockPath: string): number {
  const segments = lockPath.split('node_modules/').length - 1;
  return Math.max(0, segments);
}

function parsePackageLock(lockPath: string): DependencyInfo[] {
  const content = JSON.parse(readFileSync(lockPath, 'utf-8'));
  const deps: DependencyInfo[] = [];

  if (content.packages) {
    for (const [name, info] of Object.entries(content.packages)) {
      if (name === '' || !name.includes('node_modules')) continue;

      const pkgName = normalizePackageName(name);
      const version = (info as { version?: string }).version;
      if (!version) continue;

      deps.push({
        name: pkgName,
        version,
        resolved: (info as { resolved?: string }).resolved,
        integrity: (info as { integrity?: string }).integrity,
        dev: (info as { dev?: boolean }).dev || false,
        optional: (info as { optional?: boolean }).optional || false,
        depth: depthFromLockPath(name),
      });
    }
    return deps;
  }

  if (content.dependencies) {
    walkPackageLockV1(content.dependencies, deps, 0);
  }

  return deps;
}

function walkPackageLockV1(
  tree: Record<string, unknown>,
  deps: DependencyInfo[],
  depth: number
): void {
  for (const [name, info] of Object.entries(tree)) {
    const node = info as {
      version?: string;
      resolved?: string;
      integrity?: string;
      dev?: boolean;
      optional?: boolean;
      dependencies?: Record<string, unknown>;
    };
    if (node.version) {
      deps.push({
        name,
        version: node.version,
        resolved: node.resolved,
        integrity: node.integrity,
        dev: node.dev || false,
        optional: node.optional || false,
        depth,
      });
    }
    if (node.dependencies) {
      walkPackageLockV1(node.dependencies, deps, depth + 1);
    }
  }
}

function parsePnpmLock(lockPath: string): DependencyInfo[] {
  const content = readFileSync(lockPath, 'utf-8');
  const deps: DependencyInfo[] = [];
  const lines = content.replace(/\r\n/g, '\n').split('\n');
  let currentPkg: Partial<DependencyInfo> | null = null;
  let inPackages = false;

  for (const line of lines) {
    if (line.trim() === 'packages:') {
      inPackages = true;
      continue;
    }

    if (!inPackages) continue;

    const legacyMatch = line.match(/^ {2}\/((?:@[^/]+\/)?[^@]+)@([^:]+):$/);
    const quotedMatch = line.match(/^ {2}['"]([^'"]+)['"]:\s*$/);
    const plainMatch = !legacyMatch && !quotedMatch
      ? line.match(/^ {2}((?:@[^/]+\/)?[^@\s]+)@([^:\s]+):\s*$/)
      : null;

    if (legacyMatch || quotedMatch || plainMatch) {
      if (currentPkg?.name && currentPkg.version) {
        deps.push(currentPkg as DependencyInfo);
      }

      if (legacyMatch) {
        currentPkg = {
          name: legacyMatch[1],
          version: legacyMatch[2],
          depth: 0,
        };
      } else if (plainMatch) {
        currentPkg = {
          name: plainMatch[1],
          version: plainMatch[2],
          depth: 0,
        };
      } else {
        const descriptor = quotedMatch![1];
        const atIndex = descriptor.lastIndexOf('@');
        currentPkg = {
          name: atIndex > 0 ? descriptor.slice(0, atIndex) : descriptor,
          version: atIndex > 0 ? descriptor.slice(atIndex + 1) : 'unknown',
          depth: 0,
        };
      }
      continue;
    }

    const integrityMatch = line.match(/integrity:\s+(sha512-[A-Za-z0-9+/=]+)/);
    if (integrityMatch && currentPkg) {
      currentPkg.integrity = integrityMatch[1].trim();
      continue;
    }

    const tarballMatch = line.match(/tarball:\s+(https?:\/\/[^\s},]+)/);
    if (tarballMatch && currentPkg) {
      currentPkg.resolved = tarballMatch[1].trim();
      continue;
    }

    const simpleResMatch = line.match(/^ {4}resolution:\s+"([^"]+)"/);
    if (simpleResMatch && currentPkg) {
      currentPkg.resolved = simpleResMatch[1];
    }
  }

  if (currentPkg?.name && currentPkg.version) {
    deps.push(currentPkg as DependencyInfo);
  }

  return deps;
}

function parseYarnLock(lockPath: string): DependencyInfo[] {
  const content = readFileSync(lockPath, 'utf-8');
  const deps: DependencyInfo[] = [];
  const lines = content.replace(/\r\n/g, '\n').split('\n');
  let currentPkg: Partial<DependencyInfo> | null = null;
  let inPackageBlock = false;

  for (const line of lines) {
    if (/^\s/.test(line)) {
      if (inPackageBlock && currentPkg) {
        const versionMatch = line.match(/^\s+version[:\s]+"([^"]+)"/);
        if (versionMatch) currentPkg.version = versionMatch[1];

        const resMatch = line.match(/^\s+resolved[:\s]+"([^"]+)"/);
        if (resMatch) currentPkg.resolved = resMatch[1];

        const intMatch = line.match(/^\s+integrity[:\s]+"([^"]+)"/);
        if (intMatch) currentPkg.integrity = intMatch[1];
      }
      continue;
    }

    const quotedHeader = line.match(/^"(.+@.+)":$/);
    const unquotedHeader = line.match(/^(?!")((?:@[^/]+\/)?[^@\s]+)@([^:\s]+):$/);

    if (quotedHeader || unquotedHeader) {
      if (currentPkg?.name && currentPkg.version) {
        deps.push(currentPkg as DependencyInfo);
      }

      if (unquotedHeader) {
        currentPkg = {
          name: unquotedHeader[1],
          version: unquotedHeader[2],
          depth: 0,
        };
      } else {
        const descriptor = quotedHeader![1];
        const atIndex = descriptor.lastIndexOf('@');
        currentPkg = {
          name: descriptor.slice(0, atIndex),
          version: descriptor.slice(atIndex + 1),
          depth: 0,
        };
      }

      inPackageBlock = true;
      continue;
    }

    if (line.trim() === '') {
      if (currentPkg?.name && currentPkg.version) {
        deps.push(currentPkg as DependencyInfo);
      }
      currentPkg = null;
      inPackageBlock = false;
    }
  }

  if (currentPkg?.name && currentPkg.version) {
    deps.push(currentPkg as DependencyInfo);
  }

  return deps;
}

export function getPackagePath(projectPath: string, packageName: string, version?: string): string {
  const direct = join(projectPath, 'node_modules', ...packageName.split('/'));
  if (existsSync(join(direct, 'package.json'))) {
    return direct;
  }

  if (version) {
    const pnpmFolder = packageName.startsWith('@')
      ? `${packageName.replace('/', '+')}@${version}`
      : `${packageName}@${version}`;
    const pnpmPath = join(
      projectPath,
      'node_modules',
      '.pnpm',
      pnpmFolder,
      'node_modules',
      ...packageName.split('/')
    );
    if (existsSync(join(pnpmPath, 'package.json'))) {
      return pnpmPath;
    }
  }

  return direct;
}

export function getMaxDependencyDepth(deps: DependencyInfo[]): number {
  return deps.reduce((max, dep) => Math.max(max, dep.depth ?? 0), 0);
}

export function getDirectDependencyCount(deps: DependencyInfo[]): number {
  return deps.filter((dep) => (dep.depth ?? 0) === 0).length;
}
