import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';

export type LockFileType = 'package-lock.json' | 'pnpm-lock.yaml' | 'yarn.lock';

export interface DependencyInfo {
  name: string;
  version: string;
  resolved?: string;
  integrity?: string;
  dev?: boolean;
  optional?: boolean;
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

  if (lockPath.endsWith('package-lock.json')) {
    return parsePackageLock(lockPath);
  } else if (lockPath.endsWith('pnpm-lock.yaml')) {
    return parsePnpmLock(lockPath);
  } else if (lockPath.endsWith('yarn.lock')) {
    return parseYarnLock(lockPath);
  }

  throw new Error(`Unsupported lock file format: ${lockPath}`);
}

function parsePackageLock(lockPath: string): DependencyInfo[] {
  const content = JSON.parse(readFileSync(lockPath, 'utf-8'));
  const deps: DependencyInfo[] = [];

  if (!content.packages) {
    return deps;
  }

  for (const [name, info] of Object.entries(content.packages)) {
    // Skip root package and node_modules entries
    if (name === '' || !name.startsWith('node_modules/')) {
      continue;
    }

    const pkgName = name.replace(/^node_modules\//, '');
    const version = (info as any).version;
    
    if (!version) {
      continue;
    }

    const dep: DependencyInfo = {
      name: pkgName,
      version,
      resolved: (info as any).resolved,
      integrity: (info as any).integrity,
      dev: (info as any).dev || false,
      optional: (info as any).optional || false,
    };

    deps.push(dep);
  }

  return deps;
}

function parsePnpmLock(lockPath: string): DependencyInfo[] {
  const content = readFileSync(lockPath, 'utf-8');
  const deps: DependencyInfo[] = [];
  
  // Simple YAML parser for pnpm-lock.yaml
  const lines = content.split('\n');
  let currentPkg: Partial<DependencyInfo> | null = null;
  
  for (const line of lines) {
    // Match package entry like " /package-name@1.0.0:"
    const pkgMatch = line.match(/^ +\/([^@]+)@([^:]+):$/);
    if (pkgMatch) {
      if (currentPkg && currentPkg.name && currentPkg.version) {
        deps.push(currentPkg as DependencyInfo);
      }
      currentPkg = {
        name: pkgMatch[1],
        version: pkgMatch[2],
      };
      continue;
    }
    
    // Match resolution field
    const resMatch = line.match(/^    resolution:\s+"([^"]+)"/);
    if (resMatch && currentPkg) {
      currentPkg.resolved = resMatch[1];
      continue;
    }
    
    // Match checksum field
    const chkMatch = line.match(/^    checksum:\s+"([^"]+)"/);
    if (chkMatch && currentPkg) {
      currentPkg.integrity = `sha512-${chkMatch[1]}`;
      continue;
    }
  }
  
  // Don't forget the last package
  if (currentPkg && currentPkg.name && currentPkg.version) {
    deps.push(currentPkg as DependencyInfo);
  }
  
  return deps;
}

function parseYarnLock(lockPath: string): DependencyInfo[] {
  const content = readFileSync(lockPath, 'utf-8');
  const deps: DependencyInfo[] = [];
  
  // Simple Yarn lock parser
  const lines = content.split('\n');
  let currentPkg: Partial<DependencyInfo> | null = null;
  let inPackageBlock = false;
  
  for (const line of lines) {
    // Match package entry like "package@1.0.0:"
    const pkgMatch = line.match(/^("[^"]+"|[^:]+)@([^:]+):$/);
    if (pkgMatch) {
      if (currentPkg && currentPkg.name && currentPkg.version) {
        deps.push(currentPkg as DependencyInfo);
      }
      
      const name = pkgMatch[1].replace(/"/g, '');
      currentPkg = {
        name,
        version: pkgMatch[2],
      };
      inPackageBlock = true;
      continue;
    }
    
    // Empty line ends package block
    if (line.trim() === '') {
      if (currentPkg && currentPkg.name && currentPkg.version) {
        deps.push(currentPkg as DependencyInfo);
      }
      currentPkg = null;
      inPackageBlock = false;
      continue;
    }
    
    if (inPackageBlock && currentPkg) {
      // Match resolved field
      const resMatch = line.match(/^\s+resolved:\s+"([^"]+)"/);
      if (resMatch) {
        currentPkg.resolved = resMatch[1];
        continue;
      }
      
      // Match integrity/checksum field
      const intMatch = line.match(/^\s+integrity:\s+"([^"]+)"/);
      if (intMatch) {
        currentPkg.integrity = intMatch[1];
        continue;
      }
    }
  }
  
  // Don't forget the last package
  if (currentPkg && currentPkg.name && currentPkg.version) {
    deps.push(currentPkg as DependencyInfo);
  }
  
  return deps;
}

export function getPackagePath(projectPath: string, packageName: string): string {
  return join(projectPath, 'node_modules', packageName);
}

export async function downloadPackage(packageName: string, version: string, destDir: string): Promise<string> {
  const { exec } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const { mkdtemp, writeFile } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  
  const execAsync = promisify(exec);
  
  // Create temp directory
  const tempDir = await mkdtemp(join(tmpdir(), 'scs-'));
  
  try {
    // Use npm pack to download the package
    await execAsync(`npm pack ${packageName}@${version} --pack-destination ${tempDir}`, {
      timeout: 60000,
    });
    
    // Extract the tarball
    const { execSync } = await import('node:child_process');
    const tarball = execSync(`ls ${tempDir}/*.tgz`, { encoding: 'utf-8' }).trim();
    
    // Return path to extracted package
    return tempDir;
  } catch (error) {
    throw new Error(`Failed to download package ${packageName}@${version}: ${error instanceof Error ? error.message : String(error)}`);
  }
}
