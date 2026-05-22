/**
 * NPM Registry API wrapper for fetching package metadata
 */

export interface PackageMetadata {
  name: string;
  version: string;
  description?: string;
  license?: string;
  author?: MaintainerInfo;
  maintainers: MaintainerInfo[];
  contributors?: MaintainerInfo[];
  repository?: RepositoryInfo;
  bugs?: BugsInfo;
  homepage?: string;
  keywords?: string[];
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  engines?: Record<string, string>;
  scripts?: Record<string, string>;
  funding?: FundingInfo | FundingInfo[];
  time: TimeInfo;
  dist: DistInfo;
}

export interface MaintainerInfo {
  name: string;
  email?: string;
  url?: string;
}

export interface RepositoryInfo {
  type: string;
  url: string;
}

export interface BugsInfo {
  url?: string;
  email?: string;
}

export interface FundingInfo {
  type: string;
  url: string;
}

export interface TimeInfo {
  created: string;
  modified: string;
  [key: string]: string;
}

export interface DistInfo {
  tarball: string;
  shasum: string;
  integrity?: string;
  signatures?: SignatureInfo[];
}

export interface SignatureInfo {
  keyid: string;
  sig: string;
}

export interface DownloadStats {
  downloads: number;
  start: string;
  end: string;
}

/**
 * Fetch package metadata from npm registry
 */
export async function fetchPackageMetadata(pkgName: string): Promise<PackageMetadata> {
  const url = `https://registry.npmjs.org/${encodeURIComponent(pkgName)}`;
  
  const response = await fetch(url, {
    headers: {
      'Accept': 'application/json',
    },
  });
  
  if (!response.ok) {
    if (response.status === 404) {
      throw new Error(`Package "${pkgName}" not found in npm registry`);
    }
    throw new Error(`Failed to fetch metadata for "${pkgName}": ${response.statusText}`);
  }
  
  const data = await response.json();
  return data as PackageMetadata;
}

/**
 * Fetch weekly download count for a package
 */
export async function fetchDownloadCount(pkgName: string): Promise<number> {
  const url = `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(pkgName)}`;
  
  const response = await fetch(url, {
    headers: {
      'Accept': 'application/json',
    },
  });
  
  if (!response.ok) {
    // Return 0 if package has no downloads or API error
    return 0;
  }
  
  const data = await response.json();
  return data.downloads || 0;
}

/**
 * Fetch all versions of a package
 */
export async function fetchPackageVersions(pkgName: string): Promise<string[]> {
  const metadata = await fetchPackageMetadata(pkgName);
  return Object.keys(metadata.time).filter(version => version !== 'created' && version !== 'modified');
}

/**
 * Get the latest version tag info
 */
export async function getLatestVersion(pkgName: string): Promise<string> {
  const metadata = await fetchPackageMetadata(pkgName);
  return metadata['dist-tags']?.latest || Object.keys(metadata.time).pop() || 'unknown';
}

/**
 * Fetch package history (time-based events)
 */
export async function fetchPackageHistory(pkgName: string): Promise<TimeInfo> {
  const metadata = await fetchPackageMetadata(pkgName);
  return metadata.time;
}

/**
 * Check if package has been published recently
 */
export async function isRecentlyUpdated(pkgName: string, daysThreshold: number = 90): Promise<boolean> {
  const history = await fetchPackageHistory(pkgName);
  const lastModified = new Date(history.modified);
  const now = new Date();
  const diffDays = (now.getTime() - lastModified.getTime()) / (1000 * 60 * 60 * 24);
  return diffDays <= daysThreshold;
}

/**
 * Get package maintainer information
 */
export function getMaintainers(metadata: PackageMetadata): MaintainerInfo[] {
  return [...metadata.maintainers];
}

/**
 * Get contributor information
 */
export function getContributors(metadata: PackageMetadata): MaintainerInfo[] {
  return metadata.contributors || [];
}

/**
 * Check if package has funding sources
 */
export function hasFunding(metadata: PackageMetadata): boolean {
  if (!metadata.funding) return false;
  if (Array.isArray(metadata.funding)) {
    return metadata.funding.length > 0;
  }
  return !!metadata.funding.url;
}

/**
 * Get total dependency count
 */
export function getTotalDependencyCount(metadata: PackageMetadata): number {
  let count = 0;
  count += Object.keys(metadata.dependencies || {}).length;
  count += Object.keys(metadata.devDependencies || {}).length;
  count += Object.keys(metadata.peerDependencies || {}).length;
  count += Object.keys(metadata.optionalDependencies || {}).length;
  return count;
}

/**
 * Check if package uses unsafe scripts
 */
export function hasUnsafeScripts(metadata: PackageMetadata): boolean {
  const dangerousScripts = ['install', 'postinstall', 'preinstall', 'prepare', 'prepublish'];
  return Object.keys(metadata.scripts || {}).some(script => 
    dangerousScripts.includes(script)
  );
}
