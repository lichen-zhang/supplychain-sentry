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

interface NpmPackument {
  name: string;
  'dist-tags'?: Record<string, string>;
  maintainers?: MaintainerInfo[];
  time?: TimeInfo;
  versions?: Record<string, Partial<PackageMetadata>>;
}

export function normalizePackument(data: NpmPackument): PackageMetadata {
  const latest =
    data['dist-tags']?.latest ||
    Object.keys(data.versions || {})
      .filter((v) => v !== 'created' && v !== 'modified')
      .sort()
      .pop();

  const versionData = latest && data.versions ? data.versions[latest] : undefined;

  return {
    name: data.name,
    version: latest || 'unknown',
    description: versionData?.description,
    license: typeof versionData?.license === 'string' ? versionData.license : undefined,
    author: versionData?.author as MaintainerInfo | undefined,
    maintainers: data.maintainers || versionData?.maintainers || [],
    contributors: versionData?.contributors,
    repository: versionData?.repository as RepositoryInfo | undefined,
    bugs: versionData?.bugs as BugsInfo | undefined,
    homepage: versionData?.homepage,
    keywords: versionData?.keywords,
    dependencies: versionData?.dependencies,
    devDependencies: versionData?.devDependencies,
    peerDependencies: versionData?.peerDependencies,
    optionalDependencies: versionData?.optionalDependencies,
    engines: versionData?.engines,
    scripts: versionData?.scripts,
    funding: versionData?.funding as FundingInfo | FundingInfo[] | undefined,
    time: data.time || { created: '', modified: '' },
    dist: (versionData?.dist as DistInfo) || { tarball: '', shasum: '' },
  };
}

export async function fetchPackageMetadata(pkgName: string): Promise<PackageMetadata> {
  const url = `https://registry.npmjs.org/${encodeURIComponent(pkgName)}`;

  const response = await fetch(url, {
    headers: {
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    if (response.status === 404) {
      throw new Error(`Package "${pkgName}" not found in npm registry`);
    }
    throw new Error(`Failed to fetch metadata for "${pkgName}": ${response.statusText}`);
  }

  const data = (await response.json()) as NpmPackument;
  return normalizePackument(data);
}

export async function fetchDownloadCount(pkgName: string): Promise<number> {
  const url = `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(pkgName)}`;

  const response = await fetch(url, {
    headers: {
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    return 0;
  }

  const data = (await response.json()) as { downloads?: number };
  return data.downloads || 0;
}

export async function fetchPackageVersions(pkgName: string): Promise<string[]> {
  const metadata = await fetchPackageMetadata(pkgName);
  return Object.keys(metadata.time).filter((version) => version !== 'created' && version !== 'modified');
}

export async function getLatestVersion(pkgName: string): Promise<string> {
  const metadata = await fetchPackageMetadata(pkgName);
  return metadata.version;
}

export async function fetchPackageHistory(pkgName: string): Promise<TimeInfo> {
  const metadata = await fetchPackageMetadata(pkgName);
  return metadata.time;
}

export async function isRecentlyUpdated(pkgName: string, daysThreshold = 90): Promise<boolean> {
  const history = await fetchPackageHistory(pkgName);
  const lastModified = new Date(history.modified);
  const now = new Date();
  const diffDays = (now.getTime() - lastModified.getTime()) / (1000 * 60 * 60 * 24);
  return diffDays <= daysThreshold;
}

export function getMaintainers(metadata: PackageMetadata): MaintainerInfo[] {
  return [...metadata.maintainers];
}

export function getContributors(metadata: PackageMetadata): MaintainerInfo[] {
  return metadata.contributors || [];
}

export function hasFunding(metadata: PackageMetadata): boolean {
  if (!metadata.funding) return false;
  if (Array.isArray(metadata.funding)) {
    return metadata.funding.length > 0;
  }
  return !!metadata.funding.url;
}

export function getTotalDependencyCount(metadata: PackageMetadata): number {
  let count = 0;
  count += Object.keys(metadata.dependencies || {}).length;
  count += Object.keys(metadata.devDependencies || {}).length;
  count += Object.keys(metadata.peerDependencies || {}).length;
  count += Object.keys(metadata.optionalDependencies || {}).length;
  return count;
}

export function hasUnsafeScripts(metadata: PackageMetadata): boolean {
  const dangerousScripts = ['install', 'postinstall', 'preinstall', 'prepare', 'prepublish'];
  return Object.keys(metadata.scripts || {}).some((script) => dangerousScripts.includes(script));
}
