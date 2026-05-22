import { PackageMetadata, DownloadStats } from './npm-api.js';

export interface ReputationScore {
  total: number;           // 0-100 overall score
  maintainerScore: number; // Score based on maintainers count and activity
  recencyScore: number;    // Score based on last update time
  popularityScore: number; // Score based on download statistics
  complexityScore: number; // Score based on dependency complexity
  securityScore: number;   // Score based on security indicators
}

export interface ScoreBreakdown {
  factors: ScoreFactor[];
  warnings: string[];
}

export interface ScoreFactor {
  name: string;
  score: number;
  maxScore: number;
  weight: number;
  description: string;
}

/**
 * Calculate reputation score for a package
 */
export function calculateReputationScore(
  metadata: PackageMetadata,
  downloadStats?: DownloadStats
): ReputationScore & ScoreBreakdown {
  const factors: ScoreFactor[] = [];
  const warnings: string[] = [];

  // 1. Maintainer Score (weight: 20%)
  const maintainerScore = calculateMaintainerScore(metadata);
  factors.push({
    name: 'Maintainers',
    score: maintainerScore.score,
    maxScore: maintainerScore.max,
    weight: 0.2,
    description: maintainerScore.description,
  });
  if (maintainerScore.warnings.length > 0) {
    warnings.push(...maintainerScore.warnings);
  }

  // 2. Recency Score (weight: 20%)
  const recencyScore = calculateRecencyScore(metadata.time);
  factors.push({
    name: 'Last Updated',
    score: recencyScore.score,
    maxScore: recencyScore.max,
    weight: 0.2,
    description: recencyScore.description,
  });
  if (recencyScore.warnings.length > 0) {
    warnings.push(...recencyScore.warnings);
  }

  // 3. Popularity Score (weight: 25%)
  const popularityScore = calculatePopularityScore(downloadStats);
  factors.push({
    name: 'Downloads',
    score: popularityScore.score,
    maxScore: popularityScore.max,
    weight: 0.25,
    description: popularityScore.description,
  });
  if (popularityScore.warnings.length > 0) {
    warnings.push(...popularityScore.warnings);
  }

  // 4. Complexity Score (weight: 15%)
  const complexityScore = calculateComplexityScore(metadata);
  factors.push({
    name: 'Dependencies',
    score: complexityScore.score,
    maxScore: complexityScore.max,
    weight: 0.15,
    description: complexityScore.description,
  });
  if (complexityScore.warnings.length > 0) {
    warnings.push(...complexityScore.warnings);
  }

  // 5. Security Score (weight: 20%)
  const securityScore = calculateSecurityScore(metadata);
  factors.push({
    name: 'Security Indicators',
    score: securityScore.score,
    maxScore: securityScore.max,
    weight: 0.2,
    description: securityScore.description,
  });
  if (securityScore.warnings.length > 0) {
    warnings.push(...securityScore.warnings);
  }

  // Calculate weighted total
  const total = Math.round(
    factors.reduce((sum, factor) => sum + (factor.score * factor.weight), 0)
  );

  return {
    total,
    maintainerScore: maintainerScore.score,
    recencyScore: recencyScore.score,
    popularityScore: popularityScore.score,
    complexityScore: complexityScore.score,
    securityScore: securityScore.score,
    factors,
    warnings,
  };
}

/**
 * Calculate maintainer score based on maintainers count and contributors
 */
function calculateMaintainerScore(metadata: PackageMetadata): {
  score: number;
  max: number;
  description: string;
  warnings: string[];
} {
  const warnings: string[] = [];
  const maintainersCount = metadata.maintainers?.length || 0;
  const contributorsCount = metadata.contributors?.length || 0;
  const totalActiveMaintainers = maintainersCount + contributorsCount;

  let score = 0;
  let description = '';

  if (totalActiveMaintainers === 0) {
    score = 0;
    description = 'No maintainers or contributors found';
    warnings.push('Package has no listed maintainers');
  } else if (totalActiveMaintainers === 1) {
    score = 40;
    description = `Single maintainer (${maintainersCount} maintainer${maintainersCount > 1 ? 's' : ''})`;
    warnings.push('Package has only one maintainer - consider bus factor risk');
  } else if (totalActiveMaintainers <= 3) {
    score = 70;
    description = `${totalActiveMaintainers} active maintainers/contributors`;
  } else if (totalActiveMaintainers <= 5) {
    score = 85;
    description = `${totalActiveMaintainers} active maintainers/contributors`;
  } else {
    score = 100;
    description = `${totalActiveMaintainers} active maintainers/contributors`;
  }

  // Bonus for having funding
  if (metadata.funding) {
    score = Math.min(100, score + 10);
    description += ' (has funding)';
  }

  return { score, max: 100, description, warnings };
}

/**
 * Calculate recency score based on last update time
 */
function calculateRecencyScore(timeInfo: Record<string, string>): {
  score: number;
  max: number;
  description: string;
  warnings: string[];
} {
  const warnings: string[] = [];
  const lastModified = new Date(timeInfo.modified || timeInfo.created || Date.now().toString());
  const now = new Date();
  const diffDays = Math.floor((now.getTime() - lastModified.getTime()) / (1000 * 60 * 60 * 24));

  let score = 0;
  let description = '';

  if (diffDays < 7) {
    score = 100;
    description = 'Updated within the last week';
  } else if (diffDays < 30) {
    score = 90;
    description = `Updated ${diffDays} days ago`;
  } else if (diffDays < 90) {
    score = 75;
    description = `Updated ${diffDays} days ago`;
  } else if (diffDays < 180) {
    score = 50;
    description = `Updated ${diffDays} days ago`;
    warnings.push('Package not updated in the last 6 months');
  } else if (diffDays < 365) {
    score = 25;
    description = `Updated ${diffDays} days ago`;
    warnings.push('Package not updated in the last year');
  } else {
    score = 0;
    description = `Updated ${diffDays} days ago`;
    warnings.push('Package appears to be abandoned (not updated in over a year)');
  }

  return { score, max: 100, description, warnings };
}

/**
 * Calculate popularity score based on download statistics
 */
function calculatePopularityScore(downloadStats?: DownloadStats): {
  score: number;
  max: number;
  description: string;
  warnings: string[];
} {
  const warnings: string[] = [];
  const downloads = downloadStats?.downloads || 0;

  let score = 0;
  let description = '';

  if (downloads === 0) {
    score = 0;
    description = 'No download data available';
    warnings.push('No download statistics available');
  } else if (downloads >= 1_000_000) {
    score = 100;
    description = `${downloads.toLocaleString()} weekly downloads`;
  } else if (downloads >= 100_000) {
    score = 85;
    description = `${downloads.toLocaleString()} weekly downloads`;
  } else if (downloads >= 10_000) {
    score = 70;
    description = `${downloads.toLocaleString()} weekly downloads`;
  } else if (downloads >= 1_000) {
    score = 50;
    description = `${downloads.toLocaleString()} weekly downloads`;
  } else if (downloads >= 100) {
    score = 30;
    description = `${downloads.toLocaleString()} weekly downloads`;
    warnings.push('Low download count');
  } else {
    score = 10;
    description = `${downloads.toLocaleString()} weekly downloads`;
    warnings.push('Very low download count');
  }

  return { score, max: 100, description, warnings };
}

/**
 * Calculate complexity score based on dependency count
 */
function calculateComplexityScore(metadata: PackageMetadata): {
  score: number;
  max: number;
  description: string;
  warnings: string[];
} {
  const warnings: string[] = [];
  
  const depsCount = Object.keys(metadata.dependencies || {}).length;
  const devDepsCount = Object.keys(metadata.devDependencies || {}).length;
  const peerDepsCount = Object.keys(metadata.peerDependencies || {}).length;
  const optionalDepsCount = Object.keys(metadata.optionalDependencies || {}).length;
  
  const totalDeps = depsCount + devDepsCount + peerDepsCount + optionalDepsCount;

  let score = 0;
  let description = '';

  if (totalDeps === 0) {
    score = 100;
    description = 'No dependencies (zero-dependency package)';
  } else if (totalDeps <= 3) {
    score = 90;
    description = `${totalDeps} dependencies`;
  } else if (totalDeps <= 10) {
    score = 75;
    description = `${totalDeps} dependencies`;
  } else if (totalDeps <= 20) {
    score = 50;
    description = `${totalDeps} dependencies`;
    warnings.push('Moderate dependency count');
  } else if (totalDeps <= 50) {
    score = 30;
    description = `${totalDeps} dependencies`;
    warnings.push('High dependency count increases attack surface');
  } else {
    score = 10;
    description = `${totalDeps} dependencies`;
    warnings.push('Very high dependency count - significant supply chain risk');
  }

  return { score, max: 100, description, warnings };
}

/**
 * Calculate security score based on security indicators
 */
function calculateSecurityScore(metadata: PackageMetadata): {
  score: number;
  max: number;
  description: string;
  warnings: string[];
} {
  const warnings: string[] = [];
  let score = 100;

  // Check for dangerous scripts
  const dangerousScripts = ['install', 'postinstall', 'preinstall', 'prepare'];
  const hasDangerousScript = Object.keys(metadata.scripts || {}).some(script =>
    dangerousScripts.includes(script)
  );

  if (hasDangerousScript) {
    score -= 20;
    warnings.push('Package defines potentially dangerous lifecycle scripts');
  }

  // Check for missing README
  if (!metadata.description && !metadata.homepage) {
    score -= 15;
    warnings.push('Package lacks description or homepage');
  }

  // Check for missing repository
  if (!metadata.repository) {
    score -= 10;
    warnings.push('Package has no repository URL');
  }

  // Check for missing license
  if (!metadata.license) {
    score -= 10;
    warnings.push('Package has no license specified');
  }

  // Check for private packages
  if (metadata.name.startsWith('@') && metadata.name.split('/')[1]?.startsWith('-')) {
    score -= 5;
    warnings.push('Package name suggests it may be private/internal');
  }

  // Ensure score doesn't go below 0
  score = Math.max(0, score);

  return {
    score,
    max: 100,
    description: `Security score: ${score}/100`,
    warnings,
  };
}

/**
 * Get score grade based on total score
 */
export function getScoreGrade(score: number): 'A+' | 'A' | 'B' | 'C' | 'D' | 'F' {
  if (score >= 95) return 'A+';
  if (score >= 85) return 'A';
  if (score >= 70) return 'B';
  if (score >= 55) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

/**
 * Get color code for score display
 */
export function getScoreColor(score: number): string {
  if (score >= 80) return '\x1b[32m'; // Green
  if (score >= 60) return '\x1b[33m'; // Yellow
  if (score >= 40) return '\x1b[31m'; // Red
  return '\x1b[35m'; // Purple
}

/**
 * Reset ANSI color codes
 */
export function resetColor(): string {
  return '\x1b[0m';
}
