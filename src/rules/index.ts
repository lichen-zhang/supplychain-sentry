import { readFileSync } from 'node:fs';
import { KNOWN_MALICIOUS_PACKAGES, OFFICIAL_REGISTRIES } from './blacklist.js';
import {
  ALL_LIFECYCLE_HOOKS,
  extractRelevantCode,
  findReadmePath,
  getAllScannableSources,
  getSourceFileCount,
  readPackageJson,
  scanSources,
} from './helpers.js';
import {
  AXIOS_REGEX,
  BASE64_REGEX,
  CHILD_PROCESS_REQUIRE,
  CURL_REGEX,
  ENV_EXPORT_REGEX,
  EVAL_REGEX,
  EXEC_REGEX,
  FETCH_REGEX,
  HTTP_GET_REGEX,
  NEW_FUNCTION_REGEX,
  SENSITIVE_FILE_REGEX,
  SPAWN_REGEX,
  TIMER_STRING_REGEX,
} from './patterns.js';

export interface RuleResult {
  ruleId: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  packageName: string;
  message: string;
  evidence?: string;
  recommendation?: string;
}

export type RuleFunction = (
  pkgPath: string,
  pkgName: string,
  context?: RuleContext
) => Promise<RuleResult | null>;

export interface RuleContext {
  resolved?: string;
  dependencyDepth?: number;
}

export async function detectSuspiciousPackageName(
  _pkgPath: string,
  pkgName: string
): Promise<RuleResult | null> {
  const suspiciousPatterns = [
    /npm-worm/i,
    /malware/i,
    /backdoor/i,
    /keylogger/i,
    /ransomware/i,
    /trojan/i,
    /cryptominer/i,
    /coinminer/i,
    /stealer/i,
    /infostealer/i,
    /data-theft/i,
    /credential-harvester/i,
  ];

  for (const pattern of suspiciousPatterns) {
    if (pattern.test(pkgName)) {
      return {
        ruleId: 'R001',
        severity: 'critical',
        packageName: pkgName,
        message: `Package name contains suspicious pattern matching "${pattern.source}"`,
        recommendation: 'Do not install this package. It may be a known malicious package.',
      };
    }
  }

  return null;
}

export async function detectEvalCall(pkgPath: string, pkgName: string): Promise<RuleResult | null> {
  const sources = getAllScannableSources(pkgPath);
  const match = scanSources(sources, (content, label) => {
    if (EVAL_REGEX.test(content)) {
      return {
        message: `Dynamic code execution via eval() in ${label}`,
        evidence: extractRelevantCode(content, EVAL_REGEX),
      };
    }
    if (NEW_FUNCTION_REGEX.test(content)) {
      return {
        message: `Dynamic code execution via new Function() in ${label}`,
        evidence: extractRelevantCode(content, NEW_FUNCTION_REGEX),
      };
    }
    return null;
  });

  if (match) {
    return {
      ruleId: 'R002',
      severity: 'high',
      packageName: pkgName,
      message: match.message || 'Package uses dynamic code execution',
      evidence: match.evidence,
      recommendation: 'Review install scripts and entry files for arbitrary code execution.',
    };
  }
  return null;
}

export async function detectTimersWithStrings(
  pkgPath: string,
  pkgName: string
): Promise<RuleResult | null> {
  const sources = getAllScannableSources(pkgPath);
  const match = scanSources(sources, (content, label) => {
    if (TIMER_STRING_REGEX.test(content)) {
      return {
        message: `setTimeout/setInterval with string argument in ${label}`,
        evidence: extractRelevantCode(content, TIMER_STRING_REGEX),
      };
    }
    return null;
  });

  if (match) {
    return {
      ruleId: 'R003',
      severity: 'medium',
      packageName: pkgName,
      message: match.message || 'Timer with string argument detected',
      evidence: match.evidence,
      recommendation: 'Pass a function reference instead of a string.',
    };
  }
  return null;
}

export async function detectChildProcess(
  pkgPath: string,
  pkgName: string
): Promise<RuleResult | null> {
  const sources = getAllScannableSources(pkgPath);
  const match = scanSources(sources, (content, label) => {
    if (EXEC_REGEX.test(content) || CHILD_PROCESS_REQUIRE.test(content)) {
      return {
        message: `Shell command execution via child_process in ${label}`,
        evidence: extractRelevantCode(content, EXEC_REGEX),
      };
    }
    if (SPAWN_REGEX.test(content)) {
      return {
        message: `Process spawn detected in ${label}`,
        evidence: extractRelevantCode(content, SPAWN_REGEX),
      };
    }
    return null;
  });

  if (match) {
    return {
      ruleId: 'R004',
      severity: 'high',
      packageName: pkgName,
      message: match.message || 'Package executes external commands',
      evidence: match.evidence,
      recommendation: 'Ensure command inputs are sanitized and scripts are reviewed.',
    };
  }
  return null;
}

export async function detectUnencryptedNetwork(
  pkgPath: string,
  pkgName: string
): Promise<RuleResult | null> {
  const sources = getAllScannableSources(pkgPath);
  const httpRegex =
    /http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

  for (const source of sources) {
    const matches = source.content.match(httpRegex);
    if (matches?.length) {
      return {
        ruleId: 'R005',
        severity: 'medium',
        packageName: pkgName,
        message: `Unencrypted HTTP URLs in ${source.label}`,
        evidence: matches.slice(0, 3).join(', '),
        recommendation: 'Use HTTPS for all network communications.',
      };
    }
  }
  return null;
}

export async function detectBase64Strings(
  pkgPath: string,
  pkgName: string
): Promise<RuleResult | null> {
  const sources = getAllScannableSources(pkgPath);

  for (const source of sources) {
    const matches = source.content.match(BASE64_REGEX);
    if (!matches) continue;

    for (const match of matches) {
      const b64Str = match.replace(/["']/g, '');
      try {
        const decoded = Buffer.from(b64Str, 'base64').toString('utf-8');
        if (/[\{\};\(\)=<>!+\-*/&|%^~?]/.test(decoded) && decoded.length > 20) {
          return {
            ruleId: 'R006',
            severity: 'high',
            packageName: pkgName,
            message: `Obfuscated base64-encoded code in ${source.label}`,
            evidence: `${b64Str.substring(0, 50)}...`,
            recommendation: 'Review decoded content for malicious behavior.',
          };
        }
      } catch {
        // invalid base64
      }
    }
  }
  return null;
}

export async function detectRemoteCodeDownload(
  pkgPath: string,
  pkgName: string
): Promise<RuleResult | null> {
  const sources = getAllScannableSources(pkgPath);
  const networkRegex = new RegExp(
    [FETCH_REGEX.source, HTTP_GET_REGEX.source, AXIOS_REGEX.source, CURL_REGEX.source].join('|')
  );

  const match = scanSources(sources, (content, label) => {
    if (networkRegex.test(content)) {
      return {
        message: `Network request detected in ${label}`,
        evidence: extractRelevantCode(content, FETCH_REGEX),
      };
    }
    return null;
  });

  if (match) {
    return {
      ruleId: 'R007',
      severity: 'medium',
      packageName: pkgName,
      message: match.message || 'Package initiates network requests',
      evidence: match.evidence,
      recommendation: 'Verify remote endpoints and downloaded content.',
    };
  }
  return null;
}

export async function detectInstallHooks(pkgPath: string, pkgName: string): Promise<RuleResult | null> {
  const packageJson = readPackageJson(pkgPath);
  if (!packageJson?.scripts) return null;

  const foundHooks = ALL_LIFECYCLE_HOOKS.filter(
    (hook) => packageJson.scripts?.[hook] && typeof packageJson.scripts[hook] === 'string'
  );

  if (foundHooks.length === 0) return null;

  const dangerous = ['install', 'postinstall', 'preinstall'];
  const hasDangerousHook = foundHooks.some((h) => dangerous.includes(h));

  return {
    ruleId: 'R008',
    severity: hasDangerousHook ? 'high' : 'medium',
    packageName: pkgName,
    message: `Package defines lifecycle hook(s): ${foundHooks.join(', ')}`,
    evidence: foundHooks.map((h) => `${h}: ${packageJson.scripts![h]}`).join('; '),
    recommendation: 'Review lifecycle scripts for malicious behavior.',
  };
}

export async function detectExcessiveDependencies(
  pkgPath: string,
  pkgName: string
): Promise<RuleResult | null> {
  const packageJson = readPackageJson(pkgPath);
  if (!packageJson) return null;

  const totalDeps =
    Object.keys(packageJson.dependencies || {}).length +
    Object.keys(packageJson.devDependencies || {}).length;

  if (totalDeps > 50) {
    return {
      ruleId: 'R009',
      severity: 'low',
      packageName: pkgName,
      message: `Package has excessive dependencies (${totalDeps} total)`,
      evidence: `dependencies: ${Object.keys(packageJson.dependencies || {}).length}, devDependencies: ${Object.keys(packageJson.devDependencies || {}).length}`,
      recommendation: 'Large dependency trees increase attack surface.',
    };
  }
  return null;
}

export async function detectMissingDocumentation(
  pkgPath: string,
  pkgName: string
): Promise<RuleResult | null> {
  if (!findReadmePath(pkgPath)) {
    return {
      ruleId: 'R010',
      severity: 'low',
      packageName: pkgName,
      message: 'Package lacks documentation (no README found)',
      recommendation: 'Well-maintained packages typically include documentation.',
    };
  }
  return null;
}

export async function detectSensitiveFileAccess(
  pkgPath: string,
  pkgName: string
): Promise<RuleResult | null> {
  const sources = getAllScannableSources(pkgPath);
  const match = scanSources(sources, (content, label) => {
    if (SENSITIVE_FILE_REGEX.test(content)) {
      return {
        message: `Sensitive file or env access in ${label}`,
        evidence: extractRelevantCode(content, SENSITIVE_FILE_REGEX),
      };
    }
    return null;
  });

  if (match) {
    return {
      ruleId: 'R011',
      severity: 'high',
      packageName: pkgName,
      message: match.message || 'Access to sensitive files or environment detected',
      evidence: match.evidence,
      recommendation: 'Packages should not read credentials, SSH keys, or export process.env.',
    };
  }
  return null;
}

export async function detectKnownMaliciousPackage(
  _pkgPath: string,
  pkgName: string
): Promise<RuleResult | null> {
  const baseName = pkgName.includes('/') ? pkgName.split('/').pop()! : pkgName;
  if (KNOWN_MALICIOUS_PACKAGES.has(pkgName) || KNOWN_MALICIOUS_PACKAGES.has(baseName)) {
    return {
      ruleId: 'R012',
      severity: 'critical',
      packageName: pkgName,
      message: 'Package matches community-reported malicious package blacklist',
      recommendation: 'Remove this dependency immediately and audit your lock file history.',
    };
  }
  return null;
}

export async function detectSuspiciousReadme(
  pkgPath: string,
  pkgName: string
): Promise<RuleResult | null> {
  const readmePath = findReadmePath(pkgPath);
  if (!readmePath) return null;

  try {
    const content = readFileSync(readmePath, 'utf-8').trim();
    const sourceFiles = getSourceFileCount(pkgPath);

    if (content.length > 5000 && sourceFiles <= 1) {
      return {
        ruleId: 'R013',
        severity: 'medium',
        packageName: pkgName,
        message: 'Unusually long README relative to minimal code (possible padding attack)',
        evidence: `README: ${content.length} chars, source files: ${sourceFiles}`,
        recommendation: 'Review whether documentation is artificially inflated.',
      };
    }

    const uniqueWords = new Set(content.toLowerCase().split(/\s+/).filter(Boolean));
    if (content.length > 2000 && uniqueWords.size < 50) {
      return {
        ruleId: 'R013',
        severity: 'medium',
        packageName: pkgName,
        message: 'README appears repetitive or low-information (heuristic)',
        evidence: `${uniqueWords.size} unique words in ${content.length} characters`,
        recommendation: 'Verify package legitimacy beyond surface documentation.',
      };
    }
  } catch {
    // unreadable readme
  }
  return null;
}

export async function detectNonOfficialRegistry(
  _pkgPath: string,
  pkgName: string,
  context?: RuleContext
): Promise<RuleResult | null> {
  if (!context?.resolved) return null;

  if (/^(file:|link:)/.test(context.resolved)) return null;

  try {
    const host = new URL(context.resolved).hostname;
    if (!OFFICIAL_REGISTRIES.some((registry) => host === registry || host.endsWith(`.${registry}`))) {
      return {
        ruleId: 'R014',
        severity: 'high',
        packageName: pkgName,
        message: `Package resolved from non-official registry: ${host}`,
        evidence: context.resolved,
        recommendation: 'Prefer packages from registry.npmjs.org unless using a trusted private registry.',
      };
    }
  } catch {
    // invalid URL
  }
  return null;
}

function getAuthorName(author: unknown): string {
  if (!author) return '';
  if (typeof author === 'string') return author;
  if (typeof author === 'object' && author !== null && 'name' in author) {
    return String((author as { name?: string }).name || '');
  }
  return '';
}

function getRepositoryUrl(repository: unknown): string {
  if (!repository) return '';
  if (typeof repository === 'string') return repository;
  if (typeof repository === 'object' && repository !== null && 'url' in repository) {
    return String((repository as { url?: string }).url || '');
  }
  return '';
}

export async function detectSuspiciousMetadata(
  pkgPath: string,
  pkgName: string
): Promise<RuleResult | null> {
  const packageJson = readPackageJson(pkgPath);
  if (!packageJson) return null;

  const issues: string[] = [];
  const author = getAuthorName(packageJson.author).trim();
  const repo = getRepositoryUrl(packageJson.repository).trim();

  if (!author) issues.push('missing author');
  if (!repo) issues.push('missing repository');

  if (author && repo) {
    const authorToken = author.toLowerCase().replace(/[^a-z0-9]/g, '');
    const repoLower = repo.toLowerCase();
    if (authorToken.length > 2 && !repoLower.includes(authorToken.slice(0, 4))) {
      issues.push('author/repository mismatch');
    }
  }

  if (issues.length === 0) return null;

  return {
    ruleId: 'R015',
    severity: issues.includes('missing repository') ? 'medium' : 'low',
    packageName: pkgName,
    message: `Suspicious package.json metadata: ${issues.join(', ')}`,
    evidence: `author="${author || 'N/A'}", repository="${repo || 'N/A'}"`,
    recommendation: 'Verify maintainer identity and source repository before trusting the package.',
  };
}

export async function detectEnvExportInScripts(
  pkgPath: string,
  pkgName: string
): Promise<RuleResult | null> {
  const sources = getAllScannableSources(pkgPath);
  const match = scanSources(sources, (content, label) => {
    if (ENV_EXPORT_REGEX.test(content)) {
      return {
        message: `Environment variable export or mutation in ${label}`,
        evidence: extractRelevantCode(content, ENV_EXPORT_REGEX),
      };
    }
    return null;
  });

  if (match) {
    return {
      ruleId: 'R016',
      severity: 'medium',
      packageName: pkgName,
      message: match.message || 'Script modifies or exports process.env',
      evidence: match.evidence,
      recommendation: 'Install scripts should not alter environment variables.',
    };
  }
  return null;
}

export const rules: Record<string, RuleFunction> = {
  R001: detectSuspiciousPackageName,
  R002: detectEvalCall,
  R003: detectTimersWithStrings,
  R004: detectChildProcess,
  R005: detectUnencryptedNetwork,
  R006: detectBase64Strings,
  R007: detectRemoteCodeDownload,
  R008: detectInstallHooks,
  R009: detectExcessiveDependencies,
  R010: detectMissingDocumentation,
  R011: detectSensitiveFileAccess,
  R012: detectKnownMaliciousPackage,
  R013: detectSuspiciousReadme,
  R014: detectNonOfficialRegistry,
  R015: detectSuspiciousMetadata,
  R016: detectEnvExportInScripts,
};

export const ruleMetadata: Record<
  string,
  { name: string; description: string; falsePositiveRisk: 'low' | 'medium' | 'high' }
> = {
  R001: {
    name: 'Suspicious Package Name',
    description: 'Detects package names containing malicious keywords',
    falsePositiveRisk: 'low',
  },
  R002: {
    name: 'Eval Usage',
    description: 'Detects eval() or new Function() in entry files and install scripts',
    falsePositiveRisk: 'medium',
  },
  R003: {
    name: 'Timer with String',
    description: 'Detects setTimeout/setInterval with string arguments',
    falsePositiveRisk: 'medium',
  },
  R004: {
    name: 'Child Process Execution',
    description: 'Detects child_process exec/spawn usage in code and scripts',
    falsePositiveRisk: 'medium',
  },
  R005: {
    name: 'Unencrypted Network',
    description: 'Detects unencrypted HTTP URLs in code',
    falsePositiveRisk: 'low',
  },
  R006: {
    name: 'Obfuscated Code',
    description: 'Detects suspicious base64-encoded strings',
    falsePositiveRisk: 'medium',
  },
  R007: {
    name: 'Network Requests',
    description: 'Detects fetch, http(s).request, axios, curl in code and scripts',
    falsePositiveRisk: 'medium',
  },
  R008: {
    name: 'Lifecycle Hooks',
    description: 'Detects install lifecycle hooks in package.json scripts',
    falsePositiveRisk: 'low',
  },
  R009: {
    name: 'Excessive Dependencies',
    description: 'Detects packages with unusually large dependency trees',
    falsePositiveRisk: 'low',
  },
  R010: {
    name: 'Missing Documentation',
    description: 'Detects packages without README',
    falsePositiveRisk: 'high',
  },
  R011: {
    name: 'Sensitive File Access',
    description: 'Detects reads of ~/.npmrc, ~/.aws/credentials, /etc/passwd, .env',
    falsePositiveRisk: 'medium',
  },
  R012: {
    name: 'Malicious Package Blacklist',
    description: 'Matches community-reported malicious package names',
    falsePositiveRisk: 'low',
  },
  R013: {
    name: 'Suspicious README',
    description: 'Heuristic for padded or low-information README content',
    falsePositiveRisk: 'high',
  },
  R014: {
    name: 'Non-Official Registry',
    description: 'Detects packages resolved from outside registry.npmjs.org',
    falsePositiveRisk: 'medium',
  },
  R015: {
    name: 'Suspicious Metadata',
    description: 'Detects missing or mismatched author/repository fields',
    falsePositiveRisk: 'medium',
  },
  R016: {
    name: 'Environment Export',
    description: 'Detects process.env export or mutation in scripts',
    falsePositiveRisk: 'medium',
  },
};

export function getHighestSeverity(
  issues: RuleResult[]
): 'critical' | 'high' | 'medium' | 'low' | 'info' | 'none' {
  const order = ['critical', 'high', 'medium', 'low', 'info'] as const;
  for (const level of order) {
    if (issues.some((i) => i.severity === level)) return level;
  }
  return 'none';
}
