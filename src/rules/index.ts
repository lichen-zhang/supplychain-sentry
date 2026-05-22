import { readFileSync } from 'node:fs';
import path from 'node:path';

export interface RuleResult {
  ruleId: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  packageName: string;
  message: string;
  evidence?: string;
  recommendation?: string;
}

export type RuleFunction = (pkgPath: string, pkgName: string) => Promise<RuleResult | null>;

// R001: Suspicious package name patterns
export async function detectSuspiciousPackageName(pkgName: string): Promise<RuleResult | null> {
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

// R002: eval() usage detection
export async function detectEvalCall(pkgPath: string, pkgName: string): Promise<RuleResult | null> {
  const mainEntry = getMainEntry(pkgPath);
  const entryPath = path.join(pkgPath, mainEntry);
  
  try {
    const code = readFileSync(entryPath, 'utf-8');
    
    // Detect eval( or new Function( patterns, ignoring comments
    const evalRegex = /(?:^|[^a-zA-Z0-9_$])eval\s*\(/;
    const functionRegex = /(?:^|[^a-zA-Z0-9_$])new\s+Function\s*\(/;
    
    if (evalRegex.test(code)) {
      return {
        ruleId: 'R002',
        severity: 'high',
        packageName: pkgName,
        message: 'Package uses eval() which can execute arbitrary code',
        evidence: extractRelevantCode(code, evalRegex),
        recommendation: 'Consider using safer alternatives like JSON.parse() or specific parsers.',
      };
    }
    
    if (functionRegex.test(code)) {
      return {
        ruleId: 'R002',
        severity: 'high',
        packageName: pkgName,
        message: 'Package uses new Function() which can execute arbitrary code',
        evidence: extractRelevantCode(code, functionRegex),
        recommendation: 'Consider using safer alternatives like JSON.parse() or specific parsers.',
      };
    }
  } catch (e) {
    // File not found or unreadable, skip
  }
  
  return null;
}

// R003: setTimeout/setInterval with string argument
export async function detectTimersWithStrings(pkgPath: string, pkgName: string): Promise<RuleResult | null> {
  const mainEntry = getMainEntry(pkgPath);
  const entryPath = path.join(pkgPath, mainEntry);
  
  try {
    const code = readFileSync(entryPath, 'utf-8');
    
    // Detect setTimeout/setInterval with string argument
    const timerRegex = /\b(setTimeout|setInterval)\s*\(\s*["'\`]/;
    
    if (timerRegex.test(code)) {
      return {
        ruleId: 'R003',
        severity: 'medium',
        packageName: pkgName,
        message: 'Package uses setTimeout/setInterval with string argument (similar to eval)',
        evidence: extractRelevantCode(code, timerRegex),
        recommendation: 'Pass a function reference instead of a string.',
      };
    }
  } catch (e) {
    // File not found or unreadable, skip
  }
  
  return null;
}

// R004: Child process execution
export async function detectChildProcess(pkgPath: string, pkgName: string): Promise<RuleResult | null> {
  const mainEntry = getMainEntry(pkgPath);
  const entryPath = path.join(pkgPath, mainEntry);
  
  try {
    const code = readFileSync(entryPath, 'utf-8');
    
    // Detect child_process.exec/ execFile/ spawn with shell option
    const execRegex = /\bexec\s*\(\s*["'\`]/;
    const execFileRegex = /\bexecFile\s*\(\s*["'\`]/;
    const spawnRegex = /\bspawn\s*\([^)]*shell\s*[:=]\s*true/;
    
    if (execRegex.test(code) || execFileRegex.test(code)) {
      return {
        ruleId: 'R004',
        severity: 'high',
        packageName: pkgName,
        message: 'Package executes shell commands via child_process.exec/execFile',
        evidence: extractRelevantCode(code, execRegex),
        recommendation: 'Ensure command inputs are properly sanitized and validated.',
      };
    }
    
    if (spawnRegex.test(code)) {
      return {
        ruleId: 'R004',
        severity: 'medium',
        packageName: pkgName,
        message: 'Package spawns shell processes with shell option enabled',
        evidence: extractRelevantCode(code, spawnRegex),
        recommendation: 'Disable shell option unless absolutely necessary.',
      };
    }
  } catch (e) {
    // File not found or unreadable, skip
  }
  
  return null;
}

// R005: Unencrypted network requests
export async function detectUnencryptedNetwork(pkgPath: string, pkgName: string): Promise<RuleResult | null> {
  const mainEntry = getMainEntry(pkgPath);
  const entryPath = path.join(pkgPath, mainEntry);
  
  try {
    const code = readFileSync(entryPath, 'utf-8');
    
    // Detect http:// URLs (unencrypted)
    const httpRegex = /https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const matches = code.match(httpRegex);
    
    if (matches && matches.some(url => url.startsWith('http://'))) {
      const insecureUrls = matches.filter(url => url.startsWith('http://'));
      return {
        ruleId: 'R005',
        severity: 'medium',
        packageName: pkgName,
        message: 'Package contains unencrypted HTTP URLs',
        evidence: insecureUrls.slice(0, 3).join(', '),
        recommendation: 'Use HTTPS for all network communications.',
      };
    }
  } catch (e) {
    // File not found or unreadable, skip
  }
  
  return null;
}

// R006: Suspicious base64 encoded strings
export async function detectBase64Strings(pkgPath: string, pkgName: string): Promise<RuleResult | null> {
  const mainEntry = getMainEntry(pkgPath);
  const entryPath = path.join(pkgPath, mainEntry);
  
  try {
    const code = readFileSync(entryPath, 'utf-8');
    
    // Detect long base64-like strings that might be obfuscated code
    const base64Regex = /["']([A-Za-z0-9+/]{50,}={0,2})["']/g;
    const matches = code.match(base64Regex);
    
    if (matches && matches.length > 0) {
      // Try to decode and check if it looks like code
      for (const match of matches) {
        const b64Str = match.replace(/["']/g, '');
        try {
          const decoded = Buffer.from(b64Str, 'base64').toString('utf-8');
          // Check if decoded content looks like JavaScript
          if (/[\{\};\(\)=<>!+\-*/&|%^~?]/.test(decoded) && decoded.length > 20) {
            return {
              ruleId: 'R006',
              severity: 'high',
              packageName: pkgName,
              message: 'Package contains suspicious base64-encoded strings that may be obfuscated code',
              evidence: `${b64Str.substring(0, 50)}...`,
              recommendation: 'Review the decoded content for potential malicious code.',
            };
          }
        } catch (e) {
          // Invalid base64, continue
        }
      }
    }
  } catch (e) {
    // File not found or unreadable, skip
  }
  
  return null;
}

// R007: Remote code download
export async function detectRemoteCodeDownload(pkgPath: string, pkgName: string): Promise<RuleResult | null> {
  const mainEntry = getMainEntry(pkgPath);
  const entryPath = path.join(pkgPath, mainEntry);
  
  try {
    const code = readFileSync(entryPath, 'utf-8');
    
    // Detect fetch/axios/get with dynamic URLs
    const fetchRegex = /\bfetch\s*\(\s*["'\`][^"\`]*\$\{|\bfetch\s*\(\s*["'\`][^"\`]*\)/;
    const axiosGetRegex = /\baxios\.get\s*\(\s*["'\`][^"\`]*\$\{|\baxios\.get\s*\(\s*["'\`][^"\`]*\)/;
    const httpsGetRegex = /\bhttps\.get\s*\(/;
    
    if (fetchRegex.test(code) || axiosGetRegex.test(code) || httpsGetRegex.test(code)) {
      return {
        ruleId: 'R007',
        severity: 'medium',
        packageName: pkgName,
        message: 'Package downloads code from remote sources',
        evidence: extractRelevantCode(code, fetchRegex),
        recommendation: 'Ensure downloaded code is verified and sandboxed before execution.',
      };
    }
  } catch (e) {
    // File not found or unreadable, skip
  }
  
  return null;
}

// R008: Package.json lifecycle hooks
export async function detectInstallHooks(pkgPath: string, pkgName: string): Promise<RuleResult | null> {
  const packageJsonPath = path.join(pkgPath, 'package.json');
  
  try {
    const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));
    const hooks = ['preinstall', 'postinstall', 'prepublish', 'prepare', 'prepack', 'postpack'];
    const dangerousScripts = ['install', 'postinstall', 'preinstall'];
    
    const foundHooks: string[] = [];
    
    for (const hook of hooks) {
      if (packageJson[hook] && typeof packageJson[hook] === 'string') {
        foundHooks.push(hook);
      }
    }
    
    if (foundHooks.length > 0) {
      const hasDangerousHook = dangerousHooks.some(h => foundHooks.includes(h));
      
      return {
        ruleId: 'R008',
        severity: hasDangerousHook ? 'high' : 'medium',
        packageName: pkgName,
        message: `Package defines ${foundHooks.length} lifecycle hook(s): ${foundHooks.join(', ')}`,
        evidence: foundHooks.join(', '),
        recommendation: 'Review lifecycle scripts for potentially malicious behavior.',
      };
    }
  } catch (e) {
    // package.json not found or invalid, skip
  }
  
  return null;
}

// R009: Excessive dependencies
export async function detectExcessiveDependencies(pkgPath: string, pkgName: string): Promise<RuleResult | null> {
  const packageJsonPath = path.join(pkgPath, 'package.json');
  
  try {
    const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));
    const deps = Object.keys(packageJson.dependencies || {});
    const devDeps = Object.keys(packageJson.devDependencies || {});
    const totalDeps = deps.length + devDeps.length;
    
    if (totalDeps > 50) {
      return {
        ruleId: 'R009',
        severity: 'low',
        packageName: pkgName,
        message: `Package has excessive dependencies (${totalDeps} total)`,
        evidence: `dependencies: ${deps.length}, devDependencies: ${devDeps.length}`,
        recommendation: 'Consider if all dependencies are necessary. Large dependency trees increase attack surface.',
      };
    }
  } catch (e) {
    // package.json not found or invalid, skip
  }
  
  return null;
}

// R010: Missing README or documentation
export async function detectMissingDocumentation(pkgPath: string, pkgName: string): Promise<RuleResult | null> {
  const readmePaths = ['README.md', 'README.txt', 'readme.md'];
  let hasReadme = false;
  
  for (const readmePath of readmePaths) {
    try {
      const stat = await import('node:fs').then(m => m.statSync(path.join(pkgPath, readmePath)));
      if (stat.isFile()) {
        hasReadme = true;
        break;
      }
    } catch (e) {
      // File doesn't exist, continue checking
    }
  }
  
  if (!hasReadme) {
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

// Helper functions
function getMainEntry(pkgPath: string): string {
  const packageJsonPath = path.join(pkgPath, 'package.json');
  try {
    const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));
    return packageJson.main || 'index.js';
  } catch (e) {
    return 'index.js';
  }
}

function extractRelevantCode(code: string, regex: RegExp): string {
  const lines = code.split('\n');
  const matches: string[] = [];
  
  for (let i = 0; i < lines.length; i++) {
    if (regex.test(lines[i])) {
      matches.push(`Line ${i + 1}: ${lines[i].trim().substring(0, 100)}`);
      if (matches.length >= 3) break;
    }
  }
  
  return matches.join('\n');
}

const dangerousHooks = ['install', 'postinstall', 'preinstall'];

// Export all rules
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
};

export const ruleMetadata: Record<string, { name: string; description: string }> = {
  R001: {
    name: 'Suspicious Package Name',
    description: 'Detects package names containing malicious keywords',
  },
  R002: {
    name: 'Eval Usage',
    description: 'Detects use of eval() or new Function() which can execute arbitrary code',
  },
  R003: {
    name: 'Timer with String',
    description: 'Detects setTimeout/setInterval with string arguments',
  },
  R004: {
    name: 'Child Process Execution',
    description: 'Detects execution of shell commands via child_process',
  },
  R005: {
    name: 'Unencrypted Network',
    description: 'Detects unencrypted HTTP URLs in code',
  },
  R006: {
    name: 'Obfuscated Code',
    description: 'Detects suspicious base64-encoded strings that may be obfuscated code',
  },
  R007: {
    name: 'Remote Code Download',
    description: 'Detects downloading code from remote sources',
  },
  R008: {
    name: 'Lifecycle Hooks',
    description: 'Detects package.json lifecycle hooks that run during installation',
  },
  R009: {
    name: 'Excessive Dependencies',
    description: 'Detects packages with an unusually large number of dependencies',
  },
  R010: {
    name: 'Missing Documentation',
    description: 'Detects packages without README or documentation',
  },
};
