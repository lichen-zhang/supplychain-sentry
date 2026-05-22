import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { readPackageJson } from '../rules/helpers.js';
import { analyzeInstallScriptStatically } from './static-analysis.js';

const execFileAsync = promisify(execFile);

export interface SandboxFinding {
  type: 'network' | 'file-access' | 'env-mutation' | 'persistence' | 'error' | 'info';
  message: string;
  detail?: string;
}

export interface SandboxResult {
  packageName: string;
  packageVersion: string;
  ran: boolean;
  skipped: boolean;
  skipReason?: string;
  findings: SandboxFinding[];
  stdout?: string;
  stderr?: string;
  durationMs?: number;
}

export interface SandboxOptions {
  timeoutSeconds?: number;
  verbose?: boolean;
}

let dockerAvailability: boolean | null = null;

export async function isDockerAvailable(): Promise<boolean> {
  if (dockerAvailability !== null) return dockerAvailability;

  try {
    await execFileAsync('docker', ['version', '--format', '{{.Server.Version}}'], {
      timeout: 5000,
      windowsHide: true,
    });
    dockerAvailability = true;
  } catch {
    dockerAvailability = false;
  }

  return dockerAvailability;
}

function getInstallScript(packagePath: string): { hook: string; command: string } | null {
  const packageJson = readPackageJson(packagePath);
  if (!packageJson?.scripts) return null;

  for (const hook of ['postinstall', 'install', 'preinstall'] as const) {
    const command = packageJson.scripts[hook];
    if (command && typeof command === 'string') {
      return { hook, command };
    }
  }
  return null;
}

function analyzeSandboxOutput(stdout: string, stderr: string): SandboxFinding[] {
  const findings: SandboxFinding[] = [];
  const combined = `${stdout}\n${stderr}`;

  const networkPatterns = [
    /ENOTFOUND|ECONNREFUSED|ETIMEDOUT/i,
    /fetch failed|network request|curl:|wget /i,
    /https?:\/\//i,
  ];
  if (networkPatterns.some((p) => p.test(combined))) {
    findings.push({
      type: 'network',
      message: 'Install script attempted or referenced network activity',
      detail: combined.split('\n').find((line) => /https?:\/\//.test(line))?.trim(),
    });
  }

  const filePatterns = [/\/etc\//, /\.ssh/, /\.aws/, /\.npmrc/, /\/passwd/];
  if (filePatterns.some((p) => p.test(combined))) {
    findings.push({
      type: 'file-access',
      message: 'Install script referenced sensitive filesystem paths',
      detail: combined.split('\n').find((line) => filePatterns.some((p) => p.test(line)))?.trim(),
    });
  }

  if (/process\.env|PATH=|export\s+[A-Z_]+=/i.test(combined)) {
    findings.push({
      type: 'env-mutation',
      message: 'Install script referenced environment variable mutation',
    });
  }

  if (/cron|setInterval|nohup|daemon|pm2|forever/i.test(combined)) {
    findings.push({
      type: 'persistence',
      message: 'Install script referenced persistent or background processes',
    });
  }

  return findings;
}

export async function runSandboxAnalysis(
  packagePath: string,
  packageName: string,
  packageVersion: string,
  options: SandboxOptions = {}
): Promise<SandboxResult> {
  const timeoutSeconds = options.timeoutSeconds ?? 30;
  const installScript = getInstallScript(packagePath);

  const staticFindings = analyzeInstallScriptStatically(packagePath);
  const staticAsSandbox: SandboxFinding[] = staticFindings.map((finding) => ({
    type: finding.type,
    message: `[Static] ${finding.message}`,
    detail: `${finding.source}: ${finding.evidence || ''}`.trim(),
  }));

  if (!installScript) {
    return {
      packageName,
      packageVersion,
      ran: false,
      skipped: true,
      skipReason: 'No install lifecycle script found',
      findings: staticAsSandbox,
    };
  }

  const dockerOk = await isDockerAvailable();
  if (!dockerOk) {
    return {
      packageName,
      packageVersion,
      ran: false,
      skipped: true,
      skipReason:
        'Docker is not available. Install Docker Desktop (Windows/macOS) or docker.io (Linux) to enable sandbox analysis.',
      findings: [
        ...staticAsSandbox,
        {
          type: 'info',
          message: 'Sandbox skipped because Docker is unavailable',
        },
      ],
    };
  }

  if (!existsSync(packagePath)) {
    return {
      packageName,
      packageVersion,
      ran: false,
      skipped: true,
      skipReason: 'Package directory not found in node_modules',
      findings: [],
    };
  }

  const start = Date.now();
  const mountPath = path.resolve(packagePath).replace(/\\/g, '/');
  const shellCommand = `cd /pkg && npm run ${installScript.hook} --if-present || ${installScript.command}`;

  try {
    const { stdout, stderr } = await execFileAsync(
      'docker',
      [
        'run',
        '--rm',
        '--security-opt',
        'no-new-privileges',
        '--cap-drop',
        'ALL',
        '--network=none',
        '--read-only',
        '--tmpfs',
        '/tmp:rw,noexec,nosuid,size=64m',
        '-v',
        `${mountPath}:/pkg:ro`,
        '-w',
        '/pkg',
        'node:20-alpine',
        'sh',
        '-c',
        shellCommand,
      ],
      {
        timeout: timeoutSeconds * 1000,
        maxBuffer: 1024 * 1024,
        windowsHide: true,
      }
    );

    const findings = [...staticAsSandbox, ...analyzeSandboxOutput(stdout, stderr)];
    return {
      packageName,
      packageVersion,
      ran: true,
      skipped: false,
      findings,
      stdout,
      stderr,
      durationMs: Date.now() - start,
    };
  } catch (error) {
    const err = error as { stdout?: string; stderr?: string; message?: string };
    const stdout = err.stdout || '';
    const stderr = err.stderr || err.message || '';
    const findings = [...staticAsSandbox, ...analyzeSandboxOutput(stdout, stderr)];

    if (findings.length === 0) {
      findings.push({
        type: 'error',
        message: 'Sandbox execution failed',
        detail: stderr.slice(0, 500),
      });
    }

    return {
      packageName,
      packageVersion,
      ran: true,
      skipped: false,
      findings,
      stdout,
      stderr,
      durationMs: Date.now() - start,
    };
  }
}

export function shouldRunSandbox(
  reputationScore: number,
  issues: { severity: string }[],
  threshold = 30
): boolean {
  const hasHighRisk = issues.some((issue) => issue.severity === 'critical' || issue.severity === 'high');
  return reputationScore < threshold || hasHighRisk;
}

export function readLocalPackageMeta(packagePath: string): { scripts: Record<string, string> } | null {
  try {
    return JSON.parse(readFileSync(path.join(packagePath, 'package.json'), 'utf-8'));
  } catch {
    return null;
  }
}
