import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

export interface SentryConfig {
  ignorePackages?: string[];
  ignoreRules?: string[];
  thresholds?: {
    reputation?: number;
    severity?: 'critical' | 'high' | 'medium' | 'low' | 'none';
  };
  sandbox?: {
    enabled?: boolean;
    timeout?: number;
  };
  reputation?: {
    enabled?: boolean;
  };
  staticRules?: {
    enabled?: boolean;
  };
  output?: {
    json?: boolean;
    html?: boolean | string;
  };
  logging?: {
    verbose?: boolean;
    quiet?: boolean;
  };
}

export async function loadConfig(projectPath: string): Promise<SentryConfig> {
  const candidates = ['.sentryrc.json', 'sentry.config.json'];

  for (const fileName of candidates) {
    const configPath = join(projectPath, fileName);
    if (!existsSync(configPath)) continue;

    try {
      const content = readFileSync(configPath, 'utf-8');
      return JSON.parse(content) as SentryConfig;
    } catch (error) {
      console.warn(
        `Warning: Failed to parse ${fileName}:`,
        error instanceof Error ? error.message : String(error)
      );
    }
  }

  return {};
}

export function validateConfig(config: SentryConfig): string[] {
  const warnings: string[] = [];

  if (config.thresholds?.reputation !== undefined) {
    if (config.thresholds.reputation < 0 || config.thresholds.reputation > 100) {
      warnings.push('Reputation threshold must be between 0 and 100');
    }
  }

  if (config.thresholds?.severity !== undefined) {
    const validSeverities = ['critical', 'high', 'medium', 'low', 'none'];
    if (!validSeverities.includes(config.thresholds.severity)) {
      warnings.push(`Severity must be one of: ${validSeverities.join(', ')}`);
    }
  }

  if (config.sandbox?.timeout !== undefined && config.sandbox.timeout < 1) {
    warnings.push('Sandbox timeout must be at least 1 second');
  }

  return warnings;
}
