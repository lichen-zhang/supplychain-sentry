import { getInstallScriptSources } from '../rules/helpers.js';
import {
  CHILD_PROCESS_REQUIRE,
  CURL_REGEX,
  ENV_EXPORT_REGEX,
  EVAL_REGEX,
  FETCH_REGEX,
  HTTP_GET_REGEX,
  NEW_FUNCTION_REGEX,
  SENSITIVE_FILE_REGEX,
} from '../rules/patterns.js';

export interface StaticSandboxFinding {
  source: string;
  type: 'network' | 'file-access' | 'env-mutation' | 'persistence' | 'error' | 'info';
  message: string;
  evidence?: string;
}

export function analyzeInstallScriptStatically(packagePath: string): StaticSandboxFinding[] {
  const findings: StaticSandboxFinding[] = [];
  const sources = getInstallScriptSources(packagePath);

  for (const source of sources) {
    if (EVAL_REGEX.test(source.content) || NEW_FUNCTION_REGEX.test(source.content)) {
      findings.push({
        source: source.label,
        type: 'error',
        message: 'Install script contains dynamic code execution',
        evidence: source.content.slice(0, 120),
      });
    }

    if (FETCH_REGEX.test(source.content) || HTTP_GET_REGEX.test(source.content) || CURL_REGEX.test(source.content)) {
      findings.push({
        source: source.label,
        type: 'network',
        message: 'Install script references outbound network APIs',
        evidence: source.content.slice(0, 120),
      });
    }

    if (SENSITIVE_FILE_REGEX.test(source.content)) {
      findings.push({
        source: source.label,
        type: 'file-access',
        message: 'Install script references sensitive filesystem paths',
        evidence: source.content.slice(0, 120),
      });
    }

    if (CHILD_PROCESS_REQUIRE.test(source.content) || /\bexecSync\b/.test(source.content)) {
      findings.push({
        source: source.label,
        type: 'persistence',
        message: 'Install script invokes shell/process execution',
        evidence: source.content.slice(0, 120),
      });
    }

    if (ENV_EXPORT_REGEX.test(source.content) || /\bprocess\.env\b/.test(source.content)) {
      findings.push({
        source: source.label,
        type: 'env-mutation',
        message: 'Install script reads or mutates environment variables',
        evidence: source.content.slice(0, 120),
      });
    }
  }

  return findings;
}
