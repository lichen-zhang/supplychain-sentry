import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  detectEvalCall,
  detectSuspiciousPackageName,
  detectInstallHooks,
  detectSensitiveFileAccess,
  detectRemoteCodeDownload,
  detectKnownMaliciousPackage,
  detectSuspiciousMetadata,
  rules,
  ruleMetadata,
} from '../../../src/rules/index';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixtures = path.join(__dirname, '../../fixtures');

describe('Rules - Static Analysis', () => {
  it('exports at least 12 rules', () => {
    expect(Object.keys(rules).length).toBeGreaterThanOrEqual(12);
    expect(Object.keys(ruleMetadata).length).toBeGreaterThanOrEqual(12);
  });

  describe('detectEvalCall', () => {
    it('detects eval in main entry', async () => {
      const result = await detectEvalCall(path.join(fixtures, 'malicious-eval'), 'malicious-eval');
      expect(result?.ruleId).toBe('R002');
      expect(result?.severity).toBe('high');
    });

    it('detects new Function in postinstall script', async () => {
      const result = await detectEvalCall(
        path.join(fixtures, 'malicious-postinstall'),
        'malicious-postinstall'
      );
      expect(result?.ruleId).toBe('R002');
    });
  });

  describe('detectInstallHooks', () => {
    it('reads scripts section correctly', async () => {
      const result = await detectInstallHooks(
        path.join(fixtures, 'malicious-postinstall'),
        'malicious-postinstall'
      );
      expect(result?.ruleId).toBe('R008');
      expect(result?.evidence).toContain('postinstall');
    });
  });

  describe('detectRemoteCodeDownload', () => {
    it('detects https.get in install script', async () => {
      const result = await detectRemoteCodeDownload(
        path.join(fixtures, 'malicious-network'),
        'malicious-network'
      );
      expect(result?.ruleId).toBe('R007');
    });
  });

  describe('detectSensitiveFileAccess', () => {
    it('detects sensitive credential paths', async () => {
      const result = await detectSensitiveFileAccess(
        path.join(fixtures, 'malicious-sensitive'),
        'malicious-sensitive'
      );
      expect(result?.ruleId).toBe('R011');
    });
  });

  describe('detectSuspiciousPackageName', () => {
    it('detects malware keyword in package name', async () => {
      const result = await detectSuspiciousPackageName('', 'npm-malware-packet');
      expect(result?.ruleId).toBe('R001');
    });

    it('returns null for safe package name', async () => {
      const result = await detectSuspiciousPackageName('', 'lodash');
      expect(result).toBeNull();
    });
  });

  describe('detectKnownMaliciousPackage', () => {
    it('flags blacklisted package names', async () => {
      const result = await detectKnownMaliciousPackage('', 'flatmap-stream');
      expect(result?.ruleId).toBe('R012');
      expect(result?.severity).toBe('critical');
    });
  });

  describe('detectSuspiciousMetadata', () => {
    it('does not flag well-documented safe package', async () => {
      const result = await detectSuspiciousMetadata(path.join(fixtures, 'safe-package'), 'safe-package');
      expect(result).toBeNull();
    });
  });
});
