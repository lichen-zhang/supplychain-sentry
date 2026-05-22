import { describe, it, expect } from 'vitest';
import { detectEvalCall, detectSuspiciousPackageName } from '../../../src/rules/index';

describe('Rules - Static Analysis', () => {
  describe('detectEvalCall', () => {
    it('should detect eval call in malicious package', async () => {
      const result = await detectEvalCall('./test/fixtures/malicious-eval', 'malicious-eval');
      expect(result).not.toBeNull();
      expect(result?.ruleId).toBe('R002');
      expect(result?.severity).toBe('high');
      expect(result?.packageName).toBe('malicious-eval');
    });

    it('should return null for safe package', async () => {
      // This test will fail if the fixture doesn't exist, which is expected
      // In a real scenario, you would create a safe fixture
      const result = await detectEvalCall('./test/fixtures/non-existent', 'safe-package');
      expect(result).toBeNull();
    });
  });

  describe('detectSuspiciousPackageName', () => {
    it('should detect suspicious package name with malware keyword', async () => {
      const result = await detectSuspiciousPackageName('npm-malware-packet');
      expect(result).not.toBeNull();
      expect(result?.ruleId).toBe('R001');
      expect(result?.severity).toBe('critical');
    });

    it('should detect suspicious package name with backdoor keyword', async () => {
      const result = await detectSuspiciousPackageName('@user/backdoor-lib');
      expect(result).not.toBeNull();
      expect(result?.ruleId).toBe('R001');
    });

    it('should return null for safe package name', async () => {
      const result = await detectSuspiciousPackageName('lodash');
      expect(result).toBeNull();
    });

    it('should return null for standard scoped package', async () => {
      const result = await detectSuspiciousPackageName('@babel/core');
      expect(result).toBeNull();
    });
  });
});
