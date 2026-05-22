import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    exclude: ['node_modules', 'dist'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'json-summary'],
      include: [
        'src/rules/**',
        'src/reputation/**',
        'src/utils/**',
        'src/config/**',
        'src/orchestrator.ts',
        'src/reporters/json.ts',
      ],
      thresholds: {
        lines: 80,
        functions: 80,
        statements: 80,
        branches: 58,
      },
    },
  },
  esbuild: {
    target: 'node18',
  },
});
