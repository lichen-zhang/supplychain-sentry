import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/cli.ts'],
  format: ['cjs', 'esm'],
  dts: true,
  clean: true,
  shims: true,
  sourcemap: true,
  minify: true,
  outDir: 'dist',
  target: 'node18',
  platform: 'node',
  splitting: false,
  treeshake: true,
});
