/** Community-reported malicious or compromised package names */
export const KNOWN_MALICIOUS_PACKAGES = new Set([
  'flatmap-stream',
  'eslint-scope',
  'crossenv',
  'cross-env.js',
  'babelcli',
  'babel-cli',
  'colors.js',
  'faker',
  'npm-api-client',
  'discord.js-selfbot-v13',
  'discord-selfbot-v11',
  'discord-selfbot-v12',
  'discord-selfbot-tools',
  'event-stream',
  'rc-extended',
  'ua-parser-js',
  'coa',
  'rc',
  'node-ipc',
  'peacenotwar',
  'styled-components-package',
  'npm-compromised-pkg-test',
]);

export const OFFICIAL_REGISTRIES = [
  'registry.npmjs.org',
  'registry.yarnpkg.com',
];
