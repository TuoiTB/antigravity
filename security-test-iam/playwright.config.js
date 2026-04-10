// @ts-check
const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './tests',
  testMatch: '**/*.spec.js',
  use: {
    ignoreHTTPSErrors: true,
  },
  reporter: [
    ['line'],
    ['html', { outputFolder: 'playwright-report', open: 'never' }],
  ],
  projects: [
    {
      name: 'integration-email',
      testDir: './tests/integration-email',
      testMatch: '**/*.spec.js',
    },
    {
      name: 'integration-ldap',
      testDir: './tests/integration-ldap',
      testMatch: '**/*.spec.js',
    },
    {
      name: 'module-integration-configs',
      testDir: './tests/module-integration-configs',
      testMatch: '**/*.spec.js',
    },
  ],
});
