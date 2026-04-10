import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  testMatch: ['tests/**/*.spec.ts', '*.spec.ts'],
  use: {
    ignoreHTTPSErrors: true,
  },
  reporter: [['line'], ['html', { outputFolder: 'playwright-report', open: 'never' }]],
  projects: [
    {
      name: 'integration-email',
      testMatch: '**/integration_email_security.spec.ts',
    },
    {
      name: 'integration-ldap',
      testMatch: '**/integration_ldap_security.spec.ts',
    },
    {
      name: 'module-integration-configs',
      testMatch: '**/module_config_security.spec.ts',
    },
  ],
});

