/**
 * Playwright Configuration for paranoid E2E Testing
 * 
 * This config runs browser tests against the paranoid password generator
 * to verify the full end-to-end flow: HTML → CSS → JS → WASM.
 * 
 * USAGE:
 *   # Via Docker Compose (recommended)
 *   docker compose up --build --abort-on-container-exit
 *   
 *   # Local (requires site to be served at localhost:8080)
 *   npx playwright test
 */

import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests/e2e',
  
  /* Maximum time one test can run */
  timeout: 30 * 1000,
  
  /* Run tests in parallel */
  fullyParallel: true,
  
  /* Fail the build on CI if you accidentally left test.only in the source code */
  forbidOnly: !!process.env.CI,
  
  /* Retry on CI only */
  retries: process.env.CI ? 2 : 0,
  
  /* Reporter to use */
  reporter: [
    ['html', { outputFolder: 'playwright-report' }],
    ['list'],
  ],
  
  /* Shared settings for all projects */
  use: {
    /* Base URL for all tests */
    baseURL: process.env.BASE_URL || 'http://localhost:8080',
    
    /* Collect trace when retrying the failed test */
    trace: 'on-first-retry',
    
    /* Screenshot on failure */
    screenshot: 'only-on-failure',
    
    /* Video on failure */
    video: 'on-first-retry',
  },

  /* Output folder for test artifacts */
  outputDir: 'test-results',

  /* Configure projects for major browsers */
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },
  ],
});
