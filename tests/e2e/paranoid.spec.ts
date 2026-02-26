/**
 * paranoid E2E Tests — Full System Verification
 *
 * These tests verify the complete end-to-end flow:
 *   HTML → CSS → JavaScript → WASM → Password Generation
 *
 * The same cryptographic logic tested in acutest C tests
 * is exercised here through the browser interface to ensure:
 *   1. WASM loads and initializes correctly
 *   2. UI renders properly (CSS wizard state machine)
 *   3. Password generation works through JS bridge
 *   4. Audit stages complete successfully
 *   5. Statistical tests pass (chi-squared, serial correlation)
 *   6. Results are displayed correctly
 *
 * Run via Docker Compose:
 *   docker compose up --build --abort-on-container-exit
 */

import { test, expect } from '@playwright/test';

test.describe('paranoid Password Generator E2E', () => {

  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    // Wait for WASM to load — app.js sets #status-text to 'ready'
    await page.waitForFunction(() => {
      const el = document.getElementById('status-text');
      return el && el.textContent === 'ready';
    }, { timeout: 15000 });
  });

  test('page loads and WASM initializes', async ({ page }) => {
    // Verify page title
    await expect(page).toHaveTitle(/paranoid/i);

    // Verify engine badge shows WASI OpenSSL DRBG
    const engineBadge = page.locator('#engine-badge');
    await expect(engineBadge).toHaveText('WASI OpenSSL DRBG');

    // Verify status shows ready
    const statusText = page.locator('#status-text');
    await expect(statusText).toHaveText('ready');
  });

  test('generate password with default settings', async ({ page }) => {
    // Click launch button
    const launchBtn = page.locator('#btn-launch');
    await launchBtn.click();

    // Wait for audit to complete — app.js sets data-stage="complete" on #audit-runner
    await page.waitForSelector('#audit-runner[data-stage="complete"]', {
      timeout: 30000
    });

    // Verify password was generated (displayed in #audit-password div)
    const passwordEl = page.locator('#audit-password');
    const password = await passwordEl.textContent();
    expect(password).toBeTruthy();
    expect(password!.length).toBeGreaterThanOrEqual(8);
  });

  test('password generation produces unique results', async ({ page }) => {
    const passwords: string[] = [];

    // Generate 3 passwords and verify uniqueness (fewer to save time)
    for (let i = 0; i < 3; i++) {
      // Full page reload to reset wizard state between generations
      if (i > 0) {
        await page.goto('/');
        await page.waitForFunction(() => {
          const el = document.getElementById('status-text');
          return el && el.textContent === 'ready';
        }, { timeout: 15000 });
      }

      const launchBtn = page.locator('#btn-launch');
      await launchBtn.click();

      await page.waitForSelector('#audit-runner[data-stage="complete"]', {
        timeout: 30000
      });

      const passwordEl = page.locator('#audit-password');
      const password = await passwordEl.textContent();
      expect(password).toBeTruthy();

      // Verify this password is unique
      expect(passwords).not.toContain(password);
      passwords.push(password!);
    }

    // All passwords should be unique
    const uniquePasswords = new Set(passwords);
    expect(uniquePasswords.size).toBe(passwords.length);
  });

  test('audit stages progress correctly', async ({ page }) => {
    const launchBtn = page.locator('#btn-launch');
    await launchBtn.click();

    // Wait for final stage
    await page.waitForSelector('#audit-runner[data-stage="complete"]', {
      timeout: 30000
    });

    // Verify stage results are populated (not "pending")
    const stageResults = [
      '#res-generate',
      '#res-chi2',
      '#res-serial',
      '#res-collisions',
      '#res-proofs',
      '#res-patterns',
      '#res-threats'
    ];

    for (const selector of stageResults) {
      const el = page.locator(selector);
      const text = await el.textContent();
      expect(text).not.toBe('pending');
    }
  });

  test('chi-squared test passes', async ({ page }) => {
    const launchBtn = page.locator('#btn-launch');
    await launchBtn.click();

    await page.waitForSelector('#audit-runner[data-stage="complete"]', {
      timeout: 30000
    });

    // Check chi-squared result shows p-value (indicates pass)
    const chi2Result = page.locator('#res-chi2');
    const text = await chi2Result.textContent();
    expect(text).toMatch(/^p=/);  // Pass shows "p=0.xxx"
  });

  test('serial correlation test passes', async ({ page }) => {
    const launchBtn = page.locator('#btn-launch');
    await launchBtn.click();

    await page.waitForSelector('#audit-runner[data-stage="complete"]', {
      timeout: 30000
    });

    // Check serial correlation result shows r= (indicates pass)
    const serialResult = page.locator('#res-serial');
    const text = await serialResult.textContent();
    expect(text).toMatch(/^r=/);  // Pass shows "r=0.xxxx"
  });

  test('entropy calculation is displayed', async ({ page }) => {
    const launchBtn = page.locator('#btn-launch');
    await launchBtn.click();

    await page.waitForSelector('#audit-runner[data-stage="complete"]', {
      timeout: 30000
    });

    // Get entropy value from proofs result
    const proofsResult = page.locator('#res-proofs');
    const text = await proofsResult.textContent();

    // Should show "XXX bits"
    const match = text?.match(/(\d+)\s*bits/);
    expect(match).toBeTruthy();

    const entropy = parseInt(match![1]);
    expect(entropy).toBeGreaterThan(50);
  });

  test('SHA-256 hash is displayed', async ({ page }) => {
    const launchBtn = page.locator('#btn-launch');
    await launchBtn.click();

    await page.waitForSelector('#audit-runner[data-stage="complete"]', {
      timeout: 30000
    });

    // Check SHA-256 hash display in audit panel
    const hashEl = page.locator('#audit-hash');
    const hash = await hashEl.textContent();

    // SHA-256 should be 64 hex characters
    expect(hash).toMatch(/^[a-f0-9]{64}$/i);
  });

  test('password length respects configuration', async ({ page }) => {
    const targetLength = 24;

    // Set password length via range slider
    const lengthInput = page.locator('#cfg-length');
    await lengthInput.fill(targetLength.toString());

    const launchBtn = page.locator('#btn-launch');
    await launchBtn.click();

    await page.waitForSelector('#audit-runner[data-stage="complete"]', {
      timeout: 30000
    });

    // Verify password length
    const passwordEl = page.locator('#audit-password');
    const password = await passwordEl.textContent();
    expect(password!.length).toBe(targetLength);
  });

  test('no collisions in batch generation', async ({ page }) => {
    const launchBtn = page.locator('#btn-launch');
    await launchBtn.click();

    await page.waitForSelector('#audit-runner[data-stage="complete"]', {
      timeout: 30000
    });

    // Check collision detection result shows "0 dupes"
    const collisionResult = page.locator('#res-collisions');
    await expect(collisionResult).toHaveText('0 dupes');
  });

  test('CSS wizard navigation works', async ({ page }) => {
    // Verify initial state (configure panel visible)
    const configPanel = page.locator('#panel-configure');
    await expect(configPanel).toBeVisible();

    // Generate password to trigger state transition
    const launchBtn = page.locator('#btn-launch');
    await launchBtn.click();

    // Audit panel should become visible (wizard advances via JS)
    const auditPanel = page.locator('#panel-audit');
    await expect(auditPanel).toBeVisible();

    // Wait for completion
    await page.waitForSelector('#audit-runner[data-stage="complete"]', {
      timeout: 30000
    });

    // After completion, results panel should be visible
    const resultsPanel = page.locator('#panel-results');
    await expect(resultsPanel).toBeVisible();
  });

  test('responsive design works on mobile viewport', async ({ page }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });

    // Page should still be functional
    const launchBtn = page.locator('#btn-launch');
    await expect(launchBtn).toBeVisible();

    await launchBtn.click();

    await page.waitForSelector('#audit-runner[data-stage="complete"]', {
      timeout: 30000
    });

    // Verify password generated
    const passwordEl = page.locator('#audit-password');
    const password = await passwordEl.textContent();
    expect(password).toBeTruthy();
  });

  test('screenshot capture for visual verification', async ({ page }) => {
    // Capture initial state
    await page.screenshot({
      path: 'test-results/screenshots/01-initial.png',
      fullPage: true
    });

    // Generate password
    const launchBtn = page.locator('#btn-launch');
    await launchBtn.click();

    // Wait for audit to start and capture in progress
    await page.waitForSelector('#audit-runner:not([data-stage="idle"])', {
      timeout: 5000
    });
    await page.screenshot({
      path: 'test-results/screenshots/02-audit-progress.png',
      fullPage: true
    });

    // Wait for completion
    await page.waitForSelector('#audit-runner[data-stage="complete"]', {
      timeout: 30000
    });

    // Capture final results
    await page.screenshot({
      path: 'test-results/screenshots/03-results.png',
      fullPage: true
    });
  });

  test('verdict banner displays correctly', async ({ page }) => {
    const launchBtn = page.locator('#btn-launch');
    await launchBtn.click();

    await page.waitForSelector('#audit-runner[data-stage="complete"]', {
      timeout: 30000
    });

    // Wait for results panel to be visible
    await page.waitForSelector('#panel-results', { state: 'visible' });

    // Verdict should show pass or fail
    const verdictText = page.locator('#verdict-text');
    const text = await verdictText.textContent();
    expect(text).toMatch(/CRYPTOGRAPHICALLY SOUND|REVIEW FLAGGED ITEMS/);
  });

});
