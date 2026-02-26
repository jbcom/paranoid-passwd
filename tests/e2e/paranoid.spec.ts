/**
 * paranoid E2E Tests — Full System Verification
 * 
 * These tests verify the complete end-to-end flow:
 *   HTML → CSS → JavaScript → WASM → Password Generation
 * 
 * The same cryptographic logic tested in munit C tests (test_munit.c)
 * is exercised here through the browser interface to ensure:
 *   1. WASM loads and initializes correctly
 *   2. UI renders properly (CSS state machine)
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
    // Wait for WASM to load
    await page.waitForFunction(() => {
      return (window as any).paranoidReady === true;
    }, { timeout: 10000 });
  });

  test('page loads and WASM initializes', async ({ page }) => {
    // Verify page title
    await expect(page).toHaveTitle(/paranoid/i);
    
    // Verify WASM status indicator shows success
    const wasmStatus = page.locator('[data-wasm-status]');
    await expect(wasmStatus).toHaveAttribute('data-wasm-status', 'loaded');
  });

  test('generate password with default settings', async ({ page }) => {
    // Click generate button
    const generateBtn = page.locator('#btn-generate, [data-action="generate"]');
    await generateBtn.click();
    
    // Wait for audit to complete
    await page.waitForSelector('[data-stage="complete"], [data-audit-complete]', { 
      timeout: 30000 
    });
    
    // Verify password was generated
    const passwordField = page.locator('#password, [data-password]');
    const password = await passwordField.inputValue() || await passwordField.textContent();
    expect(password).toBeTruthy();
    expect(password!.length).toBeGreaterThanOrEqual(8);
  });

  test('password generation produces unique results', async ({ page }) => {
    const passwords: string[] = [];
    
    // Generate 5 passwords and verify uniqueness
    for (let i = 0; i < 5; i++) {
      const generateBtn = page.locator('#btn-generate, [data-action="generate"]');
      await generateBtn.click();
      
      await page.waitForSelector('[data-stage="complete"], [data-audit-complete]', { 
        timeout: 30000 
      });
      
      const passwordField = page.locator('#password, [data-password]');
      const password = await passwordField.inputValue() || await passwordField.textContent();
      expect(password).toBeTruthy();
      
      // Verify this password is unique
      expect(passwords).not.toContain(password);
      passwords.push(password!);
      
      // Wait for UI to be ready for next generation
      await page.waitForSelector('#btn-generate:not([disabled]), [data-action="generate"]:not([disabled])', {
        timeout: 5000
      });
    }
    
    // All passwords should be unique
    const uniquePasswords = new Set(passwords);
    expect(uniquePasswords.size).toBe(passwords.length);
  });

  test('audit stages progress correctly', async ({ page }) => {
    const generateBtn = page.locator('#btn-generate, [data-action="generate"]');
    await generateBtn.click();
    
    // Verify stages progress
    const stages = [
      'generate',
      'chi2',
      'serial',
      'collision',
      'entropy',
      'pattern',
      'hash',
      'complete'
    ];
    
    // Wait for final stage
    await page.waitForSelector('[data-stage="complete"], [data-audit-complete]', { 
      timeout: 30000 
    });
    
    // Verify all stages passed (look for checkmarks or pass indicators)
    const passIndicators = page.locator('.stage-pass, [data-stage-status="pass"]');
    const passCount = await passIndicators.count();
    expect(passCount).toBeGreaterThanOrEqual(6); // At least 6 audit stages should pass
  });

  test('chi-squared test passes', async ({ page }) => {
    const generateBtn = page.locator('#btn-generate, [data-action="generate"]');
    await generateBtn.click();
    
    await page.waitForSelector('[data-stage="complete"], [data-audit-complete]', { 
      timeout: 30000 
    });
    
    // Check chi-squared result
    const chi2Status = page.locator('[data-test="chi2"] .status, #chi2-status');
    await expect(chi2Status).toContainText(/pass|✓|ok/i);
  });

  test('serial correlation test passes', async ({ page }) => {
    const generateBtn = page.locator('#btn-generate, [data-action="generate"]');
    await generateBtn.click();
    
    await page.waitForSelector('[data-stage="complete"], [data-audit-complete]', { 
      timeout: 30000 
    });
    
    // Check serial correlation result
    const serialStatus = page.locator('[data-test="serial"] .status, #serial-status');
    await expect(serialStatus).toContainText(/pass|✓|ok/i);
  });

  test('entropy calculation is correct', async ({ page }) => {
    const generateBtn = page.locator('#btn-generate, [data-action="generate"]');
    await generateBtn.click();
    
    await page.waitForSelector('[data-stage="complete"], [data-audit-complete]', { 
      timeout: 30000 
    });
    
    // Get entropy value
    const entropyEl = page.locator('#entropy, [data-entropy]');
    const entropyText = await entropyEl.textContent();
    
    // Entropy should be a positive number (e.g., "128 bits" or "128.5")
    const entropyMatch = entropyText?.match(/(\d+\.?\d*)/);
    expect(entropyMatch).toBeTruthy();
    
    const entropy = parseFloat(entropyMatch![1]);
    expect(entropy).toBeGreaterThan(50); // Reasonable minimum for a secure password
  });

  test('SHA-256 hash is displayed', async ({ page }) => {
    const generateBtn = page.locator('#btn-generate, [data-action="generate"]');
    await generateBtn.click();
    
    await page.waitForSelector('[data-stage="complete"], [data-audit-complete]', { 
      timeout: 30000 
    });
    
    // Check SHA-256 hash display
    const hashEl = page.locator('#sha256, [data-sha256]');
    const hash = await hashEl.textContent();
    
    // SHA-256 should be 64 hex characters
    expect(hash).toMatch(/^[a-f0-9]{64}$/i);
  });

  test('custom charset works', async ({ page }) => {
    // Set custom charset (digits only)
    const charsetInput = page.locator('#charset, [data-charset]');
    await charsetInput.fill('0123456789');
    
    const generateBtn = page.locator('#btn-generate, [data-action="generate"]');
    await generateBtn.click();
    
    await page.waitForSelector('[data-stage="complete"], [data-audit-complete]', { 
      timeout: 30000 
    });
    
    // Verify password only contains digits
    const passwordField = page.locator('#password, [data-password]');
    const password = await passwordField.inputValue() || await passwordField.textContent();
    expect(password).toMatch(/^[0-9]+$/);
  });

  test('password length respects configuration', async ({ page }) => {
    const targetLength = 24;
    
    // Set password length
    const lengthInput = page.locator('#length, [data-length]');
    await lengthInput.fill(targetLength.toString());
    
    const generateBtn = page.locator('#btn-generate, [data-action="generate"]');
    await generateBtn.click();
    
    await page.waitForSelector('[data-stage="complete"], [data-audit-complete]', { 
      timeout: 30000 
    });
    
    // Verify password length
    const passwordField = page.locator('#password, [data-password]');
    const password = await passwordField.inputValue() || await passwordField.textContent();
    expect(password!.length).toBe(targetLength);
  });

  test('no collisions in batch generation', async ({ page }) => {
    const generateBtn = page.locator('#btn-generate, [data-action="generate"]');
    await generateBtn.click();
    
    await page.waitForSelector('[data-stage="complete"], [data-audit-complete]', { 
      timeout: 30000 
    });
    
    // Check collision detection result
    const collisionStatus = page.locator('[data-test="collision"] .status, #collision-status');
    await expect(collisionStatus).toContainText(/pass|✓|ok|0/i);
  });

  test('CSS state machine navigation works', async ({ page }) => {
    // Verify initial state (configure panel visible)
    const configPanel = page.locator('#panel-configure, [data-panel="configure"]');
    await expect(configPanel).toBeVisible();
    
    // Generate password to trigger state transition
    const generateBtn = page.locator('#btn-generate, [data-action="generate"]');
    await generateBtn.click();
    
    // Audit panel should become visible
    const auditPanel = page.locator('#panel-audit, [data-panel="audit"]');
    await expect(auditPanel).toBeVisible();
    
    // Wait for completion
    await page.waitForSelector('[data-stage="complete"], [data-audit-complete]', { 
      timeout: 30000 
    });
    
    // Results panel should be visible
    const resultsPanel = page.locator('#panel-results, [data-panel="results"]');
    await expect(resultsPanel).toBeVisible();
  });

  test('responsive design works on mobile viewport', async ({ page }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Page should still be functional
    const generateBtn = page.locator('#btn-generate, [data-action="generate"]');
    await expect(generateBtn).toBeVisible();
    
    await generateBtn.click();
    
    await page.waitForSelector('[data-stage="complete"], [data-audit-complete]', { 
      timeout: 30000 
    });
    
    // Verify password generated
    const passwordField = page.locator('#password, [data-password]');
    const password = await passwordField.inputValue() || await passwordField.textContent();
    expect(password).toBeTruthy();
  });

  test('screenshot capture for visual verification', async ({ page }) => {
    // Capture initial state
    await page.screenshot({ 
      path: 'test-results/screenshots/01-initial.png',
      fullPage: true 
    });
    
    // Generate password
    const generateBtn = page.locator('#btn-generate, [data-action="generate"]');
    await generateBtn.click();
    
    // Wait for audit to start and capture in progress
    await page.waitForSelector('[data-stage]:not([data-stage="idle"]), [data-audit-started]', { 
      timeout: 5000 
    });
    await page.screenshot({ 
      path: 'test-results/screenshots/02-audit-progress.png',
      fullPage: true 
    });
    
    // Wait for completion
    await page.waitForSelector('[data-stage="complete"], [data-audit-complete]', { 
      timeout: 30000 
    });
    
    // Capture final results
    await page.screenshot({ 
      path: 'test-results/screenshots/03-results.png',
      fullPage: true 
    });
  });

});
