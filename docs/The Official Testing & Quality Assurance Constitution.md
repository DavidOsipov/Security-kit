# The Official Testing & Quality Assurance Constitution (v2.6)

**Document Status:** Final, Mandatory
**SPDX-License-Identifier:** MIT
**SPDX-FileCopyrightText:** © 2025 David Osipov <personal@david-osipov.vision>

---

> This document is the authoritative, machine-verifiable specification for *how* quality, security, performance, accessibility, and SEO are proven in this project. Tests are not optional commentary—they are the specification. If a feature or rule cannot be verified by an automated test, it is considered broken.

## 0. Introduction

### 0.1. Goals & Vision

This constitution codifies the mandatory testing, verification, and CI enforcement rules for this project. It is the practical implementation of the project's core philosophies, ensuring that all other constitutions are not just documents, but enforced realities. Our guiding principles are:

*   **Security First (Zero Trust):** Every input and surface is assumed hostile until proven safe by automated tests. This constitution provides the verifiable proof for the `Security Constitution`.
*   **Performance is a Feature:** Performance budgets defined in the `JS Performance & Engineering Constitution` are enforced automatically in CI.
*   **SEO as Architecture (Entity-First):** The correctness of JSON-LD and the entity `@graph`, as mandated by `The SEO Master Blueprint`, are verified by dedicated tests.
*   **Verifiable Quality:** A feature is not "done" until an automated test demonstrates its compliance with all project requirements.
*   **Accessibility by Default:** WCAG 2.2 compliance is measured and enforced automatically, fulfilling the requirements of the `Project Constitution`.

### 0.2. Audience & Scope

This constitution is mandatory for all personnel contributing code, tests, infrastructure, or content. The CI/CD pipeline is the ultimate enforcer of these rules; a failing test **MUST** block a merge.

---

## Part I: Core Philosophy & Principles

1.  **Tests are the Specification.** The single source of truth for system behavior is the test suite. Tests must be readable, deterministic, and serve as living documentation.
2.  **Trust, but Verify (with Automation).** Developer intent is honored only after an automated verification step proves it is secure, performant, accessible, and functionally correct.
3.  **Test the User's Reality.** Tests must validate user-facing outcomes (keyboard navigation, visual stability, schema correctness) rather than only internal implementation details.
4.  **Fail Loudly, Fail Safely.** Tests that expose regressions must fail the CI pipeline and produce actionable diagnostics. The system must never silently degrade.
5.  **Test for Failure, Not Just Success.** We write adversarial and edge-case tests that prove our code can gracefully handle invalid, malicious, and unexpected inputs.
6.  **The Testing Pyramid is Law.** We use a balanced portfolio of tests: a large base of fast unit tests, a focused set of integration tests, and a small, critical suite of E2E tests.
7.  **Automate Everything That Can Be Automated.** Manual verification is reserved for un-automatable user experience validation and exploratory testing only.

---

## Part II: The Testing Hierarchy & Mandated Methodologies

This section defines the mandatory types of tests required for this project. Each layer of the testing hierarchy and each specialized methodology serves a distinct purpose in verifying the quality, security, and performance of the application. Adherence to this structure is non-negotiable.

### 2.1. The Testing Pyramid (Core Strategy)

Our testing strategy is modeled on the "Testing Pyramid," which mandates a healthy balance of tests at different levels of granularity.

#### RULE: Unit Tests (Foundation)

-   **Statement:** Every logical unit of code (function, class method) **MUST** be covered by unit tests. This forms the largest portion of our test suite.
-   **Scope:** A single function or module in complete isolation from its dependencies.
-   **Purpose:** To verify the correctness of business logic, algorithms, and data transformations under a wide range of inputs. They are the first line of defense against regressions.
-   **What they test:**
    *   **Happy Path:** Correct output for valid, expected inputs.
    *   **Edge Cases:** Behavior with `null`, `undefined`, empty strings/arrays, zero, and other boundary conditions.
    *   **Error Handling:** Correct error types are thrown for invalid inputs.
-   **Mandated Tool:** `Vitest`.

#### RULE: Integration Tests (Connective Tissue)

-   **Statement:** Critical interactions between modules and components **MUST** be verified by integration tests.
-   **Scope:** Two or more modules working together. This includes testing Astro components with their props, data flow between a page and its components, or the interaction between the configuration and cryptographic modules.
-   **Purpose:** To find bugs in the "glue" that connects different parts of the application, such as incorrect data passing, state management flaws, or event handling errors.
-   **Mandated Tools:** `Vitest` with `@testing-library/astro`.

#### RULE: End-to-End (E2E) Tests (User Simulation)

-   **Statement:** The most critical, user-facing journeys **MUST** be validated by E2E tests.
-   **Scope:** The entire application running in a real (or headless) browser.
-   **Purpose:** To verify that complete user flows work from start to finish, simulating real user interaction. This is the ultimate validation that the system as a whole is functional.
-   **What they test:**
    *   User navigation between pages.
    *   Form submissions and interactions.
    *   End-to-end data display from the source to the screen.
-   **Mandated Tool:** `Playwright`.

### 2.2. Specialized Testing Methodologies (Cross-Cutting Mandates)

These methodologies are applied across the testing pyramid to ensure we meet our stringent quality, security, and performance goals.

#### RULE: Adversarial & Fuzz Testing (Security)

-   **Statement:** All public APIs and functions that process untrusted input **MUST** be subjected to adversarial and fuzz testing.
-   **Scope:** Primarily unit and integration tests.
-   **Purpose:** To proactively find security vulnerabilities and resilience issues by feeding the application malicious, unexpected, and random data. This is a direct implementation of the "Test for Failure" principle.
-   **What they test:**
    *   **Security Vectors:** Defenses against known attack patterns like Prototype Pollution, XSS payloads, and path traversal.
    *   **Resilience:** The application's ability to handle garbage input without crashing or entering an inconsistent state.
-   **Mandated Tools:** Custom test harnesses within `Vitest`; manual adversarial thinking during test creation.

#### RULE: Mutation Testing (Test Quality Verification)

-   **Statement:** The quality and effectiveness of the unit test suite **MUST** be measured and enforced via Mutation Testing.
-   **Scope:** Applied to the unit test suite.
-   **Purpose:** To move beyond nominal code coverage and provide a verifiable metric of how well our tests can detect actual bugs. A high mutation score gives us confidence that our safety net is strong.
-   **Mandated Tool:** `StrykerJS`.

#### RULE: Property-Based Testing (Edge Case Discovery)

-   **Statement:** Core algorithms and data-handling functions **SHOULD** be tested using property-based testing.
-   **Scope:** Unit tests.
-   **Purpose:** To automatically discover edge cases that human developers might miss. Instead of testing one example at a time, we define a general "property" that must always be true and let the framework generate hundreds of inputs to try and falsify it.
-   **Mandated Tool:** `fast-check`.

#### RULE: Performance Budget Testing (Performance)

-   **Statement:** The application's core web vitals and critical performance metrics **MUST** be automatically tested against predefined budgets.
-   **Scope:** E2E tests.
-   **Purpose:** To prevent performance regressions and ensure the application remains fast and responsive for users, fulfilling the `JS Performance & Engineering Constitution`.
-   **What they test:**
    *   Largest Contentful Paint (LCP)
    *   Cumulative Layout Shift (CLS)
    *   Total Blocking Time (TBT)
-   **Mandated Tool:** `Playwright` with custom performance metric collection.

#### RULE: Accessibility (a11y) Testing (Accessibility)

-   **Statement:** All user-facing components and pages **MUST** be automatically scanned for WCAG 2.2 violations.
-   **Scope:** Integration and E2E tests.
-   **Purpose:** To ensure the application is usable by people with disabilities and to catch accessibility regressions before they reach production.
-   **Mandated Tool:** `axe-core` integrated with Vitest via `vitest-axe` and with Playwright via `@playwright/test-axe`.

#### RULE: Visual Regression Testing (UI Consistency)

-   **Statement:** Key pages and components **SHOULD** be covered by visual regression tests to prevent unintended UI changes.
-   **Scope:** E2E tests.
-   **Purpose:** To act as a safety net against visual bugs (CSS issues, layout shifts, broken styles) that are difficult to catch with functional tests alone.
-   **Mandated Tool:** `Playwright`'s built-in screenshot assertion capabilities.

---

## Part III: Prescriptive Testing Rules (The "How")

Every rule below is mandatory. Each test file should include a comment referencing the rule it validates (e.g., `// RULE-ID: comp-prop-validation`).

### RULE: Component Prop & Slot Validation (MUST)

*   **Statement:** Every Astro component that accepts `props` or `slots` **MUST** have tests that validate its rendering based on both valid and edge-case inputs (e.g., `null`, `undefined`, empty strings/arrays).
*   **Rationale:** Ensures components are robust and prevents runtime errors in the static build process.
*   **Test Implementation (`ServiceCard.astro` example):**
    ```javascript
    // tests/components/ServiceCard.test.ts
    // RULE-ID: comp-prop-validation
    import { render } from '@testing-library/astro';
    import { expect, test } from 'vitest';
    import ServiceCard from '@components/Services/ServiceCard.astro';

    test('ServiceCard should render title and description correctly', async () => {
      const service = { title: 'Market Analysis', description: 'Comprehensive research.' };
      const { getByText } = await render(ServiceCard, { props: { service } });
      expect(getByText('Market Analysis')).to.exist;
      expect(getByText('Comprehensive research.')).to.exist;
    });

    test('ServiceCard should not crash with null props', async () => {
      const { container } = await render(ServiceCard, { props: { service: null } });
      expect(container).to.exist; // The component should still render without throwing an error.
    });
    ```
*   **CI Check:** Failure of any component test **MUST** block the PR.

### RULE: Security: Trusted Types Sanitization (MUST)

*   **Statement:** There **MUST** be a test that proves the `Trusted Types` policy correctly sanitizes malicious HTML input, preventing XSS.
*   **Rationale:** Provides verifiable proof of compliance with Rule 2.2 (`Trusted Types`) of the `Security Constitution`.
*   **Test Implementation (Conceptual `DOMPurify` mock):**
    ```javascript
    // tests/security/trusted-types.test.ts
    // RULE-ID: trusted-types-sanitization
    import { expect, test } from 'vitest';

    const createTrustedHtml = (input) => {
      // In a real scenario, this would be DOMPurify.sanitize(input).
      const sanitized = input.replace(/onerror="[^"]*"/g, '');
      return sanitized;
    };

    test('Trusted Types policy must neutralize onerror attributes', () => {
      const maliciousHTML = '<img src=x onerror="alert(1)">';
      const sanitizedHTML = createTrustedHtml(maliciousHTML);
      expect(sanitizedHTML).not.to.include('onerror');
      expect(sanitizedHTML).to.equal('<img src=x>');
    });
    ```
*   **CI Check:** The `security` test suite **MUST** pass. Failure blocks the PR.

### RULE: Security: postMessage Origin Validation (MUST)

*   **Statement:** All `window.postMessage` handlers **MUST** validate `event.origin` against a strict allowlist.
*   **Rationale:** Verifies compliance with Rule 2.9 of the `Security Constitution`, preventing cross-origin injection attacks.
*   **Test Implementation:**
    ```javascript
    // tests/security/postMessage.test.ts
    // RULE-ID: postmessage-origin
    import { test, expect } from 'vitest';
    import { handleMessage } from '../../src/lib/postMessageHandler'; // Assuming a dedicated handler module

    test('postMessage handler must reject messages from unknown origins', () => {
      const allowedOrigins = ['https://david-osipov.vision'];
      const maliciousEvent = { origin: 'https://evil.com', data: 'payload' };
      
      // The handler function must return a rejection or not process the data.
      const result = handleMessage(maliciousEvent, allowedOrigins);
      expect(result.processed).to.be.false;
    });
    ```
*   **CI Check:** The `security` test suite **MUST** pass.

### RULE: SEO: Structured Data Graph Integrity (MUST)

*   **Statement:** There **MUST** be a test that validates the generated JSON-LD `@graph` for critical page types, ensuring all entities are present and correctly linked via their canonical `@id`.
*   **Rationale:** The "Entity-First" SEO strategy is entirely dependent on the correctness of the schema.
*   **Test Implementation (`StructuredDataEnhancer.astro` example):**
    ```javascript
    // tests/seo/structured-data.test.ts
    // RULE-ID: structured-data-graph
    import { render } from '@testing-library/astro';
    import { expect, test } from 'vitest';
    import StructuredDataEnhancer from '@components/accessibility/StructuredDataEnhancer.astro';

    test('StructuredDataEnhancer must link Person and WebSite schema correctly', async () => {
      const { container } = await render(StructuredDataEnhancer, { props: { contentType: 'homepage', data: {} } });
      const scriptTag = container.querySelector('script[type="application/ld+json"]');
      const schema = JSON.parse(scriptTag.textContent);
      const graph = schema['@graph'];

      const person = graph.find(e => e['@type'] === 'Person');
      const webSite = graph.find(e => e['@type'] === 'WebSite');

      expect(person).to.exist;
      expect(webSite).to.exist;
      expect(webSite.publisher['@id']).to.equal(person['@id']);
      expect(person['@id']).to.include('https://david-osipov.vision');
    });
    ```
*   **CI Check:** The `seo` test suite **MUST** pass.

### RULE: Accessibility: Focus Management & Trapping (MUST)

*   **Statement:** All modal dialogs **MUST** have tests that validate focus is correctly moved into the element, trapped within it, and returned to the trigger element on close.
*   **Rationale:** This is a critical WCAG requirement for keyboard accessibility.
*   **Test Implementation (Conceptual):**
    ```javascript
    // tests/a11y/MobileMenu.test.ts
    // RULE-ID: a11y-modal-focus
    import { render, fireEvent } from '@testing-library/astro';
    import { expect, test } from 'vitest';
    import MobileMenu from '@components/Header/MobileMenu.astro';

    test('MobileMenu should trap focus when opened', async () => {
      const { getByRole } = await render(MobileMenu);
      const openButton = getByRole('button', { name: /open menu/i });
      const originalActiveElement = document.activeElement;
      fireEvent.click(openButton);
      const dialog = getByRole('dialog');
      const firstLinkInDialog = dialog.querySelector('a');
      expect(document.activeElement).to.equal(firstLinkInDialog);
      fireEvent.keyDown(dialog, { key: 'Escape' });
      expect(document.activeElement).to.equal(originalActiveElement);
    });
    ```
*   **CI Check:** The `a11y` test suite **MUST** pass.

### RULE: Performance: Budget Enforcement (MUST)

*   **Statement:** Critical user flows **MUST** be tested against performance budgets (LCP, CLS, TBT) in an E2E testing environment.
*   **Rationale:** Enforces the performance targets from the `JS Performance & Engineering Constitution`.
*   **Test Implementation (Conceptual E2E Test Logic):**
    ```javascript
    // tests/performance/homepage.perf.test.ts
    // RULE-ID: perf-lcp-budget
    test('Homepage LCP must be under 1.8 seconds', async ({ page }) => {
      await page.goto('/');
      const lcp = await page.evaluate(() => new Promise(resolve => {
        new PerformanceObserver(list => {
          const entries = list.getEntries();
          resolve(entries[entries.length - 1].startTime);
        }).observe({ type: 'largest-contentful-paint', buffered: true });
      }));
      expect(lcp).toBeLessThan(1800); // Budget: 1800ms
    });
    ```
*   **CI Check:** The `performance` test suite **MUST** pass.

### RULE: Visual Regression (SHOULD)

*   **Statement:** Visual regression snapshots **SHOULD** be taken for critical pages and reusable components (e.g., homepage, header, blog post template).
*   **Rationale:** Prevents unintended UI regressions from CSS or layout changes.
*   **Test Implementation (Conceptual E2E Snapshot):**
    ```javascript
    // tests/visual/header.snapshot.test.ts
    // RULE-ID: visual-snapshot-header
    test('Header component should match the approved snapshot', async ({ page }) => {
      await page.goto('/');
      const header = await page.locator('header');
      await expect(header).toHaveScreenshot('header-snapshot.png', { maxDiffPixels: 100 });
    });
    ```
*   **CI Check:** A visual diff **SHOULD** trigger a manual review and approval step in the PR.

### RULE: Internationalization (i18n) & Hreflang (MUST)

*   **Statement:** Every page with translations **MUST** include correct `link rel="alternate" hreflang="..."` tags.
*   **Rationale:** Critical for international SEO and crawler behavior.
*   **Test Implementation:**
    ```javascript
    // tests/i18n/hreflang.test.ts
    // RULE-ID: i18n-hreflang
    import { render } from '@testing-library/astro';
    import { expect, test } from 'vitest';
    import AboutPage from '@pages/en/about.astro'; // Assuming a page with translations

    test('About page should render correct hreflang tags', async () => {
      const { container } = await render(AboutPage);
      const enLink = container.querySelector('link[hreflang="en"]');
      const ruLink = container.querySelector('link[hreflang="ru"]');
      const xDefaultLink = container.querySelector('link[hreflang="x-default"]');
      
      expect(enLink).to.exist;
      expect(ruLink).to.exist;
      expect(xDefaultLink).to.exist;
      expect(enLink.href).to.include('/en/about');
      expect(xDefaultLink.href).to.equal(enLink.href);
    });
    ```
*   **CI Check:** The `i18n` test suite **MUST** pass.


### RULE: Logic Purity and Determinism (MUST)

- **Statement:** All functions intended to be "pure" (as defined in the Security & Engineering Constitution, Rule III.E) **MUST** have unit tests that verify their purity and determinism.
- **Rationale:** This rule provides the verifiable proof for our functional programming architecture. It ensures that our core logic is free of side effects and behaves predictably, which is critical for security and maintainability.
- **Test Implementation:**
    ```javascript
    // tests/unit/pure-logic.test.ts
    // RULE-ID: logic-purity
    import { expect, test, vi } from 'vitest';
    import { createGreeting } from '@src/pure-logic'; // Assuming this is a pure function

    test('createGreeting should be deterministic', () => {
      // Calling the function multiple times with the same input MUST produce the exact same output.
      expect(createGreeting('World')).to.equal('Hello, World!');
      expect(createGreeting('World')).to.equal('Hello, World!');
    });

    test('createGreeting should have no side effects', () => {
      // Spy on potential side-effect sources (e.g., global objects, console).
      const consoleSpy = vi.spyOn(console, 'log');
      const docSpy = vi.spyOn(document, 'getElementById');

      createGreeting('Test');

      // Assert that no side effects occurred.
      expect(consoleSpy).not.toHaveBeenCalled();
      expect(docSpy).not.toHaveBeenCalled();
    });
    ```
*   **CI Check:** The `unit` test suite **MUST** pass. Code reviews must ensure that functions in designated `pure-logic/` directories have corresponding purity tests.


---

## Part IV: The Testing Gauntlet (Verification & Enforcement)

This section defines the automated quality gates that **MUST** be passed before any code is merged into the `main` branch.

1.  **Pre-Commit Hook (Local):**
    *   **Action:** Runs `npm run lint` and a quick subset of fast unit tests.
    *   **Goal:** Catch simple errors before they are ever committed.

2.  **Pull Request Pipeline (CI):**
    *   **Trigger:** On every `git push` to a pull request branch.
    *   **Jobs:**
        1.  `npm ci`: Installs dependencies from the lockfile.
        2.  `npm run lint`: Enforces code style and static analysis rules.
        3.  `npm run typecheck`: Runs `astro check` to validate all TypeScript types.
        4.  `npm test`: Runs the **entire** Vitest suite (Unit, Integration, Security, a11y, SEO, i18n).
        5.  `npm run build`: Ensures the project builds successfully.
    *   **Gate:** A failing result in **any** of these jobs **MUST** block the pull request from being merged.

3.  **Post-Merge Pipeline (Staging):**
    *   **Trigger:** On every merge to `main`.
    *   **Action:** Deploys the build to a staging environment and runs the full E2E and Performance test suites.
    *   **Gate:** A failure here **MUST** trigger an alert and may require a revert.

4.  **Production Smoke Test:**
    *   **Trigger:** After a successful production deployment.
    *   **Action:** A small "smoke test" suite is run against the live URL.
    *   **Gate:** A failure here **MUST** trigger an immediate high-priority alert and initiate the Incident Response plan.

---

## Part V: Tooling & Environment

To ensure consistency, the project **MUST** use the following standardized toolset.

*   **Test Runner:** `Vitest`
*   **DOM Simulation:** `happy-dom`
*   **Component Testing:** `@testing-library/astro`
*   **Accessibility Testing:** `axe-core` via `vitest-axe`
*   **E2E Testing Framework:** A modern framework like `Playwright` or `Cypress`.
*   **Visual Regression:** An image snapshot library compatible with the E2E framework.

### Recommended `package.json` Scripts

```json
"scripts": {
  "test": "vitest",
  "test:unit": "vitest --run --include '**/unit/**'",
  "test:integration": "vitest --run --include '**/integration/**'",
  "test:a11y": "vitest --run --include '**/a11y/**'",
  "test:security": "vitest --run --include '**/security/**'",
  "test:seo": "vitest --run --include '**/seo/**'",
  "test:e2e": "playwright test",
  "test:perf": "playwright test --project=performance",
  "test:visual": "playwright test --project=visual",
  "lint": "eslint . --ext .ts,.astro",
  "typecheck": "astro check"
}
```

---

## Part VI: Governance & Process

*   **Ownership:** Every test suite (`security`, `a11y`, etc.) has a designated owner responsible for its maintenance.
*   **Code Review:** A PR that modifies a component must also include updates to its corresponding tests.
*   **Flaky Test Policy:** Flaky tests are treated as P1 bugs. A test that fails intermittently must be immediately quarantined and fixed or deleted.
*   **Training:** All developers must be familiar with the testing philosophy and tooling as part of their onboarding.

---

## Appendix A: Developer's Pre-Flight Checklist

This checklist **MUST** be reviewed by the developer before submitting a Pull Request.

-   [ ] **Functionality:** Does my new code have corresponding tests for both happy paths and failure cases?
-   [ ] **Security:** If my code touches user input or the DOM, have I added a test case to the `security` suite to prove it's safe?
-   [ ] **Accessibility:** Have I run `axe` on my new component and tested it with keyboard-only navigation?
-   [ ] **Performance:** Have I considered the performance implications of my code and its impact on the performance budget?
-   [ ] **SEO:** If my changes affect page content or structure, have I verified the JSON-LD output with a test?
-   [ ] **Visuals:** If my changes affect UI, have I run the visual regression tests and updated the snapshots (with justification)?
-   [ ] **Local Pass:** Have I run the entire relevant test suite (`npm test`) locally and confirmed it passes 100%?

## Appendix B: Example CI Workflow (Conceptual)

```yaml
# .github/workflows/ci.yml
name: Continuous Integration

on: [pull_request]

jobs:
  quality_checks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      - run: npm ci
      - run: npm run lint
      - run: npm run typecheck
      - run: npm run test # Runs all Vitest suites
      - run: npm run build

  e2e_and_perf:
    if: github.event_name == 'push' && github.ref == 'refs/heads/main' # Or on a special PR label
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npm run build
      # Deploy to a preview/staging environment here
      - name: Run E2E and Performance Tests
        run: npm run test:e2e && npm run test:perf
```

## Appendix C: Critical Rule Reference

| Rule ID | Description | Category |
| :--- | :--- | :--- |
| `comp-prop-validation` | Components must handle valid and edge-case props. | `Unit` |
| `trusted-types-sanitization` | Trusted Types policy must prevent XSS. | `Security` |
| `postmessage-origin` | `postMessage` handlers must validate origin. | `Security` |
| `structured-data-graph` | JSON-LD `@graph` must be correct and linked. | `SEO` |
| `a11y-modal-focus` | Modals must trap and restore focus correctly. | `Accessibility` |
| `perf-lcp-budget` | Page LCP must be within the defined budget. | `Performance` |
| `i18n-hreflang` | Pages must have correct `hreflang` tags. | `i18n` |
| `logic-purity` | Pure functions must be tested for determinism and lack of side effects. | `Unit` |