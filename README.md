# web-secure-verification

[![npm version](https://img.shields.io/npm/v/web-secure-verification.svg)](https://www.npmjs.com/package/web-secure-verification)
[![npm downloads](https://img.shields.io/npm/dm/web-secure-verification.svg)](https://www.npmjs.com/package/web-secure-verification)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org)

A security scanning CLI for **React** and **Next.js** projects. Run one command at the root of any project and get a full security report.

---

## Why not just `npm audit`?

`npm audit` only checks known CVEs in your dependency tree. `web-secure-verification` also scans **your own application code** for hardcoded secrets, dangerous DOM/eval patterns, Next.js hydration bugs, RSC boundary violations, exposed source maps, and license-compliance risks — issues `npm audit` never looks for.

---

## What This Package Does

This package scans your React or Next.js project and produces a report that tells you exactly what security problems exist in your code and dependencies. It runs 12 different checks covering:

- **Dependency vulnerabilities** — known CVEs in your installed packages (direct and transitive)
- **Outdated packages** — packages that have newer, safer versions available
- **Deprecated packages** — packages the author has officially abandoned
- **Hardcoded secrets** — API keys, tokens, private keys, and high-entropy strings left in source code
- **Code-level security** — dangerous patterns like `eval()`, `innerHTML`, `dangerouslySetInnerHTML`, and command injection
- **Next.js configuration** — missing security headers, exposed `NEXT_PUBLIC_` secrets, insecure image config
- **License compliance** — GPL/AGPL licenses that can block commercial use of your product
- **Supply chain attacks** — typosquatted package names, known malicious packages, `postinstall` shell scripts
- **RSC boundary violations** — non-serializable props crossing the Next.js server/client boundary
- **React hydration bugs** — `window`/`localStorage` used outside `useEffect`, `new Date()` in render
- **Bundle size issues** — full `lodash` or `moment` imports, heavy components not lazy-loaded
- **Exposed source maps** — `.map` files in public directories that expose your original source code

---

## How to Run This Package in Your Project

### Step 1 — Go to your project and

```bash
npm i web-secure-verification
```

### Step 2 — Run the scan

```bash
npx web-secure-verify scan
```

You will see a color-coded report in your terminal with all issues grouped by severity.

---

## Sample Output

Below is an example of what you will see in your terminal after running the scan on a typical React / Next.js project.

```
Scanning project at: /Users/dev/projects/my-nextjs-app


╔══════════════════════════════════════════════════════════════════════════════╗
║          🔒  Web Secure Verification — Security Scan Report                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

  Project:  my-nextjs-app
  Path:     /Users/dev/projects/my-nextjs-app
  Scanned:  5/12/2026, 10:30:00 AM
  Duration: 4.8s

────────────────────────────────────────────────────────────────────────────────
  SUMMARY
────────────────────────────────────────────────────────────────────────────────

  Critical    High        Medium      Low         Info
  2           5           3           2           0

  Total issues: 12

────────────────────────────────────────────────────────────────────────────────
  CRITICAL (2 issues)
────────────────────────────────────────────────────────────────────────────────

   CRITICAL   Use of eval()
        ID: code-security-eval-usage-src/utils/parser.ts-42
        File: src/utils/parser.ts:42
        Description: eval() executes arbitrary code and is a major security risk.
                     It can execute malicious code if user input is passed to it.
        Fix: Replace eval() with safer alternatives like JSON.parse() for data,
             or refactor the logic.

   CRITICAL   Hardcoded AWS Access Key
        ID: secrets-aws-access-key-src/config/aws.ts-8
        File: src/config/aws.ts:8
        Description: An AWS Access Key ID was found hardcoded in source code.
                     This key can be used to access your AWS account and incur
                     charges or expose data.
        Fix: Move this value to an environment variable and use process.env.
             Immediately rotate the key in your AWS Console.

────────────────────────────────────────────────────────────────────────────────
  HIGH (5 issues)
────────────────────────────────────────────────────────────────────────────────

    HIGH     Outdated package: react
        ID: outdated-react
        Description: react is outdated. Current: 17.0.2, Wanted: 17.0.2, Latest: 19.1.0.
                     This is a major version update.
        Fix: Run: npm install react@19.1.0

    HIGH     Outdated package: next
        ID: outdated-next
        Description: next is outdated. Current: 13.4.0, Wanted: 13.4.0, Latest: 15.3.2.
                     This is a major version update.
        Fix: Run: npm install next@15.3.2

    HIGH     dangerouslySetInnerHTML usage
        ID: code-security-dangerous-inner-html-src/components/Blog.tsx-27
        File: src/components/Blog.tsx:27
        Description: dangerouslySetInnerHTML can introduce XSS vulnerabilities
                     if the content is not properly sanitized.
        Fix: Sanitize HTML using DOMPurify before passing to dangerouslySetInnerHTML.

    HIGH     Browser API accessed outside useEffect
        ID: hydration-browser-api-in-render-src/components/Sidebar.tsx-14
        File: src/components/Sidebar.tsx:14
        Description: Accessing window during render causes hydration mismatches
                     because window does not exist on the server.
        Fix: Wrap browser API access in a useEffect hook.

    HIGH     postinstall script in dependency: husky
        ID: supply-chain-postinstall-husky
        Description: The package "husky" runs a shell script on install:
                     Script: node husky install
        Fix: Review the script contents and verify it is safe before proceeding.

────────────────────────────────────────────────────────────────────────────────
  MEDIUM (3 issues)
────────────────────────────────────────────────────────────────────────────────

   MEDIUM    Outdated package: axios
        ID: outdated-axios
        Description: axios is outdated. Current: 0.27.2, Wanted: 0.27.2, Latest: 1.7.2.
                     This is a major version update.
        Fix: Run: npm install axios@1.7.2

   MEDIUM    new Date() used in render — potential hydration mismatch
        ID: hydration-new-date-in-render-src/components/Footer.tsx-31
        File: src/components/Footer.tsx:31
        Description: Calling new Date() during render returns different timestamps
                     on the server and client, causing React hydration errors.
        Fix: Move new Date() inside a useEffect hook.

   MEDIUM    Non-standard license: some-package (UNLICENSED)
        ID: license-some-package-UNLICENSED
        Description: The package "some-package" has no declared license.
                     You cannot legally use it without permission from the author.
        Fix: Contact the package author or replace with a licensed alternative.

────────────────────────────────────────────────────────────────────────────────
  LOW (2 issues)
────────────────────────────────────────────────────────────────────────────────

     LOW     Hardcoded HTTP URL
        ID: code-security-http-hardcoded-url-src/api/client.ts-5
        File: src/api/client.ts:5
        Description: A hardcoded HTTP URL was found. HTTP traffic is unencrypted
                     and can be intercepted.
        Fix: Replace http:// with https:// for all external URLs.

     LOW     heavy component not lazy-loaded: recharts
        ID: bundle-heavy-import-src/pages/dashboard.tsx-3
        File: src/pages/dashboard.tsx:3
        Description: recharts is imported directly and will be included in the
                     initial JavaScript bundle, slowing down page load.
        Fix: Use React.lazy() or Next.js dynamic() to load it only when needed.

────────────────────────────────────────────────────────────────────────────────
  SCANNER DETAILS
────────────────────────────────────────────────────────────────────────────────

  ✓ CLEAN                        npm-audit (820ms)
  ✗ 2 issues                     outdated (1.2s)
  ✓ CLEAN                        deprecated (1.6s)
  ✗ 1 issue                      secrets (45ms)
  ✗ 2 issues                     code-security (18ms)
  ✓ CLEAN                        nextjs (3ms)
  ✗ 1 issue                      license (2ms)
  ✗ 1 issue                      supply-chain (1ms)
  ✓ CLEAN                        rsc-boundary (12ms)
  ✗ 2 issues                     hydration (10ms)
  ✗ 1 issue                      bundle (14ms)
  ✓ CLEAN                        source-maps (4ms)

════════════════════════════════════════════════════════════════════════════════
  ✗ SCAN FAILED — Critical or high severity issues found
    2 critical, 5 high severity issues must be addressed
════════════════════════════════════════════════════════════════════════════════
```

### When your project passes the scan

```
────────────────────────────────────────────────────────────────────────────────
  SCANNER DETAILS
────────────────────────────────────────────────────────────────────────────────

  ✓ CLEAN                        npm-audit (612ms)
  ✓ CLEAN                        outdated (980ms)
  ✓ CLEAN                        deprecated (1.4s)
  ✓ CLEAN                        secrets (21ms)
  ✓ CLEAN                        code-security (13ms)
  ✓ CLEAN                        nextjs (2ms)
  ✓ CLEAN                        license (1ms)
  ✓ CLEAN                        supply-chain (0ms)
  ✓ CLEAN                        rsc-boundary (0ms)
  ✓ CLEAN                        hydration (8ms)
  ✓ CLEAN                        bundle (11ms)
  ✓ CLEAN                        source-maps (3ms)

════════════════════════════════════════════════════════════════════════════════
  ✓ SCAN PASSED — No critical or high severity issues found
════════════════════════════════════════════════════════════════════════════════
```

Each issue tells you:
- **Severity** — Critical / High / Medium / Low
- **What the problem is** — plain description of the issue
- **Where it is** — the exact file and line number
- **How to fix it** — a specific action you can take right now

---

## Save the Report to a File

```bash
# HTML file — open in any browser
npx web-secure-verify scan --format html --output report.html

# JSON file — for scripts or dashboards
npx web-secure-verify scan --format json --output report.json

# Markdown — paste into a GitHub PR comment
npx web-secure-verify scan --format markdown --output report.md

# SARIF — upload to GitHub Code Scanning
npx web-secure-verify scan --format sarif --output results.sarif
```

---

## Useful Options

```bash
# Scan a specific folder (not the current directory)
npx web-secure-verify scan --path ./my-app

# Only show high and critical issues
npx web-secure-verify scan --severity high

# Skip certain checks
npx web-secure-verify scan --skip outdated,license,bundle

# Auto-fix issues interactively after the scan
npx web-secure-verify scan --fix

# See all available scanners
npx web-secure-verify list-scanners
```

---

## Install Globally (optional)

If you want to use the tool regularly without `npx`:

```bash
npm install -g web-secure-verification
web-secure-verify scan
```

---

## Requirements

- Node.js 18 or higher
- npm installed
- The project must have a `package.json` with `node_modules/` present

---

## Author

**Pruthvi Darji**

## License

MIT
