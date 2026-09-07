# PhishGuard — Privacy-First Phishing Risk Analyzer

PhishGuard is a lightweight, browser-based cybersecurity tool that analyzes URLs for common phishing indicators and suspicious structural anomalies. Built entirely with client-side web technologies, PhishGuard performs all heuristic evaluations locally in the browser, ensuring user privacy by design—no external APIs, server logs, or third-party data tracking.

Live Demo: [https://mckenzielewis348-wq.github.io/PhishGuard/](https://mckenzielewis348-wq.github.io/PhishGuard/)

---

## Features

- **Heuristic Threat Detection Engine:**
  - **Brand Impersonation:** Flags suspicious subdomains and domain permutations targeting major organizations (e.g., PayPal, Google, Microsoft, Apple, Chase).
  - **High-Risk TLD Analysis:** Identifies top-level domains frequently associated with phishing campaigns (`.zip`, `.mov`, `.top`, `.tk`, `.xyz`).
  - **Structural Anomaly Detection:** Detects excessive subdomains, multiple hyphenation patterns, and credential obfuscation via `@` symbols in the URL structure.
  - **Keyword & Protocol Inspection:** Scans for high-risk authentication keywords (`login`, `verify`, `update`, `banking`) and missing HTTPS encryption.
  - **Direct IP Address Detection:** Flags URLs relying on raw IPv4 addresses rather than domain names.
- **Privacy-First Architecture:** 100% client-side execution; input data never leaves the user's browser.
- **Local Scan History:** Persists up to 10 recent scans locally using browser `localStorage` with clear-history options.
- **Educational Guidance:** Provides actionable, context-aware security advice based on specific risk factors detected during analysis.
- **One-Click Export:** Facilitates quick copy-to-clipboard functionality for generating standardized incident summaries.

---

## Tech Stack

- **Frontend:** HTML5, CSS3, Modern JavaScript (Vanilla ES6+)
- **Storage:** Browser `localStorage` API
- **Deployment & CI/CD:** GitHub Pages via GitHub Actions workflow (`deploy.yml`)

---

## Repository Structure

```text
PhishGuard/
├── .github/
│   └── workflows/
│       └── deploy.yml    # Continuous Deployment pipeline for GitHub Pages
├── index.html            # Core Application UI & Layout
├── style.css             # Cybersecurity Dark Theme Styles
├── script.js            # Heuristic Analysis & Local Storage Logic
└── README.md             # Project Documentation
