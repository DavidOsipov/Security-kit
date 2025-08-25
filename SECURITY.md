# Security Policy

## Our Commitment to Security

The Security-kit project is architected with a "security-first" philosophy. As the maintainer, I am deeply committed to ensuring the security and integrity of this codebase. I value the work of independent security researchers and believe that responsible disclosure is essential for maintaining a safe open-source ecosystem.

This policy outlines the process for reporting security vulnerabilities and what you can expect in return.

---

## Supported Versions

Only the latest version of the scripts available in the `main` branch of this repository is actively supported. Vulnerabilities will be addressed in the most current version.

---

## 🛡️ How to Report a Vulnerability

Please choose one of the following methods to report a vulnerability.

### Method 1: GitHub Security Advisories (Preferred)

The preferred method for reporting vulnerabilities is through a private GitHub Security Advisory. This is the most secure and efficient way to report issues as it provides a collaborative space for us to discuss and resolve the vulnerability privately.

➡️ **[Create a new private vulnerability report](https://github.com/DavidOsipov/security-kit/security/advisories/new)**

### Method 2: PGP Encrypted Email (Alternative)

If you are unable to use GitHub Security Advisories, you can send a private, encrypted email to:
**personal@david-osipov.vision**

To ensure the confidentiality of your report, please encrypt your message using the PGP public key below.

- **PGP Public Key:** [`D3FC4983E500AC3F7F136EB80E55C4A47454E82E`](https://openpgpkey.david-osipov.vision/.well-known/openpgpkey/david-osipov.vision/D3FC4983E500AC3F7F136EB80E55C4A47454E82E.asc)

---

### What to Include in Your Report

To help me validate and fix the issue as quickly as possible, please include the following in your report, regardless of the method you choose:

- **A clear and descriptive title** for your report.
- **The type of vulnerability** (e.g., Cross-Site Scripting, Insecure Randomness, Prototype Pollution).
- **The affected script(s)** and version(s).
- **A detailed description** of the vulnerability and its potential impact.
- **A step-by-step proof-of-concept (PoC)** that demonstrates the vulnerability. This is the most important part.
- **Any relevant configurations** or environmental details.

---

## Our Commitment to You

When you report a vulnerability in accordance with this policy, I commit to the following:

- I will acknowledge receipt of your report within **48 business hours**.
- I will provide an initial assessment of the vulnerability's validity and severity.
- I will keep you updated on the progress of the remediation efforts.
- I will notify you when a fix has been released.
- I will publicly credit you for your discovery in the security advisory and release notes, unless you prefer to remain anonymous.

---

## Scope

This policy applies to the JavaScript code within the `/src` directory of this repository.

### Out of Scope

The following are considered out of scope for this security policy:

- Vulnerabilities in third-party websites or services that use this code.
- Vulnerabilities related to the underlying browser or Node.js runtime environment (e.g., a bug in the Web Crypto API itself). Please report these to the respective vendors.
- Issues related to the security of GitHub's infrastructure.

Thank you for helping keep Security-kit and its users safe.