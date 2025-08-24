# Security-Kit

![NPM Version](https://img.shields.io/npm/v/@david-osipov/security-kit?style=for-the-badge)
![License](https://img.shields.io/npm/l/@david-osipov/security-kit?style=for-the-badge)
![Build Status](https://img.shields.io/github/actions/workflow/status/david-osipov/Security-Kit/ci.yml?branch=main&style=for-the-badge)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white)

**Security-Kit is not just a collection of utilities; it's a security philosophy you can install.**

This is a comprehensive, opinionated, and modern security toolkit for browser-based applications. It provides both cryptographic primitives and safe development helpers, designed to be the reference implementation for a project's Security Constitution. It is built on a **Zero Trust** philosophy, assuming no part of the system is infallible.

The entire library is written in TypeScript, has zero dependencies, and leverages the native **Web Crypto API** for maximum performance and security in modern environments.

## Core Philosophy

This library is built on a set of non-negotiable principles, codified in the [Security Constitution](./Security%20Consitution.md).

*   🛡️ **Secure by Default:** The default state of every function is the most secure state. Insecure actions are forbidden.
*   🏰 **Defense in Depth:** Multiple, independent security controls are layered to protect against failure in any single component.
*   🔒 **Principle of Least Privilege:** Every component operates with the minimum level of access necessary to perform its function.
*   💥 **Fail Loudly, Fail Safely:** In the face of an error or unavailable security primitive, the system throws a specific error and never silently falls back to an insecure alternative.
*   ✅ **Verifiable Security:** A security control is considered non-existent until it is validated by an automated, adversarial test.

## Installation

```bash
npm install @david-osipov/security-kit
