# Contributing to Security-kit

Thanks for your interest in contributing to Security-kit! This project implements OWASP ASVS L3 security standards with a hybrid Deno/Node.js development pipeline for enhanced supply chain security.

## 🛡️ Security-First Development

This project prioritizes security above all else. Every contribution must maintain our OWASP ASVS L3 compliance and Zero Trust security model.

### Required Reading

1. **`docs/Constitutions/Security Constitution.md`** - THE definitive security guidelines
2. **`docs/Constitutions/The Official Testing & Quality Assurance Constitution.md`** - Testing methodology
3. **`AGENTS.md`** - AI agent instructions (contains detailed security patterns)

## 🚀 Development Environment Setup

We use a **hybrid approach** combining the best of Node.js tooling with Deno's security features:

### Prerequisites

- **Node.js 18.18.0+** (for development tooling)
- **Deno 1.x** (for security validation and testing)
- **Git** with commit signing enabled (security requirement)

### Initial Setup

```bash
# Clone and setup
git clone https://github.com/david-osipov/Security-Kit.git
cd Security-kit

# Install Node.js dependencies (development only)
npm ci

# Verify Deno security environment
deno task security:audit

# Run hybrid validation
npm run ci:hybrid
```

## 🔄 Development Workflow

### 1. Create Your Branch

```bash
git checkout -b feature/your-security-enhancement
# or
git checkout -b fix/security-vulnerability-fix
```

### 2. Development Process

Our hybrid pipeline ensures both development velocity and security:

#### For Code Changes:
```bash
# Node.js development (fast iteration)
npm run dev:hybrid          # Start hybrid development mode
npm run test:watch          # Watch tests during development

# Deno security validation (before commits)
deno task security:audit    # OWASP ASVS L3 compliance check
deno task check            # TypeScript validation
deno task test:deno        # Security-focused tests
```

#### For New Features:
1. **Implement in `src/`** (TypeScript only, strict mode)
2. **Add comprehensive tests** in `tests/` mirroring `src/` structure
3. **Create Deno test equivalent** in `tests/deno/` for security validation
4. **Update documentation** if API changes

### 3. Code Quality Standards

#### Security Requirements (MANDATORY):
- ✅ **Memory Safety**: Use `secureWipe()` for sensitive data
- ✅ **Timing Safety**: Use `secureCompareAsync()` for secret comparisons  
- ✅ **Input Validation**: Validate all parameters with typed errors
- ✅ **No Dynamic Imports**: Static imports only (supply chain security)
- ✅ **Prototype Pollution Prevention**: Use `toNullProto()` for external objects

#### Code Standards:
```bash
# Run all quality checks
npm run ci:hybrid           # Full validation pipeline

# Individual checks
npm run typecheck          # TypeScript strict mode
npm run lint               # ESLint + security rules
npm run test               # Vitest test suite
deno task security:audit   # Security compliance
deno fmt --check src/      # Code formatting
```

## 🧪 Testing Requirements

### Dual Testing Strategy

We maintain both Node.js (Vitest) and Deno tests for comprehensive validation:

#### Node.js Tests (Primary Development):
```bash
npm test                   # Full test suite
npm run test:unit          # Unit tests only
npm run test:security      # Security-focused tests
npm run test:integration   # Integration tests
```

#### Deno Tests (Security Validation):
```bash
deno task test:deno        # Security-enhanced test suite
deno task test:security    # OWASP compliance tests
```

### Test Categories Required:

1. **Unit Tests** - Core functionality
2. **Security Tests** - Adversarial inputs, timing attacks, memory safety
3. **Integration Tests** - Component interactions
4. **Performance Tests** - Benchmark critical paths
5. **Mutation Tests** - Verify test effectiveness (Stryker)

### Example Test Structure:

```typescript
// tests/unit/crypto.test.ts (Vitest)
import { describe, it, expect } from 'vitest';
import { generateSecureIdSync } from '../../src/crypto.ts';

describe('generateSecureIdSync', () => {
  it('should generate cryptographically secure IDs', () => {
    const id = generateSecureIdSync({ length: 32 });
    expect(id).toHaveLength(32);
    expect(/^[A-Za-z0-9_-]+$/.test(id)).toBe(true);
  });
});

// tests/deno/crypto.test.ts (Deno - security focused)
import { assertEquals, assertNotEquals } from "https://deno.land/std@0.210.0/assert/mod.ts";
import { generateSecureIdSync } from "../../src/crypto.ts";

Deno.test("crypto: generates unique IDs with sufficient entropy", () => {
  const ids = new Set();
  
  // Generate 1000 IDs to check for duplicates
  for (let i = 0; i < 1000; i++) {
    const id = generateSecureIdSync({ length: 32 });
    assertEquals(ids.has(id), false, "Generated duplicate ID - insufficient entropy");
    ids.add(id);
  }
});
```

## 📋 Pull Request Process

### Pre-Submit Checklist

Before opening a PR, ensure all checks pass:

```bash
# Complete validation pipeline
npm run ci:hybrid

# This runs:
# ✅ deno task security:audit     - OWASP ASVS L3 compliance  
# ✅ npm run typecheck           - TypeScript strict validation
# ✅ npm run lint                - ESLint + security rules
# ✅ npm test                    - Complete test suite
# ✅ deno task test:deno         - Security-focused Deno tests
```

### PR Requirements

#### Essential Information:
- **Security Impact Assessment**: How does this change affect security?
- **OWASP ASVS L3 Compliance**: Confirm no regressions
- **Performance Impact**: Benchmark security-critical operations
- **Breaking Changes**: Document API modifications
- **Test Coverage**: Include test strategy for changes

#### Security-Sensitive Changes:
For cryptography, input validation, or security controls:
- **Threat Model**: What attacks does this prevent/mitigate?
- **Security Testing**: Include adversarial test cases
- **Documentation**: Update security constitution if needed
- **Review Requirements**: Security team approval required

### Example PR Description:

```markdown
## Summary
Add constant-time string comparison to prevent timing attacks in token validation.

## Security Impact
- **Threat Mitigated**: Timing attack vulnerability in JWT validation
- **OWASP ASVS**: Addresses V3.4.1 (constant-time comparison requirement)
- **Attack Vector**: Eliminated side-channel timing information leakage

## Changes
- Added `secureCompareAsync()` function with constant-time implementation
- Updated all token comparison operations to use secure comparison
- Added timing-attack specific tests with statistical validation

## Testing
- ✅ Unit tests for correct comparison behavior
- ✅ Security tests for timing consistency validation  
- ✅ Performance benchmarks (no significant overhead)
- ✅ Mutation tests confirm robust test coverage

## Breaking Changes
None - internal implementation change only.
```

## 🔐 Security Review Process

### Automated Security Validation

Every PR triggers comprehensive security checks:

1. **Supply Chain Audit**: `deno task security:audit`
2. **Dependency Scanning**: npm audit + Snyk
3. **Code Security**: ESLint security rules
4. **Memory Safety**: Custom linting rules
5. **Type Safety**: Strict TypeScript validation

### Manual Security Review

Security-sensitive changes require human review:

- **Cryptography changes**: Cryptography expert approval
- **Input validation**: Security team review
- **Memory management**: Memory safety validation
- **External interfaces**: API security assessment

## 🚀 Advanced Development

### Performance Benchmarking

```bash
# Benchmark current implementation
npm run bench:compare

# Deno-specific benchmarks
deno task bench:deno
```

### Supply Chain Security

```bash
# Comprehensive security scan
deno task supply-chain:scan

# Validate all import integrity
deno run --allow-read scripts/validate-imports.ts
```

### Migration to Deno (Optional)

We're gradually migrating to Deno for enhanced security:

```bash
# Phase 2: Test migration
deno run --allow-read --allow-write scripts/setup-phase2-tests.ts

# Phase 3: Complete migration  
deno run --allow-read --allow-write scripts/setup-phase3-complete.ts
```

## 📚 Additional Resources

- **Architecture**: `docs/Documentation.md`
- **Security Guidelines**: `docs/Additional security guidelines/`
- **Testing Methodology**: `docs/Methodology/`
- **API Documentation**: Generated from TypeScript definitions

## 🤝 Community Standards

### Code of Conduct
Follow our `CODE_OF_CONDUCT.md` - we maintain a respectful, security-focused community.

### Communication
- **Security Issues**: Use private security advisory (do not open public issues)
- **Feature Discussions**: GitHub Discussions
- **Bug Reports**: GitHub Issues with security assessment

## 🏆 Recognition

Contributors who maintain our security standards and help improve OWASP ASVS L3 compliance will be recognized in our hall of fame and security acknowledgments.

---

**Remember**: Every line of code you contribute protects applications and users worldwide. Security is not optional - it's our core mission. 🛡️
