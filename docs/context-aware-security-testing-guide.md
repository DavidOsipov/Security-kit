# Context-Aware Security Testing Guide

## Overview

The Security-kit library uses a sophisticated context-aware security profile system that replaces the previous binary URL bypass logic. This guide explains how to choose appropriate security contexts for different testing scenarios while maintaining OWASP ASVS L3 compliance.

## Security Profile System

### How It Works

The security system uses configurable **security profiles** that define:
- **Threshold**: Maximum security score before input is blocked
- **Shell Metachar Penalty**: Points added per shell metacharacter detected  
- **Allow Legitimate Use**: Whether the context permits special characters in legitimate usage
- **Description**: Human-readable explanation of the context's purpose

### Context Resolution

The `resolveSecurityProfile(context)` function:
1. Checks for exact context matches first
2. Attempts pattern matching for complex contexts (e.g., "createSecureURL fragment")
3. Falls back to the default profile (threshold: 50) for unknown contexts

## Security Profile Reference

### High-Security Contexts (Strict Thresholds)

**Use these for attack vectors that must never succeed:**

```typescript
// Shell injection and command line attacks - MAXIMUM SECURITY
"shell-input"     // threshold: 20, penalty: 70
"command-line"    // threshold: 15, penalty: 80

// Example usage:
normalizeInputString(maliciousPayload, "shell-input");
```

### Moderate Security Contexts 

**Use for database/API content that could be dangerous:**

```typescript
// Database and API contexts - MODERATE SECURITY  
"database-content"  // threshold: 70, penalty: 35
"api-parameter"     // threshold: 60, penalty: 40
"input"            // threshold: 60, penalty: 45 (generic fallback)

// Example usage:
normalizeInputString(sqlPayload, "database-content");
normalizeInputString(apiData, "api-parameter");
```

### Content Processing Contexts (Higher Thresholds)

**Use for content that may legitimately contain special characters:**

```typescript
// Natural language and display contexts
"natural-language"  // threshold: 100, penalty: 20
"display-text"      // threshold: 85, penalty: 15  
"user-content"      // threshold: 90, penalty: 25

// Example usage:
normalizeInputString("Hello, World! (café)", "natural-language"); // Should PASS
normalizeInputString("User comment: Nice job! ⭐", "display-text");
```

### URL Processing Contexts (High Thresholds)

**Use for URL components that need to allow legitimate URL patterns:**

```typescript
// URL contexts - allow legitimate URL syntax
"scheme-authority"  // threshold: 130, penalty: 8
"url-component"     // threshold: 120, penalty: 10
"hostname"          // threshold: 120, penalty: 5
"path"             // threshold: 110, penalty: 8
"query"            // threshold: 100, penalty: 12
"fragment"         // threshold: 105, penalty: 10

// Function-specific contexts
"createSecureURL"   // threshold: 130, penalty: 8
"updateURLParams"   // threshold: 130, penalty: 8
"validateURL"       // threshold: 130, penalty: 8
"parseURLParams"    // threshold: 130, penalty: 8

// Example usage:
normalizeInputString("https://example.com/path?key=value", "scheme-authority");
normalizeInputString("/api/users/123", "path");
```

## Test Migration Patterns

### ❌ INCORRECT (Old Pattern)
```typescript
// DON'T: Use made-up test contexts
normalizeInputString(payload, "apt-attack");
normalizeInputString(cmdPayload, "cmd-test");
normalizeInputString(sqlPayload, "sql-test");
```

### ✅ CORRECT (New Pattern)
```typescript  
// DO: Use appropriate security profile contexts
normalizeInputString(payload, "input");              // Generic attacks
normalizeInputString(cmdPayload, "shell-input");     // Command injection  
normalizeInputString(sqlPayload, "database-content"); // SQL injection
```

## Error Handling Updates

### Import Both Error Types
```typescript
import { InvalidParameterError, SecurityValidationError } from "../../src/errors.ts";
```

### Updated Error Expectations
```typescript
// Support both error types since SecurityValidationError extends InvalidParameterError
try {
  normalizeInputString(maliciousPayload, "shell-input");
  // Should not reach here for attacks
  return false;
} catch (error) {
  if (error instanceof InvalidParameterError || error instanceof SecurityValidationError) {
    // Expected - security system blocked the attack
    expect(error.message).toMatch(
      /shell injection|expansion|bidirectional|invisible|homoglyph|security risk|cumulative security/i
    );
    return true;
  }
  throw error;
}
```

## Security Considerations

### Critical Security Rules

1. **Shell injection tests MUST use `"shell-input"` or `"command-line"` contexts** to maintain OWASP ASVS L3 compliance
2. **Never weaken security for convenience** - if a test fails, understand WHY before changing contexts
3. **Legitimate content should pass** in appropriate contexts (this is correct behavior)
4. **Attack vectors should still fail** even in permissive contexts (homoglyphs, invisible chars, etc.)

### Context Selection Guidelines

**Ask yourself:**
1. **What is the real-world usage scenario?** (shell command vs. display text vs. URL)
2. **What security threats apply?** (injection vs. spoofing vs. DoS)
3. **Should special characters be allowed?** (punctuation in names vs. metacharacters in commands)

**Choose the MOST RESTRICTIVE context that allows legitimate use cases.**

### Validation Process

After updating contexts:
1. **Run the test suite** to verify security effectiveness is maintained
2. **Check that attack vectors are still blocked** appropriately  
3. **Verify legitimate content passes** in appropriate contexts
4. **Ensure no new vulnerabilities** are introduced

## Example Test Conversions

### Shell Injection Test
```typescript
// Before:
normalizeInputString(cmdPayload, "cmd-test");

// After:  
normalizeInputString(cmdPayload, "shell-input"); // threshold: 20, strict security
```

### Path Traversal Test
```typescript
// Before:
normalizeInputString(pathPayload, "path-test"); 

// After:
normalizeInputString(pathPayload, "path"); // threshold: 110, allows URL paths
```

### Legitimate Content Test  
```typescript
// Before (might have failed):
normalizeInputString("Hello World!", "generic-test");

// After (should pass):
normalizeInputString("Hello World!", "natural-language"); // threshold: 100
```

## Debugging Context Issues

### Enable Debug Logging
The security system provides detailed debug logs:
```
[INFO] Security scoring debug | context={"context":"input","totalScore":45,"threshold":60,"blocked":false}
```

### Common Issues
- **Test fails unexpectedly**: Context threshold too low, use higher-threshold context
- **Attack bypasses defenses**: Context threshold too high, use lower-threshold context  
- **Legitimate content blocked**: Wrong context for use case, choose appropriate context

## Conclusion

The context-aware security system provides better security through appropriate context-based validation while allowing legitimate use cases to succeed. Always prioritize security effectiveness over test convenience, and ensure that the context matches the real-world usage scenario.

For questions or clarification, consult the Security Constitution and Testing Constitution documents.