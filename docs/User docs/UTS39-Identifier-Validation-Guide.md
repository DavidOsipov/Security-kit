# UTS #39 Unicode Identifier Validation Guide

## Overview

The Security Kit now includes **context-aware UTS #39 Unicode identifier validation** for programming language contexts. This feature provides robust security validation specifically for variable names, function names, class names, and other programming identifiers while preserving the library's existing functionality for URLs and general text processing.

## Key Features

- 🔒 **Context-Aware Security**: UTS #39 validation is only applied to programming identifier contexts
- ⚙️ **Fully Configurable**: Enable/disable validation and customize context detection
- 🚀 **Performance Optimized**: Configurable length limits and efficient validation
- 🔧 **Development-Friendly**: Optional validation logging in development environments
- ✅ **Non-Breaking**: All existing URL and text processing functionality remains unchanged

## Quick Start

### Basic Usage

```typescript
import { normalizeIdentifierString } from '@david-osipov/security-kit';

// ✅ Valid identifier - passes validation
const validId = normalizeIdentifierString('myVariable123');
console.log(validId); // "myVariable123"

// ❌ Invalid identifier - throws InvalidParameterError
try {
  const invalidId = normalizeIdentifierString('my@variable');
} catch (error) {
  console.error(error.message);
  // "[security-kit] identifier: Programming identifier contains restricted character '@' (U+0040) per UTS #39 identifier security guidelines."
}
```

### Automatic Context Detection

```typescript
import { normalizeInputString } from '@david-osipov/security-kit';

// Automatically triggers UTS #39 validation for identifier contexts
const functionName = normalizeInputString('validateUser', 'function name');
const className = normalizeInputString('UserClass', 'class definition');
const variableName = normalizeInputString('userData', 'variable assignment');

// URL processing continues to work normally (no UTS #39 validation applied)
const urlComponent = normalizeInputString('https://example.com/api?param=value', 'URL');
```

## Configuration

### Getting Current Configuration

```typescript
import { getUTS39IdentifierConfig } from '@david-osipov/security-kit';

const config = getUTS39IdentifierConfig();
console.log(config);
```

Default configuration:
```typescript
{
  enableUTS39Validation: true,        // UTS #39 validation is enabled
  enableContextDetection: true,       // Automatic context detection enabled
  additionalIdentifierContexts: [],   // No additional custom contexts
  maxIdentifierLength: 1024,          // Skip validation for identifiers > 1024 chars
  logIdentifierValidation: false      // No validation logging (production-safe)
}
```

### Customizing Configuration

```typescript
import { setUTS39IdentifierConfig } from '@david-osipov/security-kit';

// Disable UTS #39 validation entirely
setUTS39IdentifierConfig({
  enableUTS39Validation: false
});

// Add custom context patterns
setUTS39IdentifierConfig({
  additionalIdentifierContexts: ['customVar', 'apiKey', 'fieldName']
});

// Enable development logging
setUTS39IdentifierConfig({
  logIdentifierValidation: true  // Only works in development, blocked in production
});

// Adjust performance limits
setUTS39IdentifierConfig({
  maxIdentifierLength: 512  // Skip validation for very long identifiers
});
```

## Context Detection

### Built-in Context Patterns

The library automatically triggers UTS #39 validation when the context string contains:

- `identifier`
- `variable`
- `function`
- `class`
- `property`

### Custom Context Patterns

```typescript
import { setUTS39IdentifierConfig, normalizeInputString } from '@david-osipov/security-kit';

// Add custom patterns
setUTS39IdentifierConfig({
  additionalIdentifierContexts: ['apiEndpoint', 'databaseField']
});

// These will now trigger UTS #39 validation
const endpoint = normalizeInputString('getUserData', 'apiEndpoint processing');
const field = normalizeInputString('user_id', 'databaseField validation');
```

### Manual Override

```typescript
import { normalizeInputString } from '@david-osipov/security-kit';

// Force UTS #39 validation regardless of context
const strictId = normalizeInputString('someValue', 'any context', {
  strictIdentifierMode: true
});
```

## Security Properties

### What UTS #39 Validation Blocks

The identifier validation blocks characters that are inappropriate for programming identifiers:

- **Control characters**: `\u0000-\u001F`, `\u007F-\u009F`
- **Invisible/bidirectional characters**: `\u200B-\u200F`, `\u202A-\u202E`, `\u2066-\u2069`
- **Structural characters**: `<>'"&%@#$[]{}()\\/`

### What It Allows

Valid programming identifier characters including:
- ASCII letters: `a-z`, `A-Z`
- Digits: `0-9`
- Underscore: `_`
- Unicode letters and valid identifier characters per UTS #39

### Important: Context Specificity

⚠️ **Critical**: UTS #39 validation is **NOT applied to URLs or general text** because it would block essential characters like `/`, `?`, `&`, `@`, `=`, `#`, `%`.

```typescript
// ✅ This works - URL processing bypasses UTS #39
const url = normalizeInputString('https://api.example.com/users?id=123&format=json');

// ✅ This works - identifier gets UTS #39 validation
const identifier = normalizeIdentifierString('userName');

// ❌ This fails - trying to use identifier validation on URL
const badUsage = normalizeIdentifierString('https://example.com'); // Throws error!
```

## Error Handling

```typescript
import { normalizeIdentifierString, InvalidParameterError } from '@david-osipov/security-kit';

try {
  const result = normalizeIdentifierString('invalid@identifier');
} catch (error) {
  if (error instanceof InvalidParameterError) {
    console.error('Validation failed:', error.message);
    console.error('Error code:', error.code); // "ERR_INVALID_PARAMETER"
  }
}
```

## Performance Considerations

### Length Limits

By default, identifiers longer than 1024 characters skip UTS #39 validation for performance:

```typescript
// Configure shorter limit for stricter performance
setUTS39IdentifierConfig({
  maxIdentifierLength: 256
});
```

### Validation Logging

Development logging can help with debugging but is automatically blocked in production:

```typescript
// Development only - helps debug validation issues
setUTS39IdentifierConfig({
  logIdentifierValidation: true  // Throws error if NODE_ENV=production
});
```

## Integration Examples

### Express.js Route Parameters

```typescript
import { normalizeInputString } from '@david-osipov/security-kit';

app.get('/api/:functionName', (req, res) => {
  try {
    // Automatically triggers UTS #39 validation for function names
    const safeFunctionName = normalizeInputString(req.params.functionName, 'function parameter');
    // Process with validated identifier...
  } catch (error) {
    res.status(400).json({ error: 'Invalid function name' });
  }
});
```

### Database Column/Field Validation

```typescript
import { normalizeInputString, setUTS39IdentifierConfig } from '@david-osipov/security-kit';

// Configure custom contexts for database operations
setUTS39IdentifierConfig({
  additionalIdentifierContexts: ['column', 'field', 'table']
});

function validateColumnName(columnName: string): string {
  return normalizeInputString(columnName, 'database column');
}
```

### Code Generation Tools

```typescript
import { normalizeIdentifierString } from '@david-osipov/security-kit';

class CodeGenerator {
  generateMethod(methodName: string, params: string[]): string {
    // Validate method name
    const safeMethodName = normalizeIdentifierString(methodName, 'method name');
    
    // Validate parameter names
    const safeParams = params.map(param => 
      normalizeIdentifierString(param, 'parameter name')
    );
    
    return `function ${safeMethodName}(${safeParams.join(', ')}) { /* ... */ }`;
  }
}
```

## Migration Guide

### Existing Code

If you're already using the security kit, **no changes are required**. All existing functionality continues to work exactly as before.

### Opting Into UTS #39 Validation

To start using UTS #39 validation:

1. **Replace general normalization calls** for identifiers:
   ```typescript
   // Before
   const id = normalizeInputString(userInput, 'some context');
   
   // After (for identifiers)
   const id = normalizeIdentifierString(userInput, 'variable name');
   ```

2. **Configure context detection** for your use cases:
   ```typescript
   setUTS39IdentifierConfig({
     additionalIdentifierContexts: ['your', 'custom', 'contexts']
   });
   ```

3. **Test thoroughly** with your existing identifiers to ensure compatibility.

## Best Practices

### ✅ Do

- Use `normalizeIdentifierString()` for programming language identifiers
- Configure custom contexts for your specific use cases
- Handle `InvalidParameterError` appropriately in your application
- Test identifier validation with your existing data
- Use context detection for automatic validation

### ❌ Don't

- Use identifier validation for URLs, file paths, or general text
- Disable validation globally unless necessary
- Set extremely high length limits (DoS risk)
- Enable logging in production environments
- Mix identifier and general text validation inappropriately

## Troubleshooting

### Common Issues

**Issue**: "URL processing fails with UTS #39 error"
**Solution**: Don't use `normalizeIdentifierString()` for URLs. Use `normalizeInputString()` instead.

**Issue**: "Valid identifier is rejected"
**Solution**: Check if the identifier contains characters that are invalid in programming contexts but valid in other contexts.

**Issue**: "Configuration changes don't take effect"
**Solution**: Ensure configuration is set before calling `sealSecurityKit()`.

**Issue**: "Logging doesn't work"
**Solution**: Logging is only available in development environments.

## Security Considerations

### Defense in Depth

UTS #39 identifier validation is **one layer** of the security kit's multi-layered defense:

1. **Context-aware validation** ensures appropriate security levels
2. **Pattern-based threat detection** catches sophisticated attacks
3. **Normalization bomb prevention** protects against DoS
4. **Multi-vector scoring** prevents threshold evasion

### Threat Model

This feature specifically addresses:

- **Code injection** via identifier manipulation
- **Visual spoofing** in programming contexts
- **Supply chain attacks** through malicious identifiers
- **Trojan Source attacks** in identifier names

## API Reference

### Functions

- `normalizeIdentifierString(input, context?, options?)` - Normalize with UTS #39 validation
- `getUTS39IdentifierConfig()` - Get current configuration
- `setUTS39IdentifierConfig(config)` - Update configuration

### Types

```typescript
interface UTS39IdentifierConfig {
  enableUTS39Validation: boolean;
  enableContextDetection: boolean;
  additionalIdentifierContexts: readonly string[];
  maxIdentifierLength: number;
  logIdentifierValidation: boolean;
}
```

## Conclusion

The UTS #39 identifier validation feature provides robust, context-aware security for programming language identifiers while maintaining the library's existing functionality. By properly configuring and using this feature, you can significantly enhance the security posture of applications that process user-provided identifiers.

For questions or issues, please refer to the main project documentation or open an issue on GitHub.