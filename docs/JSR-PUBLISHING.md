# JSR Publishing Guide

## 🚀 Publishing to JSR (JavaScript Registry)

JSR is the secure, Deno-native package registry with built-in TypeScript support.

### Benefits over npm:
- ✅ **Native TypeScript** - no build step required
- ✅ **Cryptographic verification** - all packages signed
- ✅ **Zero configuration** - works out of the box
- ✅ **Secure by default** - permissions model integrated

### Publishing Steps:

1. **Authenticate with JSR**
   ```bash
   deno run -A jsr:@jsr/publish-helper
   ```

2. **Validate Package**
   ```bash
   deno publish --dry-run
   ```

3. **Publish**
   ```bash
   deno publish
   ```

### Usage by Consumers:

```typescript
// Direct JSR import
import { generateSecureIdSync } from "jsr:@david-osipov/security-kit";

// Specific module import
import { secureCompareAsync } from "jsr:@david-osipov/security-kit/crypto";
```

### Version Management:

```json
{
  "version": "0.8.0",
  "imports": {
    "@david-osipov/security-kit": "jsr:@david-osipov/security-kit@^0.8.0"
  }
}
```

## 🔐 Security Features

- **Immutable packages** - can't be modified after publishing
- **Provenance tracking** - full audit trail
- **Automatic vulnerability scanning** 
- **TypeScript-first** - no supply chain attacks via build process
