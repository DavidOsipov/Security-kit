# SecureLRUCache - Comprehensive Usage Examples

The `SecureLRUCache` is a security-hardened, high-performance LRU cache designed for storing sensitive byte arrays with built-in protections against timing attacks, memory exhaustion, and data leakage.

## Table of Contents

1. [Basic Usage](#basic-usage)
2. [Security-Focused Configurations](#security-focused-configurations)
3. [Real-World Applications](#real-world-applications)
4. [Performance Optimization](#performance-optimization)
5. [Error Handling](#error-handling)
6. [TypeScript Usage](#typescript-usage)

## Basic Usage

### Simple Cache Setup

```typescript
import { SecureLRUCache } from '@david-osipov/security-kit';

// Create a basic cache
const cache = new SecureLRUCache({
  maxEntries: 100,
  maxBytes: 5 * 1024 * 1024, // 5MB
  defaultTtlMs: 300_000, // 5 minutes
});

// Store data
const data = new TextEncoder().encode('Hello, World!');
cache.set('greeting', data);

// Retrieve data
const retrieved = cache.get('greeting');
if (retrieved) {
  console.log(new TextDecoder().decode(retrieved)); // "Hello, World!"
}

// Check cache statistics
console.log(cache.getStats());
```

### Using the Singleton for Simple Cases

```typescript
import { VerifiedByteCache } from '@david-osipov/security-kit';

// Store global configuration
const config = new TextEncoder().encode(JSON.stringify({
  apiUrl: 'https://api.example.com',
  version: '1.0.0'
}));
VerifiedByteCache.set('app:config', config);

// Retrieve anywhere in your app
const configData = VerifiedByteCache.get('app:config');
if (configData) {
  const config = JSON.parse(new TextDecoder().decode(configData));
  console.log('App config:', config);
}
```

## Security-Focused Configurations

### Maximum Security Setup

```typescript
import { SecureLRUCache } from '@david-osipov/security-kit';

const secureCache = new SecureLRUCache({
  maxEntries: 50,
  maxBytes: 1024 * 1024, // 1MB
  defaultTtlMs: 60 * 1000, // 1 minute - short TTL for sensitive data
  
  // Security options
  copyOnSet: true, // Store defensive copies
  copyOnGet: true, // Return defensive copies
  freezeReturns: true, // Freeze returned arrays
  rejectSharedBuffers: true, // Reject SharedArrayBuffer views
  
  // Memory management
  highWatermarkBytes: 800 * 1024, // Cleanup at 80% capacity
  maxSyncEvictions: 3, // Limit blocking operations
  
  // Monitoring
  onEvict: (entry) => {
    console.log(`[SECURITY] Evicted sensitive data: ${entry.url} (${entry.reason})`);
  },
  onWipeError: (error) => {
    console.error('[CRITICAL] Failed to wipe sensitive data:', error);
    // Alert security team
  },
  
  // Production settings
  includeUrlsInStats: false, // Don't leak URLs in telemetry
});

// Store encryption keys
const encryptionKey = crypto.getRandomValues(new Uint8Array(32));
secureCache.set('crypto:key:user:123', encryptionKey);

// Data is automatically wiped on eviction
```

### Development vs Production Configuration

```typescript
import { SecureLRUCache } from '@david-osipov/security-kit';

const isDevelopment = process.env.NODE_ENV === 'development';

const cache = new SecureLRUCache({
  maxEntries: isDevelopment ? 20 : 200,
  maxBytes: isDevelopment ? 1024 * 1024 : 10 * 1024 * 1024,
  defaultTtlMs: isDevelopment ? 30_000 : 300_000,
  
  // Debug options for development
  includeUrlsInStats: isDevelopment,
  logger: isDevelopment ? console : undefined,
  
  onEvict: isDevelopment 
    ? (entry) => console.log(`[DEV] Evicted: ${entry.url}`)
    : undefined,
});
```

## Real-World Applications

### User Session Cache

```typescript
import { SecureLRUCache } from '@david-osipov/security-kit';

interface UserSession {
  userId: string;
  permissions: string[];
  loginTime: number;
  csrfToken: string;
}

class SessionManager {
  private sessionCache = new SecureLRUCache({
    maxEntries: 10000,
    maxBytes: 50 * 1024 * 1024, // 50MB
    defaultTtlMs: 30 * 60 * 1000, // 30 minutes
    onEvict: (entry) => {
      console.log(`Session expired: ${entry.url.replace('session:', '')}`);
    }
  });

  storeSession(sessionId: string, session: UserSession, customTtl?: number): void {
    const sessionData = new TextEncoder().encode(JSON.stringify(session));
    this.sessionCache.set(`session:${sessionId}`, sessionData, {
      ttlMs: customTtl
    });
  }

  getSession(sessionId: string): UserSession | null {
    const sessionData = this.sessionCache.get(`session:${sessionId}`);
    if (!sessionData) return null;
    
    try {
      return JSON.parse(new TextDecoder().decode(sessionData));
    } catch {
      // Invalid session data
      this.sessionCache.delete(`session:${sessionId}`);
      return null;
    }
  }

  invalidateSession(sessionId: string): void {
    this.sessionCache.delete(`session:${sessionId}`);
  }

  getActiveSessions(): number {
    return this.sessionCache.getStats().size;
  }
}

// Usage
const sessionManager = new SessionManager();
sessionManager.storeSession('abc123', {
  userId: 'user456',
  permissions: ['read', 'write'],
  loginTime: Date.now(),
  csrfToken: 'secure-token-here'
});
```

### API Response Cache

```typescript
import { SecureLRUCache } from '@david-osipov/security-kit';

class ApiCache {
  private cache = new SecureLRUCache({
    maxEntries: 1000,
    maxBytes: 20 * 1024 * 1024, // 20MB
    defaultTtlMs: 5 * 60 * 1000, // 5 minutes
    highWatermarkBytes: 15 * 1024 * 1024, // Cleanup at 15MB
  });

  async cacheResponse(url: string, response: any, ttl?: number): Promise<void> {
    try {
      const serialized = JSON.stringify(response);
      const compressed = new TextEncoder().encode(serialized);
      
      this.cache.set(`api:${url}`, compressed, { ttlMs: ttl });
    } catch (error) {
      console.warn('Failed to cache API response:', error);
    }
  }

  getCachedResponse<T>(url: string): T | null {
    const cached = this.cache.get(`api:${url}`);
    if (!cached) return null;

    try {
      const serialized = new TextDecoder().decode(cached);
      return JSON.parse(serialized);
    } catch {
      // Corrupted cache entry
      this.cache.delete(`api:${url}`);
      return null;
    }
  }

  invalidatePattern(pattern: string): void {
    const stats = this.cache.getStats();
    // Note: URLs only included in dev mode for security
    if (stats.urls.length > 0) {
      stats.urls
        .filter(url => url.includes(pattern))
        .forEach(url => this.cache.delete(url));
    }
  }

  getCacheMetrics() {
    const stats = this.cache.getStats();
    return {
      hitRate: stats.hits / (stats.hits + stats.misses) * 100,
      memoryUsage: stats.totalBytes,
      entryCount: stats.size,
      evictionRate: stats.evictions / stats.setOps * 100
    };
  }
}

// Usage with fetch wrapper
const apiCache = new ApiCache();

async function fetchWithCache<T>(url: string, options?: RequestInit): Promise<T> {
  // Try cache first (for GET requests)
  if (!options?.method || options.method === 'GET') {
    const cached = apiCache.getCachedResponse<T>(url);
    if (cached) return cached;
  }

  // Fetch from API
  const response = await fetch(url, options);
  const data = await response.json();

  // Cache successful GET responses
  if (response.ok && (!options?.method || options.method === 'GET')) {
    // Cache for different durations based on endpoint
    const ttl = url.includes('/user/') ? 60_000 : 300_000; // 1min vs 5min
    await apiCache.cacheResponse(url, data, ttl);
  }

  return data;
}
```

### File Content Cache

```typescript
import { SecureLRUCache } from '@david-osipov/security-kit';

class FileCache {
  private cache = new SecureLRUCache({
    maxEntries: 100,
    maxBytes: 100 * 1024 * 1024, // 100MB
    defaultTtlMs: 60 * 60 * 1000, // 1 hour
    maxEntryBytes: 10 * 1024 * 1024, // 10MB per file
    onEvict: (entry) => {
      console.log(`File evicted from cache: ${entry.url.replace('file:', '')}`);
    }
  });

  async cacheFile(filePath: string, content: ArrayBuffer): Promise<void> {
    if (content.byteLength > 10 * 1024 * 1024) {
      throw new Error('File too large for cache (max 10MB)');
    }

    const bytes = new Uint8Array(content);
    this.cache.set(`file:${filePath}`, bytes);
  }

  getCachedFile(filePath: string): Uint8Array | null {
    return this.cache.get(`file:${filePath}`) || null;
  }

  async readFileWithCache(filePath: string): Promise<Uint8Array> {
    // Try cache first
    const cached = this.getCachedFile(filePath);
    if (cached) return cached;

    // Read from filesystem (Node.js example)
    const fs = await import('fs/promises');
    const content = await fs.readFile(filePath);
    
    // Cache for next time
    await this.cacheFile(filePath, content.buffer);
    
    return new Uint8Array(content);
  }

  getCacheStatus() {
    const stats = this.cache.getStats();
    return {
      cachedFiles: stats.size,
      totalSize: `${(stats.totalBytes / 1024 / 1024).toFixed(2)} MB`,
      hitRate: `${(stats.hits / (stats.hits + stats.misses) * 100).toFixed(1)}%`
    };
  }
}
```

## Performance Optimization

### Memory-Conscious Configuration

```typescript
import { SecureLRUCache } from '@david-osipov/security-kit';

// For memory-constrained environments
const memoryOptimizedCache = new SecureLRUCache({
  maxEntries: 50,
  maxBytes: 2 * 1024 * 1024, // 2MB total
  highWatermarkBytes: 1.5 * 1024 * 1024, // Cleanup at 1.5MB
  maxSyncEvictions: 2, // Prevent blocking
  defaultTtlMs: 60 * 1000, // Short TTL to prevent memory buildup
  
  onEvict: (entry) => {
    if (entry.reason === 'capacity') {
      console.warn('Memory pressure detected - consider increasing cache size');
    }
  }
});
```

### High-Performance Configuration

```typescript
import { SecureLRUCache } from '@david-osipov/security-kit';

// For high-throughput applications
const highPerfCache = new SecureLRUCache({
  maxEntries: 10000,
  maxBytes: 500 * 1024 * 1024, // 500MB
  defaultTtlMs: 15 * 60 * 1000, // 15 minutes
  
  // Optimize for performance
  copyOnGet: false, // Disable if you control the data
  copyOnSet: false, // Disable if you control the data
  freezeReturns: false, // Disable for performance
  
  // Larger sync eviction limit for batch operations
  maxSyncEvictions: 10,
  
  // Monitor performance
  onEvict: (entry) => {
    // Log only capacity evictions to avoid spam
    if (entry.reason === 'capacity') {
      console.log(`Capacity eviction: ${entry.bytesLength} bytes`);
    }
  }
});

// Batch operations for better performance
function batchStore(entries: Array<{key: string, data: Uint8Array}>) {
  entries.forEach(({key, data}) => {
    try {
      highPerfCache.set(key, data);
    } catch (error) {
      console.warn(`Failed to cache ${key}:`, error);
    }
  });
}
```

## Error Handling

### Comprehensive Error Handling

```typescript
import { SecureLRUCache, InvalidParameterError } from '@david-osipov/security-kit';

class RobustCache {
  private cache = new SecureLRUCache({
    maxEntries: 100,
    maxBytes: 10 * 1024 * 1024,
    defaultTtlMs: 300_000,
    onWipeError: (error) => {
      // Critical: failed to wipe sensitive data
      console.error('[SECURITY ALERT] Wipe failed:', error);
      this.notifySecurityTeam(error);
    }
  });

  safeSet(key: string, data: Uint8Array, options?: { ttlMs?: number }): boolean {
    try {
      this.cache.set(key, data, options);
      return true;
    } catch (error) {
      if (error instanceof InvalidParameterError) {
        console.warn(`Invalid cache parameters for ${key}:`, error.message);
      } else {
        console.error(`Unexpected cache error for ${key}:`, error);
      }
      return false;
    }
  }

  safeGet(key: string): Uint8Array | null {
    try {
      return this.cache.get(key) || null;
    } catch (error) {
      console.error(`Error retrieving ${key}:`, error);
      return null;
    }
  }

  private notifySecurityTeam(error: unknown): void {
    // Implementation for security alerts
    console.error('CRITICAL: Security team notification required');
  }
}
```

## TypeScript Usage

### Strongly Typed Cache Wrapper

```typescript
import { SecureLRUCache } from '@david-osipov/security-kit';

interface CacheValue<T> {
  data: T;
  timestamp: number;
  version: string;
}

class TypedCache<T> {
  private cache = new SecureLRUCache({
    maxEntries: 1000,
    maxBytes: 20 * 1024 * 1024,
    defaultTtlMs: 600_000,
  });

  set(key: string, value: T, ttlMs?: number): boolean {
    try {
      const wrapper: CacheValue<T> = {
        data: value,
        timestamp: Date.now(),
        version: '1.0'
      };
      
      const serialized = JSON.stringify(wrapper);
      const bytes = new TextEncoder().encode(serialized);
      
      this.cache.set(key, bytes, { ttlMs });
      return true;
    } catch {
      return false;
    }
  }

  get(key: string): T | null {
    try {
      const bytes = this.cache.get(key);
      if (!bytes) return null;

      const serialized = new TextDecoder().decode(bytes);
      const wrapper: CacheValue<T> = JSON.parse(serialized);
      
      return wrapper.data;
    } catch {
      // Clean up corrupted entry
      this.cache.delete(key);
      return null;
    }
  }

  has(key: string): boolean {
    return this.cache.get(key) !== undefined;
  }

  delete(key: string): void {
    this.cache.delete(key);
  }
}

// Usage with specific types
interface User {
  id: string;
  name: string;
  email: string;
}

const userCache = new TypedCache<User>();
userCache.set('user:123', {
  id: '123',
  name: 'John Doe',
  email: 'john@example.com'
});

const user = userCache.get('user:123');
if (user) {
  console.log(`Welcome, ${user.name}!`);
}
```

## Advanced Patterns

### Cache Warming Strategy

```typescript
import { SecureLRUCache } from '@david-osipov/security-kit';

class WarmingCache {
  private cache = new SecureLRUCache({
    maxEntries: 500,
    maxBytes: 25 * 1024 * 1024,
    defaultTtlMs: 600_000,
  });

  async warmCache(keys: string[]): Promise<void> {
    console.log(`Warming cache with ${keys.length} entries...`);
    
    const promises = keys.map(async (key) => {
      try {
        const data = await this.fetchData(key);
        const bytes = new TextEncoder().encode(JSON.stringify(data));
        this.cache.set(key, bytes);
      } catch (error) {
        console.warn(`Failed to warm cache for ${key}:`, error);
      }
    });

    await Promise.allSettled(promises);
    
    const stats = this.cache.getStats();
    console.log(`Cache warmed: ${stats.size} entries loaded`);
  }

  private async fetchData(key: string): Promise<any> {
    // Simulate data fetching
    const response = await fetch(`/api/data/${key}`);
    return response.json();
  }
}
```

These examples demonstrate the versatility and security features of `SecureLRUCache`. The cache can be used for various scenarios while maintaining security best practices and optimal performance.