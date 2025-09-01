// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov
/**
 * Demo showcasing SecureLRUCache as a standalone caching solution
 * This demo can be run independently of the secure API signing features
 */

import { SecureLRUCache, VerifiedByteCache, type EvictedEntry } from '../dist/index.mjs';

// Demo 1: Basic caching for application data
console.log('=== Demo 1: Basic Application Data Cache ===');

const appCache = new SecureLRUCache({
  maxEntries: 100,
  maxBytes: 5 * 1024 * 1024, // 5MB
  defaultTtlMs: 5 * 60 * 1000, // 5 minutes
  onEvict: (entry) => {
    console.log(`📤 Evicted: ${entry.url} (${entry.reason})`);
  }
});

// Store some application configuration
const config = {
  apiUrl: 'https://api.example.com',
  version: '2.1.0',
  features: ['darkMode', 'notifications', 'analytics']
};

const configBytes = new TextEncoder().encode(JSON.stringify(config));
appCache.set('app:config', configBytes);

// Store user preferences
const userPrefs = {
  theme: 'dark',
  language: 'en-US',
  timezone: 'America/New_York'
};

const prefsBytes = new TextEncoder().encode(JSON.stringify(userPrefs));
appCache.set('user:prefs:12345', prefsBytes);

// Retrieve and display
const retrievedConfig = appCache.get('app:config');
if (retrievedConfig) {
  const config = JSON.parse(new TextDecoder().decode(retrievedConfig));
  console.log('✅ Retrieved app config:', config);
}

const retrievedPrefs = appCache.get('user:prefs:12345');
if (retrievedPrefs) {
  const prefs = JSON.parse(new TextDecoder().decode(retrievedPrefs));
  console.log('✅ Retrieved user preferences:', prefs);
}

console.log('📊 Cache stats:', appCache.getStats());

// Demo 2: Secure token caching with automatic expiration
console.log('\n=== Demo 2: Secure Token Cache ===');

const tokenCache = new SecureLRUCache({
  maxEntries: 50,
  maxBytes: 1024 * 1024, // 1MB
  defaultTtlMs: 60 * 1000, // 1 minute for demo (normally longer)
  copyOnGet: true,
  copyOnSet: true,
  rejectSharedBuffers: true,
  onEvict: (entry) => {
    console.log(`🔒 Token evicted: ${entry.url.replace('token:', '')} (${entry.reason})`);
  }
});

// Simulate storing JWT tokens
const generateMockToken = (userId: string) => {
  const payload = {
    sub: userId,
    exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour
    iat: Math.floor(Date.now() / 1000),
    scope: 'read write'
  };
  return `mock.jwt.${btoa(JSON.stringify(payload))}`;
};

// Store tokens for multiple users
for (let i = 1; i <= 5; i++) {
  const userId = `user${i}`;
  const token = generateMockToken(userId);
  const tokenBytes = new TextEncoder().encode(token);
  
  // Vary TTL based on user type
  const ttl = userId === 'user1' ? 30000 : undefined; // VIP user gets longer cache
  tokenCache.set(`token:${userId}`, tokenBytes, { ttlMs: ttl });
  
  console.log(`🎫 Cached token for ${userId}`);
}

// Retrieve a token
const user1Token = tokenCache.get('token:user1');
if (user1Token) {
  const token = new TextDecoder().decode(user1Token);
  console.log('✅ Retrieved token for user1:', token.substring(0, 20) + '...');
}

// Demo 3: Global singleton usage
console.log('\n=== Demo 3: Global Singleton Cache ===');

// Store global application state
const appState = {
  isAuthenticated: true,
  currentRoute: '/dashboard',
  notifications: 3,
  lastSync: Date.now()
};

const stateBytes = new TextEncoder().encode(JSON.stringify(appState));
VerifiedByteCache.set('app:state', stateBytes);

// Store cached API responses
const apiResponse = {
  users: [
    { id: 1, name: 'Alice' },
    { id: 2, name: 'Bob' }
  ],
  total: 2,
  page: 1
};

const responseBytes = new TextEncoder().encode(JSON.stringify(apiResponse));
VerifiedByteCache.set('api:users:page1', responseBytes);

// Retrieve from global cache
const cachedState = VerifiedByteCache.get('app:state');
if (cachedState) {
  const state = JSON.parse(new TextDecoder().decode(cachedState));
  console.log('✅ Global app state:', state);
}

const cachedResponse = VerifiedByteCache.get('api:users:page1');
if (cachedResponse) {
  const response = JSON.parse(new TextDecoder().decode(cachedResponse));
  console.log('✅ Cached API response:', response);
}

console.log('📊 Global cache stats:', VerifiedByteCache.getStats());

// Demo 4: Memory management and eviction
console.log('\n=== Demo 4: Memory Management Demo ===');

const smallCache = new SecureLRUCache({
  maxEntries: 3, // Very small for demo
  maxBytes: 1024, // 1KB total
  defaultTtlMs: 10000, // 10 seconds
  onEvict: (entry) => {
    console.log(`🗑️  Evicted due to ${entry.reason}: ${entry.url} (${entry.bytesLength} bytes)`);
  }
});

// Fill the cache beyond capacity to demonstrate eviction
const largeData = new Uint8Array(300); // 300 bytes each
largeData.fill(65); // Fill with 'A'

console.log('Adding entries to small cache...');
for (let i = 1; i <= 5; i++) {
  const key = `data:item${i}`;
  smallCache.set(key, largeData);
  console.log(`📥 Added ${key}`);
  
  const stats = smallCache.getStats();
  console.log(`   Cache: ${stats.size} entries, ${stats.totalBytes} bytes`);
}

// Demo 5: TTL expiration
console.log('\n=== Demo 5: TTL Expiration Demo ===');

const ttlCache = new SecureLRUCache({
  maxEntries: 10,
  maxBytes: 10240,
  defaultTtlMs: 2000, // 2 seconds for demo
  onEvict: (entry) => {
    if (entry.reason === 'ttl') {
      console.log(`⏰ Expired: ${entry.url}`);
    }
  }
});

// Add some data with short TTL
const shortLivedData = new TextEncoder().encode('This will expire soon');
ttlCache.set('temp:data1', shortLivedData);
ttlCache.set('temp:data2', shortLivedData, { ttlMs: 1000 }); // Even shorter TTL

console.log('📥 Added temporary data (will expire in 1-2 seconds)');

// Wait and try to retrieve
setTimeout(() => {
  console.log('⏱️  After 1.5 seconds...');
  
  const data1 = ttlCache.get('temp:data1');
  const data2 = ttlCache.get('temp:data2');
  
  console.log('temp:data1 still cached:', !!data1);
  console.log('temp:data2 still cached:', !!data2);
  
  const stats = ttlCache.getStats();
  console.log(`📊 TTL Cache stats: ${stats.expired} expired, ${stats.size} remaining`);
}, 1500);

// Final summary
setTimeout(() => {
  console.log('\n=== Demo Summary ===');
  console.log('✅ Basic application data caching');
  console.log('✅ Secure token management with automatic cleanup');
  console.log('✅ Global singleton pattern for simple use cases');
  console.log('✅ Automatic memory management and LRU eviction');
  console.log('✅ Time-based expiration for temporary data');
  console.log('\n🎉 SecureLRUCache is ready for standalone use in your applications!');
}, 3000);