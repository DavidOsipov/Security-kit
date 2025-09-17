#!/usr/bin/env -S deno run --allow-read --allow-write
/**
 * Fix remaining TypeScript errors for Deno migration
 */

const fixes = [
  // Fix duplicate function declarations in config.ts
  {
    file: "src/config.ts",
    description: "Remove duplicate sealUnicodeSecurityConfig functions",
    action: async (content: string) => {
      // Find and remove duplicate function declarations
      const lines = content.split('\n');
      let inDuplicateFunction = false;
      let braceCount = 0;
      const filteredLines: string[] = [];
      
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        
        // Check if this is the start of a duplicate function
        if (line.includes('export function sealUnicodeSecurityConfig()') && 
            filteredLines.some(prevLine => prevLine.includes('export function sealUnicodeSecurityConfig()'))) {
          inDuplicateFunction = true;
          braceCount = 0;
          continue;
        }
        
        if (inDuplicateFunction) {
          // Count braces to find the end of the function
          braceCount += (line.match(/{/g) || []).length;
          braceCount -= (line.match(/}/g) || []).length;
          
          if (braceCount <= 0 && line.includes('}')) {
            inDuplicateFunction = false;
          }
          continue;
        }
        
        filteredLines.push(line);
      }
      
      return filteredLines.join('\n');
    }
  },
  
  // Fix readonly array mutations in unicode-optimized-loader.ts
  {
    file: "src/generated/unicode-optimized-loader.ts", 
    description: "Fix readonly array mutations",
    action: async (content: string) => {
      return content
        .replace(/array\.push\(m\.target\);/g, '(array as string[]).push(m.target);')
        .replace(/mappings\[index\] = /g, '(mappings as UnicodeConfusableEntry[])[index] = ')
        .replace(/single\[index\] = /g, '(single as string[])[index] = ')
        .replace(/multi\[index_\] = /g, '(multi as string[])[index_] = ')
        .replace(/mappings\[index\+\+\] = /g, '(mappings as UnicodeConfusableEntry[])[index++] = ');
    }
  },
  
  // Fix undefined checks in dom.ts
  {
    file: "src/dom.ts",
    description: "Add proper undefined checks",
    action: async (content: string) => {
      return content
        .replace(/if \(this\.#validationCounter > max\) \{/g, 'if (max && this.#validationCounter > max) {')
        .replace(/if \(s\.length > maxLength\) \{/g, 'if (maxLength && s.length > maxLength) {')
        .replace(/if \(last && now - last <= ttl\) \{/g, 'if (ttl && last && now - last <= ttl) {')
        .replace(/timeoutMs,/g, 'timeoutMs ?? 1500,');
    }
  },
  
  // Fix ArrayBuffer type issues
  {
    file: "src/dom.ts",
    description: "Fix ArrayBuffer type issue in crypto digest",
    action: async (content: string) => {
      return content.replace(
        'this._data = bytes;',
        'this._data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);'
      );
    }
  }
];

async function applyFixes() {
  console.log("🔧 Applying remaining TypeScript fixes...\n");
  
  for (const fix of fixes) {
    try {
      const filePath = `/home/david/Security-kit/${fix.file}`;
      
      let content;
      try {
        content = await Deno.readTextFile(filePath);
      } catch {
        console.log(`⏭️  ${fix.file}: File not found, skipping`);
        continue;
      }
      
      const newContent = await fix.action(content);
      
      if (newContent !== content) {
        await Deno.writeTextFile(filePath, newContent);
        console.log(`✅ ${fix.file}: ${fix.description}`);
      } else {
        console.log(`⏭️  ${fix.file}: No changes needed`);
      }
    } catch (error) {
      console.error(`❌ ${fix.file}: ${error.message}`);
    }
  }
  
  console.log("\n🎯 Running TypeScript check again...");
  const check = new Deno.Command("deno", {
    args: ["check", "src/index.ts"],
    cwd: "/home/david/Security-kit"
  });
  
  const result = await check.output();
  if (result.success) {
    console.log("✅ TypeScript compilation successful!");
  } else {
    console.log("⚠️  Some issues remain:");
    console.log(new TextDecoder().decode(result.stderr));
  }
}

if (import.meta.main) {
  await applyFixes();
}