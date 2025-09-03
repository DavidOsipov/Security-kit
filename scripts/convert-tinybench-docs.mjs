#!/usr/bin/env node
// Convert TypeDoc-generated HTML files under `docs/Tinybench docs` into
// a single LLM-friendly Markdown file `docs/tinybench-merged.md`.
// Preserves JS/TS code blocks and strips other HTML/JS assets.

import fs from 'fs/promises';
import path from 'path';
import { JSDOM } from 'jsdom';

const SRC_DIR = path.resolve('docs', 'Tinybench docs');
const OUT_FILE = path.resolve('docs', 'tinybench-merged.md');

async function listHtmlFiles(dir) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const files = [];
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      const sub = await listHtmlFiles(full);
      files.push(...sub);
    } else if (e.isFile() && e.name.endsWith('.html')) {
      files.push(full);
    }
  }
  return files;
}

function textFromNode(node) {
  // Return trimmed text content with normalized whitespace
  if (!node || !node.textContent) return '';
  return node.textContent.replace(/\u00A0/g, ' ').replace(/\s+/g, ' ').trim();
}

function isCodeLike(text) {
  if (!text) return false;
  // heuristics: contains JS/TS keywords or typical symbols
  const jsHints = ['function', '=>', 'const ', 'let ', 'var ', 'class ', 'interface ', 'export ', 'import '];
  if (jsHints.some(h => text.includes(h))) return true;
  // simple token+paren detection
  return /\b\w+\(/.test(text);
}

function nodeToMarkdown(document) {
  const md = [];

  // Try to find the main content area used by TypeDoc
  const content = document.querySelector('.col-content') || document.querySelector('.tsd-panel') || document.body;

  // Convert headings to markdown headings
  for (const el of content.querySelectorAll('h1,h2,h3,h4,h5,h6')) {
    const level = Number(el.tagName[1]);
    const txt = textFromNode(el);
    const md = '\n' + '#'.repeat(level) + ' ' + txt + '\n';
    el.replaceWith(document.createTextNode(md));
  }

  // Convert code blocks: preserve code fences and language hints
  for (const pre of content.querySelectorAll('pre')) {
    const code = pre.querySelector('code');
    const raw = code ? code.textContent : pre.textContent;
    // Determine language from class like language-ts or language-js
    let lang = '';
    if (code && code.className) {
      const m = code.className.match(/language-(\w+)/i);
      if (m) lang = m[1].toLowerCase();
    }
    if (!lang && isCodeLike(raw)) {
      // prefer ts for typed-looking code
      lang = /:\s*\w+/.test(raw) || /interface\s+\w+/.test(raw) ? 'ts' : 'js';
    }
    const fence = '```' + (lang || '');
    // trim leading/trailing blank lines from code content
    const cleanedRaw = String(raw).replace(/\r\n?/g, '\n').replace(/^\n+/, '').replace(/\n+$/, '');
    const node = document.createTextNode('\n' + fence + '\n' + cleanedRaw + '\n```\n');
    pre.replaceWith(node);
  }

  // Remove nav, header, footer, scripts, styles, asides, menus
  // Remove TypeDoc UI chrome and scripts
  const removeSelectors = [
    'header', 'footer', 'script', 'style', '.page-menu', '.col-sidebar', '.tsd-navigation', '.tsd-page-toolbar', '.overlay', '.tsd-anchor-icon', '.tsd-sources', '.tsd-accordion', '.tsd-filter-visibility', '.tsd-theme-toggle', '.tsd-generator'
  ];
  for (const sel of removeSelectors) {
    for (const n of content.querySelectorAll(sel)) n.remove();
  }

  // Replace links with plain text (keep link text)
  for (const a of content.querySelectorAll('a')) {
    const txt = textFromNode(a);
    const href = a.getAttribute && a.getAttribute('href');
    if (href && !href.startsWith('#')) {
      // external or relative link -> markdown link
      a.replaceWith(document.createTextNode('[' + txt + '](' + href + ')'));
    } else {
      a.replaceWith(document.createTextNode(txt));
    }
  }

  // Convert paragraphs to text with blank lines
  for (const p of content.querySelectorAll('p')) {
    const txt = textFromNode(p);
    p.replaceWith(document.createTextNode('\n' + txt + '\n'));
  }
  // Convert inline code
  for (const code of content.querySelectorAll('code')) {
    // skip code already handled inside pre
    if (code.closest('pre')) continue;
    const txt = code.textContent || '';
    code.replaceWith(document.createTextNode('`' + txt + '`'));
  }
  // Convert lists
  for (const ul of content.querySelectorAll('ul')) {
    const items = Array.from(ul.querySelectorAll('li')).map(li => '- ' + textFromNode(li));
    ul.replaceWith(document.createTextNode('\n' + items.join('\n') + '\n'));
  }
  for (const ol of content.querySelectorAll('ol')) {
    const items = Array.from(ol.querySelectorAll('li')).map((li, i) => (i + 1) + '. ' + textFromNode(li));
    ol.replaceWith(document.createTextNode('\n' + items.join('\n') + '\n'));
  }

  // Preserve tables as markdown
  for (const table of content.querySelectorAll('table')) {
    const rows = Array.from(table.querySelectorAll('tr'));
    const matrix = rows.map(r => Array.from(r.querySelectorAll('th,td')).map(c => textFromNode(c)));
    if (matrix.length === 0) { table.remove(); continue; }
    const header = matrix[0];
    const aligns = header.map(() => '---');
    const lines = [];
    lines.push('| ' + header.join(' | ') + ' |');
    lines.push('| ' + aligns.join(' | ') + ' |');
    for (let i = 1; i < matrix.length; i++) lines.push('| ' + matrix[i].join(' | ') + ' |');
    table.replaceWith(document.createTextNode('\n' + lines.join('\n') + '\n'));
  }

  // Finally, get cleaned text and post-process
  let cleaned = String(content.textContent || '')
    .replace(/\r\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .replace(/[ \t]+\n/g, '\n')
    .trim();

  // Collapse consecutive duplicate lines (e.g., repeated signatures or titles)
  const lines = cleaned.split('\n');
  const outLines = [];
  for (let i = 0; i < lines.length; i++) {
    if (i > 0 && lines[i].trim() === lines[i - 1].trim()) continue;
    outLines.push(lines[i]);
  }
  cleaned = outLines.join('\n').replace(/\n{3,}/g, '\n\n');

  md.push(cleaned);
  return md.join('\n\n');
}

async function convert() {
  const files = await listHtmlFiles(SRC_DIR);
  // Prioritize index.html first
  files.sort((a, b) => (path.basename(a) === 'index.html' ? -1 : path.basename(b) === 'index.html' ? 1 : a.localeCompare(b)));

  const parts = [];
  for (const f of files) {
    try {
      const raw = await fs.readFile(f, 'utf8');
      const dom = new JSDOM(raw);
      const doc = dom.window.document;
      const titleEl = doc.querySelector('h1') || doc.querySelector('.tsd-page-title h1');
      const title = titleEl ? textFromNode(titleEl) : path.basename(f);
      // remove original H1 from document to avoid duplicate top-level headings
      if (titleEl && titleEl.parentNode) titleEl.parentNode.removeChild(titleEl);
      parts.push('# ' + title + '\n');
      parts.push(nodeToMarkdown(doc));
      parts.push('\n---\n');
    } catch (err) {
      console.error('Failed to convert', f, err);
    }
  }

  const out = parts.join('\n\n');
  // Post-process the entire merged output: wrap inline interface/type/class declarations
  let final = out.replace(/\u00A0/g, ' ');
  // Wrap single-line inline interface/type/class declarations into TS code blocks
  // Wrap short interface/type/class blocks into TypeScript fenced code blocks.
  // Match starts at line boundary then keyword, then non-greedy until next blank line or EOF.
  final = final.replace(/(^|\n)(\s*)(?:interface|type|class)\b([\s\S]*?)(?=\n\s*\n|$)/gim, (m, p1, p2, p3) => {
    const block = (p2 || '') + (p3 || '');
    // Avoid wrapping extremely large blocks — only wrap reasonable-size declarations
    if (block.length > 2000) return m;
    const trimmed = (p1 || '') + block.replace(/^\s*\n/, '\n').trim();
    return '\n```ts\n' + trimmed + '\n```\n';
  });

  // Additional cleanup: normalize code fences and remove small redundant list items
  // Trim leading/trailing whitespace
  final = final.trim();

  // Remove backticked `Optional` artefacts
  final = final.replace(/`Optional`/g, 'Optional');

  // Normalize code-fence blank lines
  final = final.replace(/```(\w*)\n\s+/g, '```$1\n');
  final = final.replace(/\n\s+```/g, '\n```');

  // Robust duplicate/collapse pass
  const lines = final.split('\n');
  const outLines = [];
  let lastHeadingToken = null;
  let lastNonEmpty = '';
  for (const rawLine of lines) {
    const line = rawLine.replace(/\s+$/g, '');
    const trimmed = line.trim();
    if (!trimmed) {
      // always preserve single blank lines, but avoid many in a row
      if (outLines.length && outLines[outLines.length - 1].trim() === '') continue;
      outLines.push('');
      continue;
    }
    // heading detection
    const h = trimmed.match(/^#+\s+(.*)$/);
    if (h) {
      const headingText = h[1].trim();
      const words = headingText.split(/\s+/);
      lastHeadingToken = words.length ? words[words.length - 1].replace(/[^\w\-"']+$/u, '') : null;
      if (outLines.length && outLines[outLines.length - 1].trim() === trimmed) continue; // skip exact repeat
      outLines.push(line);
      lastNonEmpty = trimmed;
      continue;
    }
    // skip bullet that repeats heading token
    if (trimmed.startsWith('- ') && lastHeadingToken) {
      const content = trimmed.slice(2).trim().replace(/^[`"']|[`"']$/g, '');
      if (content.toLowerCase() === lastHeadingToken.toLowerCase()) continue;
    }
    // collapse duplicate consecutive lines
    if (trimmed === lastNonEmpty) continue;
    outLines.push(line);
    lastNonEmpty = trimmed;
  }
  final = outLines.join('\n').trim();

  // Split signature-like bullets into fenced TypeScript blocks with separated descriptions.
  // We'll process line-by-line to avoid heavy global regexes.
  {
    const inLines = final.split('\n');
    const out = [];
    for (let i = 0; i < inLines.length; i++) {
      const line = inLines[i];
      const sigMatch = line.match(/^-\s*([\w$<>[\]]+)\s*\(([^)]*)\)\s*:\s*(.*)$/);
      if (sigMatch) {
        const name = sigMatch[1];
        const args = sigMatch[2] || '';
        let rest = sigMatch[3] || '';
        // If rest contains '####' headings or 'Parameters', split and keep description
        let desc = '';
        const markers = ['####', 'Parameters', 'Returns'];
        for (const marker of markers) {
          const idx = rest.indexOf(marker);
          if (idx !== -1) {
            desc = rest.slice(idx).replace(/^\s*#####?\s*/, '');
            rest = rest.slice(0, idx).trim();
            break;
          }
        }
        // If the next line(s) are short description lines (not bullet or heading), collect them
        let j = i + 1;
        while (j < inLines.length && inLines[j].trim() && !inLines[j].trim().startsWith('-') && !inLines[j].trim().startsWith('#')) {
          desc += (desc ? ' ' : '') + inLines[j].trim();
          j++;
        }
        // advance i to consumed description lines
        if (j > i + 1) i = j - 1;

        const retType = rest.split(/\s+/)[0] || 'void';
        out.push('```ts');
        out.push(`function ${name}(${args.trim()}): ${retType}`);
        out.push('```');
        if (desc.trim()) {
          out.push('');
          out.push(desc.trim());
        }
        continue;
      }
      out.push(line);
    }
    final = out.join('\n');
  }

  // Ensure declaration blocks that look like "Name { ... }" are converted to "interface Name { ... }"
  final = final.replace(/```ts\n\s*(\w+)\s*\{([\s\S]*?)\}\s*```/g, (m, name, body) => {
    // split the inline body into comma-separated fields and produce one-per-line
    const fields = (body || '').replace(/\s+/g, ' ').trim();
    const parts = fields.split(/[;,\n]/).map(s => s.trim()).filter(Boolean);
    const lines = parts.map(p => '  ' + p.replace(/\s+/g, ' '));
    const decl = `interface ${name} {\n${lines.join('\n')}\n}`;
    return '```ts\n' + decl + '\n```';
  });

  // Fix common concatenation artifacts like 'Optionalmode' or 'Optionaltask'
  final = final.replace(/Optionalmode/g, 'Optional mode').replace(/Optionaltask/g, 'Optional task');

  // Extract 'Parameters' or 'Returns' tokens embedded after signatures into subheadings
  final = final.replace(/Parameters\s+([^\n]+)/g, '\n### Parameters\n$1');
  final = final.replace(/Returns\s+([^\n]+)/g, '\n### Returns\n$1');

  // Normalize Parameters sections into bullet lists when possible.
  // Look for lines starting with '### Parameters' and following text that contains 'name: description' patterns.
  final = final.replace(/### Parameters\n([\s\S]*?)(?=\n\n|\n### |$)/g, (m, block) => {
    const lines = block.split(/\n/).map(l => l.trim()).filter(Boolean);
    const bullets = lines.map(l => {
      // if pattern 'name: description' convert to '- name — description'
      const p = l.match(/^([\w\-]+)[:\s]+(.+)$/);
      if (p) return `- ${p[1]} — ${p[2].trim()}`;
      return `- ${l}`;
    });
    return '### Parameters\n' + bullets.join('\n');
  });

  // Normalize Returns sections (single-line -> bullet or paragraph)
  final = final.replace(/### Returns\n([\s\S]*?)(?=\n\n|\n### |$)/g, (m, block) => {
    const t = block.trim();
    if (!t) return '### Returns\n';
    // if single line, keep as paragraph
    if (!t.includes('\n')) return '### Returns\n' + t;
    // otherwise convert to bullet list
    return '### Returns\n' + t.split(/\n/).map(s => '- ' + s.trim()).join('\n');
  });

  await fs.writeFile(OUT_FILE, final, 'utf8');
  console.log('Wrote', OUT_FILE);
}

if (process.argv.includes('--help') || process.argv.includes('-h')) {
  console.log('Usage: convert-tinybench-docs.mjs');
  process.exit(0);
}

convert().catch(err => { console.error(err); process.exit(2); });
