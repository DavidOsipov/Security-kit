import { ESLint } from 'eslint';

async function run() {
  const eslint = new ESLint({
    overrideConfig: {
      parserOptions: { ecmaVersion: 2020, sourceType: 'module' },
      rules: {},
    },
    allowInlineConfig: true,
  });

  const samples = [
    {
      name: 'inline-disable-with-code',
      code: "// eslint-disable-next-line no-unused-vars const x = 1;\n",
    },
    {
      name: 'block-disable-with-code',
      code: "/* eslint-disable no-console */ console.log('test');\n",
    },
    {
      name: 'proper-disable-next-line',
      code: "// eslint-disable-next-line no-unused-vars\nconst x = 1;\n",
    },
  ];

  for (const s of samples) {
    console.log('--- Sample:', s.name, '---');
    try {
      const results = await eslint.lintText(s.code, { filePath: 'sample.js' });
      for (const res of results) {
        if (!res.messages || res.messages.length === 0) {
          console.log('No diagnostics');
        } else {
          for (const msg of res.messages) {
            console.log('message:', {
              ruleId: msg.ruleId,
              message: msg.message,
              line: msg.line,
              column: msg.column,
              endLine: msg.endLine,
              endColumn: msg.endColumn,
              severity: msg.severity,
            });
          }
        }
      }
    } catch (err) {
      console.error('Error linting sample', s.name, err && err.stack ? err.stack : err);
    }
    console.log('\n');
  }
}

run().catch(err => {
  console.error('Error running ESLint check:', err);
  process.exit(2);
});
