const fs = require('fs');
const path = require('path');
const covPath = path.resolve(process.cwd(), 'coverage/coverage-final.json');
const target = path.resolve(process.cwd(), 'src/url.ts');
if (!fs.existsSync(covPath)) {
  console.error('coverage file not found:', covPath);
  process.exit(2);
}
const cov = JSON.parse(fs.readFileSync(covPath, 'utf8'));
let entry = Object.keys(cov).find(k=>k===target || k.endsWith('/src/url.ts') || k==='src/url.ts');
if (!entry) {
  console.error('src/url.ts not found in coverage keys');
  process.exit(3);
}
const data = cov[entry];
console.log('Found coverage entry for:', entry);
const stmts = data.statementMap || {};
const branches = data.branchMap || {};
const sCounts = data.s || {};
const bCounts = data.b || {};
function uncoveredStatements(){
  const arr = [];
  for (const [id, loc] of Object.entries(stmts)){
    const count = sCounts[id] || 0;
    if (!count){
      arr.push({id: Number(id), line: loc.start.line});
    }
  }
  return arr.sort((a,b)=>a.line-b.line);
}
function uncoveredBranches(){
  const arr = [];
  for (const [id, meta] of Object.entries(branches)){
    const counts = bCounts[id] || [];
    const loc = meta.loc || meta;
    const anyTaken = counts.some(c=>c>0);
    if (!anyTaken){
      arr.push({id: Number(id), line: loc.start.line});
    } else {
      // find which branch locations are zero
      (meta.locations||meta).forEach((locItem, idx)=>{
        if (!counts[idx]) arr.push({id: Number(id)+'.'+idx, line: locItem.start.line});
      });
    }
  }
  return arr.sort((a,b)=>a.line-b.line);
}
const us = uncoveredStatements();
const ub = uncoveredBranches();
console.log('Totals: statements:', Object.keys(stmts).length,'branches:', Object.keys(branches).length,'functions:', Object.keys(data.fnMap||{}).length);
console.log('Uncovered statements count:', us.length);
console.log('Uncovered branches count:', ub.length);
console.log('First 200 uncovered statements (line,id):');
console.log(us.slice(0,200).map(x=>`${x.line}:${x.id}`).join(', '));
console.log('\nFirst 200 uncovered branches (line,id):');
console.log(ub.slice(0,200).map(x=>`${x.line}:${x.id}`).join(', '));
