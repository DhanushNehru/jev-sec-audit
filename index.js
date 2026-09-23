#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// ANSI Colors for minimalist formatting (Zero dependencies)
const c = {
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  cyan: (s) => `\x1b[36m${s}\x1b[0m`,
  magenta: (s) => `\x1b[35m${s}\x1b[0m`,
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
  bgRed: (s) => `\x1b[41m\x1b[37m${s}\x1b[0m`
};

// Simple Levenshtein distance for typosquatting
const levenshtein = (a, b) => {
  const m = [];
  for (let i = 0; i <= b.length; i++) { m[i] = [i]; }
  for (let j = 0; j <= a.length; j++) { m[0][j] = j; }
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) m[i][j] = m[i - 1][j - 1];
      else m[i][j] = Math.min(m[i - 1][j - 1] + 1, Math.min(m[i][j - 1] + 1, m[i - 1][j] + 1));
    }
  }
  return m[b.length][a.length];
};

const TOP_PACKAGES = ['react', 'react-dom', 'express', 'lodash', 'moment', 'chalk', 'request', 'commander', 'axios', 'async', 'webpack', 'vue', 'angular', 'jest', 'eslint', 'typescript'];

const args = process.argv.slice(2);
const apiKey = process.env.JEV_API_KEY || (args.includes('-k') ? args[args.indexOf('-k') + 1] : null);
const file = args.find(a => !a.startsWith('-') && a !== apiKey) || 'package.json';

console.log(c.bold(c.cyan('\n🛡️  jev-sec-audit: System 1 Security Scanner (Zero-Dep Mode)\n')));

const filePath = path.resolve(process.cwd(), file);
if (!fs.existsSync(filePath)) {
  console.error(c.red(`❌ Error: File not found at ${filePath}`));
  process.exit(1);
}

let pkgData;
try {
  pkgData = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
} catch (e) {
  console.error(c.red(`❌ Failed to parse ${file} as JSON.`));
  process.exit(1);
}

const deps = Object.keys({ ...pkgData.dependencies, ...pkgData.devDependencies });
const scripts = pkgData.scripts || {};
let findings = [];

// 1. Typosquatting Check
for (const dep of deps) {
  for (const topPkg of TOP_PACKAGES) {
    if (dep !== topPkg && Math.abs(dep.length - topPkg.length) <= 2) {
      const dist = levenshtein(dep, topPkg);
      if (dist === 1 || dist === 2) {
        findings.push({ target: dep, type: 'Typosquatting', risk: 'HIGH', detail: `Looks like popular package '${topPkg}'` });
      }
    }
  }
}

// 2. Suspicious Scripts Check
const patterns = [
  { regex: /curl.*\|.*bash/i, name: 'Remote Execution (curl | bash)' },
  { regex: /eval\(/i, name: 'Eval Injection' },
  { regex: /Buffer\.from\(.*'base64'\)/i, name: 'Base64 Obfuscation' },
  { regex: /nc\s+-e/i, name: 'Reverse Shell' }
];

for (const [sName, sContent] of Object.entries(scripts)) {
  for (const p of patterns) {
    if (p.regex.test(sContent)) findings.push({ target: `Script: ${sName}`, type: 'Malicious Payload', risk: 'CRITICAL', detail: `Detected: ${p.name}` });
  }
  if (sName === 'postinstall') findings.push({ target: `Script: postinstall`, type: 'Lifecycle Risk', risk: 'MEDIUM', detail: `Runs automatically on install.` });
}

// Minimal Output
if (findings.length === 0) {
  console.log(c.bold(c.green('✅ No threats detected! Supply chain looks clean.')));
  process.exit(0);
}

console.log(c.bold(c.red(`⚠️  Found ${findings.length} potential security risks:\n`)));

// Minimal Table Output
console.log(`${c.bold(c.cyan('RISK'.padEnd(10)))} | ${c.bold(c.cyan('TARGET'.padEnd(20)))} | ${c.bold(c.cyan('DETAILS'))}`);
console.log(''.padEnd(70, '-'));

findings.forEach(f => {
  let r = f.risk;
  if (r === 'CRITICAL') r = c.bgRed(` ${r} `);
  else if (r === 'HIGH') r = c.red(r);
  else if (r === 'MEDIUM') r = c.yellow(r);
  console.log(`${r.padEnd(10 + (r.length - f.risk.length))} | ${c.bold(f.target).padEnd(20 + 8)} | ${f.type} - ${c.magenta(f.detail)}`);
});

console.log(c.yellow('\nTip: Set JEV_API_KEY to enable deep AI semantic analysis (System 1 models).'));
process.exit(1);
