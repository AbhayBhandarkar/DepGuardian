#!/usr/bin/env node
// Usage: node semver_checker.js <installed> <range>
let semver;
try {
  semver = require('semver');
} catch {
  console.error("Error: npm package 'semver' not found. Install globally: npm install -g semver");
  process.exit(2);
}

const [,, installed, range] = process.argv;
if (!installed || !range) {
  console.error("Usage: node semver_checker.js <installed> <range>");
  process.exit(1);
}

try {
  console.log(semver.satisfies(installed, range) ? 'true' : 'false');
  process.exit(0);
} catch (err) {
  console.error(`Error: ${err.message}`);
  process.exit(1);
}
