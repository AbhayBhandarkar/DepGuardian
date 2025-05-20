#!/usr/bin/env node
// Purpose: Checks if an installed version satisfies a semantic version range.
// Called by the Python script. Expects 'semver' package to be available.
// Usage: node semver_checker.js <installed_version> <version_range>
// Output: Prints 'true' or 'false' to stdout. Exits non-zero on error.

let semver;
try {
  // Assumes 'semver' is installed either globally or in a node_modules
  // directory accessible from where this script is run.
  semver = require('semver');
} catch (e) {
  console.error("Error: Failed to load the 'semver' package.");
  console.error("Ensure 'semver' is installed (e.g., run 'npm install' in the DepGuardian project root).");
  console.error("Original error:", e.message);
  process.exit(2); // Exit code 2 for setup/dependency issues
}

const [,, installedVersion, versionRange] = process.argv;

if (!installedVersion || !versionRange) {
  console.error("Usage: node semver_checker.js <installed_version> <version_range>");
  process.exit(1); // Exit code 1 for usage errors
}

try {
  const result = semver.satisfies(installedVersion, versionRange);
  console.log(result ? 'true' : 'false');
  process.exit(0); 
} catch (err) {
  console.error(`Error checking semver satisfaction: ${err.message}`);
  process.exit(1);
}
