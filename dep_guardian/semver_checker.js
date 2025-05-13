#!/usr/bin/env node
// Purpose: Checks if an installed version satisfies a semantic version range.
// Called by the Python script. Expects 'semver' package to be available.
// Usage: node semver_checker.js <installed_version> <version_range>
// Output: Prints 'true' or 'false' to stdout. Exits non-zero on error.

let semver;
try {
  // Assumes 'semver' is installed either globally or in a node_modules
  // directory accessible from where this script is run.
  // The calling Python script should ensure 'npm install' was run in the root.
  semver = require('semver');
} catch (e) {
  // Provide a more informative error message if require fails
  console.error("Error: Failed to load the 'semver' package.");
  console.error("Ensure 'semver' is installed (e.g., run 'npm install' in the DepGuardian project root).");
  console.error("Original error:", e.message);
  process.exit(2); // Exit code 2 for setup/dependency issues
}

// Get arguments from command line
const [,, installedVersion, versionRange] = process.argv;

// Validate input arguments
if (!installedVersion || !versionRange) {
  console.error("Usage: node semver_checker.js <installed_version> <version_range>");
  process.exit(1); // Exit code 1 for usage errors
}

try {
  // Use semver.satisfies() to perform the check
  const result = semver.satisfies(installedVersion, versionRange);
  // Output 'true' or 'false' directly to stdout
  console.log(result ? 'true' : 'false');
  process.exit(0); // Exit code 0 for success
} catch (err) {
  // Handle errors during semver processing (e.g., invalid version format)
  console.error(`Error checking semver satisfaction: ${err.message}`);
  process.exit(1); // Exit code 1 for runtime errors
}