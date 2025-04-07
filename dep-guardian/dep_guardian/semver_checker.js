// Check if 'semver' module is available
let semver;
try {
  semver = require('semver');
} catch (e) {
  console.error("Error: Node.js 'semver' package not found.");
  console.error("Please install it globally ('npm install -g semver') or ensure it's available locally.");
  process.exit(2); // Use a specific exit code for missing module
}

const version = process.argv[2];
const range = process.argv[3];

if (!version || !range) {
  console.error("Usage: node semver_checker.js <version> <range>");
  process.exit(1);
}

try {
  // Use the definitive semver.satisfies function
  const result = semver.satisfies(version, range);
  // Output ONLY 'true' or 'false' to stdout for easy parsing in Python
  console.log(result ? 'true' : 'false');
  process.exit(0);
} catch (err) {
  // Output actual errors to stderr
  console.error(`Error checking semver range '<span class="math-inline">\{range\}' for version '</span>{version}': ${err.message}`);
  process.exit(1);
}