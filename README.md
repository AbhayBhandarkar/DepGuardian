# DepGuardian

DepGuardian is a Python CLI tool that helps you **monitor and update your project dependencies**. It currently focuses on Node.js (NPM) dependencies, checking if your direct dependencies are up-to-date and if any installed packages (direct or transitive) have known vulnerabilities. It can even automate the process of updating a dependency by opening a GitHub Pull Request with the updated package.

## Features

- **Outdated Dependency Check:** Scans your `package.json` and `package-lock.json` to find direct dependencies that are out of date with respect to the NPM registry. Reports the latest available version for each and whether the installed version satisfies the specified range in `package.json`.
- **Vulnerability Audit:** Queries the *Open Source Vulnerabilities (OSV)* database for any known vulnerabilities in your project’s installed packages.
- **Automated Update (Beta):** Optionally, for the first outdated dependency found, DepGuardian can create a new git branch, bump the package to its latest version, commit the change, push the branch, and open a Pull Request on GitHub – all automatically, to streamline updating. (This requires a clean Git repository and a GitHub token.)

## Installation

```bash
# From PyPI
pip install dep-guardian

# From source
git clone https://github.com/AbhayBhandarkar/DepGuardian.git
cd DepGuardian
pip install .
```

## Usage

```bash
# Basic audit in the current folder
depg check

# Specify a project path
depg check --path /path/to/project

# Audit + automated PR (requires clean git repo + token)
export GITHUB_TOKEN=<your-token>
depg check --create-pr --github-repo owner/repo

```

