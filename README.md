# DepGuardian

[![PyPI version](https://badge.fury.io/py/dep-guardian.svg?icon=si%3Apython )](https://badge.fury.io/py/dep-guardian )
[![DepGuardian CI/CD](https://github.com/AbhayBhandarkar/DepGuardian/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/AbhayBhandarkar/DepGuardian/actions/workflows/ci.yml)

**DepGuardian** is a Python CLI tool that helps you **monitor and update your project dependencies**. It currently focuses on Node.js (NPM) dependencies, checking if your direct dependencies are up-to-date and if any installed packages (direct or transitive) have known vulnerabilities. It can even automate the process of updating a single dependency by opening a GitHub Pull Request.

## Features

- **Outdated Dependency Check:**  
  Scans your `package.json` and `package-lock.json` (v1, v2, v3 supported) to find direct dependencies that are out of date compared to the NPM registry's `latest` tag. Reports the installed version, latest available version, and whether the installed version satisfies the range specified in `package.json`.

- **Vulnerability Audit:**  
  Queries the *Open Source Vulnerabilities (OSV)* database ([osv.dev](https://osv.dev/ )) for any known vulnerabilities affecting your project’s *installed* package versions (from `package-lock.json`).

- **Automated Update PR (Experimental):**  
  Optionally, for the *first* outdated direct dependency found, DepGuardian can:
  1. Create a new git branch (e.g., `depguardian/update-express-4.18.2`).
  2. Run `npm install <package>@<latest_version>`.
  3. Commit the `package.json` and `package-lock.json` changes.
  4. Push the branch to your `origin` remote.
  5. Open a Pull Request on GitHub targeting your repository's default branch.

  **Prerequisites for PR creation:**
  - A clean Git working directory (no uncommitted changes or untracked files).
  - The `git` command available in your PATH.
  - The `node` and `npm` commands available in your PATH.
  - A GitHub Personal Access Token with `repo` scope provided via `--github-token` or `GITHUB_TOKEN`.
  - The target GitHub repository specified via `--github-repo` or `GITHUB_REPOSITORY` (in `owner/repo` format).

## Requirements

- Python 3.8+
- Node.js and npm (for interacting with Node.js projects and running the `semver_checker.js` helper)
- Git (for the automated PR creation feature)

## Installation

### From PyPI (Recommended)

```bash
pip install dep-guardian
```

### From Source (for development)

```bash
git clone https://github.com/AbhayBhandarkar/DepGuardian.git 
cd DepGuardian

# Create and activate a virtual environment (recommended)
python -m venv .venv
# On macOS/Linux:
source .venv/bin/activate
# On Windows (Command Prompt):
# .\.venv\Scripts\activate
# On Windows (PowerShell):
# .\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements_dev.txt
pip install -e .
npm install
```

## Usage

### Checking Dependencies

Navigate to your Node.js project directory (which should contain `package.json` and `package-lock.json`) and run:

```bash
depg check
```

To scan a specific project:

```bash
depg check --path /path/to/your/nodejs_project
```

#### Example Output:

```
Scanning project at: /path/to/your/project
Found 2 direct dependencies in package.json.
Found 158 installed packages in package-lock.json.
--------------------

Checking Direct Dependencies against NPM Registry:
- Checking express (^4.17.1)... Installed=4.17.1 | Latest=4.18.2 | satisfies range | Update available: 4.18.2
- Checking jest (^27.0.0)... Installed=27.5.1 | Latest=29.5.0 | DOES NOT satisfy range | Update available: 29.5.0
--------------------

Checking for Known Vulnerabilities (OSV API):
Querying OSV for 158 package versions...
OSV query complete. Found 0 vulnerabilities affecting 0 package versions.
No known vulnerabilities found in installed packages.
--------------------

Summary:
2 direct dependencies are outdated.
No vulnerabilities found.
```

### Common Options

- `--path /path/to/project`: Specify the project directory.
- `--verbose` or `-v`: Show more detailed debug logging.

### Creating an Automated Pull Request

To automatically create a PR for the first outdated direct dependency found:

1. Prepare your target project (Git repo with clean working directory).
2. Set your GitHub Token:

   ```bash
   export GITHUB_TOKEN="ghp_YourTokenHere..."
   ```

3. Run:

   ```bash
   depg check --path /path/to/your/nodejs_project --create-pr --github-repo YourGitHubUsername/TargetRepoName --verbose
   ```

#### Example Output for PR Creation:

```
... [previous check output] ...
Summary:
1 direct dependencies are outdated.
No vulnerabilities found.

Attempting to auto-update express from 4.17.1 -> 4.18.2
Found Git repository at: /path/to/your/nodejs_project
Creating new branch 'depguardian/update-express-4.18.2' from 'main'
Running: npm install express@4.18.2 in /path/to/your/nodejs_project
Staging files: ['package.json', 'package-lock.json']
Committing with message: Update express from 4.17.1 to 4.18.2

Automated by DepGuardian.
Pushing branch 'depguardian/update-express-4.18.2' to remote 'origin'...
Branch 'depguardian/update-express-4.18.2' pushed successfully.
Creating Pull Request on 'YourGitHubUsername/TargetRepoName' from 'depguardian/update-express-4.18.2' to 'main'...
Pull Request created: https://github.com/YourGitHubUsername/TargetRepoName/pull/123   

Check complete.
```

### Exit Codes

- `0`: Check completed successfully (or PR created successfully if requested).
- `1`: Outdated dependencies or vulnerabilities found, or an error occurred.
- `2`: Usage error (e.g., invalid command-line arguments).

## Development

```bash
git clone https://github.com/AbhayBhandarkar/DepGuardian.git 
cd DepGuardian

# Create and activate a Python virtual environment
python -m venv .venv
# On macOS/Linux:
source .venv/bin/activate
# On Windows (Command Prompt):
# .\.venv\Scripts\activate
# On Windows (PowerShell):
# .\.venv\Scripts\Activate.ps1

# Install development dependencies and DepGuardian in editable mode
pip install -r requirements_dev.txt
pip install -e .

# Install Node.js helper dependency
npm install

# Check code formatting (and reformat if necessary)
black . --check  # or `black .` to auto-fix

# Run tests
pytest
```

## Roadmap / Future Features 🚀

- **GUI Dashboard**: Develop a local web-based graphical user interface to visualize dependency reports, explore dependency graphs, and manage updates more interactively.
- **LLM-Powered Conflict Insights**: Integrate a Large Language Model (LLM) to help analyze complex inter-dependency conflicts and suggest resolution strategies.
- **Dockerization**: Provide an official Docker image for DepGuardian to ensure consistent execution across environments.
- **Expanded Ecosystem Support**: Add support for other package managers and ecosystems (Python’s Pip, Java’s Maven, RubyGems, etc.).
- **Enhanced Update Strategies**: Configure update strategies (patch/minor/major), ignore specific packages, or schedule checks.
- **Batch PR Creation / Grouped Updates**: Create PRs for multiple outdated dependencies simultaneously or group related updates.
- **Notification System**: Notify users about newly discovered vulnerabilities or critical updates.
- **Deeper Conflict Analysis (Pre-Update)**: Predict potential conflicts before updating packages.

## License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.
