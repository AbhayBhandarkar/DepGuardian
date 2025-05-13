# DepGuardian

[![PyPI version](https://badge.fury.io/py/dep-guardian.svg)](https://badge.fury.io/py/dep-guardian)
DepGuardian is a Python CLI tool that helps you **monitor and update your project dependencies**. It currently focuses on Node.js (NPM) dependencies, checking if your direct dependencies are up-to-date and if any installed packages (direct or transitive) have known vulnerabilities. It can even automate the process of updating a single dependency by opening a GitHub Pull Request.

## Features

-   **Outdated Dependency Check:** Scans your `package.json` and `package-lock.json` (v1, v2, v3 supported) to find direct dependencies that are out of date compared to the NPM registry's 'latest' tag. Reports the installed version, latest available version, and whether the installed version satisfies the range specified in `package.json`.
-   **Vulnerability Audit:** Queries the *Open Source Vulnerabilities (OSV)* database ([osv.dev](https://osv.dev/)) for any known vulnerabilities affecting your project’s *installed* package versions (from `package-lock.json`).
-   **Automated Update PR (Experimental):** Optionally, for the *first* outdated direct dependency found, DepGuardian can:
    1.  Create a new git branch (e.g., `depguardian/update-express-4.18.2`).
    2.  Run `npm install <package>@<latest_version>`.
    3.  Commit the `package.json` and `package-lock.json` changes.
    4.  Push the branch to your `origin` remote.
    5.  Open a Pull Request on GitHub targeting your repository's default branch.

    * **Prerequisites for PR creation:**
        * A clean Git working directory (no uncommitted changes or untracked files).
        * The `git` command available in your PATH.
        * The `node` and `npm` commands available in your PATH.
        * A GitHub Personal Access Token (Classic or Fine-Grained) with `repo` scope (or specific write permissions for PRs/code) provided via the `--github-token` option or `GITHUB_TOKEN` environment variable.
        * The target GitHub repository specified via `--github-repo` or the `GITHUB_REPOSITORY` environment variable (in `owner/repo` format).

## Installation

```bash
# From PyPI (Recommended)
pip install dep-guardian

# From source (for development)
git clone [https://github.com/AbhayBhandarkar/DepGuardian.git](https://github.com/AbhayBhandarkar/DepGuardian.git)
cd DepGuardian
pip install -r requirements_dev.txt # Install dev dependencies
pip install -e . # Install in editable mode
npm install # Install Node.js 'semver' package needed by the helper script
```

## Usage

### Checking Dependencies

Navigate to your Node.js project directory (containing `package.json` and `package-lock.json`) and run:

```bash
depg check
```

**Example Output:**

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

**Options:**

* `--path /path/to/project`: Specify the project directory if not the current one.
* `--verbose` or `-v`: Show more detailed debug logging.

### Creating an Automated Pull Request

To automatically create a PR for the *first* outdated dependency found:

```bash
# Ensure GITHUB_TOKEN is set in your environment
export GITHUB_TOKEN="ghp_YourTokenHere..."

# Run the check with the --create-pr flag and specify the repo
depg check --create-pr --github-repo YourGitHubUsername/YourRepoName
```

**Output for PR Creation:**

```
... [previous check output] ...
Summary:
2 direct dependencies are outdated.
No vulnerabilities found.

Attempting to auto-update express from 4.17.1 -> 4.18.2
Found Git repository at: /path/to/your/project
Creating new branch 'depguardian/update-express-4.18.2' from 'main'
Running: npm install express@4.18.2 in /path/to/your/project
Staging files: ['package.json', 'package-lock.json']
Committing with message: Update express from 4.17.1 to 4.18.2

Automated by DepGuardian.
Pushing branch 'depguardian/update-express-4.18.2' to remote 'origin'...
Branch 'depguardian/update-express-4.18.2' pushed successfully.
Creating Pull Request on 'YourGitHubUsername/YourRepoName' from 'depguardian/update-express-4.18.2' to 'main'...
Pull Request created: [https://github.com/YourGitHubUsername/YourRepoName/pull/123](https://github.com/YourGitHubUsername/YourRepoName/pull/123)

Check complete.
```

**Exit Codes:**

* `0`: Check completed successfully, no outdated dependencies or vulnerabilities found (or PR created successfully if requested).
* `1`: Check completed, but outdated dependencies or vulnerabilities were found, OR an error occurred during processing (e.g., network issue, PR creation failure). Check logs for details.
* `2`: Usage error (e.g., invalid command-line arguments).

## Development

1.  Clone the repository.
2.  Create a virtual environment: `python -m venv .venv && source .venv/bin/activate`
3.  Install dependencies: `pip install -r requirements_dev.txt && pip install -e .`
4.  Install Node helper dependency: `npm install`
5.  Run linters: `flake8 .` and `black --check .`
6.  Run tests: `pytest`

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.