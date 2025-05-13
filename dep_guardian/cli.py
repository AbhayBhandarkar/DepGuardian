# dep_guardian/cli.py
import os
import json
import sys
import click
import requests
import subprocess
import logging
from packaging.version import parse as parse_version
from github import Github, GithubException
from git import Repo, GitCommandError

# --- Configuration ---
OSV_API_URL = "https://api.osv.dev/v1/querybatch"
NPM_REGISTRY_URL = "https://registry.npmjs.org/{package_name}"
REQUEST_TIMEOUT = 15  # seconds for network requests
NPM_INSTALL_TIMEOUT = 120  # seconds for npm install

# --- Setup Logging ---
# Configure logging for better debugging, especially in CI
logging.basicConfig(
    level=os.environ.get("LOGLEVEL", "INFO").upper(),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("depg")


# --- Helper Functions ---


def _run_semver_check(installed_version, version_range):
    """Runs the bundled semver_checker.js script."""
    script_path = os.path.join(os.path.dirname(__file__), "semver_checker.js")
    if not os.path.exists(script_path):
        logger.error("semver_checker.js not found at %s", script_path)
        return None
    if not installed_version or not version_range:
        logger.warning(
            "Invalid input for semver check: installed=%s, range=%s",
            installed_version,
            version_range,
        )
        return None

    command = ["node", script_path, installed_version, version_range]
    try:
        # Ensure Node is installed and semver package is available (via root package.json)
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
            encoding="utf-8",
        )
        output = result.stdout.strip().lower()
        if output == "true":
            return True
        elif output == "false":
            return False
        else:
            logger.error("semver_checker.js produced unexpected output: %s", output)
            if result.stderr:
                logger.error("stderr: %s", result.stderr.strip())
            return None
    except FileNotFoundError:
        logger.error(
            "Error: 'node' command not found. Please ensure Node.js is installed and in PATH."
        )
        return None
    except subprocess.CalledProcessError as e:
        logger.error(
            "semver_checker.js failed (exit code %d): %s",
            e.returncode,
            e.stderr.strip(),
        )
        if "Error: npm package 'semver' not found" in e.stderr:
            logger.error(
                "Hint: Run 'npm install' in the DepGuardian root directory first."
            )
        return None
    except subprocess.TimeoutExpired:
        logger.error("semver_checker.js timed out.")
        return None
    except Exception as e:
        logger.error("Error running semver_checker.js: %s", e)
        return None


def parse_package_json(file_path):
    """Parses package.json for direct dependencies and devDependencies."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        deps = data.get("dependencies", {})
        dev_deps = data.get("devDependencies", {})
        return {**deps, **dev_deps}  # Combine both dependency types
    except FileNotFoundError:
        logger.error("package.json not found at %s", file_path)
        return None
    except json.JSONDecodeError as e:
        logger.error("Error decoding package.json: %s", e)
        return None
    except Exception as e:
        logger.error("Error reading package.json: %s", e)
        return None


def parse_package_lock(file_path):
    """Parses package-lock.json (v1, v2, v3) for installed package versions."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        lockfile_version = data.get("lockfileVersion", 0)
        packages_data = data.get("packages", {})
        dependencies_data = data.get("dependencies", {})  # For v1

        installed_packages = {}

        if lockfile_version >= 2 and packages_data:
            # Handle v2/v3 structure
            for path, info in packages_data.items():
                if not path:
                    continue  # Skip the root package entry ""
                # Extract package name from node_modules path
                parts = path.split("node_modules/")
                if len(parts) > 1 and "version" in info:
                    package_name = parts[-1]
                    # Handle scoped packages like @babel/core
                    if "/" in package_name and not package_name.startswith("@"):
                        # Avoid potential nested dependency paths misinterpreted as package names
                        # A more robust parser might be needed for complex monorepos
                        # For now, assume the last part is the package name
                        package_name = package_name.split("/")[-1]

                    installed_packages[package_name] = {
                        "version": info["version"],
                        "dev": info.get("dev", False),
                        "path": path,  # Store the full path for potential debugging
                    }
        elif lockfile_version == 1 and dependencies_data:
            # Handle v1 structure (less detailed, usually top-level)
            logger.warning(
                "Detected package-lock.json v1. Information might be less accurate."
            )
            for name, info in dependencies_data.items():
                if "version" in info:
                    installed_packages[name] = {
                        "version": info["version"],
                        "dev": info.get("dev", False),
                        "path": f"node_modules/{name}",
                    }
                    # Recursively add nested dependencies if present (limited depth)
                    nested_deps = info.get("dependencies", {})
                    for nested_name, nested_info in nested_deps.items():
                        if (
                            "version" in nested_info
                            and nested_name not in installed_packages
                        ):
                            installed_packages[nested_name] = {
                                "version": nested_info["version"],
                                "dev": nested_info.get(
                                    "dev", False
                                ),  # Guessing dev status
                                "path": f"node_modules/{name}/node_modules/{nested_name}",
                            }

        else:
            logger.error("Unsupported or empty package-lock.json format.")
            return None

        logger.info(
            "Found %d packages in lock file (v%d)",
            len(installed_packages),
            lockfile_version,
        )
        return installed_packages

    except FileNotFoundError:
        logger.error("package-lock.json not found at %s", file_path)
        return None
    except json.JSONDecodeError as e:
        logger.error("Error decoding package-lock.json: %s", e)
        return None
    except Exception as e:
        logger.error("Error reading package-lock.json: %s", e)
        return None


def get_npm_package_info(package_name):
    """Fetches latest version information from the NPM registry."""
    url = NPM_REGISTRY_URL.format(package_name=package_name.replace("/", "%2F"))
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()  # Raises HTTPError for bad responses (4xx or 5xx)
        data = response.json()
        latest_version = data.get("dist-tags", {}).get("latest")
        if not latest_version:
            logger.warning("Could not find 'latest' tag for package %s", package_name)
        return latest_version
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            logger.warning("Package '%s' not found on npm registry.", package_name)
        else:
            logger.error("HTTP error fetching '%s': %s", package_name, e)
    except requests.exceptions.Timeout:
        logger.error("Timeout fetching info for package '%s'", package_name)
    except requests.exceptions.RequestException as e:
        logger.error("Network error fetching '%s': %s", package_name, e)
    except json.JSONDecodeError:
        logger.error(
            "Could not decode JSON response for '%s' from %s", package_name, url
        )
    except Exception as e:
        logger.error("Unexpected error fetching '%s': %s", package_name, e)
    return None


def query_osv_api(installed_packages):
    """Queries the OSV API for vulnerabilities in a batch."""
    if not installed_packages:
        return {}

    queries = []
    package_keys = []  # To map results back to package@version

    for name, info in installed_packages.items():
        version = info.get("version")
        if not version:
            logger.warning("Skipping OSV check for %s: No version found.", name)
            continue
        queries.append(
            {"package": {"ecosystem": "npm", "name": name}, "version": version}
        )
        package_keys.append(f"{name}@{version}")

    if not queries:
        logger.info("No valid packages with versions found to query OSV.")
        return {}

    logger.info("Querying OSV for %d package versions...", len(queries))
    try:
        response = requests.post(
            OSV_API_URL, json={"queries": queries}, timeout=REQUEST_TIMEOUT * 2
        )  # Longer timeout for batch
        response.raise_for_status()
        results = response.json().get("results", [])

        vulnerabilities = {}
        found_vulns_count = 0
        if len(results) != len(package_keys):
            logger.warning(
                "OSV API returned %d results, but expected %d.",
                len(results),
                len(package_keys),
            )
            # Attempt matching based on available data if lengths mismatch (though shouldn't happen)

        for i, res in enumerate(results):
            if i >= len(package_keys):
                break  # Safety break if lengths mismatch
            key = package_keys[i]
            package_vulns = res.get("vulns", [])
            if package_vulns:
                vuln_ids = [v.get("id") for v in package_vulns if v.get("id")]
                if vuln_ids:
                    vulnerabilities[key] = vuln_ids
                    found_vulns_count += len(vuln_ids)

        logger.info(
            "OSV query complete. Found %d vulnerabilities affecting %d package versions.",
            found_vulns_count,
            len(vulnerabilities),
        )
        return vulnerabilities

    except requests.exceptions.HTTPError as e:
        logger.error("HTTP error querying OSV: %s", e)
    except requests.exceptions.Timeout:
        logger.error("Timeout querying OSV API.")
    except requests.exceptions.RequestException as e:
        logger.error("Network error querying OSV: %s", e)
    except json.JSONDecodeError:
        logger.error("Could not decode JSON response from OSV API.")
    except Exception as e:
        logger.error("Unexpected error querying OSV: %s", e)
    return None  # Indicate failure


def find_git_repo(path):
    """Finds the Git repository root starting from the given path."""
    try:
        repo = Repo(path, search_parent_directories=True)
        repo_root = repo.working_tree_dir
        logger.info("Found Git repository at: %s", repo_root)
        return repo
    except GitCommandError as e:
        logger.error("Git error while searching for repository: %s", e)
        return None
    except Exception as e:  # Catch potential git.InvalidGitRepositoryError etc.
        logger.error("Could not find Git repository starting from %s: %s", path, e)
        return None


def create_update_branch(repo, package_name, new_version):
    """Creates and checks out a new branch for the update."""
    branch_name = f"depguardian/update-{package_name}-{new_version}"
    try:
        if repo.is_dirty(untracked_files=True):
            click.echo(
                click.style(
                    "Error: Git repository has uncommitted changes or untracked files.",
                    fg="red",
                ),
                err=True,
            )
            click.echo(
                "Please commit or stash changes before creating an update PR.", err=True
            )
            return None, None

        # Check if branch already exists locally
        if branch_name in repo.heads:
            logger.info(
                "Branch '%s' already exists locally. Checking it out.", branch_name
            )
            repo.heads[branch_name].checkout()
        else:
            # Create branch from the default branch (e.g., main or master) head
            # Assuming 'origin' is the name of the remote
            default_branch_name = (
                repo.active_branch.tracking_branch().remote_head
                if repo.active_branch.tracking_branch()
                else "main"
            )  # Heuristic
            logger.info(
                "Creating new branch '%s' from '%s'", branch_name, default_branch_name
            )
            # Fetch latest changes from remote default branch before creating new branch
            try:
                origin = repo.remotes.origin
                origin.fetch(default_branch_name)
                base_commit = origin.refs[default_branch_name].commit
                repo.create_head(branch_name, base_commit).checkout()
            except (AttributeError, IndexError, GitCommandError) as fetch_err:
                logger.warning(
                    "Could not fetch or find default branch '%s' on remote 'origin'. Creating branch from current HEAD. Error: %s",
                    default_branch_name,
                    fetch_err,
                )
                repo.create_head(branch_name).checkout()  # Fallback to current HEAD

        return repo, branch_name

    except GitCommandError as e:
        logger.error("Git command error during branch creation: %s", e)
        return None, None
    except Exception as e:
        logger.error("Error creating/checking out branch '%s': %s", branch_name, e)
        return None, None


def perform_npm_update(project_path, package_name, new_version):
    """Runs 'npm install' to update the specific package."""
    command = ["npm", "install", f"{package_name}@{new_version}"]
    click.echo(f"Running: {' '.join(command)} in {project_path}")
    try:
        result = subprocess.run(
            command,
            cwd=project_path,  # Run npm in the project directory
            check=True,
            capture_output=True,
            text=True,
            timeout=NPM_INSTALL_TIMEOUT,
            encoding="utf-8",
        )
        logger.info("npm install stdout:\n%s", result.stdout)
        if result.stderr:
            logger.warning("npm install stderr:\n%s", result.stderr)
        return True
    except FileNotFoundError:
        logger.error(
            "Error: 'npm' command not found. Please ensure Node.js/npm is installed and in PATH."
        )
        return False
    except subprocess.CalledProcessError as e:
        logger.error("npm install failed (exit code %d):", e.returncode)
        logger.error("stdout:\n%s", e.stdout)
        logger.error("stderr:\n%s", e.stderr)
        return False
    except subprocess.TimeoutExpired:
        logger.error("npm install timed out after %d seconds.", NPM_INSTALL_TIMEOUT)
        return False
    except Exception as e:
        logger.error("Error running npm install: %s", e)
        return False


def commit_and_push_update(
    repo, branch_name, package_name, old_version, new_version, project_path
):
    """Commits changes and pushes the update branch."""
    try:
        # Add package.json and package-lock.json relative to repo root
        repo_root = repo.working_tree_dir
        pj_path = os.path.relpath(os.path.join(project_path, "package.json"), repo_root)
        pl_path = os.path.relpath(
            os.path.join(project_path, "package-lock.json"), repo_root
        )

        add_files = [pj_path, pl_path]
        logger.info("Staging files: %s", add_files)
        repo.index.add(add_files)

        commit_message = f"Update {package_name} from {old_version} to {new_version}\n\nAutomated by DepGuardian."
        logger.info("Committing with message: %s", commit_message)
        repo.index.commit(commit_message)

        # Push the new branch to the remote
        origin = repo.remotes.origin
        click.echo(f"Pushing branch '{branch_name}' to remote 'origin'...")
        push_info = origin.push(f"{branch_name}:{branch_name}")

        # Basic check on push results
        if push_info and (push_info[0].flags & push_info[0].ERROR):
            logger.error("Error during git push: %s", push_info[0].summary)
            return False
        elif push_info and (push_info[0].flags & push_info[0].REJECTED):
            logger.error("Git push rejected: %s", push_info[0].summary)
            click.echo(
                click.style(
                    "Error: Push rejected. Does the remote branch already exist?",
                    fg="red",
                ),
                err=True,
            )
            return False

        logger.info("Branch '%s' pushed successfully.", branch_name)
        return True

    except GitCommandError as e:
        logger.error("Git command error during commit/push: %s", e)
        return False
    except Exception as e:
        logger.error("Error committing or pushing changes: %s", e)
        return False


def create_github_pr(
    github_token, github_repo_name, branch_name, package_name, old_version, new_version
):
    """Creates a GitHub Pull Request."""
    if not github_token:
        logger.error("GITHUB_TOKEN is missing.")
        click.echo(
            click.style(
                "Error: GitHub token not provided. Set GITHUB_TOKEN environment variable.",
                fg="red",
            ),
            err=True,
        )
        return None
    if not github_repo_name:
        logger.error("--github-repo not specified.")
        click.echo(
            click.style(
                "Error: GitHub repository (owner/repo) not specified.", fg="red"
            ),
            err=True,
        )
        return None

    try:
        g = Github(github_token)
        repo = g.get_repo(github_repo_name)
        default_branch = repo.default_branch

        pr_title = f"DepGuardian: Update {package_name} to {new_version}"
        pr_body = (
            f"Automated dependency update by DepGuardian.\n\n"
            f"**Package:** `{package_name}`\n"
            f"**From:** `{old_version}`\n"
            f"**To:** `{new_version}`\n\n"
            f"Please review and merge."
        )

        click.echo(
            f"Creating Pull Request on '{github_repo_name}' from '{branch_name}' to '{default_branch}'..."
        )

        # Check if a PR already exists for this branch
        try:
            existing_prs = repo.get_pulls(
                state="open", head=f"{repo.owner.login}:{branch_name}"
            )
            if existing_prs.totalCount > 0:
                pr = existing_prs[0]
                click.echo(
                    click.style(
                        f"Pull request for branch '{branch_name}' already exists: {pr.html_url}",
                        fg="yellow",
                    )
                )
                return pr.html_url
        except GithubException as e:
            logger.warning("Could not check for existing PRs: %s", e)

        pr = repo.create_pull(
            title=pr_title,
            body=pr_body,
            base=default_branch,
            head=branch_name,
            maintainer_can_modify=True,  # Allow maintainers to modify the PR branch
        )
        logger.info("Pull Request created successfully: %s", pr.html_url)
        click.echo(click.style(f"Pull Request created: {pr.html_url}", fg="green"))
        return pr.html_url

    except GithubException as e:
        logger.error("GitHub API error: %s", e.data.get("message", str(e)))
        click.echo(
            click.style(
                f"Error creating PR: {e.status} - {e.data.get('message', 'Unknown GitHub API error')}",
                fg="red",
            ),
            err=True,
        )
        if e.status == 401:
            click.echo(
                click.style(
                    "Hint: Check if your GITHUB_TOKEN is valid and has 'repo' permissions.",
                    fg="yellow",
                ),
                err=True,
            )
        elif e.status == 404:
            click.echo(
                click.style(
                    f"Hint: Check if the repository '{github_repo_name}' exists and you have access.",
                    fg="yellow",
                ),
                err=True,
            )
        elif e.status == 422:  # Often validation errors, like PR already exists
            click.echo(
                click.style(
                    f"Hint: Validation error - {e.data.get('errors', '')}", fg="yellow"
                ),
                err=True,
            )
    except Exception as e:
        logger.error("Unexpected error creating GitHub PR: %s", e)
        click.echo(
            click.style(f"An unexpected error occurred: {e}", fg="red"), err=True
        )
    return None


# --- CLI Command ---


@click.group()
def cli():
    """
    DepGuardian: Audit & auto-update Node.js dependencies.

    Checks for outdated NPM dependencies and known vulnerabilities using the OSV database.
    Can optionally create GitHub Pull Requests to update dependencies.
    """
    pass


@cli.command()
@click.option(
    "--path",
    default=".",
    help="Path to the Node.js project directory.",
    type=click.Path(exists=True, file_okay=False, resolve_path=True),
)
@click.option(
    "--create-pr",
    is_flag=True,
    help="Automatically create a GitHub PR for the first outdated dependency found.",
)
@click.option(
    "--github-repo",
    envvar="GITHUB_REPOSITORY",
    help='GitHub repository name in "owner/repo" format (for PR creation). Uses GITHUB_REPOSITORY env var if set.',
)
@click.option(
    "--github-token",
    envvar="GITHUB_TOKEN",
    help="GitHub Personal Access Token (for PR creation). Uses GITHUB_TOKEN env var if set.",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging.")
def check(path, create_pr, github_repo, github_token, verbose):
    """Checks dependencies for updates and vulnerabilities."""

    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled.")

    click.echo(f"\nScanning project at: {click.format_filename(path)}")

    package_json_path = os.path.join(path, "package.json")
    package_lock_path = os.path.join(path, "package-lock.json")

    direct_dependencies = parse_package_json(package_json_path)
    if direct_dependencies is None:
        sys.exit(1)  # Error message already logged by parser
    click.echo(f"Found {len(direct_dependencies)} direct dependencies in package.json.")

    installed_packages = parse_package_lock(package_lock_path)
    if installed_packages is None:
        sys.exit(1)  # Error message already logged by parser
    click.echo(
        f"Found {len(installed_packages)} installed packages in package-lock.json."
    )
    click.echo("-" * 20)

    outdated_direct = []
    dependency_status = {}  # Store status for summary

    click.echo("\nChecking Direct Dependencies against NPM Registry:")
    for name, required_range in direct_dependencies.items():
        click.echo(
            f"- Checking {click.style(name, bold=True)} ({required_range})... ",
            nl=False,
        )

        latest_version = get_npm_package_info(name)
        installed_info = installed_packages.get(name)
        installed_version = installed_info.get("version") if installed_info else None

        if not installed_version:
            status_msg = click.style("Not found in lock file!", fg="yellow")
            click.echo(status_msg)
            dependency_status[name] = {"status": "missing_lock", "message": status_msg}
            continue

        if not latest_version:
            status_msg = click.style(
                f"Installed={installed_version}, Latest=Unknown", fg="yellow"
            )
            click.echo(status_msg)
            dependency_status[name] = {
                "status": "unknown_latest",
                "message": status_msg,
            }
            continue

        # Check if installed satisfies the range in package.json
        satisfies_range = _run_semver_check(installed_version, required_range)
        range_msg = ""
        if satisfies_range is True:
            range_msg = click.style("satisfies range", fg="green")
        elif satisfies_range is False:
            range_msg = click.style("DOES NOT satisfy range", fg="red")
        else:
            range_msg = click.style("range check failed", fg="yellow")  # Error occurred

        # Check if installed is outdated compared to latest
        is_outdated = False
        update_msg = ""
        try:
            if parse_version(latest_version) > parse_version(installed_version):
                is_outdated = True
                update_msg = click.style(
                    f"Update available: {latest_version}", fg="cyan"
                )
                outdated_direct.append(
                    {
                        "name": name,
                        "installed": installed_version,
                        "latest": latest_version,
                    }
                )
            else:
                update_msg = click.style("Up-to-date", fg="green")
        except Exception as e:
            logger.warning(
                "Could not compare versions for %s (%s vs %s): %s",
                name,
                installed_version,
                latest_version,
                e,
            )
            update_msg = click.style("Version compare error", fg="yellow")

        # Combine messages
        status_parts = [f"Installed={installed_version}", f"Latest={latest_version}"]
        if range_msg:
            status_parts.append(range_msg)
        if update_msg:
            status_parts.append(update_msg)
        final_status = " | ".join(status_parts)
        click.echo(final_status)
        dependency_status[name] = {
            "status": "checked",
            "outdated": is_outdated,
            "message": final_status,
        }

    click.echo("-" * 20)

    # Vulnerability Check
    click.echo("\nChecking for Known Vulnerabilities (OSV API):")
    vulnerabilities = query_osv_api(installed_packages)

    if vulnerabilities is None:
        click.echo(click.style("Vulnerability check failed.", fg="red"))
    elif not vulnerabilities:
        click.echo(
            click.style(
                "No known vulnerabilities found in installed packages.", fg="green"
            )
        )
    else:
        click.echo(
            click.style(
                f"Found {len(vulnerabilities)} vulnerable package versions:",
                fg="red",
                bold=True,
            )
        )
        for pkg_version, vuln_ids in vulnerabilities.items():
            click.echo(
                click.style(f"  - {pkg_version}: {', '.join(vuln_ids)}", fg="red")
            )
    click.echo("-" * 20)

    # Summary
    click.echo("\nSummary:")
    num_outdated = len(outdated_direct)
    num_vulnerable = len(vulnerabilities) if vulnerabilities else 0

    if num_outdated > 0:
        click.echo(
            click.style(f"{num_outdated} direct dependencies are outdated.", fg="cyan")
        )
    else:
        click.echo(click.style("All direct dependencies seem up-to-date.", fg="green"))

    if num_vulnerable > 0:
        click.echo(
            click.style(
                f"{num_vulnerable} installed package versions have known vulnerabilities.",
                fg="red",
            )
        )
    elif vulnerabilities is not None:  # Check wasn't skipped
        click.echo(click.style("No vulnerabilities found.", fg="green"))

    # --- Auto PR Creation ---
    if create_pr:
        if not outdated_direct:
            click.echo("\nNo outdated direct dependencies found to create a PR for.")
            sys.exit(0)

        # Find the git repo root relative to the project path
        repo = find_git_repo(path)
        if not repo:
            click.echo(
                click.style(
                    "Could not find Git repository. Cannot create PR.", fg="red"
                ),
                err=True,
            )
            sys.exit(1)

        # Decide which dependency to update (start with the first one)
        # TODO: Add option to select dependency or update all possible?
        dep_to_update = outdated_direct[0]
        pkg_name = dep_to_update["name"]
        inst_ver = dep_to_update["installed"]
        new_ver = dep_to_update["latest"]

        click.echo(
            f"\nAttempting to auto-update {click.style(pkg_name, bold=True)} from {inst_ver} -> {new_ver}"
        )

        # 1. Create Branch
        repo, branch = create_update_branch(repo, pkg_name, new_ver)
        if not repo or not branch:
            click.echo(
                click.style("Failed to create update branch.", fg="red"), err=True
            )
            sys.exit(1)

        # 2. Run npm install
        if not perform_npm_update(path, pkg_name, new_ver):
            click.echo(
                click.style(f"Failed to update {pkg_name} using npm.", fg="red"),
                err=True,
            )
            # Optional: attempt to switch back to original branch?
            # repo.git.checkout(original_branch) # Need to store original branch name
            sys.exit(1)

        # 3. Commit and Push
        if not commit_and_push_update(repo, branch, pkg_name, inst_ver, new_ver, path):
            click.echo(
                click.style("Failed to commit or push changes.", fg="red"), err=True
            )
            sys.exit(1)

        # 4. Create PR
        pr_url = create_github_pr(
            github_token, github_repo, branch, pkg_name, inst_ver, new_ver
        )
        if not pr_url:
            click.echo(
                click.style("Failed to create GitHub Pull Request.", fg="red"), err=True
            )
            sys.exit(1)
            # Optionally offer advice like checking token permissions

        # Optional: switch back to the original branch after successful PR creation
        # try: repo.git.checkout(original_branch)
        # except: pass # Ignore errors if switching back fails

    click.echo("\nCheck complete.")

    # Exit with non-zero code if issues were found
    if num_outdated > 0 or num_vulnerable > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    cli()
