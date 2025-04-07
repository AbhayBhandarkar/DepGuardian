#!/usr/bin/env python3
"""
DepGuardian CLI Tool

Analyzes project dependencies (currently npm) for outdated packages and vulnerabilities.
Optionally creates branches and prepares updates for Pull Requests (currently GitHub).
"""

import click
import os
import json
import requests
import subprocess
from packaging.version import parse as parse_version
import git # GitPython

# --- Helper Function: Parse package.json ---
def parse_package_json(file_path):
    """Parses package.json to get direct dependencies."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            # Combine dependencies and devDependencies
            dependencies = data.get('dependencies', {})
            dev_dependencies = data.get('devDependencies', {})
            # Dev deps first, prod deps overwrite if name clashes
            all_direct_deps = {**dev_dependencies, **dependencies}
            return all_direct_deps
    except FileNotFoundError:
        click.echo(click.style(f"Error: '{os.path.basename(file_path)}' not found.", fg='red'))
        return None
    except json.JSONDecodeError:
        click.echo(click.style(f"Error: Could not decode JSON from '{os.path.basename(file_path)}'.", fg='red'))
        return None
    except Exception as e:
        click.echo(click.style(f"An unexpected error occurred reading '{os.path.basename(file_path)}': {e}", fg='red'))
        return None

# --- Helper Function: Parse package-lock.json (v2/v3) ---
def parse_package_lock_v2_v3(file_path):
    """Parses package-lock.json (v2/v3) to get all installed package versions and dev status."""
    packages = {}
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Check lockfile version - we primarily target v2/v3 with the 'packages' key
        lockfile_version = data.get('lockfileVersion')
        if lockfile_version is None or lockfile_version < 2:
             click.echo(click.style(f"Warning: Lockfile version is {lockfile_version}. This parser primarily handles v2/v3. Results might be incomplete.", fg='yellow'))
             return {} # Or raise NotImplementedError("Parsing for lockfile v1 not implemented")

        # Iterate through the flat 'packages' structure in v2/v3
        for path, details in data.get('packages', {}).items():
            if not path: # Skip root project entry ""
                continue
            # Extract package name from path like "node_modules/@types/node" -> "@types/node"
            parts = path.split('node_modules/')
            if len(parts) > 1:
                package_name = parts[-1]
                # Ensure details is a dictionary and contains version before proceeding
                if isinstance(details, dict) and package_name and 'version' in details:
                    packages[package_name] = {
                        'version': details['version'],
                        'dev': details.get('dev', False) # Track if it's a dev dependency
                    }

        return packages

    except FileNotFoundError:
         # Should be caught earlier, but good practice
         click.echo(click.style(f"Error: '{os.path.basename(file_path)}' not found.", fg='red'))
         return None
    except json.JSONDecodeError:
        click.echo(click.style(f"Error: Could not decode JSON from '{os.path.basename(file_path)}'.", fg='red'))
        return None
    except Exception as e:
        click.echo(click.style(f"An unexpected error occurred reading '{os.path.basename(file_path)}': {e}", fg='red'))
        return None

# --- Helper Function: Get package info from npm ---
def get_npm_package_info(package_name):
    """Fetches package information from the npm registry."""
    # URL encode package name for safety, especially with scopes
    safe_package_name = requests.utils.quote(package_name, safe='')
    registry_url = f"https://registry.npmjs.org/{safe_package_name}"
    try:
        response = requests.get(registry_url, timeout=10) # Add a timeout
        response.raise_for_status() # Raises HTTPError for bad responses (4XX, 5XX)

        data = response.json()
        latest_version = data.get('dist-tags', {}).get('latest')
        return {
            'latest_version': latest_version,
        }

    except requests.exceptions.HTTPError as e:
        # Output on newline for clarity in check loop
        if e.response.status_code == 404:
            click.echo(click.style(f" -> Warning: Package '{package_name}' not found on npm registry.", fg='yellow'), nl=True)
        else:
            click.echo(click.style(f" -> Error fetching data for '{package_name}': HTTP {e.response.status_code}", fg='red'), nl=True)
        return None
    except requests.exceptions.RequestException as e:
        click.echo(click.style(f" -> Error fetching data for '{package_name}': {e}", fg='red'), nl=True)
        return None
    except json.JSONDecodeError:
         click.echo(click.style(f" -> Error decoding registry response for '{package_name}'.", fg='red'), nl=True)
         return None

# --- Helper Function: Check npm range satisfaction via Node.js ---
def check_npm_range_satisfaction(version, range_spec):
    """Uses Node.js subprocess to check if version satisfies npm range."""
    # Assumes semver_checker.js is in the same directory as this script's package
    script_dir = os.path.dirname(os.path.abspath(__file__))
    checker_script = os.path.join(script_dir, 'semver_checker.js')

    # Check if script exists
    if not os.path.exists(checker_script):
        # Print error on separate line for visibility
        click.echo(click.style(f"\nError: Node helper script not found at {checker_script}", fg='red'), err=True, nl=True)
        return None # Indicate error

    command = ['node', checker_script, version, range_spec]
    try:
        # Use check=False initially to handle errors gracefully
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding='utf-8', # Specify encoding
            timeout=5,
            check=False # We check returncode manually
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip() or result.stdout.strip() # Try both streams
            # Keep error message brief for inline display
            click.echo(click.style(f" (Node err: {error_msg.splitlines()[0]})", fg='red'), nl=False, err=True)
            return None

        # Read stdout (should be 'true' or 'false')
        output = result.stdout.strip().lower()
        return output == 'true'

    except FileNotFoundError:
        # This means 'node' command was not found
        click.echo(click.style(" (Node not found)", fg='red'), nl=False, err=True)
        return None # Indicate error
    except subprocess.TimeoutExpired:
         click.echo(click.style(" (Node timeout)", fg='red'), nl=False, err=True)
         return None
    except Exception as e:
        # Catch any other unexpected errors during subprocess call
        click.echo(click.style(f" (Subprocess err: {e})", fg='red'), nl=False, err=True)
        return None

# --- Helper Function: Query OSV API ---
def query_osv_api(packages_dict):
    """Queries the OSV API for vulnerabilities for the given packages."""
    osv_url = "https://api.osv.dev/v1/querybatch"
    queries = []
    # Keep track of the query order to map results back
    query_map = []

    for name, details in packages_dict.items():
        version = details.get('version')
        if name and version:
            queries.append({
                "version": version,
                "package": {
                    "name": name,
                    "ecosystem": "npm" # Specific to this phase
                }
            })
            query_map.append(f"{name}@{version}") # Unique key for mapping results

    if not queries:
        return {} # No packages to query

    # OSV recommends batches, but let's send all at once for simplicity first
    payload = {"queries": queries}
    vulnerabilities = {}

    try:
        response = requests.post(osv_url, json=payload, timeout=30) # Longer timeout
        response.raise_for_status()
        results = response.json()

        if not results or 'results' not in results:
             click.echo(click.style("Warning: OSV API returned empty or invalid response.", fg='yellow'))
             return {}

        # Process results - they should be in the same order as the queries
        for i, res in enumerate(results.get('results', [])):
             # Check if res is not empty and contains 'vulns' key
             if res and isinstance(res, dict) and 'vulns' in res:
                 package_key = query_map[i] # Get "pkg@version" key
                 # Filter out potential None values from v.get('id')
                 vuln_ids = [v_id for v in res['vulns'] if (v_id := v.get('id'))]
                 if vuln_ids:
                     vulnerabilities[package_key] = vuln_ids

        return vulnerabilities

    except requests.exceptions.RequestException as e:
        click.echo(click.style(f"Error querying OSV API: {e}", fg='red'))
        return None # Indicate failure
    except json.JSONDecodeError:
         click.echo(click.style("Error decoding OSV API response.", fg='red'))
         return None # Indicate failure

# --- Helper Function: Create Git Update Branch ---
def create_update_branch(repo_path, package_name, new_version):
    """Creates and checks out a new branch for the dependency update."""
    try:
        # Search parent directories to find the actual .git folder
        repo = git.Repo(repo_path, search_parent_directories=True)
        repo_root = repo.working_tree_dir
        click.echo(f"Operating on Git repo found at: {repo_root}")

        # Check if the repo is dirty from the repo root perspective
        if repo.is_dirty(untracked_files=True):
            click.echo(click.style(f"Error: Repository at {repo_root} has uncommitted changes. Please commit or stash them.", fg='red'))
            return None, None # Indicate failure

        # Define branch name
        branch_name = f"depguardian/update-{package_name}-{new_version}"
        click.echo(f"Attempting to create branch: {branch_name}")

        # Check if branch already exists
        if branch_name in repo.heads:
            click.echo(click.style(f"Warning: Branch '{branch_name}' already exists. Checking it out.", fg='yellow'))
            existing_branch = repo.heads[branch_name]
            # Ensure we are on the branch if it already exists
            if repo.active_branch != existing_branch:
                 existing_branch.checkout()
            return repo, branch_name # Return existing branch

        # Create and checkout the new branch from the current head
        # Ensure we are on a known branch first (e.g., main/master) - might need refinement
        # For now, assume current head is suitable starting point
        current_head_commit = repo.head.commit
        new_branch = repo.create_head(branch_name, commit=current_head_commit)
        new_branch.checkout()
        click.echo(f"Successfully created and checked out branch '{branch_name}'.")
        return repo, branch_name

    except git.InvalidGitRepositoryError:
        click.echo(click.style(f"Error: No valid Git repository found at or above '{repo_path}'.", fg='red'))
        return None, None
    except git.GitCommandError as e:
        click.echo(click.style(f"Git command error during branching: {e}", fg='red'))
        return None, None
    except Exception as e:
         click.echo(click.style(f"An unexpected error occurred during Git operations: {e}", fg='red'))
         return None, None

# --- Helper Function: Run npm install ---
def run_npm_install(project_path, package_name, version):
    """Runs 'npm install package@version' in the specified project path."""
    # Ensure package_name and version are reasonably safe for shell command
    # Basic check: disallow characters often used in command injection.
    # A more robust solution might involve input validation schemas.
    if not all(c.isalnum() or c in '-_@.^~/' for c in package_name) or \
       not all(c.isalnum() or c in '-_.' for c in version):
        click.echo(click.style(f"Error: Invalid characters in package name or version for npm install.", fg='red'))
        return False

    command = ['npm', 'install', f"{package_name}@{version}"]
    click.echo(f"Running command: `{' '.join(command)}` in '{project_path}'...")
    try:
        # Use check=True to automatically raise CalledProcessError on failure
        result = subprocess.run(
            command,
            cwd=project_path, # Run in the directory with package.json
            capture_output=True,
            text=True,
            encoding='utf-8',
            check=True, # Raise exception on non-zero exit code
            timeout=180 # Increased timeout to 3 minutes for npm install
        )
        click.echo(click.style("npm install completed successfully.", fg='green'))
        return True
    except FileNotFoundError:
        click.echo(click.style("Error: 'npm' command not found. Please ensure Node.js/npm is installed and in your PATH.", fg='red'))
        return False
    except subprocess.CalledProcessError as e:
        # Try to print helpful info from stderr if npm install fails
        click.echo(click.style(f"Error during `npm install` (exit code {e.returncode}): {e}", fg='red'))
        if e.stderr:
            click.echo(click.style(f"npm stderr:\n{e.stderr.strip()}", fg='red'))
        elif e.stdout: # Sometimes errors might go to stdout
            click.echo(click.style(f"npm stdout:\n{e.stdout.strip()}", fg='red'))
        return False
    except subprocess.TimeoutExpired:
        click.echo(click.style("Error: `npm install` timed out after 3 minutes.", fg='red'))
        return False
    except Exception as e:
        click.echo(click.style(f"An unexpected error occurred running npm install: {e}", fg='red'))
        return False


# --- Main CLI Group ---
@click.group()
def cli():
    """A tool to analyze project dependencies and manage updates."""
    pass

# --- Check Command ---
@cli.command()
@click.option('--path', default='.', help='Path to the project directory (containing package.json). Defaults to current directory.')
@click.option('--create-pr', is_flag=True, default=False, help='Attempt to create a branch and Pull Request on GitHub for the first found update.')
@click.option('--github-repo', default=None, help='Target GitHub repository in "owner/repo" format (required if --create-pr).')
@click.option('--github-token', default=None, help='GitHub Personal Access Token (required if --create-pr). Reads from GITHUB_TOKEN env var if not set.')
def check(path, create_pr, github_repo, github_token):
    """Checks dependencies and optionally creates update PRs."""
    project_path = os.path.abspath(path) # Use absolute path
    _github_token = None # Define variable for token storage

    # --- PR Pre-checks ---
    if create_pr:
        token = github_token or os.environ.get('GITHUB_TOKEN')
        if not token:
            click.echo(click.style("Error: --create-pr requires a GitHub token via --github-token option or GITHUB_TOKEN environment variable.", fg='red'))
            return
        if not github_repo or '/' not in github_repo:
            click.echo(click.style("Error: --create-pr requires --github-repo in 'owner/repo' format.", fg='red'))
            return
        _github_token = token # Store token securely if needed later
        click.echo("PR creation mode enabled.")

    # --- 1 & 2. Parsing ---
    click.echo(f"Checking project at path: {project_path}")
    package_json_path = os.path.join(project_path, 'package.json')
    package_lock_path = os.path.join(project_path, 'package-lock.json')

    direct_dependencies = parse_package_json(package_json_path)
    if direct_dependencies is None: return
    click.echo(f"\nFound {len(direct_dependencies)} direct dependencies in package.json.")

    if not os.path.exists(package_lock_path):
         click.echo(click.style(f"Error: 'package-lock.json' not found at {package_lock_path}. Required for analysis.", fg='red'))
         return
    installed_packages = parse_package_lock_v2_v3(package_lock_path)
    if installed_packages is None: return
    click.echo(f"Found {len(installed_packages)} total installed packages in package-lock.json.")

    # --- 3. Check latest versions for direct dependencies ---
    click.echo("\nChecking direct dependencies against npm registry:")
    outdated_direct_deps = []
    node_available = True # Flag to avoid repeated 'node not found' errors

    for name, required_range in direct_dependencies.items():
        click.echo(f" - Checking {name} ({required_range})...", nl=False)

        installed_detail = installed_packages.get(name)
        installed_version_str = installed_detail.get('version') if installed_detail else None
        info = get_npm_package_info(name) # Fetches latest version

        # Check if mandatory info is missing
        if not info or not info.get('latest_version'):
             click.echo("") # Ensure newline after failed check
             continue # Skip package if latest version not found
        if not installed_version_str:
             click.echo(click.style(f" -> Warning: '{name}' not found in lock file!", fg='yellow'), nl=True)
             continue # Skip package if not found in lock file

        try:
            latest_version_str = info['latest_version']
            # Use packaging.version for robust comparison
            latest_version_obj = parse_version(latest_version_str)
            installed_version_obj = parse_version(installed_version_str)

            status = ""
            status_color = 'green'
            satisfies = None # Initialize satisfies status

            # Check range satisfaction using Node helper script
            if node_available:
                satisfies = check_npm_range_satisfaction(installed_version_str, required_range)
                if satisfies is None and "(Node not found)" in click.get_current_context().err.getvalue():
                     node_available = False # Don't try node again if it's not found

            # Determine status based on checks
            if satisfies is None:
                status = "Range check error" # Error occurred (node not found, script error, etc.)
                status_color = 'red'
            elif not satisfies:
                 status = f"Installed {installed_version_str} invalid for {required_range}!"
                 status_color = 'red'

            # Check if an update is available
            update_available = latest_version_obj > installed_version_obj
            if update_available:
                 # Append update info, preserving error status if present
                 status += f" Update available: {latest_version_str}"
                 status_color = 'yellow' if status_color == 'green' else status_color # Keep red/yellow precedence
                 # Add to list of outdated packages for potential PR creation
                 outdated_direct_deps.append({
                     'name': name,
                     'installed': installed_version_str,
                     'latest': latest_version_str,
                     'required': required_range
                 })
            elif not status and satisfies is not None: # OK only if no issues AND range check succeeded
                 status = "OK"
            # If range check failed (satisfies is None), status remains "Range check error" or empty

            # Print final status for the package
            click.echo(click.style(f" -> Installed: {installed_version_str}, Latest: {latest_version_str}. Status: {status}", fg=status_color), nl=True) # Ensure newline

        except Exception as e: # Catch other errors like packaging.version.parse
             click.echo(click.style(f" -> Error processing Python versions for {name}: {e}", fg='red'), nl=True)

    # --- Summary of Outdated Dependencies ---
    if outdated_direct_deps:
         click.echo(f"\nFound {len(outdated_direct_deps)} potentially outdated direct dependencies.")
    else:
         click.echo("\nAll direct dependencies seem up-to-date according to the registry and satisfy package.json ranges (where checkable).")

    # --- 4. Query OSV for Vulnerabilities ---
    click.echo("\nQuerying OSV API for vulnerabilities for all installed packages...")
    vulnerabilities_found = query_osv_api(installed_packages)

    if vulnerabilities_found is None:
        click.echo(click.style("Vulnerability check failed due to API error.", fg='red'))
    elif not vulnerabilities_found:
        click.echo(click.style("No known vulnerabilities found in installed packages via OSV.", fg='green'))
    else:
        click.echo(click.style(f"\nWARNING: Found vulnerabilities in {len(vulnerabilities_found)} package versions:", fg='red', bold=True))
        # Sort by package name for consistent output
        for package_key, vuln_ids in sorted(vulnerabilities_found.items()):
            click.echo(click.style(f"  - {package_key}: {', '.join(vuln_ids)}", fg='red'))

    # --- 5. Attempt PR Creation ---
    if create_pr and outdated_direct_deps:
        click.echo("\nAttempting to create PR for the first outdated dependency...")
        # Select the first outdated dependency
        dep_to_update = outdated_direct_deps[0]
        pkg_name = dep_to_update['name']
        latest_ver = dep_to_update['latest']
        installed_ver = dep_to_update['installed'] # Get installed version for commit message
        click.echo(f"Targeting update for: {pkg_name} from {installed_ver} to version {latest_ver}")

        # Step 5a: Create Branch
        repo_obj, new_branch_name = create_update_branch(project_path, pkg_name, latest_ver)

        if repo_obj and new_branch_name:
            click.echo(f"Branch '{new_branch_name}' is ready.")

            # Step 5b: Run 'npm install <pkg>@<version>'
            # project_path is the directory containing package.json
            install_success = run_npm_install(project_path, pkg_name, latest_ver)

            if install_success:
                # --- Step 5c: Commit changes using GitPython ---
                try:
                    click.echo("Staging changes...")
                    # Calculate paths relative to the repo root
                    repo_root = repo_obj.working_tree_dir
                    # Ensure the paths exist before adding - primarily for lock file if install failed partially?
                    pkg_json_abs = os.path.join(project_path, 'package.json')
                    pkg_lock_abs = os.path.join(project_path, 'package-lock.json')

                    rel_pkg_path = os.path.relpath(pkg_json_abs, repo_root)
                    rel_lock_path = os.path.relpath(pkg_lock_abs, repo_root)

                    files_to_add = []
                    # Check if files are modified relative to the index or HEAD
                    # A simpler check might be just trying to add them
                    # Let's rely on add not failing if unchanged, but check existence
                    if os.path.exists(pkg_json_abs): files_to_add.append(rel_pkg_path)
                    if os.path.exists(pkg_lock_abs): files_to_add.append(rel_lock_path)


                    if not files_to_add:
                         click.echo(click.style("Warning: Cannot find package files to stage.", fg='yellow'))
                    else:
                         # Use add command on repo object directly
                         repo_obj.git.add(files_to_add)
                         click.echo(f"Staged {files_to_add}.")

                    # Construct commit message
                    commit_message = f"chore(deps): update {pkg_name} from {installed_ver} to {latest_ver}\n\nAutomatically updated by DepGuardian."

                    # Check if index has changes compared to HEAD before committing
                    if repo_obj.is_dirty(index=True, working_tree=False): # Check staged changes
                         click.echo("Committing changes...")
                         repo_obj.index.commit(commit_message)
                         click.echo(click.style(f"Successfully committed update for {pkg_name}.", fg='green'))
                    else:
                         # This might happen if npm install didn't change anything, or if commit happened previously
                         click.echo("No changes staged for commit, skipping commit step.")


                    # --- NEXT STEPS WITHIN THIS BLOCK ---
                    # 5d. Push branch using GitPython (repo_obj.remotes.origin.push)
                    # 5e. Create PR using PyGithub (requires github_repo, _github_token)
                    click.echo("TODO: Implement push and PR creation.") # Placeholder

                except git.GitCommandError as e:
                    click.echo(click.style(f"Git command error during staging/commit: {e}", fg='red'))
                except Exception as e:
                     click.echo(click.style(f"An unexpected error occurred during Git commit: {e}", fg='red'))

            else:
                click.echo(click.style("npm install failed. Aborting automatic commit.", fg='red'))
                # Consider checking out the original branch if npm install fails?
                # For now, leave the user on the potentially broken branch.
        else:
             click.echo(click.style("Branch creation failed. Cannot proceed with PR.", fg='red'))

    click.echo("\nCheck complete.")


# --- Script Entry Point ---
if __name__ == '__main__':
    cli()