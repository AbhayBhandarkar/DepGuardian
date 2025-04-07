import click
import os
import json
import requests
import subprocess
from packaging.version import parse as parse_version
# NEW Imports
import git # For GitPython
# We'll import Github later when we use it

# --- Helper functions (parse_package_json, parse_package_lock_v2_v3, get_npm_package_info, check_npm_range_satisfaction, query_osv_api) remain the same ---
# [Keep the previous functions here]
# --- Helper Function to parse package.json ---
def parse_package_json(file_path):
    """Parses package.json to get direct dependencies."""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            dependencies = data.get('dependencies', {})
            dev_dependencies = data.get('devDependencies', {})
            all_direct_deps = {**dev_dependencies, **dependencies} # Dev deps first, then overwrite with prod deps if name clash
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

# --- Helper Function to parse package-lock.json (v2/v3) ---
def parse_package_lock_v2_v3(file_path):
    """Parses package-lock.json (v2/v3) to get all installed package versions."""
    packages = {}
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)

        lockfile_version = data.get('lockfileVersion')
        if lockfile_version is None or lockfile_version < 2:
             click.echo(click.style(f"Warning: Lockfile version is {lockfile_version}. This parser primarily handles v2/v3. Results might be incomplete.", fg='yellow'))
             return {} # Or raise NotImplementedError("Parsing for lockfile v1 not implemented")

        for path, details in data.get('packages', {}).items():
            if not path:
                continue
            parts = path.split('node_modules/')
            if len(parts) > 1:
                package_name = parts[-1]
                if package_name and 'version' in details:
                    packages[package_name] = {
                        'version': details['version'],
                        'dev': details.get('dev', False)
                    }

        return packages

    except FileNotFoundError:
         click.echo(click.style(f"Error: '{os.path.basename(file_path)}' not found.", fg='red'))
         return None
    except json.JSONDecodeError:
        click.echo(click.style(f"Error: Could not decode JSON from '{os.path.basename(file_path)}'.", fg='red'))
        return None
    except Exception as e:
        click.echo(click.style(f"An unexpected error occurred reading '{os.path.basename(file_path)}': {e}", fg='red'))
        return None


# --- Helper Function to get package info from npm ---
def get_npm_package_info(package_name):
    """Fetches package information from the npm registry."""
    registry_url = f"https://registry.npmjs.org/{package_name.replace('/', '%2F')}"
    try:
        response = requests.get(registry_url, timeout=10)
        response.raise_for_status()
        data = response.json()
        latest_version = data.get('dist-tags', {}).get('latest')
        return {
            'latest_version': latest_version,
        }
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
             # Changed nl=True to ensure this warning is on its own line
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

# --- Helper Function to check range using Node.js ---
def check_npm_range_satisfaction(version, range_spec):
    """Uses Node.js subprocess to check if version satisfies npm range."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    checker_script = os.path.join(script_dir, 'semver_checker.js')

    if not os.path.exists(checker_script):
        click.echo(click.style(f"\nError: Node helper script not found at {checker_script}", fg='red'), err=True, nl=True)
        return None

    command = ['node', checker_script, version, range_spec]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False) # Use check=False

        if result.returncode != 0:
            error_msg = result.stderr.strip() or result.stdout.strip()
            # Make error message slightly more compact for the flow
            click.echo(click.style(f" (Node err: {error_msg})", fg='red'), nl=False, err=True) # Keep on same line
            return None

        output = result.stdout.strip()
        return output == 'true'

    except FileNotFoundError:
        click.echo(click.style(" (Node not found)", fg='red'), nl=False, err=True)
        return None
    except subprocess.TimeoutExpired:
         click.echo(click.style(" (Node timeout)", fg='red'), nl=False, err=True)
         return None
    except Exception as e:
        click.echo(click.style(f" (Subprocess err: {e})", fg='red'), nl=False, err=True)
        return None


# --- Helper Function to query OSV API ---
def query_osv_api(packages_dict):
    """Queries the OSV API for vulnerabilities for the given packages."""
    osv_url = "https://api.osv.dev/v1/querybatch"
    queries = []
    query_map = []

    for name, details in packages_dict.items():
        version = details.get('version')
        if name and version:
            queries.append({
                "version": version,
                "package": {"name": name, "ecosystem": "npm"}
            })
            query_map.append(f"{name}@{version}")

    if not queries: return {}
    payload = {"queries": queries}
    vulnerabilities = {}

    try:
        response = requests.post(osv_url, json=payload, timeout=30)
        response.raise_for_status()
        results = response.json()

        if not results or 'results' not in results:
             click.echo(click.style("Warning: OSV API returned empty or invalid response.", fg='yellow'))
             return {}

        for i, res in enumerate(results.get('results', [])):
             if res and 'vulns' in res:
                 package_key = query_map[i]
                 vuln_ids = [v.get('id') for v in res['vulns'] if v.get('id')]
                 if vuln_ids:
                     vulnerabilities[package_key] = vuln_ids
        return vulnerabilities
    # Consolidated error handling for brevity
    except requests.exceptions.RequestException as e:
        click.echo(click.style(f"Error querying OSV API: {e}", fg='red'))
        return None # Indicate failure
    except json.JSONDecodeError:
         click.echo(click.style("Error decoding OSV API response.", fg='red'))
         return None # Indicate failure


# --- NEW Helper Function for Git Branching ---
# --- Helper Function for Git Branching ---
def create_update_branch(repo_path, package_name, new_version):
    """Creates and checks out a new branch for the dependency update."""
    try:
        # MODIFIED: Added search_parent_directories=True
        repo = git.Repo(repo_path, search_parent_directories=True)
        # Get the actual repo root found
        repo_root = repo.working_tree_dir
        click.echo(f"Operating on Git repo found at: {repo_root}")


        # Check if the repo is dirty (check from the found root)
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
        current_head = repo.head.commit
        new_branch = repo.create_head(branch_name, commit=current_head)
        new_branch.checkout()
        click.echo(f"Successfully created and checked out branch '{branch_name}'.")
        return repo, branch_name

    except git.InvalidGitRepositoryError:
        # This error is less likely now with search_parent_directories=True,
        # but keep it just in case. It would mean no .git folder was found
        # in repo_path or any parent directory.
        click.echo(click.style(f"Error: No valid Git repository found at or above '{repo_path}'.", fg='red'))
        return None, None
    except git.GitCommandError as e:
        click.echo(click.style(f"Git command error during branching: {e}", fg='red'))
        return None, None
    except Exception as e:
         click.echo(click.style(f"An unexpected error occurred during Git operations: {e}", fg='red'))
         return None, None


@click.group()
def cli():
    """A tool to analyze project dependencies."""
    pass

# --- Add new options to the check command ---
@cli.command()
@click.option('--path', default='.', help='Path to the project directory (containing package.json and Git repo). Defaults to current directory.')
@click.option('--create-pr', is_flag=True, default=False, help='Attempt to create a branch and Pull Request on GitHub for the first found update.')
@click.option('--github-repo', default=None, help='Target GitHub repository in "owner/repo" format (required if --create-pr).')
@click.option('--github-token', default=None, help='GitHub Personal Access Token (required if --create-pr). Reads from GITHUB_TOKEN env var if not set.')
def check(path, create_pr, github_repo, github_token):
    """Checks dependencies and optionally creates update PRs."""

    # --- PR Pre-checks ---
    if create_pr:
        token = github_token or os.environ.get('GITHUB_TOKEN')
        if not token:
            click.echo(click.style("Error: --create-pr requires a GitHub token via --github-token option or GITHUB_TOKEN environment variable.", fg='red'))
            return
        if not github_repo:
            click.echo(click.style("Error: --create-pr requires --github-repo 'owner/repo'.", fg='red'))
            return
        # Store token securely if needed later (don't print it)
        _github_token = token # Use internal variable
        click.echo("PR creation mode enabled.") # Inform user

    # --- 1 & 2. Parsing (remains the same) ---
    click.echo(f"Checking project at path: {os.path.abspath(path)}")
    package_json_path = os.path.join(path, 'package.json')
    package_lock_path = os.path.join(path, 'package-lock.json')
    direct_dependencies = parse_package_json(package_json_path)
    if direct_dependencies is None: return
    click.echo(f"\nFound {len(direct_dependencies)} direct dependencies in package.json.")
    if not os.path.exists(package_lock_path):
         click.echo(click.style(f"Error: 'package-lock.json' not found.", fg='red')); return
    installed_packages = parse_package_lock_v2_v3(package_lock_path)
    if installed_packages is None: return
    click.echo(f"Found {len(installed_packages)} total installed packages in package-lock.json.")

    # --- 3. Check latest versions (remains the same logic) ---
    # [This section remains the same - iterates, calls helpers, collects outdated_direct_deps]
    click.echo("\nChecking direct dependencies against npm registry:")
    outdated_direct_deps = []
    node_available = True # Flag to avoid repeated 'node not found' errors

    for name, required_range in direct_dependencies.items():
        click.echo(f" - Checking {name} ({required_range})...", nl=False)

        info = get_npm_package_info(name)
        installed_detail = installed_packages.get(name)
        installed_version_str = installed_detail.get('version') if installed_detail else None

        if not info or not info.get('latest_version'):
            # Error already printed by helper
            click.echo("") # Add newline if error occurred
            continue

        if not installed_version_str:
             click.echo(click.style(f" -> Warning: '{name}' not found in lock file!", fg='yellow'), nl=True)
             continue

        try:
            latest_version_str = info['latest_version']
            latest_version_obj = parse_version(latest_version_str)
            installed_version_obj = parse_version(installed_version_str)

            status = ""
            status_color = 'green'
            satisfies = None # Define satisfies before the check

            if node_available:
                satisfies = check_npm_range_satisfaction(installed_version_str, required_range)

            if satisfies is None:
                # Error during check, message printed by helper or node error detected
                status = "Range check error" # Keep status brief here
                status_color = 'red'
                if "(Node not found)" in click.get_current_context().err.getvalue(): # Check if node is missing
                     node_available = False # Don't try node again
            elif not satisfies:
                 status = f"Installed version {installed_version_str} does NOT satisfy {required_range}!"
                 status_color = 'red'

            # Check for updates
            update_available = latest_version_obj > installed_version_obj
            if update_available:
                 status += f" Update available: {latest_version_str}"
                 status_color = 'yellow' if status_color == 'green' else status_color # Keep red if already red
                 outdated_direct_deps.append({
                     'name': name,
                     'installed': installed_version_str,
                     'latest': latest_version_str,
                     'required': required_range
                 })
            elif not status and satisfies is not None: # OK only if no issues and range check passed
                 status = "OK"
            elif satisfies is None: # If range check failed, don't say OK
                 pass # Status already indicates failure

            click.echo(click.style(f" -> Installed: {installed_version_str}, Latest: {latest_version_str}. Status: {status}", fg=status_color), nl=True) # Ensure newline

        except Exception as e: # Catch errors from packaging.version.parse etc.
             click.echo(click.style(f" -> Error processing Python versions for {name}: {e}", fg='red'), nl=True)

    # --- Summary of outdated ---
    if outdated_direct_deps:
         click.echo(f"\nFound {len(outdated_direct_deps)} potentially outdated direct dependencies.")
    else:
         click.echo("\nAll direct dependencies seem up-to-date according to the registry and satisfy package.json ranges (where checkable).")


    # --- 4. Query OSV (remains the same logic) ---
    # [This section remains the same - calls query_osv_api, reports results]
    click.echo("\nQuerying OSV API for vulnerabilities for all installed packages...")
    vulnerabilities_found = query_osv_api(installed_packages)

    if vulnerabilities_found is None:
        click.echo(click.style("Vulnerability check failed due to API error.", fg='red'))
    elif not vulnerabilities_found:
        click.echo(click.style("No known vulnerabilities found in installed packages via OSV.", fg='green'))
    else:
        click.echo(click.style(f"\nWARNING: Found vulnerabilities in {len(vulnerabilities_found)} package versions:", fg='red', bold=True))
        for package_key, vuln_ids in sorted(vulnerabilities_found.items()):
            click.echo(click.style(f"  - {package_key}: {', '.join(vuln_ids)}", fg='red'))


    # --- 5. Attempt PR Creation (NEW) ---
    if create_pr and outdated_direct_deps:
        click.echo("\nAttempting to create PR for the first outdated dependency...")
        # Select the first outdated dependency
        dep_to_update = outdated_direct_deps[0]
        pkg_name = dep_to_update['name']
        latest_ver = dep_to_update['latest']

        click.echo(f"Targeting update for: {pkg_name} to version {latest_ver}")

        # Step 5a: Create Branch
        repo_obj, new_branch_name = create_update_branch(path, pkg_name, latest_ver)

        if repo_obj and new_branch_name:
            click.echo(f"Branch '{new_branch_name}' is ready.")
            # --- NEXT STEPS WITHIN THIS BLOCK ---
            # 5b. Run 'npm install <pkg>@<version>' using subprocess
            # 5c. Commit changes using GitPython (repo_obj.index.add, repo_obj.index.commit)
            # 5d. Push branch using GitPython (repo_obj.remotes.origin.push)
            # 5e. Create PR using PyGithub (requires github_repo, _github_token)
            click.echo("TODO: Implement npm install, commit, push, and PR creation.") # Placeholder
        else:
             click.echo(click.style("Branch creation failed. Cannot proceed with PR.", fg='red'))


    click.echo("\nCheck complete.")


if __name__ == '__main__':
    cli()