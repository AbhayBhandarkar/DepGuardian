# dep_guardian/cli.py
import os
import json
import sys
import click
import requests
import subprocess
import logging
from datetime import datetime, timezone
import asyncio
import tempfile
import zipfile
import glob
import time 
import shutil  

from packaging.version import parse as parse_version
from github import Github, GithubException
from git import Repo, GitCommandError

# Conditional import for Gemini
try:
    import google.generativeai as genai
except ImportError:
    genai = None
    logging.warning(
        "google-generativeai library not found. Gemini features will be unavailable. Please install 'pip install google-generativeai'"
    )


from .__version__ import __version__

# --- Configuration ---
OSV_API_URL = "https://api.osv.dev/v1/querybatch"
NPM_REGISTRY_URL = "https://registry.npmjs.org/{package_name}"
REQUEST_TIMEOUT = 15
NPM_INSTALL_TIMEOUT = 120

# Gemini Configuration (can be overridden by environment variables or CLI options)
GEMINI_MODEL_NAME_DEFAULT = os.environ.get(
    "DEPGUARDIAN_GEMINI_MODEL", "gemini-1.5-flash-latest"
)
GEMINI_MAX_RETRIES_DEFAULT = 2
GEMINI_API_REQUEST_TIMEOUT = 480


# --- Setup Logging ---
logging.basicConfig(
    level=os.environ.get("LOGLEVEL", "INFO").upper(),
    format="%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d - %(funcName)s] - %(message)s",
)
logger = logging.getLogger("depg")
if logging.getLogger("depg").getEffectiveLevel() > logging.DEBUG:
    if genai:
        logging.getLogger("google.api_core.retry").setLevel(logging.WARNING)


# --- Helper Functions ---
def _run_semver_check(installed_version, version_range):
    script_path = os.path.join(os.path.dirname(__file__), "semver_checker.js")
    if not os.path.exists(script_path):
        logger.error("semver_checker.js not found at %s", script_path)
        return None
    if not installed_version or not version_range:
        logger.warning("Invalid input for semver check.")
        return None
    if shutil.which("node") is None:
        logger.error("Node.js ('node') is not installed. Please install Node.js.")
        return None

    command = ["node", script_path, installed_version, version_range]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        output = result.stdout.strip().lower()
        return output == "true"
    except subprocess.CalledProcessError as e:
        if "Cannot find module 'semver'" in e.stderr:
            logger.warning("Node.js semver module not found. Installing locally...")
            install_result = subprocess.run(
                ["npm", "install", "semver"],
                cwd=os.path.dirname(__file__),
                capture_output=True,
                text=True,
            )
            if install_result.returncode == 0:
                logger.info("Successfully installed 'semver'. Retrying...")
                return _run_semver_check(installed_version, version_range)
            else:
                logger.error("Failed to install 'semver': %s", install_result.stderr.strip())
                return None
        else:
            logger.error("semver_checker.js failed (exit %d): %s", e.returncode, e.stderr.strip())
            return None
    except subprocess.TimeoutExpired:
        logger.error("semver_checker.js timed out.")
        return None
    except Exception as e:
        logger.error("Unexpected error running semver_checker.js: %s", e)
        return None



def parse_package_json(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        deps = data.get("dependencies", {})
        dev_deps = data.get("devDependencies", {})
        return {**deps, **dev_deps}
    except FileNotFoundError:
        logger.error("package.json not found: %s", file_path)
        return None
    except json.JSONDecodeError as e:
        logger.error("Error decoding package.json: %s", e)
        return None
    except Exception as e:
        logger.error("Error reading package.json: %s", e)
        return None


def parse_package_lock(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        lockfile_version = data.get("lockfileVersion", 0)
        packages_data = data.get("packages", {})
        dependencies_data = data.get("dependencies", {})
        installed_packages_dict = {}
        if lockfile_version >= 2 and packages_data:
            for path, info in packages_data.items():
                if not path or not isinstance(info, dict):
                    continue
                parts = path.split("node_modules/")
                raw_version = info.get("version")
                if (
                    len(parts) > 1
                    and raw_version
                    and isinstance(raw_version, str)
                    and raw_version.strip()
                ):
                    package_name = parts[-1]
                    if "/" in package_name and not package_name.startswith("@"):
                        package_name = package_name.split("/")[-1]
                    installed_packages_dict[package_name] = {
                        "name": package_name,
                        "version": raw_version.strip(),
                        "is_dev_dependency_heuristic": info.get("dev", False),
                        "path_in_node_modules": path,
                    }
                elif len(parts) > 1:
                    logger.warning(
                        f"Path '{path}' in lock missing version. Info: {info}"
                    )
        elif lockfile_version == 1 and dependencies_data:
            logger.warning("Detected v1 lockfile. Dev status heuristic.")
            for name, info in dependencies_data.items():
                if not isinstance(info, dict):
                    continue
                raw_version = info.get("version")
                if raw_version and isinstance(raw_version, str) and raw_version.strip():
                    installed_packages_dict[name] = {
                        "name": name,
                        "version": raw_version.strip(),
                        "is_dev_dependency_heuristic": info.get("dev", False),
                        "path_in_node_modules": f"node_modules/{name}",
                    }
                else:
                    logger.warning(
                        f"Package '{name}' in v1 lock missing version. Info: {info}"
                    )
        else:
            logger.error("Unsupported lock format v%s", lockfile_version)
            return None, None
        installed_packages_list = list(installed_packages_dict.values())
        logger.info(
            "Parsed %d unique packages from lock file (v%d)",
            len(installed_packages_list),
            lockfile_version,
        )
        return installed_packages_list, lockfile_version
    except FileNotFoundError:
        logger.error("package-lock.json not found: %s", file_path)
        return None, None
    except json.JSONDecodeError as e:
        logger.error("Error decoding package-lock.json: %s", e)
        return None, None
    except Exception as e:
        logger.error("Error reading package-lock.json: %s", e)
        return None, None


def get_npm_package_info(package_name):
    url = NPM_REGISTRY_URL.format(package_name=package_name.replace("/", "%2F"))
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        data = response.json()
        latest_version = data.get("dist-tags", {}).get("latest")
        if not latest_version:
            logger.warning("No 'latest' tag for %s", package_name)
        return latest_version
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            logger.warning("Package '%s' not on npm.", package_name)
        else:
            logger.error("HTTP error for '%s': %s", package_name, e)
    except requests.exceptions.Timeout:
        logger.error("Timeout for '%s'", package_name)
    except requests.exceptions.RequestException as e:
        logger.error("Network error for '%s': %s", package_name, e)
    except json.JSONDecodeError:
        logger.error("Bad JSON for '%s' from %s", package_name, url)
    except Exception as e:
        logger.error("Unexpected error for '%s': %s", package_name, e)
    return None


def query_osv_api(installed_packages_list):
    if not installed_packages_list:
        return []

    queries = []
    for pkg_info in installed_packages_list:
        if not isinstance(pkg_info, dict):
            logger.warning("Skipping non-dict pkg_info: %s", pkg_info)
            continue
        name, version = pkg_info.get("name"), pkg_info.get("version")
        if not (name and isinstance(name, str) and name.strip()):
            logger.warning("Skipping OSV for invalid name: %s", pkg_info)
            continue
        if not (version and isinstance(version, str) and version.strip()):
            logger.warning(
                "Skipping OSV for '%s' (invalid version): %s", name, pkg_info
            )
            continue
        queries.append(
            {"package": {"ecosystem": "npm", "name": name, "version": version}}
        )

    if not queries:
        logger.info("No valid packages for OSV query.")
        return []

    logger.info("Querying OSV for %d package versions (in batches)...", len(queries))
    vulnerabilities_found = []
    BATCH_SIZE = 100

    for i in range(0, len(queries), BATCH_SIZE):
        batch = queries[i:i + BATCH_SIZE]
        try:
            response = requests.post(
                OSV_API_URL, json={"queries": batch}, timeout=REQUEST_TIMEOUT * 2
            )
            response.raise_for_status()
            results = response.json().get("results", [])
            if len(results) != len(batch):
                logger.warning(
                    "OSV results/queries count mismatch in batch %d-%d: %d vs %d",
                    i, i + len(batch), len(results), len(batch)
                )

            for j, res_item in enumerate(results):
                queried_pkg = batch[j]["package"]
                if not res_item or not isinstance(res_item, dict):
                    logger.debug("No/invalid OSV result for %s", queried_pkg)
                    continue
                package_vulns_osv = res_item.get("vulns", [])
                if package_vulns_osv and isinstance(package_vulns_osv, list):
                    osv_ids = [
                        v.get("id")
                        for v in package_vulns_osv
                        if isinstance(v, dict) and v.get("id")
                    ]
                    if osv_ids:
                        first_vuln = package_vulns_osv[0] if package_vulns_osv else {}
                        vulnerabilities_found.append(
                            {
                                "package_name": queried_pkg["name"],
                                "vulnerable_version_installed": queried_pkg["version"],
                                "osv_ids": osv_ids,
                                "summary": first_vuln.get("summary", "N/A"),
                                "details_url": f"https://osv.dev/vulnerability/{osv_ids[0]}"
                                if osv_ids else "N/A",
                            }
                        )
        except requests.exceptions.HTTPError as e:
            logger.error(
                "HTTP error querying OSV (batch %d-%d): %s",
                i, i + len(batch), e
            )
            if hasattr(e, "response") and e.response is not None:
                logger.error("OSV Response: %s", e.response.text[:500])
        except requests.exceptions.Timeout:
            logger.error("Timeout querying OSV API (batch %d-%d)", i, i + len(batch))
        except requests.exceptions.RequestException as e:
            logger.error("Network error querying OSV (batch %d-%d): %s", i, i + len(batch), e)
        except json.JSONDecodeError as e_json:
            logger.error("Could not decode JSON from OSV in batch %d-%d: %s", i, i + len(batch), e_json)
        except Exception as e:
            logger.error("Unexpected error querying OSV in batch %d-%d: %s", i, i + len(batch), e, exc_info=True)

    logger.info(
        "OSV query complete. Found %d entries with vulnerabilities.",
        len(vulnerabilities_found),
    )
    return vulnerabilities_found



def find_git_repo(path):
    try:
        repo = Repo(path, search_parent_directories=True)
        logger.info("Found Git repository at: %s", repo.working_tree_dir)
        return repo
    except Exception as e:
        logger.error("Could not find Git repo from %s: %s", path, e)
        return None


def create_update_branch(repo, package_name, new_version):
    branch_name = f"depguardian/update-{package_name}-{new_version}"
    try:
        if repo.is_dirty(untracked_files=True):
            logger.error("Git repo dirty, cannot create PR branch.")
            return None, None
        default_branch_name = "main"
        try:
            if repo.active_branch.tracking_branch():
                default_branch_name = repo.active_branch.tracking_branch().remote_head
            elif "main" in repo.heads:
                default_branch_name = "main"
            elif "master" in repo.heads:
                default_branch_name = "master"
        except TypeError:
            logger.warning("No tracking branch/detached HEAD, defaulting to 'main'.")
        logger.info(
            "Attempting to create new branch '%s' from '%s'",
            branch_name,
            default_branch_name,
        )
        if branch_name in repo.heads:
            repo.heads[branch_name].checkout()
        else:
            base_commit_ref = default_branch_name
            try:
                if hasattr(repo.remotes, "origin"):
                    origin = repo.remotes.origin
                    logger.debug(
                        f"Fetching remote '{default_branch_name}' from 'origin'..."
                    )
                    origin.fetch(default_branch_name, progress=logger.debug)
                    if default_branch_name in origin.refs:
                        base_commit_ref = origin.refs[default_branch_name].commit
                        logger.info(
                            f"Base commit for new branch will be remote '{default_branch_name}'."
                        )
                    else:
                        logger.warning(
                            f"Remote branch 'origin/{default_branch_name}' not found. Using local or HEAD."
                        )
                        base_commit_ref = repo.heads.get(
                            default_branch_name, repo.head
                        ).commit
                else:
                    logger.warning("Remote 'origin' not found. Using local or HEAD.")
                    base_commit_ref = repo.heads.get(
                        default_branch_name, repo.head
                    ).commit
                repo.create_head(branch_name, base_commit_ref).checkout()
                logger.info(f"Created and checked out branch '{branch_name}'.")
            except Exception as fetch_err:
                logger.warning("Branch base error: %s. Using current HEAD.", fetch_err)
                repo.create_head(branch_name).checkout()
        return repo, branch_name
    except Exception as e:
        logger.error(
            "Branch creation error for '%s': %s", branch_name, e, exc_info=True
        )
        return None, None


def perform_npm_update(project_path, package_name, new_version):
    command = ["npm", "install", f"{package_name}@{new_version}"]
    logger.info(f"Running: {' '.join(command)} in {project_path}")
    try:
        result = subprocess.run(
            command,
            cwd=project_path,
            check=False,
            capture_output=True,
            text=True,
            timeout=NPM_INSTALL_TIMEOUT,
            encoding="utf-8",
        )
        logger.info("npm install stdout:\n%s", result.stdout)
        if result.stderr:
            if result.returncode != 0:
                logger.error("npm install stderr:\n%s", result.stderr)
            else:
                logger.warning(
                    "npm install stderr (command succeeded but stderr not empty):\n%s",
                    result.stderr,
                )
        return result.returncode == 0, result.stdout, result.stderr
    except FileNotFoundError:
        logger.error("Error: 'npm' command not found.")
        return False, "", "npm command not found."
    except subprocess.TimeoutExpired:
        logger.error("npm install timed out after %d seconds.", NPM_INSTALL_TIMEOUT)
        return False, "", "npm install timed out."
    except Exception as e:
        logger.error("Error running npm install: %s", e, exc_info=True)
        return False, "", str(e)


def commit_and_push_update(
    repo, branch_name, package_name, old_version, new_version, project_path
):
    try:
        repo_root = repo.working_tree_dir
        paths_rel = [
            os.path.relpath(os.path.join(project_path, f), repo_root)
            for f in ["package.json", "package-lock.json"]
        ]
        files_to_stage = [
            p for p in paths_rel if os.path.exists(os.path.join(repo_root, p))
        ]
        if not files_to_stage:
            logger.error("No package files found to commit.")
            return False
        logger.info("Staging: %s", files_to_stage)
        repo.index.add(files_to_stage)
        if not repo.index.diff("HEAD"):
            logger.warning("No actual changes staged.")
        commit_msg = f"Update {package_name} from {old_version} to {new_version}\n\nAutomated by DepGuardian."
        logger.info("Committing: %s", commit_msg)
        repo.index.commit(commit_msg)
        origin = repo.remotes.origin
        logger.info("Pushing branch '%s' to 'origin'...", branch_name)
        push_results = origin.push(f"{branch_name}:{branch_name}")
        for info in push_results:
            if info.flags & (info.ERROR | info.REJECTED):
                logger.error("Push error/rejection: %s", info.summary)
                return False
        logger.info("Branch '%s' pushed.", branch_name)
        return True
    except Exception as e:
        logger.error("Commit/push error: %s", e, exc_info=True)
        return False


def create_github_pr(
    github_token, github_repo_name, branch_name, package_name, old_version, new_version
):
    if not github_token:
        logger.error("GITHUB_TOKEN missing for PR.")
        return None
    if not github_repo_name:
        logger.error("--github-repo missing for PR.")
        return None
    try:
        g = Github(github_token)
        repo = g.get_repo(github_repo_name)
        default_branch = repo.default_branch
        pr_title = f"DepGuardian: Update {package_name} to {new_version}"
        pr_body = f"Automated dependency update by DepGuardian.\n\n**Package:** `{package_name}`\n**From:** `{old_version}`\n**To:** `{new_version}`\n\nPlease review and merge."
        logger.info(
            "Creating PR on '%s' from '%s' to '%s'...",
            github_repo_name,
            branch_name,
            default_branch,
        )
        head_branch_for_pr = f"{repo.owner.login}:{branch_name}"
        existing_prs = repo.get_pulls(
            state="open", head=head_branch_for_pr, base=default_branch
        )
        if existing_prs.totalCount > 0:
            pr = existing_prs[0]
            logger.warning(f"PR for '%s' already exists: {pr.html_url}")
            return pr.html_url
        pr = repo.create_pull(
            title=pr_title,
            body=pr_body,
            base=default_branch,
            head=branch_name,
            maintainer_can_modify=True,
        )
        logger.info("PR created: %s", pr.html_url)
        return pr.html_url
    except GithubException as e:
        error_msg = e.data.get("message", str(e))
        logger.error("GitHub API error PR: %s - %s", e.status, error_msg)
        return None
    except Exception as e:
        logger.error("Unexpected error creating PR: %s", e, exc_info=True)
        return None


def _format_report_for_console(report_data):
    output_lines = []
    try:
        scan_meta = report_data.get("scan_metadata", {})
        output_lines.append(
            f"\nScanning project at: {str(scan_meta.get('project_path', 'N/A'))}"
        )
        direct_deps = report_data.get("direct_dependencies", [])
        output_lines.append(
            f"Found {len(direct_deps)} direct dependencies in package.json."
        )

        project_info = report_data.get("project_info", {})
        installed_packages_info = report_data.get("installed_packages", {})
        lock_ver = project_info.get("lockfile_version")
        lockfile_ver_str = f"(v{lock_ver})" if lock_ver is not None else "(version N/A)"
        output_lines.append(
            f"Found {installed_packages_info.get('total_count', 0)} installed packages in package-lock.json {lockfile_ver_str}."
        )

        output_lines.append("-" * 20)
        output_lines.append("\nChecking Direct Dependencies against NPM Registry:")
        if direct_deps:
            for dep in direct_deps:
                try:
                    name = str(dep.get("name", "Unknown Package"))
                    req_range = str(dep.get("required_range", "N/A"))
                    inst_ver = str(dep.get("installed_version", "N/A"))
                    latest_npm = str(dep.get("latest_version_npm", "N/A"))
                    satisfies = dep.get("satisfies_range")
                    is_outdated = dep.get("is_outdated", False)
                    update_to = str(dep.get("update_available_to", "N/A"))

                    parts_str_list = [f"Installed={inst_ver}", f"Latest={latest_npm}"]
                    if satisfies is True:
                        parts_str_list.append("satisfies range (green)")
                    elif satisfies is False:
                        parts_str_list.append("DOES NOT satisfy range (red)")
                    else:
                        parts_str_list.append("range N/A (yellow)")

                    if is_outdated:
                        parts_str_list.append(f"Update: {update_to} (cyan)")
                    elif latest_npm != "N/A":
                        parts_str_list.append("Up-to-date (green)")

                    output_lines.append(
                        f"- {click.style(name, bold=True)} ({req_range})... {' | '.join(parts_str_list)}"
                    )
                except Exception as e_dep_print_loop:
                    logger.error(
                        f"Error formatting dep {dep.get('name', 'UNKNOWN')} for console: {e_dep_print_loop}",
                        exc_info=True,
                    )
                    output_lines.append(
                        f"- Error formatting details for dependency: {dep.get('name', 'UNKNOWN')}"
                    )
        else:
            output_lines.append(
                "No direct dependencies to check or package.json was not parsed successfully."
            )

        output_lines.append("-" * 20)
        output_lines.append("\nChecking for Known Vulnerabilities (OSV API):")
        vuln_report = report_data.get("vulnerabilities_report", {})
        vulnerabilities = vuln_report.get("vulnerabilities")
        if vulnerabilities is None:
            output_lines.append(
                str(
                    click.style("Vulnerability check failed (OSV API error).", fg="red")
                )
            )
        elif not vulnerabilities:
            output_lines.append(
                str(
                    click.style(
                        "No known vulnerabilities found in installed packages.",
                        fg="green",
                    )
                )
            )
        else:
            total_vuln_pkgs = vuln_report.get(
                "total_vulnerable_packages_found", len(vulnerabilities)
            )
            output_lines.append(
                str(
                    click.style(
                        f"Found {total_vuln_pkgs} vulnerable package versions:",
                        fg="red",
                        bold=True,
                    )
                )
            )
            for v_item in vulnerabilities:
                try:
                    pkg_name_vuln = str(v_item.get("package_name", "Unknown"))
                    inst_ver_vuln = str(
                        v_item.get("vulnerable_version_installed", "N/A")
                    )
                    osv_ids_str = ", ".join(map(str, v_item.get("osv_ids", [])))
                    details_url_vuln = str(v_item.get("details_url", "N/A"))
                    output_lines.append(
                        str(
                            click.style(
                                f"  - {pkg_name_vuln}@{inst_ver_vuln}: {osv_ids_str} (Details: {details_url_vuln})",
                                fg="red",
                            )
                        )
                    )
                except Exception as e_vuln_print_loop:
                    logger.error(
                        f"Error formatting vulnerability {v_item.get('package_name', 'UNKNOWN')} for console: {e_vuln_print_loop}",
                        exc_info=True,
                    )
                    output_lines.append(
                        f"- Error formatting details for vulnerability: {v_item.get('package_name', 'UNKNOWN')}"
                    )

        output_lines.append("-" * 20)
        output_lines.append("\nSummary:")
        summary = report_data.get("scan_summary", {})
        outdated_count = summary.get("outdated_direct_dependencies_count", 0)
        vuln_pkg_count = summary.get("vulnerable_installed_packages_count", 0)

        # Fixed summary wording to include 'are'
        output_lines.append(
            str(
                click.style(
                    f"{outdated_count} direct dependencies are outdated.",
                    fg="cyan" if outdated_count > 0 else "green",
                )
            )
        )
        if vulnerabilities is not None:
            output_lines.append(
                str(
                    click.style(
                        f"{vuln_pkg_count} installed package versions have known vulnerabilities.",
                        fg="red" if vuln_pkg_count > 0 else "green",
                    )
                )
            )

        errors_scan = report_data.get("errors_during_scan", [])
        if errors_scan:
            output_lines.append(
                str(
                    click.style(
                        f"\nErrors encountered during scan ({len(errors_scan)}):",
                        fg="yellow",
                        bold=True,
                    )
                )
            )
            for err in errors_scan:
                op = str(err.get("source_operation", "Unknown Op"))
                pkg_ctx = str(err.get("package_name_context", "N/A"))
                msg = str(err.get("error_message", "No details"))
                output_lines.append(
                    str(
                        click.style(
                            f"  - Op: {op}, Pkg: {pkg_ctx}, Msg: {msg}", fg="yellow"
                        )
                    )
                )

        update_attempts = report_data.get("update_attempt_details", [])
        if update_attempts:
            output_lines.append(
                str(
                    click.style(
                        "\nDependency Update Attempt Details:", fg="blue", bold=True
                    )
                )
            )
            for attempt in update_attempts:
                pkg_name_att = str(attempt.get("package_name", "N/A"))
                target_ver_att = str(attempt.get("target_version", "N/A"))
                output_lines.append(
                    f"  Package: {click.style(pkg_name_att, bold=True)} to version {target_ver_att}"
                )
                if attempt.get("success"):
                    output_lines.append(
                        str(click.style("    Status: SUCCESS", fg="green"))
                    )
                    if attempt.get("pr_url"):
                        output_lines.append(f"      PR: {str(attempt.get('pr_url'))}")
                else:
                    output_lines.append(
                        str(click.style("    Status: FAILED", fg="red"))
                    )
                    if attempt.get("error_message"):
                        output_lines.append(
                            f"      Reason: {str(attempt.get('error_message'))}"
                        )
                    npm_err_output = str(attempt.get("npm_stderr", "")).strip()
                    if npm_err_output:
                        output_lines.append(
                            str(
                                click.style(
                                    f"    NPM Error Output (stderr):\n{npm_err_output}",
                                    fg="red",
                                )
                            )
                        )
                    elif attempt.get("npm_stdout"):
                        npm_out_output = str(attempt.get("npm_stdout", "")).strip()
                        if npm_out_output:
                            output_lines.append(
                                f"    NPM Standard Output (stdout):\n{npm_out_output}"
                            )

        for line in output_lines:
            click.echo(line)

    except Exception as e_format:
        logger.error(f"Error during console formatting: {e_format}", exc_info=True)
        click.echo(
            click.style(
                f"INTERNAL FORMATTING ERROR: {e_format}. Check logs.", fg="magenta"
            ),
            err=True,
        )


# --- Core Scan Logic (Refactored) ---
def perform_scan_logic(project_path_to_scan):
    report = {
        "scan_metadata": {
            "project_path": project_path_to_scan,
            "scan_timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "depguardian_version": __version__,
            "status": "success",
        },
        "project_info": {
            "package_json_path": None,
            "package_lock_path": None,
            "lockfile_version": None,
        },
        "direct_dependencies": [],
        "installed_packages": {"total_count": 0, "packages": []},
        "vulnerabilities_report": {
            "source": "OSV.dev",
            "total_vulnerable_packages_found": 0,
            "vulnerabilities": [],
        },
        "scan_summary": {
            "outdated_direct_dependencies_count": 0,
            "vulnerable_installed_packages_count": 0,
            "total_vulnerabilities_found": 0,
        },
        "errors_during_scan": [],
    }
    logger.info(f"Core scan logic initiated for: {project_path_to_scan}")
    package_json_file = os.path.join(project_path_to_scan, "package.json")
    package_lock_file = os.path.join(project_path_to_scan, "package-lock.json")
    report["project_info"]["package_json_path"] = package_json_file
    report["project_info"]["package_lock_path"] = package_lock_file

    if not os.path.exists(package_json_file):
        msg = f"package.json not found at {package_json_file}"
        logger.error(msg)
        report["errors_during_scan"].append(
            {"source_operation": "file_check", "error_message": msg}
        )
        report["scan_metadata"]["status"] = "error"
        return report

    direct_deps_dict = parse_package_json(package_json_file)
    if direct_deps_dict is None:
        report["errors_during_scan"].append(
            {
                "source_operation": "parse_package_json",
                "error_message": f"Failed to parse {os.path.basename(package_json_file)}",
            }
        )
        report["scan_metadata"]["status"] = "partial_error"

    installed_pkgs_list, lock_version = parse_package_lock(package_lock_file)
    if installed_pkgs_list is None:
        report["errors_during_scan"].append(
            {
                "source_operation": "parse_package_lock",
                "error_message": f"Failed to parse {os.path.basename(package_lock_file)} or file not found.",
            }
        )
        if direct_deps_dict is None:
            report["scan_metadata"]["status"] = "error"
        else:
            report["scan_metadata"]["status"] = "partial_error"
    else:
        report["installed_packages"]["total_count"] = len(installed_pkgs_list)
        report["installed_packages"]["packages"] = installed_pkgs_list
        report["project_info"]["lockfile_version"] = lock_version

    if direct_deps_dict:
        for name, required_range in direct_deps_dict.items():
            dep_info = {
                "name": name,
                "required_range": required_range,
                "installed_version": None,
                "latest_version_npm": None,
                "satisfies_range": None,
                "is_outdated": False,
                "update_available_to": None,
            }
            if installed_pkgs_list:
                for pkg in installed_pkgs_list:
                    if pkg.get("name") == name:
                        dep_info["installed_version"] = pkg.get("version")
                        break
            if not dep_info["installed_version"]:
                logger.warning(f"Direct dep '{name}' not in lockfile.")
                report["errors_during_scan"].append(
                    {
                        "source_operation": "direct_dep_check",
                        "package_name_context": name,
                        "error_message": "Not in lockfile.",
                    }
                )
            dep_info["latest_version_npm"] = get_npm_package_info(name)
            if not dep_info["latest_version_npm"]:
                report["errors_during_scan"].append(
                    {
                        "source_operation": "npm_fetch",
                        "package_name_context": name,
                        "error_message": "Failed to fetch from NPM.",
                    }
                )
            if dep_info["installed_version"] and required_range:
                dep_info["satisfies_range"] = _run_semver_check(
                    dep_info["installed_version"], required_range
                )
                if dep_info["satisfies_range"] is None:
                    report["errors_during_scan"].append(
                        {
                            "source_operation": "semver_check",
                            "package_name_context": name,
                            "error_message": "semver_checker.js failed.",
                        }
                    )
            if dep_info["installed_version"] and dep_info["latest_version_npm"]:
                try:
                    if parse_version(dep_info["latest_version_npm"]) > parse_version(
                        dep_info["installed_version"]
                    ):
                        dep_info["is_outdated"] = True
                        dep_info["update_available_to"] = dep_info["latest_version_npm"]
                except (TypeError, ValueError) as e_ver:
                    logger.warning(f"Version compare error for {name}: {e_ver}")
                    report["errors_during_scan"].append(
                        {
                            "source_operation": "version_compare",
                            "package_name_context": name,
                            "error_message": str(e_ver),
                        }
                    )
            report["direct_dependencies"].append(dep_info)

    vulns_list = []
    if installed_pkgs_list:
        vulns_list = query_osv_api(installed_pkgs_list)
        if vulns_list is None:
            report["errors_during_scan"].append(
                {
                    "source_operation": "osv_query",
                    "error_message": "OSV API query failed.",
                }
            )
            report["vulnerabilities_report"]["vulnerabilities"] = None
        if report["scan_metadata"]["status"] != "error" and vulns_list is None:
            report["scan_metadata"]["status"] = "partial_error"
        if vulns_list is not None:
            report["vulnerabilities_report"]["vulnerabilities"] = vulns_list
            report["vulnerabilities_report"]["total_vulnerable_packages_found"] = len(
                vulns_list
            )
            report["scan_summary"]["total_vulnerabilities_found"] = sum(
                len(v.get("osv_ids", [])) for v in vulns_list
            )
    else:
        logger.info("No installed packages for OSV query.")
        report["vulnerabilities_report"]["vulnerabilities"] = []

    report["scan_summary"]["outdated_direct_dependencies_count"] = sum(
        1 for d in report["direct_dependencies"] if d.get("is_outdated")
    )
    report["scan_summary"]["vulnerable_installed_packages_count"] = report[
        "vulnerabilities_report"
    ]["total_vulnerable_packages_found"]
    return report


# --- LLM Helper Functions (Gemini) ---
def _call_gemini_api_sync(
    api_key: str,
    project_files_context: str,
    dep_guardian_scan_results_json: str,
    specific_conflict_npm_stderr: str = None,
    gemini_model_name: str = GEMINI_MODEL_NAME_DEFAULT,
):
    if not genai:
        logger.error("google-generativeai library not available for Gemini call.")
        return {"error": "google-generativeai library not installed."}
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(gemini_model_name)

        prompt_parts = [
            "You are DepGuardian AI, an expert DevOps assistant specializing in Node.js dependency management and security.",
            "Analyze the provided Node.js project context, DepGuardian scan results, and any specific NPM error messages to identify inter-dependency issues, version conflicts, and potential resolutions.",
            "\n## Project Files Context (package.json, package-lock.json snippets):\n",
            project_files_context,
            "\n## DepGuardian Initial Scan Results (JSON):\n",
            dep_guardian_scan_results_json,
        ]
        if specific_conflict_npm_stderr:
            prompt_parts.extend(
                [
                    "\n## Specific NPM Conflict Error (for focused analysis):\n```\n",
                    specific_conflict_npm_stderr,
                    "\n```\n",
                    "Focus your analysis on this specific conflict, considering the broader project context.",
                ]
            )

        prompt_parts.append(
            "\n## Analysis and Recommendations Request:\n"
            "1.  **Overall Project Dependency Health:** Briefly summarize the project's status regarding outdated dependencies and vulnerabilities based on the DepGuardian scan.\n"
            "2.  **Inter-dependency Conflict Analysis:**\n"
            "    a.  Based on the provided `package.json`, `package-lock.json`, and any `npm error output`, identify potential or actual inter-dependency conflicts. Explain the nature of these conflicts (e.g., incompatible versions of a shared transitive dependency, peer dependency mismatches).\n"
            "    b.  For each identified conflict, search your knowledge (simulating web search for known issues, compatibility matrices, GitHub discussions, release notes) for common causes and solutions.\n"
            "3.  **Resolution Strategies (Prioritized):\n"
            "    a.  Suggest 2-3 specific, actionable strategies to resolve the identified conflicts. Be precise with package names and potential version adjustments (e.g., 'Consider downgrading package X to version Y.Z', 'Try overriding transitive dependency A to version B.C').\n"
            "    b.  For each strategy, explain the reasoning and any potential trade-offs or risks.\n"
            "    c.  If applicable, mention if any of the project's own code might need changes due to these dependency adjustments.\n"
            "4.  **General Recommendations:** Provide any general advice for improving dependency management in this project.\n"
            "\nPresent your findings clearly. Use Markdown for formatting if it helps readability."
        )

        full_prompt = "\n".join(prompt_parts)
        logger.info(
            f"Sending prompt to Gemini model ({gemini_model_name}). Prompt length: {len(full_prompt)} chars."
        )
        logger.debug(f"Gemini Prompt (first 500 chars):\n{full_prompt[:500]}...")

        generation_config = genai.types.GenerationConfig(
            candidate_count=1,
            temperature=0.3,
        )
        safety_settings = [
            {"category": c, "threshold": "BLOCK_MEDIUM_AND_ABOVE"}
            for c in [
                "HARM_CATEGORY_HARASSMENT",
                "HARM_CATEGORY_HATE_SPEECH",
                "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                "HARM_CATEGORY_DANGEROUS_CONTENT",
            ]
        ]

        for attempt in range(GEMINI_MAX_RETRIES_DEFAULT + 1):
            try:
                response = model.generate_content(
                    full_prompt,
                    generation_config=generation_config,
                    safety_settings=safety_settings,
                    request_options={"timeout": GEMINI_API_REQUEST_TIMEOUT},
                )

                if response.candidates and response.candidates[0].content.parts:
                    analysis_text = "".join(
                        part.text
                        for part in response.candidates[0].content.parts
                        if hasattr(part, "text")
                    )
                    logger.info("Successfully received analysis from Gemini.")
                    return {
                        "analysis": analysis_text.strip(),
                        "prompt_sent_debug": full_prompt[:2000],
                    }

                logger.warning(
                    f"Gemini response missing expected content structure (attempt {attempt + 1})."
                )
                if response.prompt_feedback and response.prompt_feedback.block_reason:
                    block_reason_msg = f"Gemini prompt blocked. Reason: {response.prompt_feedback.block_reason}."
                    if response.prompt_feedback.safety_ratings:
                        block_reason_msg += f" Safety Ratings: {response.prompt_feedback.safety_ratings}"
                    logger.error(block_reason_msg)
                    return {
                        "error": block_reason_msg,
                        "prompt_sent_debug": full_prompt[:2000],
                    }

                if attempt == GEMINI_MAX_RETRIES_DEFAULT:
                    logger.error(
                        "Gemini returned an empty or malformed response after multiple retries."
                    )
                    return {
                        "error": "Gemini empty/malformed response after retries.",
                        "prompt_sent_debug": full_prompt[:2000],
                    }

            except Exception as e:
                logger.error(
                    f"Error calling Gemini API (attempt {attempt + 1}): {e}",
                    exc_info=True,
                )
                if "API_KEY_INVALID" in str(e) or "API key not valid" in str(e):
                    return {"error": "Invalid Gemini API Key provided."}
                if "DeadlineExceeded" in str(e) or "timeout" in str(e).lower():
                    logger.warning(
                        f"Gemini API call timed out (attempt {attempt + 1}). Retrying if possible..."
                    )
                    if attempt == GEMINI_MAX_RETRIES_DEFAULT:
                        return {
                            "error": f"Gemini API call timed out after {GEMINI_MAX_RETRIES_DEFAULT + 1} attempts."
                        }
                elif attempt == GEMINI_MAX_RETRIES_DEFAULT:
                    return {
                        "error": f"An unexpected error occurred during Gemini API call: {str(e)}"
                    }

            if attempt < GEMINI_MAX_RETRIES_DEFAULT:
                sleep_duration = 2**attempt
                logger.info(f"Retrying Gemini call in {sleep_duration} seconds...")
                time.sleep(sleep_duration)

        return {"error": "Gemini API call failed after all retry attempts."}

    except Exception as e:
        logger.error(
            f"General error in _call_gemini_api_sync setup: {e}", exc_info=True
        )
        return {"error": f"Unexpected error in Gemini API call wrapper: {str(e)}"}


# --- CLI Command Group ---
@click.group(context_settings=dict(help_option_names=["-h", "--help"]))
@click.version_option(version=__version__, prog_name="depg")
def cli():
    """
    DepGuardian: Audit & auto-update Node.js dependencies.
    Generates reports and can optionally create GitHub Pull Requests.
    Includes agentic features for AI-powered analysis.
    """
    pass


@cli.command()
@click.option(
    "--path",
    "project_path_option",
    default=".",
    help="Path to Node.js project.",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, resolve_path=True),
)
@click.option(
    "--json-report",
    "json_report_path",
    type=click.Path(dir_okay=False, writable=True, resolve_path=True),
    help="Path to save scan results as JSON.",
    default=None,
)
@click.option(
    "--create-pr",
    is_flag=True,
    help="Auto-create GitHub PR for first outdated dependency.",
)
@click.option(
    "--github-repo",
    envvar="GITHUB_REPOSITORY",
    help="GitHub repo (owner/repo) for PR. Uses GITHUB_REPOSITORY env var.",
)
@click.option(
    "--github-token",
    envvar="GITHUB_TOKEN",
    help="GitHub PAT for PR. Uses GITHUB_TOKEN env var.",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose debug logging.")
def check(
    project_path_option, json_report_path, create_pr, github_repo, github_token, verbose
):
    """Checks dependencies for updates and vulnerabilities."""
    if verbose:
        logging.getLogger("depg").setLevel(logging.DEBUG)
        logger.debug("Verbose for 'check'.")
    else:
        if os.environ.get("LOGLEVEL", "INFO").upper() == "INFO":
            logging.getLogger("depg").setLevel(logging.INFO)
    current_project_path = project_path_option
    report_data = perform_scan_logic(current_project_path)
    report_data.setdefault("update_attempt_details", [])

    if create_pr and report_data.get("scan_metadata", {}).get("status") != "error":
        outdated_for_pr = []
        for dep_check in report_data.get("direct_dependencies", []):
            if dep_check.get("is_outdated"):
                if (
                    dep_check.get("name")
                    and dep_check.get("installed_version")
                    and dep_check.get("latest_version_npm")
                ):
                    outdated_for_pr.append(
                        {
                            "name": dep_check.get("name"),
                            "installed": dep_check.get("installed_version"),
                            "latest": dep_check.get("latest_version_npm"),
                        }
                    )
                else:
                    logger.warning(
                        f"Skipping PR creation for outdated dependency due to missing info: {dep_check.get('name')}"
                    )

        if not outdated_for_pr:
            click.echo("\nNo outdated direct dependencies for PR.")
        else:
            repo = find_git_repo(current_project_path)
            if not repo:
                click.echo(click.style("\nNo Git repo for PR.", fg="red"), err=True)
                report_data["errors_during_scan"].append(
                    {
                        "source_operation": "pr_git_check",
                        "error_message": "Git repo not found.",
                    }
                )
            else:
                dep = outdated_for_pr[0]
                name, inst, new = dep["name"], dep["installed"], dep["latest"]
                click.echo(
                    f"\nAttempting PR for {click.style(name, bold=True)} ({inst} → {new})..."
                )
                attempt_info = {
                    "package_name": name,
                    "current_version": inst,
                    "target_version": new,
                    "success": False,
                    "npm_stdout": None,
                    "npm_stderr": None,
                    "pr_url": None,
                    "error_message": None,
                }
                repo_pr, branch_pr = create_update_branch(repo, name, new)
                if not (repo_pr and branch_pr):
                    attempt_info["error_message"] = "Branch creation failed."
                else:
                    npm_ok, npm_out, npm_err = perform_npm_update(
                        current_project_path, name, new
                    )
                    attempt_info["npm_stdout"] = npm_out
                    attempt_info["npm_stderr"] = npm_err
                    if not npm_ok:
                        attempt_info[
                            "error_message"
                        ] = f"npm update for '{name}' failed."
                    elif not commit_and_push_update(
                        repo_pr, branch_pr, name, inst, new, current_project_path
                    ):
                        attempt_info["error_message"] = "Commit/push failed."
                    else:
                        pr_url = create_github_pr(
                            github_token, github_repo, branch_pr, name, inst, new
                        )
                        if not pr_url:
                            attempt_info["error_message"] = "PR creation failed."
                        else:
                            attempt_info["success"] = True
                            attempt_info["pr_url"] = pr_url
                            click.echo(
                                click.style(
                                    f"PR for {name} created: {pr_url}", fg="green"
                                )
                            )
                if attempt_info["error_message"]:
                    click.echo(
                        click.style(attempt_info["error_message"], fg="red"), err=True
                    )
                report_data["update_attempt_details"].append(attempt_info)

    if not json_report_path:
        _format_report_for_console(report_data)
    else:
        try:
            report_dir = os.path.dirname(json_report_path)
            if report_dir and not os.path.exists(report_dir):
                os.makedirs(report_dir, exist_ok=True)
            with open(json_report_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2)
            click.echo(
                click.style(f"\nJSON report saved: {json_report_path}", fg="green")
            )
            summary = report_data.get("scan_summary", {})
            click.echo(
                f"  Outdated: {summary.get('outdated_direct_dependencies_count',0)}, Vulnerable Pkgs: {summary.get('vulnerable_installed_packages_count',0)}"
            )
            if report_data.get("errors_during_scan"):
                click.echo(
                    click.style(
                        f"  Errors: {len(report_data['errors_during_scan'])} (JSON)",
                        fg="yellow",
                    )
                )
            if report_data.get("update_attempt_details"):
                for attempt in report_data["update_attempt_details"]:
                    if not attempt["success"]:
                        click.echo(
                            click.style(
                                f"  Update for {attempt['package_name']} FAILED (JSON).",
                                fg="red",
                            )
                        )
                        break
        except Exception as e:
            logger.error(f"Failed to save JSON: {json_report_path}: {e}", exc_info=True)
            click.echo(
                click.style(f"Error saving JSON: {json_report_path}", fg="red"),
                err=True,
            )
            _format_report_for_console(report_data)

    click.echo("\nDepGuardian check complete.")
    if (
        report_data.get("scan_metadata", {}).get("status") != "success"
        or report_data.get("scan_summary", {}).get(
            "outdated_direct_dependencies_count", 0
        )
        > 0
        or report_data.get("scan_summary", {}).get(
            "vulnerable_installed_packages_count", 0
        )
        > 0
        or any(
            not attempt.get("success", True)
            for attempt in report_data.get("update_attempt_details", [])
        )
    ):
        sys.exit(1)
    else:
        sys.exit(0)


@cli.group()
def agent():
    """Agentic features for advanced dependency analysis using LLMs."""
    pass


@agent.command("analyze-project")
@click.option(
    "--project-path",
    "project_folder_path",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, resolve_path=True),
    required=True,
    help="Path to the project folder (e.g., extracted from ZIP).",
)
@click.option(
    "--gemini-api-key",
    "gemini_key",
    type=str,
    required=True,
    envvar="GEMINI_API_KEY",
    help="Gemini API Key. Can also be set via GEMINI_API_KEY env var.",
)
@click.option(
    "--output-json",
    "output_json_path",
    type=click.Path(dir_okay=False, writable=True, resolve_path=True),
    required=True,
    help="Path to save the comprehensive AI analysis JSON report.",
)
@click.option(
    "--gemini-model",
    "cli_gemini_model",
    default=None,
    help=f"Gemini model to use. Default: {GEMINI_MODEL_NAME_DEFAULT}",
)
@click.option(
    "--verbose", "-v", is_flag=True, help="Enable verbose debug logging for the agent."
)
def agent_analyze_project(
    project_folder_path, gemini_key, output_json_path, cli_gemini_model, verbose
):
    """
    Performs DepGuardian scan, then uses Gemini AI for in-depth analysis.
    """
    if verbose:
        logging.getLogger("depg").setLevel(logging.DEBUG)
        logger.debug("Verbose for 'agent analyze-project'.")
    else:
        if os.environ.get("LOGLEVEL", "INFO").upper() == "INFO":
            logging.getLogger("depg").setLevel(logging.INFO)

    if not genai:
        click.echo(
            click.style(
                "Error: 'google-generativeai' required. 'pip install google-generativeai'",
                fg="red",
            ),
            err=True,
        )
        sys.exit(1)

    current_gemini_model = (
        cli_gemini_model if cli_gemini_model else GEMINI_MODEL_NAME_DEFAULT
    )
    click.echo(
        f"Starting AI analysis for: {project_folder_path} using Gemini: {current_gemini_model}"
    )

    click.echo("Step 1: Performing initial DepGuardian scan...")
    depg_scan_report = perform_scan_logic(project_folder_path)
    if depg_scan_report.get("scan_metadata", {}).get("status") == "error":
        click.echo(
            click.style("Initial DepGuardian scan failed. Cannot proceed.", fg="red"),
            err=True,
        )
        try:
            with open(output_json_path, "w", encoding="utf-8") as f:
                json.dump(depg_scan_report, f, indent=2)
            click.echo(
                f"Partial scan report (due to errors) saved to: {output_json_path}"
            )
        except Exception as e:
            logger.error(f"Could not save partial scan report: {e}")
        sys.exit(1)
    click.echo("Initial DepGuardian scan complete.")
    dep_guardian_scan_results_json_str = json.dumps(depg_scan_report, indent=2)

    click.echo("Step 2: Preparing project file context for Gemini...")
    project_files_context_parts = []
    files_to_include = {"package.json": 3000, "package-lock.json": 5000}
    for filename, limit in files_to_include.items():
        filepath = os.path.join(project_folder_path, filename)
        if os.path.exists(filepath):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                project_files_context_parts.append(
                    f"--- {filename} ---\n{content[:limit]}\n--------------------"
                )
                if len(content) > limit:
                    project_files_context_parts.append(
                        f"(Content of {filename} truncated for brevity)"
                    )
            except Exception as e:
                logger.warning(f"Could not read {filename}: {e}")
                project_files_context_parts.append(
                    f"--- {filename} ---\nError reading file.\n--------------------"
                )
        else:
            project_files_context_parts.append(
                f"--- {filename} ---\nNot found.\n--------------------"
            )
    project_files_context_str = "\n\n".join(project_files_context_parts)

    npm_stderr_for_gemini = None
    if "update_attempt_details" in depg_scan_report:
        for attempt in depg_scan_report["update_attempt_details"]:
            if not attempt.get("success") and attempt.get("npm_stderr"):
                npm_stderr_for_gemini = attempt["npm_stderr"]
                logger.info(
                    f"Found npm_stderr for failed update of {attempt.get('package_name')} from initial scan to include in Gemini prompt."
                )
                break

    click.echo("Step 3: Sending data to Gemini AI. This may take some time...")
    gemini_result = _call_gemini_api_sync(
        api_key=gemini_key,
        project_files_context=project_files_context_str,
        dep_guardian_scan_results_json=dep_guardian_scan_results_json_str,
        specific_conflict_npm_stderr=npm_stderr_for_gemini,
        gemini_model_name=current_gemini_model,
    )

    click.echo("Step 4: Finalizing AI-augmented report...")
    final_agent_report = {
        "agent_scan_metadata": {
            "project_path": project_folder_path,
            "analysis_timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "depguardian_version": __version__,
            "llm_provider": "Gemini",
            "llm_model_used": current_gemini_model,
        },
        "depguardian_initial_scan": depg_scan_report,
        "gemini_analysis": gemini_result,
    }
    try:
        report_dir = os.path.dirname(output_json_path)
        if report_dir and not os.path.exists(report_dir):
            os.makedirs(report_dir, exist_ok=True)
        with open(output_json_path, "w", encoding="utf-8") as f:
            json.dump(final_agent_report, f, indent=2)
        click.echo(
            click.style(
                f"Comprehensive AI analysis report saved to: {output_json_path}",
                fg="green",
            )
        )
    except Exception as e:
        logger.error(f"Failed to save final agent report: {e}", exc_info=True)
        click.echo(click.style(f"Error saving AI report: {e}", fg="red"), err=True)
        sys.exit(1)

    if "error" in gemini_result:
        click.echo(
            click.style(
                f"Gemini AI analysis encountered an error: {gemini_result['error']}. See JSON report.",
                fg="red",
            ),
            err=True,
        )
        sys.exit(1)
    click.echo("Agentic analysis complete.")


@cli.command()
@click.option(
    "--host",
    default="127.0.0.1",
    help="The interface to bind the GUI server to.",
    show_default=True,
)
@click.option(
    "--port",
    default=5001,
    type=int,
    help="The port for the GUI server.",
    show_default=True,
)
@click.option(
    "--debug-mode/--no-debug-mode",
    "debug_mode",
    default=True,
    help="Run Flask GUI in debug mode. Default is True (debug on).",
)
def gui(host, port, debug_mode):
    """Starts the DepGuardian local web GUI to view reports."""
    try:
        from .gui.app import run_server as run_gui_server

        click.echo(f"Attempting to launch DepGuardian GUI on http://{host}:{port}")
        if debug_mode:
            logger.warning(
                "Flask GUI debug mode is ON. Do not use this for production."
            )
        run_gui_server(host=host, port=port, debug=debug_mode)
    except ImportError:
        click.echo(
            click.style("Error importing GUI module (dep_guardian.gui.app).", fg="red"),
            err=True,
        )
        logger.error("Failed to import dep_guardian.gui.app.run_server", exc_info=True)
        sys.exit(1)
    except Exception as e:
        click.echo(click.style(f"Error launching GUI: {e}", fg="red"), err=True)
        logger.error(f"Unexpected error starting GUI: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    cli()
