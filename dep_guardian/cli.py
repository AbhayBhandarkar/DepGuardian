import os
import json
import click
import requests
import subprocess
from packaging.version import parse as parse_version
import git
from github import Github

# --- Helper functions ---
def parse_package_json(file_path):
    """Parse package.json for direct dependencies."""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        deps = data.get('dependencies', {})
        dev = data.get('devDependencies', {})
        return {**dev, **deps}
    except Exception as e:
        click.echo(click.style(f"Error reading package.json: {e}", fg='red'))
        return None

def parse_package_lock_v2_v3(file_path):
    """Parse package-lock.json v2/v3 for installed packages."""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        ver = data.get('lockfileVersion', 0)
        if ver < 2:
            click.echo(click.style(f"Warning: lockfileVersion={ver}, v2+ expected.", fg='yellow'))
        result = {}
        for path, info in data.get('packages', {}).items():
            if not path: continue
            parts = path.split('node_modules/')
            if len(parts) > 1 and 'version' in info:
                result[parts[-1]] = {
                    'version': info['version'],
                    'dev': info.get('dev', False)
                }
        return result
    except Exception as e:
        click.echo(click.style(f"Error reading package-lock.json: {e}", fg='red'))
        return None

def get_npm_package_info(name):
    """Fetch latest from npm registry."""
    url = f"https://registry.npmjs.org/{name.replace('/', '%2F')}"
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = r.json()
        return data.get('dist-tags', {}).get('latest')
    except requests.HTTPError as he:
        if he.response.status_code == 404:
            click.echo(click.style(f"  Warning: '{name}' not found on npm.", fg='yellow'))
        else:
            click.echo(click.style(f"  Error {he.response.status_code} fetching '{name}'", fg='red'))
    except Exception as e:
        click.echo(click.style(f"  Error fetching '{name}': {e}", fg='red'))
    return None

def check_npm_range_satisfaction(installed, req):
    """Use semver_checker.js via Node."""
    script = os.path.join(os.path.dirname(__file__), 'semver_checker.js')
    if not os.path.exists(script):
        click.echo(click.style("Error: semver_checker.js missing.", fg='red'))
        return None
    cmd = ['node', script, installed, req]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        out = res.stdout.strip()
        return out == 'true'
    except Exception:
        return None

def query_osv_api(packages):
    """Batch-query OSV for vulnerabilities."""
    url = "https://api.osv.dev/v1/querybatch"
    queries, keys = [], []
    for name, info in packages.items():
        v = info.get('version')
        if not v: continue
        queries.append({"package": {"ecosystem": "npm", "name": name}, "version": v})
        keys.append(f"{name}@{v}")
    if not queries:
        return {}
    try:
        r = requests.post(url, json={"queries": queries}, timeout=30)
        r.raise_for_status()
        results = r.json().get('results', [])
        vulns = {}
        for i, res in enumerate(results):
            vs = res.get('vulns', [])
            if vs:
                vulns[keys[i]] = [v.get('id') for v in vs if v.get('id')]
        return vulns
    except Exception as e:
        click.echo(click.style(f"Error querying OSV: {e}", fg='red'))
        return None

def create_update_branch(repo_path, pkg, new_ver):
    """Create and checkout update branch."""
    try:
        repo = git.Repo(repo_path, search_parent_directories=True)
        root = repo.working_tree_dir
        click.echo(f"Git repo root: {root}")
        if repo.is_dirty(untracked_files=True):
            click.echo(click.style("Error: repo has uncommitted changes.", fg='red'))
            return None, None
        branch = f"depguardian/update-{pkg}-{new_ver}"
        if branch in repo.heads:
            repo.heads[branch].checkout()
        else:
            repo.create_head(branch, repo.head.commit).checkout()
        return repo, branch
    except Exception as e:
        click.echo(click.style(f"Git error: {e}", fg='red'))
        return None, None

# --- CLI ---
@click.group()
def cli():
    """DepGuardian: audit & auto-update NPM deps."""
    pass

@cli.command()
@click.option('--path', default='.', help='Project directory')
@click.option('--create-pr', is_flag=True, help='Auto-update & open PR')
@click.option('--github-repo', default=None, help='owner/repo for PR')
@click.option('--github-token', default=None, help='GitHub token or GITHUB_TOKEN env')
def check(path, create_pr, github_repo, github_token):
    """Check deps and optionally create a GitHub PR."""
    path = os.path.abspath(path)
    if create_pr:
        token = github_token or os.getenv("GITHUB_TOKEN")
        if not token or not github_repo:
            click.echo(click.style("Error: --create-pr needs --github-repo and a token.", fg='red'))
            return
        click.echo("PR mode enabled.")

    click.echo(f"\nScanning project at: {path}\n")
    pj = parse_package_json(os.path.join(path, 'package.json'))
    if pj is None: return
    click.echo(f"Direct deps: {len(pj)}")
    pl = parse_package_lock_v2_v3(os.path.join(path, 'package-lock.json'))
    if pl is None: return
    click.echo(f"Installed pkgs: {len(pl)}\n")

    outdated = []
    for name, req in pj.items():
        click.echo(f"Checking {name} ({req})...", nl=False)
        latest = get_npm_package_info(name)
        inst = pl.get(name, {}).get('version')
        if not latest or not inst:
            click.echo("")
            continue
        sat = check_npm_range_satisfaction(inst, req)
        ok = [] 
        if sat is True: ok.append("satisfies range")
        if parse_version(latest) > parse_version(inst):
            ok.append(f"update available: {latest}")
            outdated.append({'name': name, 'installed': inst, 'latest': latest})
        status = ", ".join(ok) or "OK"
        click.echo(click.style(f" Installed={inst}, Latest={latest} → {status}", fg='green' if "OK" in status else 'yellow'))

    click.echo(f"\nOutdated direct deps: {len(outdated)}")

    vulns = query_osv_api(pl)
    if vulns is None:
        click.echo(click.style("Vulnerability check failed.", fg='red'))
    elif not vulns:
        click.echo(click.style("No known vulnerabilities.", fg='green'))
    else:
        click.echo(click.style(f"\nFound {len(vulns)} vulnerable package versions:", fg='red'))
        for pkg, ids in vulns.items():
            click.echo(click.style(f"  - {pkg}: {', '.join(ids)}", fg='red'))

    if create_pr and outdated:
        dep = outdated[0]
        name, latest, inst = dep['name'], dep['latest'], dep['installed']
        click.echo(f"\nAuto-updating {name} {inst} → {latest}")
        repo, branch = create_update_branch(path, name, latest)
        if not repo:
            return

        # npm install
        click.echo(f"Running npm install {name}@{latest}…")
        try:
            subprocess.run(
                ["npm", "install", f"{name}@{latest}"],
                cwd=path, check=True, capture_output=True, text=True, timeout=60
            )
        except Exception as e:
            click.echo(click.style(f"npm install failed: {e}", fg='red'))
            return

        # commit
        repo.index.add([
            os.path.join(path, "package.json"),
            os.path.join(path, "package-lock.json")
        ])
        repo.index.commit(f"Update {name} from {inst} to {latest}")

        # push
        try:
            repo.remote("origin").push(f"{branch}:{branch}")
        except Exception as e:
            click.echo(click.style(f"Push failed: {e}", fg='red'))
            return

        # PR
        gh = Github(token)
        gh_repo = gh.get_repo(github_repo)
        pr = gh_repo.create_pull(
            title=f"Update {name} → {latest}",
            body=f"Automated update of **{name}** from {inst} → {latest}.",
            base=gh_repo.default_branch,
            head=branch
        )
        click.echo(click.style(f"PR created: {pr.html_url}", fg='green'))

    click.echo("\nDone.\n")

if __name__ == "__main__":
    cli()
