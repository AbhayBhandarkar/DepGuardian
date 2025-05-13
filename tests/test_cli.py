# tests/test_cli.py
# Purpose: Contains tests for the CLI functionality.

import pytest
from click.testing import CliRunner
from dep_guardian.cli import cli  # Import your main cli function/group


# Example fixture to provide a CliRunner instance
@pytest.fixture
def runner():
    return CliRunner()


# Example fixture to set up a test project directory
@pytest.fixture(scope="module")  # Run once per module
def sample_project_path(tmp_path_factory):
    # Create a temporary directory structure similar to test-project
    project_dir = tmp_path_factory.mktemp("sample_project")
    # Create package.json
    package_json_content = """
{
    "name": "sample-test-project",
    "version": "1.0.0",
    "dependencies": {
      "express": "^4.17.1"
    },
    "devDependencies": {
      "jest": "^27.0.0"
    }
}
"""
    with open(project_dir / "package.json", "w") as f:
        f.write(package_json_content)

    # Create package-lock.json
    # Shortened integrity hash for 'express' to pass line length checks in test data
    package_lock_content = """
{
    "name": "sample-test-project",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "requires": true,
    "packages": {
        "": {
            "name": "sample-test-project",
            "version": "1.0.0",
            "dependencies": { "express": "^4.17.1" },
            "devDependencies": { "jest": "^27.0.0" }
        },
        "node_modules/express": {
            "version": "4.17.1",
            "resolved": "https://registry.npmjs.org/express/-/express-4.17.1.tgz",
            "integrity": "sha512-mHJ9O79RqlFRUNkenLJhoJnv/hVhSOME_SHORTENED_HASH"
        },
        "node_modules/jest": {
            "version": "27.0.6",
            "resolved": "https://registry.npmjs.org/jest/-/jest-27.0.6.tgz",
            "integrity": "sha512-SHORTENED_JEST_HASH",
            "dev": true
        }
    }
}
"""
    with open(project_dir / "package-lock.json", "w") as f:
        f.write(package_lock_content)

    return str(project_dir)


# --- Test Cases ---


def test_cli_help(runner):
    """Test the --help flag."""
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Usage: cli [OPTIONS] COMMAND [ARGS]..." in result.output
    assert "DepGuardian: Audit & auto-update Node.js dependencies." in result.output


def test_check_command_help(runner):
    """Test the check command's --help flag."""
    result = runner.invoke(cli, ["check", "--help"])
    assert result.exit_code == 0
    assert "Usage: cli check [OPTIONS]" in result.output
    assert "Checks dependencies for updates and vulnerabilities." in result.output


@pytest.mark.usefixtures("sample_project_path")  # Use the fixture
def test_check_basic_output(runner, mocker, sample_project_path):
    """Test basic execution of the 'check' command."""
    # Mock requests.get for npm info
    mock_npm_response = {
        "dist-tags": {"latest": "4.18.2"}
    }  # Mock latest express version
    mocker.patch(
        "requests.get",
        return_value=mocker.Mock(
            status_code=200,
            json=lambda: mock_npm_response,
            raise_for_status=lambda: None,
        ),
    )

    # Mock requests.post for OSV
    mock_osv_response = {
        "results": [  # Assuming only express and jest were queried
            {"vulns": []},  # No vulns for express@4.17.1
            {"vulns": [{"id": "OSV-XXX-123"}]},  # Mock vuln for jest@27.0.6
        ]
    }
    mocker.patch(
        "requests.post",
        return_value=mocker.Mock(
            status_code=200,
            json=lambda: mock_osv_response,
            raise_for_status=lambda: None,
        ),
    )

    # Mock subprocess.run for semver_checker.js
    mock_process = mocker.Mock(
        stdout="true",  # Assume both satisfy initially
        stderr="",
        returncode=0,
    )
    mocker.patch("subprocess.run", return_value=mock_process)

    result = runner.invoke(cli, ["check", "--path", sample_project_path])

    assert result.exit_code == 1  # Should exit 1 due to vulnerabilities / outdated
    assert "Scanning project at" in result.output
    assert "Checking express (^4.17.1)" in result.output
    assert "Installed=4.17.1" in result.output
    assert "Latest=4.18.2" in result.output  # From mock
    assert "Update available: 4.18.2" in result.output
    assert "Checking jest (^27.0.0)" in result.output
    assert "Checking for Known Vulnerabilities" in result.output
    assert "Found 1 vulnerable package versions:" in result.output
    assert "jest@27.0.6: OSV-XXX-123" in result.output  # From mock
    assert "1 direct dependencies are outdated." in result.output  # express
    assert "1 installed package versions have known vulnerabilities." in result.output


# TODO: Add more tests for:
# - Different lock file versions (e.g., v1)
# - --create-pr functionality (this will require more complex mocking for
#   git.Repo, github.Github, and subprocess calls for npm and git commands)
# - Edge cases (e.g., missing package.json, missing package-lock.json,
#   network errors during API calls, invalid NPM package names)
# - Scenarios with no outdated dependencies and no vulnerabilities (exit code 0)
# - Scenarios where installed version does NOT satisfy package.json range.
# - Scenarios where semver_checker.js fails or returns unexpected output.
