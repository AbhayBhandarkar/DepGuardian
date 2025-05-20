# setup.py
# Purpose: Defines how to build and install the Python package.

from setuptools import setup, find_packages
import os
import re


# Function to read the version from __version__.py
def get_version():
    version_file = os.path.join(
        os.path.abspath(os.path.dirname(__file__)), "dep_guardian", "__version__.py"
    )
    with open(version_file, "r", encoding="utf-8") as f:
        version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", f.read(), re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


PACKAGE_VERSION = (
    get_version()
)  # Make sure your __version__.py is updated, e.g., "0.3.0"

# Read the long description from the README file
here = os.path.abspath(os.path.dirname(__file__))
try:
    with open(os.path.join(here, "README.md"), encoding="utf-8") as f:
        long_desc = f.read()
except FileNotFoundError:
    long_desc = (
        "CLI tool to audit & auto-update Node.js dependencies, with AI insights."
    )


setup(
    name="dep-guardian",
    version=PACKAGE_VERSION,
    description="CLI tool to audit & auto-update Node.js dependencies, with AI insights.",
    long_description=long_desc,
    long_description_content_type="text/markdown",
    author="Abhay Bhandarkar",  # Replace with your name if different
    url="https://github.com/AbhayBhandarkar/DepGuardian",  # Replace with your repo URL
    license="MIT",
    packages=find_packages(
        exclude=[
            "tests*",
            "test-project*",
            "dep_guardian_gui*",
        ]  # Exclude old top-level gui dir if it exists
    ),
    include_package_data=True,  # This tells setuptools to respect MANIFEST.in for sdist
    # and also helps with package_data for wheels.
    package_data={
        # Ensure semver_checker.js and GUI templates are included in wheels
        "dep_guardian": ["semver_checker.js"],
        "dep_guardian.gui": ["templates/*.html"],
    },
    python_requires=">=3.9",  # Gemini library often prefers Python 3.9+
    install_requires=[
        "click>=8.0,<9.0",
        "requests>=2.25,<3.0",
        "packaging>=21.0,<24.0",
        "GitPython>=3.1,<4.0",
        "PyGithub>=1.55,<2.0",
        "Flask>=2.0.0",  # For the GUI
        "werkzeug>=2.0.0",  # Often needed with Flask for secure_filename etc.
        "httpx>=0.23.0,<0.28.0",  # For Ollama or other HTTP if kept, and Gemini client uses it too
        "google-generativeai>=0.4.0",  # Added Gemini SDK
    ],
    entry_points={
        "console_scripts": [
            "depg = dep_guardian.cli:cli",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Build Tools",
        "Topic :: System :: Software Distribution",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        # Add "Programming Language :: Python :: 3.12" when tested and supported
        "Environment :: Console",
        "Environment :: Web Environment",  # Added for Flask GUI
        "Operating System :: OS Independent",
        "Framework :: Flask",  # Added for Flask GUI
    ],
    keywords="npm dependency audit security vulnerability update automation github osv gui flask llm gemini agentic",
    project_urls={  # Optional: Update these if your project has them
        "Bug Reports": "https://github.com/AbhayBhandarkar/DepGuardian/issues",  # Replace
        "Source": "https://github.com/AbhayBhandarkar/DepGuardian",  # Replace
    },
)
