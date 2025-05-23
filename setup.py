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

PACKAGE_VERSION = get_version()

# Read the long description from README
here = os.path.abspath(os.path.dirname(__file__))
try:
    with open(os.path.join(here, "README.md"), encoding="utf-8") as f:
        long_desc = f.read()
except FileNotFoundError:
    long_desc = "CLI tool to audit & auto-update Node.js dependencies, with AI insights."

setup(
    name="dep-guardian",
    version=PACKAGE_VERSION,
    description="CLI tool to audit & auto-update Node.js dependencies, with AI insights.",
    long_description=long_desc,
    long_description_content_type="text/markdown",
    author="Abhay Bhandarkar",
    url="https://github.com/AbhayBhandarkar/DepGuardian",
    license="MIT",
    packages=find_packages(
        exclude=[
            "tests*",
            "test-project*",
            "dep_guardian_gui*",
        ]
    ),
    include_package_data=True,
    package_data={
        "dep_guardian": [
            "semver_checker.js",
            "package-lock.json",
            "package.json",
        ],
        "dep_guardian.gui": ["templates/*.html"],
    },
    python_requires=">=3.9",
    install_requires=[
        "click>=8.0,<9.0",
        "requests>=2.25,<3.0",
        "packaging>=21.0,<24.0",
        "GitPython>=3.1,<4.0",
        "PyGithub>=1.55,<2.0",
        "Flask>=2.0.0",
        "werkzeug>=2.0.0",
        "httpx>=0.23.0,<0.28.0",
        "google-generativeai>=0.4.0",
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
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Environment :: Console",
        "Environment :: Web Environment",
        "Operating System :: OS Independent",
        "Framework :: Flask",
    ],
    keywords="npm dependency audit security vulnerability update automation github osv gui flask llm gemini agentic",
    project_urls={
        "Bug Reports": "https://github.com/AbhayBhandarkar/DepGuardian/issues",
        "Source": "https://github.com/AbhayBhandarkar/DepGuardian",
    },
)
