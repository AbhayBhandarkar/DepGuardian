# setup.py
# Purpose: Defines how to build and install the Python package.

from setuptools import setup, find_packages
import os

# Read the long description from the README file
here = os.path.abspath(os.path.dirname(__file__))
try:
    with open(os.path.join(here, "README.md"), encoding="utf-8") as f:
        long_desc = f.read()
except FileNotFoundError:
    long_desc = "CLI tool to audit & auto-update Node.js dependencies via GitHub PRs"


# Define the current version (Consider reading from a __version__ variable)
# Ensure this matches the tag you push for releases (e.g., v0.1.1)
PACKAGE_VERSION = "0.1.1"

setup(
    name="dep-guardian",
    version=PACKAGE_VERSION,
    description="CLI tool to audit & auto-update Node.js dependencies via GitHub PRs",
    long_description=long_desc,
    long_description_content_type="text/markdown",
    author="Abhay Bhandarkar",
    # author_email="your_email@example.com", # Optional
    url="https://github.com/AbhayBhandarkar/DepGuardian",  # Project home page
    license="MIT",
    packages=find_packages(
        exclude=["tests*", "test-project*"]
    ),  # Find packages automatically, exclude tests
    include_package_data=True,  # Use MANIFEST.in
    python_requires=">=3.7",  # Minimum Python version required
    install_requires=[  # Runtime dependencies
        "click>=8.0,<9.0",
        "requests>=2.25,<3.0",
        "packaging>=21.0,<24.0",  # Using <24 until compatibility is verified
        "GitPython>=3.1,<4.0",
        "PyGithub>=1.55,<2.0",  # Check PyGithub releases for current recommendation
    ],
    entry_points={  # Creates the 'depg' command
        "console_scripts": [
            "depg = dep_guardian.cli:cli",
        ],
    },
    classifiers=[  # PyPI classifiers
        "Development Status :: 4 - Beta",  # Or 3 - Alpha, 5 - Production/Stable
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Build Tools",
        "Topic :: System :: Software Distribution",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        # "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Environment :: Console",
        "Operating System :: OS Independent",
    ],
    keywords="npm dependency audit security vulnerability update automation github osv",
    project_urls={  # Optional links displayed on PyPI
        "Bug Reports": "https://github.com/AbhayBhandarkar/DepGuardian/issues",
        "Source": "https://github.com/AbhayBhandarkar/DepGuardian",
    },
)
