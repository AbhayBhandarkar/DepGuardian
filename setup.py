# setup.py

from setuptools import setup, find_packages
import os

# Read the long description from the README file
here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, "README.md"), encoding="utf-8") as f:
    long_desc = f.read()

setup(
    name="dep-guardian",
    version="0.1.1",
    description="CLI tool to audit & auto-update Node.js dependencies via GitHub PRs",
    long_description=long_desc,
    long_description_content_type="text/markdown",
    url="https://github.com/AbhayBhandarkar/DepGuardian",
    author="Abhay Bhandarkar",
    license="MIT",
    packages=find_packages(),
    include_package_data=True,             # include files specified in MANIFEST.in
    package_data={                         # explicitly bundle our JS helper
        "dep_guardian": ["semver_checker.js"],
    },
    python_requires=">=3.7",
    install_requires=[
        "click",
        "requests",
        "packaging",
        "GitPython",
        "PyGithub",
    ],
    entry_points={
        "console_scripts": [
            "depg = dep_guardian.cli:cli",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Software Development :: Build Tools",
    ],
)
