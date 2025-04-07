from setuptools import setup, find_packages

setup(
    name='dep-guardian',
    version='0.1.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'click',
        'requests',
    ],
    entry_points={
        'console_scripts': [
            'depg = dep_guardian.cli:cli', # 'depg' is the command you'll use
        ],
    },
)