#!/usr/bin/env python3
"""
NetScan Setup Script
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="netscan",
    version="1.0.0",
    author="NetScan Team",
    author_email="team@netscan.io",
    description="High-performance network scanner inspired by Nmap",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/netscan",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: System :: Networking",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "netscan=netscan.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "netscan": [
            "data/*.txt",
            "data/*.json",
            "scripts/*.py",
        ],
    },
) 