#!/usr/bin/env python3
"""
Setup script for AgentZero109
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="agentzero109",
    version="1.0.0",
    author="AgentZero109 Team",
    description="Elite AI-Powered Bug Bounty Hunting Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/scthakurii/AgentZero109",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "agentzero=cli.agentzero:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["templates/*.yaml", "config/*.yaml"],
    },
)
