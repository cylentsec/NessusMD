"""
Setup configuration for NessusMD
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
readme_path = Path(__file__).parent / 'README.md'
long_description = readme_path.read_text() if readme_path.exists() else ''

setup(
    name='nessusmd',
    version='1.0.0',
    author='Steve',
    description='Parse Nessus .nessus files and generate Markdown reports',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/yourusername/NessusMD',
    packages=find_packages(),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
    python_requires='>=3.7',
    install_requires=[
        # No external dependencies - uses only built-in modules
    ],
    entry_points={
        'console_scripts': [
            'nessusmd=nessusmd.cli:main',
        ],
    },
)
