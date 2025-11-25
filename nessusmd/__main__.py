"""
Entry point for running nessusmd as a module.

Usage: python -m nessusmd <args>
"""

from .cli import main

if __name__ == '__main__':
    main()
