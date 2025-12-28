"""
Allow running as: python -m attestation
"""

from .cli import main

if __name__ == "__main__":
    exit(main())
