"""Entry point for running as a module: python -m repo_audit_scan"""
import sys
from repo_audit_scan.cli import main

if __name__ == "__main__":
    sys.exit(main())
