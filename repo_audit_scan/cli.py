"""CLI interface for repo-audit-scan."""
import argparse
import sys
from repo_audit_scan import __version__
from repo_audit_scan.logging_setup import setup_logging


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Security-focused code audit scanner"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a repository")
    scan_parser.add_argument("path", help="Repository path to scan")
    scan_parser.add_argument("--config", help="Config file path")
    
    # rules command
    rules_parser = subparsers.add_parser("rules", help="List available rules")
    
    # triage command
    triage_parser = subparsers.add_parser("triage", help="Generate triage report")
    triage_parser.add_argument("report", help="Report ID or path")
    triage_parser.add_argument("--limit", type=int, default=10, help="Max findings")
    
    # verify command
    verify_parser = subparsers.add_parser("verify", help="Verify a fix")
    verify_parser.add_argument("report", help="Report ID or path")
    verify_parser.add_argument("finding", help="Finding ID")
    
    args = parser.parse_args()
    
    setup_logging(verbose=args.verbose)
    
    if not args.command:
        parser.print_help()
        return 0
    
    print(f"Command: {args.command}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
