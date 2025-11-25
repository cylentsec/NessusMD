"""
Command-Line Interface Module

Provides CLI for parsing Nessus files and generating Markdown reports.
"""

import argparse
import sys
from pathlib import Path
from typing import List

from .parser import NessusParser
from .formatter import MarkdownFormatter


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description="Parse Nessus .nessus files and generate Markdown reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan_results.nessus
  %(prog)s scan_results.nessus -o report.md
  %(prog)s *.nessus -o combined_report.md
  %(prog)s scan.nessus --severity critical,high
        """
    )
    
    parser.add_argument(
        'input_files',
        nargs='+',
        type=str,
        help='One or more .nessus files to parse'
    )
    
    parser.add_argument(
        '-o', '--output',
        type=str,
        default='report.md',
        help='Output Markdown file (default: report.md)'
    )
    
    parser.add_argument(
        '--severity',
        type=str,
        help='Filter by severity levels (comma-separated: critical,high,medium,low,info)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )
    
    return parser.parse_args()


def validate_input_files(files: List[str]) -> List[Path]:
    """Validate that input files exist and are readable"""
    validated = []
    
    for file in files:
        path = Path(file)
        if not path.exists():
            print(f"Error: File not found: {file}", file=sys.stderr)
            sys.exit(1)
        if not path.is_file():
            print(f"Error: Not a file: {file}", file=sys.stderr)
            sys.exit(1)
        if not path.suffix == '.nessus':
            print(f"Warning: File does not have .nessus extension: {file}", file=sys.stderr)
        
        validated.append(path)
    
    return validated


def filter_by_severity(parser: NessusParser, severity_filter: str) -> None:
    """Filter findings by specified severity levels"""
    if not severity_filter:
        return
    
    allowed_severities = [s.strip().capitalize() for s in severity_filter.split(',')]
    valid_severities = set(NessusParser.SEVERITY_ORDER)
    
    # Validate severity levels
    for severity in allowed_severities:
        if severity not in valid_severities:
            print(f"Error: Invalid severity level: {severity}", file=sys.stderr)
            print(f"Valid levels: {', '.join(valid_severities)}", file=sys.stderr)
            sys.exit(1)
    
    # Remove findings that don't match filter
    to_remove = []
    for plugin_id, finding in parser.findings.items():
        if finding.risk not in allowed_severities:
            to_remove.append(plugin_id)
    
    for plugin_id in to_remove:
        del parser.findings[plugin_id]


def main():
    """Main entry point"""
    args = parse_arguments()
    
    # Validate input files
    input_files = validate_input_files(args.input_files)
    
    print(f"Parsing {len(input_files)} file(s)...")
    
    # Initialize parser
    parser = NessusParser()
    
    # Parse all input files
    for file in input_files:
        try:
            print(f"  - {file.name}")
            parser.parse_file(str(file))
        except Exception as e:
            print(f"Error parsing {file}: {e}", file=sys.stderr)
            sys.exit(1)
    
    # Apply severity filter if specified
    if args.severity:
        print(f"Filtering by severity: {args.severity}")
        filter_by_severity(parser, args.severity)
    
    # Generate statistics
    stats = parser.get_statistics()
    print(f"\nParsed {stats['Total Hosts']} hosts with {stats['Total Findings']} findings:")
    print(f"  - Critical: {stats['Critical']}")
    print(f"  - High: {stats['High']}")
    print(f"  - Medium: {stats['Medium']}")
    print(f"  - Low: {stats['Low']}")
    print(f"  - Info: {stats['Info']}")
    
    # Generate Markdown report
    print(f"\nGenerating Markdown report...")
    formatter = MarkdownFormatter(parser)
    report = formatter.generate_report()
    
    # Write output
    output_path = Path(args.output)
    try:
        output_path.write_text(report)
        print(f"Report written to: {output_path}")
    except Exception as e:
        print(f"Error writing output file: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
