# NessusMD

A Python3 tool that parses Nessus .nessus report files and generates formatted Markdown reports. Organizes findings by severity and provides easy-to-copy host lists.

## Features

- Parse single or multiple .nessus files
- Organize findings by severity (Critical, High, Medium, Low, Info)
- Group duplicate findings across multiple hosts
- Include all key vulnerability details:
  - CVE identifiers
  - CVSS v2.0 Base Score
  - Risk level
  - Synopsis, Description, Solution
  - See Also references
  - Exploitability information (Metasploit, Core Impact)
- List affected hosts with protocol/port information in code blocks for easy copying
- Generate table of contents with quick links
- Filter by severity levels
- No external dependencies (uses only Python standard library)

## Installation

### Option 1: Install with pipx (recommended)

```bash
pipx install /path/to/NessusMD
```

Then run as a global command:

```bash
nessusmd scan_results.nessus -o report.md
```

### Option 2: Install with pip

```bash
cd NessusMD
pip install -e .
```

Then run as a command:

```bash
nessusmd scan_results.nessus -o report.md
```

### Option 3: Run as module (no installation)

```bash
cd NessusMD
python -m nessusmd scan_results.nessus -o report.md
```

## Usage

### Basic Usage

```bash
# Parse a single file
python -m nessusmd scan.nessus

# Specify custom output file
python -m nessusmd scan.nessus -o my_report.md

# Parse multiple files into one report
python -m nessusmd scan1.nessus scan2.nessus -o combined.md
```

### Advanced Usage

```bash
# Filter by severity (show only Critical and High)
python -m nessusmd scan.nessus --severity critical,high

# Parse all .nessus files in current directory
python -m nessusmd *.nessus -o all_findings.md
```

### Command-Line Options

```
usage: nessusmd [-h] [-o OUTPUT] [--severity SEVERITY] [--version]
                input_files [input_files ...]

Parse Nessus .nessus files and generate Markdown reports

positional arguments:
  input_files           One or more .nessus files to parse

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output Markdown file (default: report.md)
  --severity SEVERITY   Filter by severity levels (comma-separated:
                        critical,high,medium,low,info)
  --version             show program's version number and exit
```

## Output Format

The generated Markdown report includes:

1. Summary Statistics
   - Total hosts scanned
   - Total findings
   - Breakdown by severity

2. Table of Contents
   - Quick links to each severity section

3. Findings by Severity
   - Organized from Critical to Info
   - Each finding includes:
     - Vulnerability name
     - CVE (if applicable)
     - CVSS v2.0 Base Score
     - Risk level
     - Synopsis
     - Description
     - Solution
     - See Also references
     - Exploitability information
     - Affected hosts (hostname preferred over IP) with protocol/port in code blocks

## Example Output

```markdown
# Nessus Vulnerability Report

## Summary Statistics

- Total Hosts Scanned: 5
- Total Findings: 23
- Critical: 2
- High: 8
- Medium: 10
- Low: 3
- Info: 0

## Table of Contents

- [Critical (2)](#critical-severity-findings)
- [High (8)](#high-severity-findings)
- [Medium (10)](#medium-severity-findings)
- [Low (3)](#low-severity-findings)

## Critical Severity Findings

---

### Apache Tomcat AJP File Read/Inclusion Vulnerability

CVE: CVE-2020-1938

CVSS v2.0 Base Score: 7.5

Risk: Critical

Synopsis:
The remote Apache Tomcat server is affected by a file read/inclusion vulnerability.

Affected Hosts:

```
webserver1.example.com (tcp/8009)
webserver2.example.com (tcp/8009)
```
```

## Requirements

- Python 3.7 or higher
- No external dependencies

## Project Structure

```
NessusMD/
├── nessusmd/
│   ├── __init__.py       # Package initialization
│   ├── __main__.py       # Module entry point
│   ├── parser.py         # XML parsing logic
│   ├── formatter.py      # Markdown formatting
│   └── cli.py            # Command-line interface
├── tests/
│   └── test_parser.py    # Unit tests
├── examples/
│   └── sample_report.md  # Example output
├── requirements.txt      # Python dependencies (none)
├── setup.py              # Package setup
├── LICENSE               # License file
└── README.md             # This file
```

## Development

### Running Tests

```bash
python -m pytest tests/
```

### Code Structure

- `parser.py`: Handles XML parsing of .nessus files
- `formatter.py`: Generates Markdown output
- `cli.py`: Provides command-line interface

## License

See LICENSE file for details.

## Contributing

Contributions are welcome. Please ensure code follows existing style and includes appropriate tests.
