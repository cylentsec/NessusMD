# NessusMD Quick Usage Guide

## Getting Started

### 1. Install (if not already installed)

```bash
# Recommended: Install with pipx
pipx install /path/to/NessusMD

# Alternative: Install with pip
pip install -e /path/to/NessusMD
```

### 2. Check Installation

```bash
# If installed with pipx or pip
nessusmd --version

# If running as module
python3 -m nessusmd --version
```

### 3. View Help

```bash
# If installed
nessusmd --help

# If running as module
python3 -m nessusmd --help
```

## Common Use Cases

### Parse a Single Nessus File

```bash
# If installed
nessusmd scan_results.nessus

# If running as module
python3 -m nessusmd scan_results.nessus
```

This creates `report.md` in the current directory.

### Specify Output File

```bash
nessusmd scan_results.nessus -o vulnerability_report.md
```

### Parse Multiple Files

```bash
nessusmd scan1.nessus scan2.nessus scan3.nessus -o combined.md
```

### Parse All .nessus Files in Directory

```bash
nessusmd *.nessus -o all_findings.md
```

### Filter by Severity

Show only Critical and High findings:

```bash
nessusmd scan.nessus --severity critical,high -o critical_high.md
```

Show only Medium findings:

```bash
nessusmd scan.nessus --severity medium -o medium_findings.md
```

## Workflow Integration

### Use in Penetration Testing

```bash
# After running Nessus scan, export .nessus file
# Process the scan results
nessusmd client_scan.nessus -o client_vulnerabilities.md

# Filter critical/high for executive summary
nessusmd client_scan.nessus --severity critical,high -o executive_summary.md
```

### Batch Processing

```bash
# Process all scans in a directory
for file in /path/to/scans/*.nessus; do
    basename="${file%.nessus}"
    nessusmd "$file" -o "${basename}_report.md"
done
```

## Output Format

The generated report includes:

- Summary statistics (total hosts, findings by severity)
- Table of contents with quick navigation
- Findings organized by severity:
  - Critical
  - High
  - Medium
  - Low
  - Info

Each finding includes:
- CVE identifiers
- CVSS v2.0 Base Score
- Synopsis and Description
- Solution
- See Also references
- Exploitability information
- Affected hosts (with hostname preferred over IP)
- Protocol and port information

## Tips

1. Hostnames vs IP Addresses
   - The tool prefers displaying hostnames when available
   - Falls back to IP addresses if no hostname is found

2. Affected Hosts
   - Listed in markdown code blocks for easy copy/paste
   - Format: `hostname (protocol/port)` or just `hostname` if no port

3. Combining Multiple Scans
   - Duplicate findings across multiple scans are automatically grouped
   - All affected hosts are listed under a single finding

4. Filtering
   - Use `--severity` to focus on specific risk levels
   - Useful for creating executive summaries
   - Comma-separated values: `critical,high,medium,low,info`

## Testing

Run the unit tests:

```bash
python3 -m unittest tests.test_parser -v
```

## Troubleshooting

### Command not found: nessusmd

If you haven't installed it, either:

```bash
# Install with pipx
pipx install /path/to/NessusMD

# Or run as module
python3 -m nessusmd scan.nessus
```

### File not found error

Ensure the .nessus file path is correct:

```bash
# Use absolute path
nessusmd /path/to/scan.nessus

# Or relative path from current directory
nessusmd ./scans/scan.nessus
```

### No findings in report

- Check that the .nessus file contains actual vulnerability findings
- Some info-level findings are automatically filtered out
- Use `--severity info` to see all findings including informational ones

## Getting .nessus Files

.nessus files are exported from Nessus/Tenable:

1. Log into Nessus web interface
2. Navigate to Scans
3. Select the completed scan
4. Click Export
5. Choose "Nessus" format
6. Download the .nessus file

## Example: Complete Workflow

```bash
# 1. Download scan from Nessus (results in scan_20240101.nessus)

# 2. Generate full report
nessusmd scan_20240101.nessus -o full_report.md

# 3. Generate executive summary (Critical/High only)
nessusmd scan_20240101.nessus --severity critical,high -o executive_summary.md

# 4. View the reports
less full_report.md
# or open in your favorite markdown viewer/editor
```
