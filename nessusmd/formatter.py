"""
Markdown Formatter Module

Generates formatted Markdown reports from parsed Nessus data.
"""

from typing import Dict, List
from .parser import Finding, NessusParser


class MarkdownFormatter:
    """Formats Nessus findings as Markdown"""
    
    def __init__(self, parser: NessusParser):
        self.parser = parser
    
    def generate_report(self) -> str:
        """Generate complete Markdown report"""
        sections = []
        
        # Title and statistics
        sections.append(self._generate_header())
        sections.append("")
        
        # Table of contents
        sections.append(self._generate_toc())
        sections.append("")
        
        # Findings by severity
        findings_by_severity = self.parser.get_findings_by_severity()
        
        for severity in self.parser.SEVERITY_ORDER:
            findings = findings_by_severity[severity]
            if findings:
                sections.append(self._generate_severity_section(severity, findings))
                sections.append("")
        
        return "\n".join(sections)
    
    def _generate_header(self) -> str:
        """Generate report header with statistics"""
        stats = self.parser.get_statistics()
        
        lines = [
            "# Nessus Vulnerability Report",
            "",
            "## Summary Statistics",
            "",
            f"- Total Hosts Scanned: {stats['Total Hosts']}",
            f"- Total Findings: {stats['Total Findings']}",
            f"- Critical: {stats['Critical']}",
            f"- High: {stats['High']}",
            f"- Medium: {stats['Medium']}",
            f"- Low: {stats['Low']}",
            f"- Info: {stats['Info']}"
        ]
        
        return "\n".join(lines)
    
    def _generate_toc(self) -> str:
        """Generate table of contents"""
        findings_by_severity = self.parser.get_findings_by_severity()
        
        lines = ["## Table of Contents", ""]
        
        for severity in self.parser.SEVERITY_ORDER:
            count = len(findings_by_severity[severity])
            if count > 0:
                anchor = severity.lower()
                lines.append(f"- [{severity} ({count})](##{anchor}-severity-findings)")
        
        return "\n".join(lines)
    
    def _generate_severity_section(self, severity: str, findings: List[Finding]) -> str:
        """Generate section for a specific severity level"""
        lines = [
            f"## {severity} Severity Findings",
            "",
            f"Total {severity} findings: {len(findings)}",
            ""
        ]
        
        for finding in findings:
            lines.append(self._format_finding(finding))
            lines.append("")
        
        return "\n".join(lines)
    
    def _format_finding(self, finding: Finding) -> str:
        """Format a single finding"""
        lines = [
            "---",
            "",
            f"### {finding.name}",
            ""
        ]
        
        # CVE
        if finding.cves:
            cve_list = ", ".join(finding.cves)
            lines.append(f"CVE: {cve_list}")
            lines.append("")
        
        # CVSS Score
        if finding.cvss_base_score:
            lines.append(f"CVSS v2.0 Base Score: {finding.cvss_base_score}")
            lines.append("")
        
        # Risk
        lines.append(f"Risk: {finding.risk}")
        lines.append("")
        
        # Synopsis
        if finding.synopsis:
            lines.append("Synopsis:")
            lines.append("")
            lines.append(finding.synopsis)
            lines.append("")
        
        # Description
        if finding.description:
            lines.append("Description:")
            lines.append("")
            lines.append(finding.description)
            lines.append("")
        
        # Solution
        if finding.solution:
            lines.append("Solution:")
            lines.append("")
            lines.append(finding.solution)
            lines.append("")
        
        # See Also
        if finding.see_also:
            lines.append("See Also:")
            lines.append("")
            for url in finding.see_also:
                lines.append(f"- {url}")
            lines.append("")
        
        # Exploitable With
        if finding.exploitable_with:
            lines.append("Exploitable With:")
            lines.append("")
            for exploit in finding.exploitable_with:
                lines.append(f"- {exploit}")
            lines.append("")
        
        # Affected Hosts
        lines.append("Affected Hosts:")
        lines.append("")
        lines.append(self._format_hosts(finding))
        
        return "\n".join(lines)
    
    def _format_hosts(self, finding: Finding) -> str:
        """Format affected hosts in a code block"""
        host_lines = []
        
        # Sort hosts for consistent output
        sorted_hosts = sorted(finding.hosts, key=lambda x: (str(x[0]), x[1], x[2]))
        
        for host, protocol, port in sorted_hosts:
            if protocol and port:
                host_lines.append(f"{host} ({protocol}/{port})")
            else:
                host_lines.append(str(host))
        
        # Return as code block for easy copying
        return "```\n" + "\n".join(host_lines) + "\n```"
