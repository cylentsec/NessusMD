"""
Nessus XML Parser Module

Parses .nessus files and extracts vulnerability data.
"""

import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field


@dataclass
class Host:
    """Represents a scanned host"""
    ip: str
    hostname: Optional[str] = None
    
    def __str__(self) -> str:
        """Return hostname if available, otherwise IP"""
        return self.hostname if self.hostname else self.ip
    
    def __hash__(self):
        return hash(self.ip)
    
    def __eq__(self, other):
        if isinstance(other, Host):
            return self.ip == other.ip
        return False


@dataclass
class Finding:
    """Represents a vulnerability finding"""
    plugin_id: str
    name: str
    severity: int
    risk: str
    cvss_base_score: Optional[str] = None
    cves: List[str] = field(default_factory=list)
    synopsis: str = ""
    description: str = ""
    solution: str = ""
    see_also: List[str] = field(default_factory=list)
    exploitable_with: List[str] = field(default_factory=list)
    hosts: Set[tuple] = field(default_factory=set)  # Set of (Host, protocol, port) tuples
    
    def add_host(self, host: Host, protocol: str, port: str):
        """Add a host with its protocol and port"""
        self.hosts.add((host, protocol, port))


class NessusParser:
    """Parser for .nessus XML files"""
    
    SEVERITY_MAP = {
        0: "Info",
        1: "Low",
        2: "Medium",
        3: "High",
        4: "Critical"
    }
    
    SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
    
    def __init__(self):
        self.findings: Dict[str, Finding] = {}  # Key: plugin_id
        self.hosts: Dict[str, Host] = {}  # Key: ip
    
    def parse_file(self, filepath: str) -> None:
        """Parse a .nessus file and extract findings"""
        tree = ET.parse(filepath)
        root = tree.getroot()
        
        # Parse each ReportHost
        for report_host in root.findall('.//ReportHost'):
            host = self._parse_host(report_host)
            self.hosts[host.ip] = host
            
            # Parse each ReportItem (vulnerability)
            for report_item in report_host.findall('ReportItem'):
                self._parse_report_item(report_item, host)
    
    def _parse_host(self, report_host_elem) -> Host:
        """Extract host information"""
        ip = report_host_elem.get('name')
        hostname = None
        
        # Try to get hostname from various sources
        host_properties = report_host_elem.find('HostProperties')
        if host_properties:
            # Try host-fqdn first
            for tag in host_properties.findall('tag'):
                if tag.get('name') == 'host-fqdn':
                    hostname = tag.text
                    break
            
            # Fallback to netbios-name
            if not hostname:
                for tag in host_properties.findall('tag'):
                    if tag.get('name') == 'netbios-name':
                        hostname = tag.text
                        break
        
        return Host(ip=ip, hostname=hostname)
    
    def _parse_report_item(self, item, host: Host) -> None:
        """Extract vulnerability data from ReportItem"""
        plugin_id = item.get('pluginID')
        severity = int(item.get('severity', 0))
        
        # Skip info findings with severity 0 unless they have meaningful content
        if severity == 0:
            plugin_name = item.get('pluginName', '')
            # Skip common info-only plugins
            skip_plugins = [
                'Target Credentialed Checks',
                'Nessus Scan Information',
                'Traceroute Information'
            ]
            if any(skip in plugin_name for skip in skip_plugins):
                return
        
        protocol = item.get('protocol', '')
        port = item.get('port', '')
        
        # Get or create finding
        if plugin_id not in self.findings:
            finding = Finding(
                plugin_id=plugin_id,
                name=item.get('pluginName', ''),
                severity=severity,
                risk=self.SEVERITY_MAP.get(severity, 'Unknown')
            )
            
            # Extract all vulnerability details
            finding.cvss_base_score = self._get_element_text(item, 'cvss_base_score')
            finding.synopsis = self._get_element_text(item, 'synopsis')
            finding.description = self._get_element_text(item, 'description')
            finding.solution = self._get_element_text(item, 'solution')
            
            # Extract CVEs
            for cve_elem in item.findall('cve'):
                if cve_elem.text:
                    finding.cves.append(cve_elem.text)
            
            # Extract See Also references
            see_also_text = self._get_element_text(item, 'see_also')
            if see_also_text:
                finding.see_also = [url.strip() for url in see_also_text.split('\n') if url.strip()]
            
            # Extract exploitability info
            exploitable_text = self._get_element_text(item, 'exploitability_ease')
            if exploitable_text:
                finding.exploitable_with.append(f"Exploitability: {exploitable_text}")
            
            # Check for Metasploit modules
            metasploit = self._get_element_text(item, 'metasploit_name')
            if metasploit:
                finding.exploitable_with.append(f"Metasploit: {metasploit}")
            
            # Check for Core Impact exploits
            core_impact = self._get_element_text(item, 'core_impact')
            if core_impact:
                finding.exploitable_with.append(f"Core Impact: {core_impact}")
            
            self.findings[plugin_id] = finding
        
        # Add host to this finding
        self.findings[plugin_id].add_host(host, protocol, port)
    
    def _get_element_text(self, parent, tag_name: str) -> Optional[str]:
        """Safely extract text from an XML element"""
        elem = parent.find(tag_name)
        return elem.text if elem is not None and elem.text else None
    
    def get_findings_by_severity(self) -> Dict[str, List[Finding]]:
        """Group findings by severity level"""
        grouped = {severity: [] for severity in self.SEVERITY_ORDER}
        
        for finding in self.findings.values():
            grouped[finding.risk].append(finding)
        
        # Sort findings within each severity by name
        for severity in grouped:
            grouped[severity].sort(key=lambda x: x.name)
        
        return grouped
    
    def get_statistics(self) -> Dict[str, int]:
        """Get summary statistics"""
        stats = {severity: 0 for severity in self.SEVERITY_ORDER}
        stats['Total Hosts'] = len(self.hosts)
        stats['Total Findings'] = len(self.findings)
        
        for finding in self.findings.values():
            stats[finding.risk] += 1
        
        return stats
