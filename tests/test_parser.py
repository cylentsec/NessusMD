"""
Unit tests for NessusMD parser module
"""

import unittest
from nessusmd.parser import NessusParser, Host, Finding


class TestHost(unittest.TestCase):
    """Tests for Host class"""
    
    def test_host_with_hostname(self):
        """Test host with hostname prefers hostname in string representation"""
        host = Host(ip="192.168.1.1", hostname="server.example.com")
        self.assertEqual(str(host), "server.example.com")
    
    def test_host_without_hostname(self):
        """Test host without hostname uses IP in string representation"""
        host = Host(ip="192.168.1.1")
        self.assertEqual(str(host), "192.168.1.1")
    
    def test_host_equality(self):
        """Test host equality is based on IP"""
        host1 = Host(ip="192.168.1.1", hostname="server1.example.com")
        host2 = Host(ip="192.168.1.1", hostname="server2.example.com")
        self.assertEqual(host1, host2)
    
    def test_host_hash(self):
        """Test host hashing is based on IP"""
        host1 = Host(ip="192.168.1.1", hostname="server1.example.com")
        host2 = Host(ip="192.168.1.1", hostname="server2.example.com")
        self.assertEqual(hash(host1), hash(host2))


class TestFinding(unittest.TestCase):
    """Tests for Finding class"""
    
    def test_finding_add_host(self):
        """Test adding hosts to finding"""
        finding = Finding(
            plugin_id="12345",
            name="Test Vulnerability",
            severity=3,
            risk="High"
        )
        
        host = Host(ip="192.168.1.1", hostname="server.example.com")
        finding.add_host(host, "tcp", "80")
        
        self.assertEqual(len(finding.hosts), 1)
        self.assertIn((host, "tcp", "80"), finding.hosts)


class TestNessusParser(unittest.TestCase):
    """Tests for NessusParser class"""
    
    def test_severity_mapping(self):
        """Test severity mapping"""
        parser = NessusParser()
        self.assertEqual(parser.SEVERITY_MAP[0], "Info")
        self.assertEqual(parser.SEVERITY_MAP[1], "Low")
        self.assertEqual(parser.SEVERITY_MAP[2], "Medium")
        self.assertEqual(parser.SEVERITY_MAP[3], "High")
        self.assertEqual(parser.SEVERITY_MAP[4], "Critical")
    
    def test_severity_order(self):
        """Test severity order"""
        parser = NessusParser()
        expected_order = ["Critical", "High", "Medium", "Low", "Info"]
        self.assertEqual(parser.SEVERITY_ORDER, expected_order)
    
    def test_get_statistics_empty(self):
        """Test statistics with empty parser"""
        parser = NessusParser()
        stats = parser.get_statistics()
        
        self.assertEqual(stats['Total Hosts'], 0)
        self.assertEqual(stats['Total Findings'], 0)
        self.assertEqual(stats['Critical'], 0)
        self.assertEqual(stats['High'], 0)
        self.assertEqual(stats['Medium'], 0)
        self.assertEqual(stats['Low'], 0)
        self.assertEqual(stats['Info'], 0)


if __name__ == '__main__':
    unittest.main()
