# Nessus Vulnerability Report

## Summary Statistics

- Total Hosts Scanned: 3
- Total Findings: 5
- Critical: 1
- High: 2
- Medium: 1
- Low: 1
- Info: 0

## Table of Contents

- [Critical (1)](#critical-severity-findings)
- [High (2)](#high-severity-findings)
- [Medium (1)](#medium-severity-findings)
- [Low (1)](#low-severity-findings)

## Critical Severity Findings

Total Critical findings: 1

---

### Apache Tomcat AJP File Read/Inclusion Vulnerability

CVE: CVE-2020-1938

CVSS v2.0 Base Score: 7.5

Risk: Critical

Synopsis:

The remote Apache Tomcat server is affected by a file read/inclusion vulnerability.

Description:

The version of Apache Tomcat installed on the remote host is affected by a file read/inclusion vulnerability. The AJP protocol implementation does not properly handle invalid AJP messages, which allows an attacker to read or include files from anywhere on the system.

Solution:

Upgrade to Apache Tomcat version 9.0.31, 8.5.51, or 7.0.100 or later. Alternatively, block access to the AJP port at the network level.

See Also:

- https://www.cve.org/CVERecord?id=CVE-2020-1938
- https://tomcat.apache.org/security-9.html

Exploitable With:

- Metasploit: exploit/multi/http/tomcat_ghostcat

Affected Hosts:

```
webserver1.example.com (tcp/8009)
webserver2.example.com (tcp/8009)
```

## High Severity Findings

Total High findings: 2

---

### SSL/TLS Protocol Weak Cipher Suites

CVE: CVE-2016-2183, CVE-2016-6329

CVSS v2.0 Base Score: 5.0

Risk: High

Synopsis:

The remote service supports weak SSL/TLS cipher suites.

Description:

The remote host supports one or more SSL/TLS cipher suites that are considered weak. These weak cipher suites can be exploited by an attacker with sufficient resources to compromise the confidentiality of communications.

Solution:

Reconfigure the affected application to avoid use of weak ciphers. For Microsoft IIS web servers, see Microsoft Knowledgebase article 245030 for instructions on disabling weak ciphers.

Affected Hosts:

```
webserver1.example.com (tcp/443)
api.example.com (tcp/8443)
```

---

### OpenSSH Weak MAC Algorithms Enabled

CVSS v2.0 Base Score: 2.6

Risk: High

Synopsis:

The remote SSH server is configured to allow weak MAC algorithms.

Description:

The remote SSH server is configured to allow MD5 and 96-bit MAC algorithms, both of which are considered weak. This may allow an attacker to recover plaintext from a block of ciphertext.

Solution:

Remove the following MAC algorithms from the SSH server configuration:
- hmac-md5
- hmac-md5-96
- hmac-sha1-96

Affected Hosts:

```
192.168.1.50 (tcp/22)
```

## Medium Severity Findings

Total Medium findings: 1

---

### HTTP Server Version Detection

Risk: Medium

Synopsis:

The remote web server is leaking its version information.

Description:

It is possible to obtain the version number of the remote web server by examining the Server response header field. This information can help an attacker target known vulnerabilities in specific versions.

Solution:

Modify the HTTP server configuration to prevent version information disclosure.

Affected Hosts:

```
webserver1.example.com (tcp/80)
webserver1.example.com (tcp/443)
api.example.com (tcp/8443)
```

## Low Severity Findings

Total Low findings: 1

---

### TCP Timestamps Enabled

Risk: Low

Synopsis:

The remote host implements TCP timestamps.

Description:

The remote host implements TCP timestamps, as defined by RFC1323. A side effect of this feature is that the uptime of the remote host can sometimes be computed.

Solution:

No solution is required. This is an informational finding.

Affected Hosts:

```
webserver1.example.com (tcp/0)
webserver2.example.com (tcp/0)
api.example.com (tcp/0)
```
