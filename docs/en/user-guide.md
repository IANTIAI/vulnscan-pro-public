# User guide

## Overview

VulnScan Pro combines inventory and active network checks. A scan discovers devices, ports, and services. When enabled, Nmap also runs selected vulnerability tests. Review the results in the web interface and export them as a PDF report.

Scanning can trigger services, create load, and alert security monitoring systems. Before scanning production or industrial systems, agree on authorization, scope, and a maintenance window with the responsible operator.

## Start a scan

1. In the **Scan** tab, enter the authorized IP ranges.
2. Select a port profile: **STD**, **HIGH**, **HIGH+**, or **DEEP**.
3. Enable or disable CVE, operating-system, and NVD checks according to the approved scope.
4. Select **Start scan** and follow progress and the event log.
5. Review findings in **Hosts**, **Map**, **Traffic**, and **Events**.

| Profile | What is scanned | Typical time per host |
|---|---|---|
| **STD** (default) | Nmap TCP top 1000 + 13 LAN UDP ports: DNS 53, DHCP 67/68, NTP 123, NetBIOS 137/138, SNMP 161/162, IPsec 500/4500, SSDP 1900, mDNS 5353, LLMNR 5355 | ~25 s |
| **HIGH** | All TCP ports assigned in the [IANA registry](https://www.iana.org/assignments/service-names-port-numbers/) (no UDP) | ~1 min |
| **HIGH+** | All IANA-assigned TCP **and** UDP ports | several minutes |
| **DEEP** | All 65535 TCP ports + UDP top 100 | up to ~10 min |

The IANA port lists ship as a local snapshot and can be refreshed in **Settings → System check**. With CVE scripts enabled, every profile takes longer.

Profiles differ in port coverage and UDP checks. **DEEP** can take considerably longer. A CVE scan is active testing and is not equivalent to passive inventory.

## PDF report and language

After a scan, use **PDF Report** to create an English report. The interface and PDF exports are fixed to English. CVE descriptions remain in the language supplied by the data provider. Reports include scan time, port profile, device inventory, CVE details, severity, source references, and KEV/EPSS data when available for a finding.

Download or delete saved reports in **Settings > Scan History**. The number of retained reports is configurable. The database remains on the local machine.

## Interpreting CVE, KEV, and EPSS data

- A CVE ID identifies a known vulnerability. A product or version match is an indicator and must be checked against vendor guidance and the actual configuration.
- CISA KEV identifies CVEs with evidence of exploitation. A KEV match does not prove that your device was compromised.
- EPSS estimates the probability of exploitation activity in the next 30 days. It is not the compromise probability for this specific device.
- CVSS describes technical severity under a published scoring vector. It is not a scan outage probability.

## BSI IT-Grundschutz guidance

The BSI architecture check (Map → BSI architecture check) reports selected observations mapped to BSI components. Results depend on scan coverage and observable signals. They do not replace an organizational review, a complete IT-Grundschutz assessment, or certification.

## Privacy and data storage

Scan inventory and reports are stored in the local SQLite database. CVE identifiers are queried against public CVE, EPSS, and KEV services for enrichment. Before publishing a report, remove IP addresses, hostnames, serial numbers, and other organization-specific data.

## Troubleshooting

- **Nmap is not found:** Install Nmap separately and ensure `nmap` is on PATH.
- **No ports found:** Check privileges, firewalls, routing, and Nmap output. A missing result does not mean a host is secure.
- **PDF error:** Check the event log and terminal output; do not publish raw data or the local database.
- **CVE details are missing:** Check the source, rate limits, network access, and the CVE ID. Incomplete enrichment must not be interpreted as “no vulnerability.”

