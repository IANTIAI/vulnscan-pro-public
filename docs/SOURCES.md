| Source | Use in VulnScan Pro | Data queried |
|---|---|---|
| [Nmap](https://nmap.org/) | Host, port, service, optional OS detection, and optional NSE checks | Active scans of targets entered by the operator |
| [CIRCL Vulnerability Lookup](https://vulnerability.circl.lu/) | Additional CVE information and product mapping | CVE identifier |
| [NVD](https://nvd.nist.gov/) | CVE details and CVSS data where available | CVE identifier; rate limits may delay enrichment |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Flags CVEs listed as known exploited vulnerabilities | Public catalog |
| [FIRST EPSS](https://www.first.org/epss/) | Daily estimate of CVE exploitation probability | CVE identifier |
| [IANA Service Name and Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/) | Port and protocol names for scan profiles | Registry lists |
| [FireHOL Level 1](https://iplists.firehol.org/) and [Spamhaus DROP](https://www.spamhaus.org/drop/) | IP blocklists for optional blacklist matching | Public lists, depending on enabled feeds |
| [Emerging Threats Compromised IPs](https://rules.emergingthreats.net/blockrules/compromised-ips.txt) | Optional threat intelligence feed | Public list when enabled |

CVE identifiers are sent to external CVE services for enrichment; target IP addresses are not. Enabled IP lists are compared locally with observed IP addresses. Nmap traffic is sent directly to targets entered by the operator.

## Notices

This product uses the NVD API but is not endorsed or certified by the NVD.

EPSS data: FIRST, Exploit Prediction Scoring System (https://www.first.org/epss). KEV data: CISA Known Exploited Vulnerabilities Catalog. Nmap is a separate program by the Nmap Project (https://nmap.org), installed by the user and not distributed with VulnScan Pro.
