# Visual guide

## Image provenance

All files in [`assets/screenshots`](assets/screenshots) are **real screenshots of the
application** (`app.py` + `index.html`, unchanged UI), captured in Google Chrome at 1440 px width.

To keep private network details out of a public repository, the devices shown use example data:

- IP addresses from the documentation ranges in RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)
- MAC addresses from the documentation range in RFC 7042 (`00:00:5E:00:53:xx`)
- host names under `.example`, vendors named "Example …"
- CVE IDs are real public records, shown as potential version matches

The report pages are the application's own PDF export of the same data.
Diagrams `07-architecture.png`, `08-workflow.png` and `architecture.svg` are explanatory drawings.

## Areas

| Area | Purpose | Screenshot |
|---|---|---|
| Scan | Enter authorized ranges, choose port profile and options, follow progress in the scan log, review discovered devices. | [01-scan](assets/screenshots/01-scan.png) |
| Hosts | Inventory grouped by subnet with type, vendor, OS, ports, CVE count and status. | [02-hosts](assets/screenshots/02-hosts.png) |
| Map | Inferred topology. It does not prove physical cabling or VLAN boundaries. | [03-map](assets/screenshots/03-map.png) |
| Traffic | Connections visible on the local machine per process, with blocklist matches. Not a network-wide capture. | [grouped](assets/screenshots/04-traffic.png) · [all connections](assets/screenshots/04b-traffic-all-connections.png) |
| Events | Application events with filters and PDF/CSV/syslog export. Not a SIEM. | [05-events](assets/screenshots/05-events.png) |
| Settings | Entry point for scheduler, blocklists, history and system check. | [06-settings](assets/screenshots/06-settings.png) |
| Scheduler & alerts | Scheduled scans, new-device and CVE alerts. | [07-scheduler](assets/screenshots/07-scheduler.png) |
| Blocklists | Public feeds (disabled by default; enabled with example entries here), custom entries, IP lookup. | [feeds](assets/screenshots/08-blocklists.png) · [lookup](assets/screenshots/15-blocklist-lookup.png) |
| BSI architecture check | Observations mapped to BSI IT-Grundschutz NET modules. Not a full assessment. | [14-map-architecture](assets/screenshots/14-map-architecture.png) |
| History | Past scans and saved PDF reports. | [09-history](assets/screenshots/09-history.png) |
| System check | Nmap, Python packages, database and IANA port lists. | [10-system-check](assets/screenshots/10-system-check.png) |
| Host detail | Open ports and CVE matches with CVSS, KEV and EPSS badges. | [11-cve-detail](assets/screenshots/11-cve-detail.png) |
| PDF report | Exported report ([sample PDF](sample-report.pdf)). | [page 1](assets/screenshots/12-report-page-1.png) · [page 2](assets/screenshots/12-report-page-2.png) · [page 3](assets/screenshots/12-report-page-3.png) |

## Screenshots

![Scan](assets/screenshots/01-scan.png)

![Hosts](assets/screenshots/02-hosts.png)

![Map](assets/screenshots/03-map.png)

![Host detail with CVE matches](assets/screenshots/11-cve-detail.png)

![Traffic grouped by host](assets/screenshots/04-traffic.png)

![Traffic, all connections](assets/screenshots/04b-traffic-all-connections.png)

![Events](assets/screenshots/05-events.png)

![Settings](assets/screenshots/06-settings.png)

![Scheduler and alerts](assets/screenshots/07-scheduler.png)

![Blocklists](assets/screenshots/08-blocklists.png)

![Blocklist IP lookup](assets/screenshots/15-blocklist-lookup.png)

![BSI architecture check](assets/screenshots/14-map-architecture.png)

![History](assets/screenshots/09-history.png)

![System check](assets/screenshots/10-system-check.png)

## PDF report

![Report page 1](assets/screenshots/12-report-page-1.png)

![Report page 2](assets/screenshots/12-report-page-2.png)

![Report page 3](assets/screenshots/12-report-page-3.png)

## Architecture and workflow

![Component architecture](assets/07-architecture.png)

![Assessment workflow](assets/08-workflow.png)
