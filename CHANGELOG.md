# Changelog

## 1.0.0 — First public release

**Start and setup (Windows 10/11)**
- One-click start with `START.bat`: asks once for administrator rights, offers to install Python or Nmap if missing, sets up everything else silently and opens the browser.
- One administrator prompt per start, so Npcap in admin-only mode does not ask again for every Nmap process during a scan.
- Local SQLite database `vulnerdb.db`; path configurable with `VULNSCAN_DB`, port with `VULNSCAN_PORT` (default 5000).

**Scanning and analysis**
- Nmap host, port and service discovery with four port profiles: STD, HIGH, HIGH+ and DEEP.
- CVE enrichment with CVSS from NVD and CIRCL, prioritized with CISA KEV and FIRST EPSS.
- BSI architecture check: the scanned network rated against BSI IT-Grundschutz NET requirements, with score and recommendations.
- Inventory per subnet/VLAN with device type detection, network map, scheduler, events and alerts.
- Traffic monitor for local connections with blocklist matching (Spamhaus DROP, FireHOL, Emerging Threats, custom entries).

**Reports and documentation**
- PDF reports with risk summary, inventory, topology, port legend and CVE action plan including KEV/EPSS.
- README with screenshots, interface tour, sample PDF report, user guide, data sources and test checklist.
