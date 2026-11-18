<p align="center">
  <img src="docs/assets/banner.png" alt="VulnScan Pro: network vulnerability scanner" width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-00e5ff?style=flat-square" alt="Version 1.0.0">
  <img src="https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/Flask-web%20UI-000000?style=flat-square&logo=flask&logoColor=white" alt="Flask">
  <img src="https://img.shields.io/badge/Nmap-required-4682B4?style=flat-square" alt="Nmap required">
  <img src="https://img.shields.io/badge/Windows-one--click%20start-0078D6?style=flat-square&logo=windows&logoColor=white" alt="Windows one-click start">
  <img src="https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D6?style=flat-square" alt="Windows 10 and 11">
  <img src="https://img.shields.io/badge/license-Apache--2.0-39ff14?style=flat-square" alt="License Apache-2.0">
</p>

<p align="center">
  <b>Local network inventory and vulnerability scanning with CVE, KEV and EPSS enrichment, traffic monitoring and PDF reports.</b><br>
  Built on <a href="https://nmap.org">Nmap</a> · self-hosted · runs on <code>127.0.0.1</code> · your scan data never leaves your machine
</p>

<p align="center">
  <a href="#-quick-start-windows">Quick start</a> ·
  <a href="#-features">Features</a> ·
  <a href="#-screenshots">Screenshots</a> ·
  <a href="#-documentation">Docs</a> ·
  <a href="#-author">Author</a>
</p>

---

<p align="center">
  <img src="docs/assets/tour.gif" alt="Tour through the VulnScan Pro interface" width="100%">
</p>

> [!NOTE]
> All screenshots show the **real application** (version 1.0.0). To protect private network details, the devices shown use example data:
> documentation IP ranges (RFC 5737), `.example` host names and documentation MAC addresses. CVE IDs are genuine public records.
> Values in your environment will differ.

## ✨ Features

| | |
|---|---|
| 🔍 **Discovery** | Nmap host, port and service detection. Four port profiles from *Nmap top 1000* to *all 65535 TCP ports* ([details](#port-profiles)), optional OS detection and Nmap vulnerability scripts |
| 🛡️ **CVE enrichment** | CVSS from NVD and CIRCL, prioritized with **CISA KEV** (known exploited) and **FIRST EPSS** (exploit probability) |
| 🗂️ **Inventory** | Hosts grouped by subnet/VLAN, automatic device type detection, first/last seen, IP change tracking, custom labels |
| 🕸️ **Network map** | Interactive topology view; vulnerable hosts highlighted in red |
| 📡 **Traffic monitor** | Shows which local process talks to which remote IP, with automatic blocklist matching |
| 🚫 **Blocklists** | FireHOL, Spamhaus DROP and Emerging Threats feeds, custom IP/CIDR entries, IP lookup |
| 🔔 **Events & alerts** | Filterable event log, new-device and CVE alerts, export to PDF, CSV and syslog |
| ⏱️ **Scheduler** | Interval, daily or weekly scans |
| 📄 **PDF reports** | Risk summary, inventory per subnet, CVE details with KEV/EPSS, recommendations |
| 🏛️ **BSI architecture check** | Checks the scanned network against BSI IT-Grundschutz NET requirements (segmentation, firewall, management, SNMP, WLAN, Telnet) with a score |

## Why I built VulnScan Pro

VulnScan Pro grew out of my experience working as an administrator in Windows environments. I often needed to get up to speed quickly: understand a network, see which services were exposed and work out what needed attention next. My colleagues and I wanted practical tools that were quick to get running and useful in day-to-day work.

That experience shaped this project: a straightforward Windows launcher, a local browser interface and inventory, vulnerability context and reporting in one place. I built it to make those first steps easier and to share the result with other administrators.

## 🚀 Quick start (Windows)

1. **Download**: green **Code** button → **Download ZIP**, then unzip.
2. **Double-click `START.bat`.**

> **First launch:** Please keep the console window open and allow a few minutes for setup. Even if Nmap is already installed, VulnScan may still need to create its Python environment and install dependencies. The browser opens after setup; a short wait does not mean the application has failed. If setup fails, read the message in the console and `setup-last.log`.

That's it. No installer, no command line. VulnScan Pro sets itself up on the first start and opens in your browser at **<http://127.0.0.1:5000>**.
Windows asks **once** for administrator rights, so Nmap can scan with full features (OS detection, UDP) and never interrupts you with further prompts.
If Python or Nmap is missing, `START.bat` offers to install it for you with one keypress. Every later start takes only a few seconds.

Enter a network range you are allowed to scan and press **Start scan**. To stop VulnScan Pro, close the console window.

> [!TIP]
> If you decline the administrator prompt, VulnScan Pro still starts, but OS detection and UDP scans are unavailable and Npcap may ask for permission during scans.

### Port profiles

| Profile | What is scanned | Typical time per host |
|---|---|---|
| **STD** (default) | Nmap TCP top 1000 + 13 LAN UDP ports: DNS 53, DHCP 67/68, NTP 123, NetBIOS 137/138, SNMP 161/162, IPsec 500/4500, SSDP 1900, mDNS 5353, LLMNR 5355 | ~25 s |
| **HIGH** | All TCP ports assigned in the [IANA registry](https://www.iana.org/assignments/service-names-port-numbers/) (no UDP) | ~1 min |
| **HIGH+** | All IANA-assigned TCP **and** UDP ports | several minutes |
| **DEEP** | All 65535 TCP ports + UDP top 100 | up to ~10 min |

The IANA port lists ship as a local snapshot and can be refreshed in **Settings → System check**. With CVE scripts enabled, every profile takes longer.

### BSI architecture check

**Map → BSI architecture check** rates the scanned network against requirements of the BSI IT-Grundschutz NET modules and shows a score, the priority (MUST/SHOULD) and a concrete recommendation for each finding.

| Requirement | What is checked |
|---|---|
| NET.1.1.A4 | Network split into zones, or everything in one segment |
| NET.1.1.A5 | Clients and servers in the same segment |
| NET.1.1.A6 | IoT devices, cameras or printers sharing a segment with servers |
| NET.1.1.A8 | Firewall detected |
| NET.1.1.A21 | Switches, routers or firewalls in a user segment (management separation) |
| NET.1.2.A10 | SNMP exposed (port 161), version review |
| NET.2.1.A6 | Wireless access points in a LAN user segment |
| NET.3.1.A4 | Telnet exposed (port 23) instead of SSH |
| NET.3.2.A2 | Reminder to review the firewall rule set |

The results are hints based on what the scan can observe. They do not replace a full IT-Grundschutz assessment.

## 📸 Screenshots

### Scan
Set the authorized ranges and port profile, then follow progress in the live scan log. Results appear as expandable device cards with KPIs on top.

<img src="docs/assets/screenshots/01-scan.png" alt="Scan view" width="100%">

### Host detail
Open ports with service banners plus CVE matches with CVSS score, severity, 🔥 KEV and EPSS badges. Every CVE links to NVD.

<img src="docs/assets/screenshots/11-cve-detail.png" alt="Host detail with CVE matches" width="100%">

<table>
  <tr>
    <td width="50%"><b>Hosts</b>: inventory per subnet with type, vendor, OS, ports, CVEs and status<br><img src="docs/assets/screenshots/02-hosts.png" alt="Hosts"></td>
    <td width="50%"><b>Map</b>: topology around the gateway; red nodes have CVE matches<br><img src="docs/assets/screenshots/03-map.png" alt="Map"></td>
  </tr>
  <tr>
    <td><b>Traffic, grouped by host</b>: external connections per remote IP, blocklist hits first<br><img src="docs/assets/screenshots/04-traffic.png" alt="Traffic grouped by host"></td>
    <td><b>Traffic, all connections</b>: flat list incl. LAN, with process, PID, local/remote address and matching feed<br><img src="docs/assets/screenshots/04b-traffic-all-connections.png" alt="Traffic all connections"></td>
  </tr>
  <tr>
    <td><b>Blocklist feeds</b>: Spamhaus DROP, FireHOL Level 1 and Emerging Threats enabled, plus custom entries<br><img src="docs/assets/screenshots/08-blocklists.png" alt="Blocklists"></td>
    <td><b>IP lookup</b>: check any address against all enabled lists<br><img src="docs/assets/screenshots/15-blocklist-lookup.png" alt="Blocklist IP lookup"></td>
  </tr>
  <tr>
    <td><b>BSI architecture check</b>: network observations mapped to BSI IT-Grundschutz NET modules with a score<br><img src="docs/assets/screenshots/14-map-architecture.png" alt="BSI architecture check"></td>
    <td><b>Events</b>: severity counters, filters and export<br><img src="docs/assets/screenshots/05-events.png" alt="Events"></td>
  </tr>
  <tr>
    <td><b>Scheduler & alerts</b>: weekly scans, new-device and CVE alerts<br><img src="docs/assets/screenshots/07-scheduler.png" alt="Scheduler"></td>
    <td><b>Settings</b>: scheduler, blocklists, history and system check<br><img src="docs/assets/screenshots/06-settings.png" alt="Settings"></td>
  </tr>
  <tr>
    <td><b>System check</b>: Nmap, Python packages, database and port lists<br><img src="docs/assets/screenshots/10-system-check.png" alt="System check"></td>
    <td><b>History</b>: past scans and saved PDF reports<br><img src="docs/assets/screenshots/09-history.png" alt="History"></td>
  </tr>
</table>

### 📄 Sample PDF report

One click on **PDF report** creates a printable report: KPI summary and risk assessment, device inventory per subnet, network topology, port status legend and a per-host action plan with CVE, KEV and EPSS data.

**➡️ [Download the sample report (PDF, 3 pages)](docs/sample-report.pdf)**: generated by the app's own PDF export from the same example data.

<table>
  <tr>
    <td width="33%" align="center"><b>Page 1</b>: summary & inventory<br><a href="docs/assets/screenshots/12-report-page-1.png"><img src="docs/assets/screenshots/12-report-page-1.png" alt="Report page 1"></a></td>
    <td width="33%" align="center"><b>Page 2</b>: topology & port legend<br><a href="docs/assets/screenshots/12-report-page-2.png"><img src="docs/assets/screenshots/12-report-page-2.png" alt="Report page 2"></a></td>
    <td width="33%" align="center"><b>Page 3</b>: CVE action plan<br><a href="docs/assets/screenshots/12-report-page-3.png"><img src="docs/assets/screenshots/12-report-page-3.png" alt="Report page 3"></a></td>
  </tr>
</table>

## 🧭 How it works

<img src="docs/assets/07-architecture.png" alt="Architecture" width="100%">

1. **Discover**: Nmap scans the authorized ranges (TCP connect scan on Windows without Npcap privileges).
2. **Classify**: devices are typed by host name, vendor (MAC OUI) and open ports.
3. **Enrich**: product and version matches are looked up in NVD/CIRCL and ranked with CISA KEV and FIRST EPSS.
4. **Review**: findings are indicators. Confirm them against vendor advisories and the real configuration.
5. **Report**: export a PDF and track changes over time in the scan history.

## 🔒 Privacy

- Scan results are stored only in the local SQLite database (`vulnerdb.db`, ignored by Git). Set `VULNSCAN_DB` to use another path.
- Only **CVE identifiers** are sent to public enrichment services. Target IP addresses are never sent.
- The web server binds to `127.0.0.1` by default.
- Remove IP addresses, host names and organization details before sharing a report.

## ⚠️ Responsible use

> [!WARNING]
> Only scan networks you own or are **explicitly authorized** to assess. Active scans create traffic, can trigger IDS/IPS alerts and may disrupt fragile or industrial devices (PLCs, HMIs, medical equipment). Agree on scope and a maintenance window first.

The BSI architecture check does not replace a full IT-Grundschutz assessment or certification.

## 📚 Documentation

| Document | Content |
|---|---|
| [User guide](docs/en/user-guide.md) | Scanning, reports, interpreting CVE/KEV/EPSS, troubleshooting |
| [Visual guide](docs/VISUAL-GUIDE.md) | All screenshots and how they were made |
| [Data sources](docs/SOURCES.md) | NVD, CIRCL, CISA KEV, FIRST EPSS, IANA, blocklist feeds |
| [Testing checklist](docs/TESTING.md) | Manual test steps |
| [Changelog](CHANGELOG.md) | Version history |
| [Security policy](SECURITY.md) | How to report a vulnerability |
| [Contributing](CONTRIBUTING.md) | How to contribute |

## 👤 Author

**VulnScan Pro** is designed and developed by **IANTIAI**.

Feedback, ideas and bug reports are welcome. Please open an [issue](../../issues). If you find VulnScan Pro useful, a ⭐ on the repository helps others discover it.

## 📝 License

Copyright © 2026 IANTIAI. Licensed under the [Apache License 2.0](LICENSE): free to use, modify and distribute, including commercially, as long as the license and copyright notice are kept.

Nmap is a separate program by the [Nmap Project](https://nmap.org) under its own license. It is not bundled; `START.bat` offers to install it.
This product uses the NVD API but is not endorsed or certified by the NVD.
