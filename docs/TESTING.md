# Test checklist

A fresh installation starts with an empty local database (`vulnerdb.db`).

1. **Windows:** double-click `START.bat`. Windows asks once for administrator rights; confirm with Yes. The first start sets everything up by itself (and offers to install Python or Nmap if missing), then opens `http://127.0.0.1:5000`. A second start should open within a few seconds.
2. Open **Settings → System check**: Nmap and all packages should show a green check mark.
3. Check navigation, settings, status fields and dynamically loaded lists. The interface and PDF reports are in English.
4. Scan only a network you own or are explicitly authorized to assess. Start with a small scope, e.g. `127.0.0.1`.
5. With results, export a PDF. Check headings, KPI fields, risk recommendations, port legend, CVE table, KEV/EPSS and the download name. CVE descriptions may stay in the language of their source.
6. Stop the app by closing the console window (or `Ctrl+C`). `vulnerdb.db` contains your local results: do not commit or share it.

**Port already in use:** set `VULNSCAN_PORT` (e.g. `set VULNSCAN_PORT=5050`) before starting.

