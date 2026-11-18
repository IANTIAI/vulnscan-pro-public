#!/usr/bin/env python3
"""
VulnScan Pro v1.0.0 - LAN/VLAN/CVE Scanner with central Event-Log
Run: sudo python3 app.py
"""

import subprocess
import socket
import ipaddress
import json
import threading
import time
import re
import sqlite3
from datetime import datetime
from flask import Flask, render_template_string, jsonify, request, make_response
from urllib.parse import urlparse, urljoin
import urllib.request
import urllib.error
import os
import sys
import shutil as _shutil


# ════════════════════════════════════════════════════════════════════
# NMAP BINARY AUTO-DETECTION — find nmap.exe/nmap on Windows/Mac/Linux
# ════════════════════════════════════════════════════════════════════
def _find_nmap_binary():
    """Find nmap binary by checking PATH, then common install locations.
    Returns absolute path if found, else 'nmap' as fallback.
    """
    # 1. PATH lookup first
    p = _shutil.which("nmap")
    if p:
        return p

    # 2. OS-specific known install locations
    candidates = []
    is_win = sys.platform.startswith("win") or os.name == "nt"
    if is_win:
        candidates = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Nmap\nmap.exe"),
            os.path.expandvars(r"%ProgramFiles%\Nmap\nmap.exe"),
            os.path.expandvars(r"%ProgramFiles(x86)%\Nmap\nmap.exe"),
        ]
    elif sys.platform == "darwin":
        candidates = [
            "/opt/homebrew/bin/nmap",
            "/usr/local/bin/nmap",
            "/opt/local/bin/nmap",
        ]
    else:  # Linux/BSD
        candidates = [
            "/usr/bin/nmap",
            "/usr/local/bin/nmap",
            "/opt/bin/nmap",
            "/usr/sbin/nmap",
        ]

    for c in candidates:
        if c and os.path.exists(c):
            return c

    # 3. Fallback — let subprocess error out clearly later
    return "nmap"


NMAP_BIN = _find_nmap_binary()
NMAP_FOUND = (NMAP_BIN != "nmap") or (_shutil.which("nmap") is not None)


app = Flask(__name__)

# --- Global scan state ---
scan_state = {
    "running": False,
    "progress": 0,
    "status": "Ready",
    "hosts_done": 0,
    "hosts_total": 0,
    "results": [],
    "last_scan": None,
    "cancel_requested": False,
    "log_events": [],   # [{t, msg, cls}]
    "log_seq": 0        # frontend polls from this seq
}

def log_event(msg, cls="info"):
    import datetime
    t = datetime.datetime.now().strftime("%H:%M:%S")
    scan_state["log_events"].append({"t": t, "msg": msg, "cls": cls})
    scan_state["log_seq"] += 1
    if len(scan_state["log_events"]) > 500:
        scan_state["log_events"] = scan_state["log_events"][-400:]
    # persist to DB (best-effort, never break live log)
    try:
        _log_persist(msg, cls)
    except Exception:
        pass


# ────────────────────────────────────────────────────────────────
# EVENT PERSISTENCE — used by the "Logs" tab (/api/logs)
# ────────────────────────────────────────────────────────────────
def _cls_to_severity(cls):
    """Map legacy scan-log cls to event severity."""
    return {
        "info":  "info",
        "found": "info",
        "batch": "info",
        "warn":  "warn",
        "cve":   "critical",
        "error": "error",
    }.get(cls, "info")


def _log_persist(msg, cls="info", source="scan", event_type="", host="", data=None):
    """Write an event to the events table."""
    import datetime, json as _j
    try:
        severity = _cls_to_severity(cls) if cls in ("info","found","batch","warn","cve","error") else cls
        # auto-detect source hint from message prefix
        src = source
        m = str(msg or "")
        low = m.lower()
        if "scheduler" in low: src = "scheduler"
        elif "snmp" in low or "dhcp" in low or "discovery" in low or "scan" in low: src = "scan"
        data_s = _j.dumps(data) if data else ""
        with db_connect() as con:
            con.execute(
                "INSERT INTO events (ts, severity, source, event_type, host, message, data_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (datetime.datetime.now().isoformat(timespec="seconds"),
                 severity, src, event_type or "", host or "", m[:2000], data_s[:4000])
            )
    except Exception:
        # DB may not exist yet at very early startup — swallow
        pass


def log_ev(severity, source, message, event_type="", host="", data=None):
    """Explicit event logger — preferred for new call-sites.
    severity: info | warn | error | critical
    source:   scan | scheduler | alert | traffic | system | user
    """
    import datetime
    # mirror into live scan log so it shows up in the UI scan-log stream
    cls = {"critical":"cve","error":"warn","warn":"warn"}.get(severity, "info")
    t = datetime.datetime.now().strftime("%H:%M:%S")
    scan_state["log_events"].append({"t": t, "msg": message, "cls": cls})
    scan_state["log_seq"] += 1
    if len(scan_state["log_events"]) > 500:
        scan_state["log_events"] = scan_state["log_events"][-400:]
    try:
        _log_persist(message, cls=severity, source=source, event_type=event_type, host=host, data=data)
    except Exception:
        pass

def log_update_at(slot, msg, cls="info"):
    import datetime
    t = datetime.datetime.now().strftime("%H:%M:%S")
    if 0 <= slot < len(scan_state["log_events"]):
        scan_state["log_events"][slot] = {"t": t, "msg": msg, "cls": cls}
        scan_state["log_seq"] += 1

DATA_FILE = os.path.join(os.path.dirname(__file__), "vulnerdb_data.json")  # legacy JSON import
DB_FILE   = os.environ.get("VULNSCAN_DB") or os.path.join(os.path.dirname(__file__), "vulnerdb.db")

IANA_CSV_URL = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
IANA_TXT_URL = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt"
UDP_CRITICAL_PORTS = [53,67,68,69,123,161,162,500,514,520,1194,4500,5060,5353]
FLAG_RE = re.compile(r"\^FLAG\^[A-Za-z0-9_\-]{16,}\$FLAG\$", re.I)

# ---------- IANA port list ----------
# All officially IANA-registered TCP ports (well-known + registered, 0-49151)
# Source: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv
# Fetched at startup and cached in SQLite. Fallback: hardcoded list below.

IANA_FALLBACK_PORTS = [
    1,7,9,11,13,15,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,
    37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,
    59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,
    81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,
    102,103,104,105,106,107,108,109,110,111,113,115,116,117,118,119,120,
    121,122,123,124,125,126,129,131,132,133,134,135,136,137,138,139,140,
    141,142,143,144,145,146,147,148,149,150,152,153,154,155,156,157,158,
    159,160,161,162,163,164,165,166,167,168,169,170,171,172,174,175,176,
    177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,192,193,
    194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,
    211,212,213,214,215,216,217,218,219,220,221,222,223,224,242,243,244,
    245,246,247,248,256,257,258,259,260,261,262,263,264,265,266,267,268,
    269,270,271,280,281,282,283,284,285,286,287,288,289,290,308,309,310,
    311,312,313,314,315,316,317,318,319,320,321,322,323,324,325,333,344,
    345,346,347,348,349,350,351,352,353,354,355,356,357,358,359,360,361,
    362,363,364,365,366,367,368,369,370,371,372,373,374,375,376,377,378,
    379,380,381,382,383,384,385,386,387,388,389,390,391,392,393,394,395,
    396,397,398,399,400,401,402,403,404,405,406,407,408,409,410,411,412,
    413,414,415,416,417,418,419,420,421,422,423,424,425,426,427,428,429,
    430,431,432,433,434,435,436,437,438,439,440,441,442,443,444,445,446,
    447,448,449,450,451,452,453,454,455,456,457,458,459,460,461,462,463,
    464,465,466,467,468,469,470,471,472,473,474,475,476,477,478,479,480,
    481,482,483,484,485,486,487,488,489,490,491,492,493,494,495,496,497,
    498,499,500,501,502,503,504,505,506,507,508,509,510,511,512,513,514,
    515,516,517,518,519,520,521,522,523,524,525,526,527,528,529,530,531,
    532,533,534,535,536,537,538,539,540,541,542,543,544,545,546,547,548,
    549,550,551,552,553,554,555,556,557,558,559,560,561,562,563,564,565,
    566,567,568,569,570,571,572,573,574,575,576,578,579,580,581,582,583,
    584,585,586,587,588,589,590,591,592,593,594,595,596,597,598,599,600,
    601,602,603,604,605,606,607,608,609,610,611,612,613,614,615,616,617,
    618,619,620,621,622,623,624,625,626,627,628,629,630,631,632,633,634,
    635,636,637,638,639,640,641,642,643,644,645,646,647,648,649,650,651,
    652,653,654,655,656,657,658,659,660,661,662,663,664,665,666,667,668,
    669,670,671,672,673,674,675,676,677,678,679,680,681,682,683,684,685,
    686,687,688,689,690,691,692,693,694,695,696,697,698,699,700,701,702,
    703,704,705,706,707,708,709,710,711,712,713,714,715,716,717,718,719,
    720,721,722,723,724,725,726,727,728,729,730,731,732,733,734,735,736,
    737,738,739,740,741,742,743,744,745,746,747,748,749,750,751,752,753,
    754,755,756,757,758,759,760,761,762,763,764,765,766,767,768,769,770,
    771,772,773,774,775,776,777,778,779,780,781,782,783,784,785,786,787,
    788,789,790,791,792,793,794,795,796,797,798,799,800,801,802,803,804,
    805,806,807,808,809,810,811,812,813,814,815,816,817,818,819,820,821,
    822,823,824,825,826,827,828,829,830,831,832,833,834,835,836,837,838,
    839,840,841,842,843,844,845,846,847,848,849,850,851,852,853,854,855,
    856,857,858,859,860,861,862,863,864,865,866,867,868,869,870,871,872,
    873,874,875,876,877,878,879,880,881,882,883,884,885,886,887,888,889,
    890,891,892,893,894,895,896,897,898,899,900,901,902,903,904,905,906,
    907,908,909,910,911,912,913,914,915,916,917,918,919,920,921,922,923,
    924,925,926,927,928,929,930,931,932,933,934,935,936,937,938,939,940,
    941,942,943,944,945,946,947,948,949,950,951,952,953,954,955,956,957,
    958,959,960,961,962,963,964,965,966,967,968,969,970,971,972,973,974,
    975,976,977,978,979,980,981,982,983,984,985,986,987,988,989,990,991,
    992,993,994,995,996,997,998,999,1000,1001,1002,1007,1008,1010,1011,
    1021,1022,1023,1024,1025,1026,1027,1029,1030,1058,1059,1067,1068,
    1080,1083,1084,1099,1109,1110,1155,1176,1182,1183,1184,1194,1198,
    1212,1214,1220,1234,1235,1236,1241,1248,1270,1293,1311,1314,1337,
    1344,1352,1433,1434,1477,1478,1484,1494,1500,1501,1503,1521,1524,
    1527,1533,1544,1545,1546,1547,1548,1553,1556,1567,1568,1569,1570,
    1581,1582,1583,1584,1585,1586,1587,1589,1604,1645,1646,1649,1677,
    1688,1701,1716,1719,1720,1723,1755,1761,1762,1801,1812,1813,1863,
    1900,1935,1985,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,
    2010,2049,2052,2053,2054,2055,2056,2080,2082,2083,2086,2087,2095,
    2096,2100,2110,2111,2121,2181,2222,2252,2302,2376,2377,2379,2380,
    2427,2447,2483,2484,2638,2745,2809,2869,2944,2945,3000,3001,3002,
    3003,3004,3005,3020,3050,3051,3052,3128,3260,3268,3269,3283,3290,
    3306,3307,3389,3396,3535,3537,3689,3690,3702,3784,3785,3790,3868,
    3872,4000,4001,4002,4003,4004,4005,4006,4045,4100,4111,4190,4197,
    4242,4321,4443,4444,4445,4446,4500,4567,4662,4711,4712,4730,4848,
    4899,4949,5000,5001,5002,5003,5004,5005,5006,5007,5008,5009,5010,
    5040,5050,5051,5060,5061,5080,5100,5101,5102,5190,5222,5223,5228,
    5269,5353,5357,5432,5500,5554,5555,5560,5601,5631,5632,5800,5801,
    5900,5901,5902,5903,5985,5986,6000,6001,6002,6003,6004,6005,6006,
    6009,6050,6051,6100,6101,6110,6111,6129,6257,6346,6347,6379,6389,
    6443,6488,6514,6543,6544,6619,6660,6661,6662,6663,6664,6665,6666,
    6667,6668,6669,6679,6697,6881,6891,6969,7000,7001,7002,7003,7004,
    7005,7006,7007,7008,7009,7010,7022,7025,7047,7070,7100,7101,7103,
    7106,7200,7201,7402,7443,7474,7547,7548,7627,7676,7706,7707,7720,
    7741,7777,7778,7779,7780,7781,7782,7783,7784,7786,7911,7915,7929,
    7932,7933,7962,7967,7979,8000,8001,8002,8003,8004,8005,8006,8007,
    8008,8009,8010,8011,8080,8081,8082,8083,8084,8085,8086,8087,8088,
    8089,8090,8091,8092,8093,8094,8095,8096,8097,8098,8099,8100,8101,
    8118,8123,8181,8182,8183,8184,8185,8186,8187,8188,8189,8243,8280,
    8281,8333,8337,8383,8443,8444,8500,8530,8531,8686,8765,8800,8834,
    8880,8881,8882,8883,8884,8888,8889,8983,9000,9001,9002,9003,9009,
    9010,9030,9042,9043,9080,9090,9091,9100,9101,9102,9160,9191,9200,
    9201,9389,9418,9443,9600,9633,9800,9943,9944,9981,9987,9993,9999,
    10000,10001,10002,10010,10050,10051,10080,10110,10243,10514,11000,
    11001,11111,11112,11211,11300,11371,12000,12001,12443,13000,13001,
    13720,13721,14000,14001,15000,15001,16000,16001,16992,16993,17000,
    17001,17500,18080,18081,19000,19001,19132,19133,20000,20001,20547,
    22000,22125,23000,25000,25010,27015,27017,28017,29000,30000,32400,
    32764,37777,41794,41795,44158,47808,49151,49152,50000,51820,54045,
    55000,55443,60000,62078,65000,65443
]

_iana_ports_cache = None
_iana_portlists_cache = None

def _parse_iana_last_updated(text):
    m = re.search(r"Last Updated\s+([0-9]{4}-[0-9]{2}-[0-9]{2})", text or "")
    return m.group(1) if m else None

def _fetch_iana_registry(timeout=10):
    import urllib.request, csv, io
    tcp_ports, udp_ports = set(), set()
    last_updated = None

    try:
        with urllib.request.urlopen(IANA_TXT_URL, timeout=timeout) as resp:
            txt = resp.read().decode("utf-8", errors="ignore")
            last_updated = _parse_iana_last_updated(txt)
    except Exception:
        last_updated = None

    with urllib.request.urlopen(IANA_CSV_URL, timeout=timeout) as resp:
        csv_text = resp.read().decode("utf-8", errors="ignore")

    for row in csv.DictReader(io.StringIO(csv_text)):
        proto = (row.get("Transport Protocol") or "").strip().lower()
        pnum = (row.get("Port Number") or "").strip()
        if not pnum.isdigit():
            continue
        port = int(pnum)
        if not (1 <= port <= 65535):
            continue
        if proto == "tcp":
            tcp_ports.add(port)
        elif proto == "udp":
            udp_ports.add(port)

    return {
        "tcp_ports": sorted(tcp_ports),
        "udp_ports": sorted(udp_ports),
        "last_updated": last_updated,
        "source": "IANA"
    }

def get_iana_port_lists(force_refresh=False):
    """Return cached or freshly downloaded IANA TCP/UDP lists incl. version metadata."""
    global _iana_portlists_cache, _iana_ports_cache
    if _iana_portlists_cache is not None and not force_refresh:
        return _iana_portlists_cache

    if not force_refresh:
        try:
            with db_connect() as con:
                row = con.execute("SELECT value FROM scheduler WHERE key='iana_meta'").fetchone()
                if row:
                    meta = json.loads(row["value"])
                    tcp_row = con.execute("SELECT value FROM scheduler WHERE key='iana_ports_tcp'").fetchone()
                    udp_row = con.execute("SELECT value FROM scheduler WHERE key='iana_ports_udp'").fetchone()
                    if tcp_row and udp_row:
                        data = {
                            "tcp_ports": json.loads(tcp_row["value"]),
                            "udp_ports": json.loads(udp_row["value"]),
                            "last_updated": meta.get("last_updated"),
                            "source": meta.get("source", "cache")
                        }
                        _iana_portlists_cache = data
                        _iana_ports_cache = data["tcp_ports"]
                        return data
        except Exception:
            pass

    try:
        data = _fetch_iana_registry()
        with db_connect() as con:
            con.execute("INSERT OR REPLACE INTO scheduler(key,value) VALUES('iana_ports_tcp',?)", (json.dumps(data["tcp_ports"]),))
            con.execute("INSERT OR REPLACE INTO scheduler(key,value) VALUES('iana_ports_udp',?)", (json.dumps(data["udp_ports"]),))
            con.execute("INSERT OR REPLACE INTO scheduler(key,value) VALUES('iana_meta',?)", (json.dumps({
                "last_updated": data.get("last_updated"),
                "source": data.get("source", "IANA"),
                "checked_at": datetime.now().strftime("%d.%m.%Y %H:%M:%S"),
                "tcp_count": len(data["tcp_ports"]),
                "udp_count": len(data["udp_ports"])
            }),))
        _iana_portlists_cache = data
        _iana_ports_cache = data["tcp_ports"]
        return data
    except Exception as e:
        print(f"IANA download failed ({e}), using fallback/cache data")
        fallback = {
            "tcp_ports": list(IANA_FALLBACK_PORTS),
            "udp_ports": sorted(set(UDP_CRITICAL_PORTS)),
            "last_updated": None,
            "source": "fallback"
        }
        _iana_portlists_cache = fallback
        _iana_ports_cache = fallback["tcp_ports"]
        return fallback

def get_iana_ports():
    """Backward-compatible TCP-only accessor for the HIGH profile."""
    return get_iana_port_lists().get("tcp_ports", IANA_FALLBACK_PORTS)


app_data = {
    "known_devices": {},   # ip -> {mac, label, first_seen, last_seen, previous_ips}
    "alerts": [],
    "scan_history": [],
    "labels":       {},
    "scheduler":    {"enabled": False, "interval_minutes": 60, "last_run": None},
    "saved_reports": [],  # PDF reports
    "max_reports": 3,
}

# ---------- SQLite helpers ----------
def db_connect():
    con = sqlite3.connect(DB_FILE, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con

def db_init():
    with db_connect() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS known_devices (
            ip TEXT PRIMARY KEY,
            mac TEXT, vendor TEXT, hostname TEXT,
            first_seen TEXT, last_seen TEXT,
            previous_ips TEXT DEFAULT '[]',
            label TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_time TEXT,
            device_count INTEGER,
            vuln_count INTEGER,
            port_count INTEGER,
            devices_json TEXT
        );
        CREATE TABLE IF NOT EXISTS saved_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT,
            label TEXT,
            pdf_data BLOB
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            type TEXT, severity TEXT, message TEXT,
            ip TEXT, data_json TEXT,
            scan_time TEXT,
            acknowledged INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS labels (
            ip TEXT PRIMARY KEY,
            label TEXT
        );
        CREATE TABLE IF NOT EXISTS scheduler (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        CREATE TABLE IF NOT EXISTS events (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ts         TEXT    NOT NULL,
            severity   TEXT    NOT NULL DEFAULT 'info',
            source     TEXT    NOT NULL DEFAULT 'system',
            event_type TEXT    DEFAULT '',
            host       TEXT    DEFAULT '',
            message    TEXT    NOT NULL,
            data_json  TEXT    DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(ts);
        CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
        CREATE INDEX IF NOT EXISTS idx_events_source   ON events(source);
        CREATE TABLE IF NOT EXISTS blacklist_feeds (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT    UNIQUE NOT NULL,
            url          TEXT    NOT NULL,
            format       TEXT    DEFAULT 'netset',
            enabled      INTEGER DEFAULT 0,
            is_custom    INTEGER DEFAULT 0,
            last_updated TEXT    DEFAULT '',
            entry_count  INTEGER DEFAULT 0,
            last_error   TEXT    DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS blacklist_entries (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_or_net TEXT    NOT NULL,
            feed_id   INTEGER,
            notes     TEXT    DEFAULT '',
            added_at  TEXT    DEFAULT '',
            FOREIGN KEY (feed_id) REFERENCES blacklist_feeds(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_bl_entries_ip   ON blacklist_entries(ip_or_net);
        CREATE INDEX IF NOT EXISTS idx_bl_entries_feed ON blacklist_entries(feed_id);
        """)
        # Seed default feeds (idempotent — INSERT OR IGNORE on unique name)
        default_feeds = [
            ("FireHOL Level 1",
             "https://iplists.firehol.org/files/firehol_level1.netset",
             "netset",
             "Low false-positive IP blocklist (spam, malware, attackers)"),
            ("Spamhaus DROP",
             "https://www.spamhaus.org/drop/drop.txt",
             "spamhaus",
             "Hijacked/stolen networks controlled by cybercriminals"),
            ("Emerging Threats Compromised",
             "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
             "plain",
             "Recently compromised hosts flagged by Proofpoint ET"),
        ]
        for name, url, fmt, note in default_feeds:
            con.execute(
                "INSERT OR IGNORE INTO blacklist_feeds (name, url, format, enabled, is_custom) "
                "VALUES (?, ?, ?, 0, 0)",
                (name, url, fmt)
            )
    print(f"SQLite DB: {DB_FILE}")


# ────────────────────────────────────────────────────────────────
# BLACKLIST — fetch, parse, lookup
# ────────────────────────────────────────────────────────────────
_BL_CACHE = {"loaded_at": 0, "networks": [], "ips": set()}  # in-memory index


def _parse_blacklist_body(body, fmt):
    """Parse a blocklist payload. Returns list of (ip_or_cidr_string)."""
    import re as _re
    out = []
    if body is None:
        return out
    text = body.decode("utf-8", errors="ignore") if isinstance(body, (bytes, bytearray)) else str(body)
    ip_re   = _re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})(?:/\d{1,2})?$")
    cidr_re = _re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if fmt in ("netset", "plain"):
            m = ip_re.match(line.split()[0] if line.split() else line)
            if m:
                out.append(line.split()[0])
        elif fmt == "spamhaus":
            # "193.169.244.0/23 ; SBL123456"
            m = cidr_re.search(line)
            if m:
                out.append(m.group(1))
        else:
            # fallback: take any ip/cidr anywhere in the line
            m = cidr_re.search(line)
            if m:
                out.append(m.group(1))
    # dedup preserving order
    seen, dedup = set(), []
    for x in out:
        if x not in seen:
            seen.add(x); dedup.append(x)
    return dedup


def _bl_refresh_index():
    """Reload the in-memory blacklist index from DB. Called after every change."""
    import ipaddress as _ipa
    networks, ips = [], set()
    try:
        with db_connect() as con:
            # only entries from enabled feeds OR custom entries (feed_id IS NULL)
            rows = con.execute("""
                SELECT e.ip_or_net FROM blacklist_entries e
                LEFT JOIN blacklist_feeds f ON e.feed_id = f.id
                WHERE (f.enabled = 1) OR (e.feed_id IS NULL)
            """).fetchall()
        for (entry,) in rows:
            entry = (entry or "").strip()
            if not entry:
                continue
            try:
                if "/" in entry:
                    networks.append(_ipa.ip_network(entry, strict=False))
                else:
                    ips.add(entry)
            except Exception:
                continue
    except Exception:
        pass
    _BL_CACHE["networks"]  = networks
    _BL_CACHE["ips"]       = ips
    _BL_CACHE["loaded_at"] = time.time()


def ip_in_blacklist(ip):
    """Return list of matches [{'feed':..., 'entry':...}] or empty list."""
    if not ip:
        return []
    if not _BL_CACHE["networks"] and not _BL_CACHE["ips"]:
        _bl_refresh_index()
    import ipaddress as _ipa
    matches = []
    # exact IP hit
    if ip in _BL_CACHE["ips"]:
        matches.append(("exact", ip))
    # CIDR check
    try:
        a = _ipa.ip_address(ip)
        for net in _BL_CACHE["networks"]:
            if a in net:
                matches.append(("cidr", str(net)))
    except Exception:
        return []
    if not matches:
        return []
    # Look up which feeds
    out = []
    try:
        with db_connect() as con:
            con.row_factory = sqlite3.Row
            for kind, entry in matches:
                rows = con.execute("""
                    SELECT e.ip_or_net, f.name AS feed_name, f.id AS feed_id
                    FROM blacklist_entries e
                    LEFT JOIN blacklist_feeds f ON e.feed_id = f.id
                    WHERE e.ip_or_net = ?
                """, (entry,)).fetchall()
                for r in rows:
                    out.append({
                        "entry":     r["ip_or_net"],
                        "match_kind": kind,
                        "feed_id":   r["feed_id"],
                        "feed":      r["feed_name"] or "Custom",
                    })
    except Exception:
        pass
    return out


def _bl_update_feed(feed_id):
    """Fetch one feed and refresh its entries. Returns (count, error_str)."""
    import urllib.request, urllib.error, datetime as _dt
    try:
        with db_connect() as con:
            con.row_factory = sqlite3.Row
            feed = con.execute("SELECT * FROM blacklist_feeds WHERE id = ?", (feed_id,)).fetchone()
            if not feed:
                return (0, "feed not found")
            url, fmt, name = feed["url"], feed["format"], feed["name"]
        req = urllib.request.Request(url, headers={"User-Agent": "VulnScan-Pro/1.0.0 blacklist-updater"})
        with urllib.request.urlopen(req, timeout=20) as r:
            body = r.read()
        entries = _parse_blacklist_body(body, fmt)
        now = _dt.datetime.now().isoformat(timespec="seconds")
        with db_connect() as con:
            con.execute("DELETE FROM blacklist_entries WHERE feed_id = ?", (feed_id,))
            con.executemany(
                "INSERT INTO blacklist_entries (ip_or_net, feed_id, added_at) VALUES (?, ?, ?)",
                [(e, feed_id, now) for e in entries]
            )
            con.execute(
                "UPDATE blacklist_feeds SET last_updated=?, entry_count=?, last_error='' WHERE id=?",
                (now, len(entries), feed_id)
            )
        _bl_refresh_index()
        log_ev("info", "system", f"Blocklists '{name}' updated: {len(entries)} entries",
               event_type="blacklist_update")
        return (len(entries), "")
    except Exception as e:
        err = str(e)[:200]
        try:
            with db_connect() as con:
                con.execute("UPDATE blacklist_feeds SET last_error=? WHERE id=?", (err, feed_id))
        except Exception:
            pass
        log_ev("error", "system", f"Blocklist update failed (feed_id={feed_id}): {err}",
               event_type="blacklist_update_error")
        return (0, err)

def save_data():
    """Save in-memory app_data to SQLite."""
    try:
        with db_connect() as con:
            # known_devices
            for ip, kd in app_data["known_devices"].items():
                con.execute("""
                    INSERT INTO known_devices (ip,mac,vendor,hostname,first_seen,last_seen,previous_ips,label)
                    VALUES (?,?,?,?,?,?,?,?)
                    ON CONFLICT(ip) DO UPDATE SET
                      mac=excluded.mac, vendor=excluded.vendor, hostname=excluded.hostname,
                      last_seen=excluded.last_seen, previous_ips=excluded.previous_ips,
                      label=excluded.label
                """, (ip, kd.get("mac",""), kd.get("vendor",""), kd.get("hostname",""),
                      kd.get("first_seen",""), kd.get("last_seen",""),
                      json.dumps(kd.get("previous_ips",[])), kd.get("label","")))
            # labels
            for ip, lbl in app_data["labels"].items():
                con.execute("INSERT OR REPLACE INTO labels(ip,label) VALUES(?,?)", (ip, lbl))
            # scheduler
            s = app_data["scheduler"]
            for k, v in s.items():
                con.execute("INSERT OR REPLACE INTO scheduler(key,value) VALUES(?,?)", (k, json.dumps(v)))
            # last scan results + mode
            if app_data.get("last_scan_results"):
                con.execute("INSERT OR REPLACE INTO scheduler(key,value) VALUES(?,?)",
                    ("last_scan_results", json.dumps(app_data["last_scan_results"])))
            if app_data.get("last_scan_time"):
                con.execute("INSERT OR REPLACE INTO scheduler(key,value) VALUES(?,?)",
                    ("last_scan_time", json.dumps(app_data["last_scan_time"])))
            if app_data.get("last_scan_mode"):
                con.execute("INSERT OR REPLACE INTO scheduler(key,value) VALUES(?,?)",
                    ("last_scan_mode", json.dumps(app_data["last_scan_mode"])))
    except Exception as e:
        print(f"SQLite save error: {e}")

def save_scan_history_db(summary):
    """Append one scan to SQLite scan_history."""
    try:
        with db_connect() as con:
            con.execute("""
                INSERT INTO scan_history(scan_time,device_count,vuln_count,port_count,devices_json)
                VALUES(?,?,?,?,?)
            """, (summary["time"], summary["device_count"], summary["vuln_count"],
                  summary["port_count"], json.dumps(summary["devices"])))
    except Exception as e:
        print(f"SQLite history save error: {e}")

def save_alert_db(alert):
    try:
        with db_connect() as con:
            data = {k:v for k,v in alert.items() if k not in ("id","type","severity","message","ip","time","acknowledged")}
            con.execute("""
                INSERT OR IGNORE INTO alerts(id,type,severity,message,ip,data_json,scan_time,acknowledged)
                VALUES(?,?,?,?,?,?,?,?)
            """, (alert["id"], alert["type"], alert["severity"], alert["message"],
                  alert.get("ip",""), json.dumps(data), alert.get("time",""), 0))
    except Exception as e:
        print(f"SQLite alert save error: {e}")

def load_data():
    global app_data
    db_init()
    try:
        with db_connect() as con:
            # known_devices
            for row in con.execute("SELECT * FROM known_devices"):
                app_data["known_devices"][row["ip"]] = {
                    "mac": row["mac"], "vendor": row["vendor"], "hostname": row["hostname"],
                    "first_seen": row["first_seen"], "last_seen": row["last_seen"],
                    "previous_ips": json.loads(row["previous_ips"] or "[]"),
                    "label": row["label"]
                }
            # labels
            for row in con.execute("SELECT * FROM labels"):
                app_data["labels"][row["ip"]] = row["label"]
            # scan_history (last 50)
            for row in con.execute("SELECT * FROM scan_history ORDER BY id DESC LIMIT 50"):
                app_data["scan_history"].insert(0, {
                    "time": row["scan_time"], "device_count": row["device_count"],
                    "vuln_count": row["vuln_count"], "port_count": row["port_count"],
                    "devices": json.loads(row["devices_json"] or "[]")
                })
            # alerts (last 100 unacknowledged or recent)
            for row in con.execute("SELECT * FROM alerts ORDER BY scan_time DESC LIMIT 100"):
                data = json.loads(row["data_json"] or "{}")
                app_data["alerts"].append({
                    "id": row["id"], "type": row["type"], "severity": row["severity"],
                    "message": row["message"], "ip": row["ip"],
                    "time": row["scan_time"], "acknowledged": bool(row["acknowledged"]),
                    **data
                })
            # scheduler
            for row in con.execute("SELECT * FROM scheduler"):
                try:
                    val = json.loads(row["value"])
                    if row["key"] == "last_scan_results":
                        app_data["last_scan_results"] = val
                    elif row["key"] == "last_scan_time":
                        app_data["last_scan_time"] = val
                    elif row["key"] == "last_scan_mode":
                        app_data["last_scan_mode"] = val
                    else:
                        app_data["scheduler"][row["key"]] = val
                except:
                    pass
        print(f"SQLite loaded: {len(app_data['known_devices'])} devices, {len(app_data['scan_history'])} scans, {len(app_data['alerts'])} alerts")
    except Exception as e:
        print(f"SQLite load error: {e}")
        # Fallback: try JSON migration
        if os.path.exists(DATA_FILE):
            try:
                with open(DATA_FILE, encoding="utf-8") as f:
                    loaded = json.load(f)
                app_data.update(loaded)
                save_data()  # migrate to SQLite
                print("Migrated from JSON to SQLite")
            except Exception as e2:
                print(f"JSON fallback error: {e2}")

load_data()

# Restore last scan results from saved data on startup
if app_data.get("last_scan_results"):
    scan_state["results"]   = app_data["last_scan_results"]
    scan_state["last_scan"] = app_data.get("last_scan_time", "")
    scan_state["last_mode"] = app_data.get("last_scan_mode", "top1000")
    n = len(scan_state["results"])
    scan_state["status"] = f"Last scan: {scan_state['last_scan']} — {n} Devices"

def check_alerts(new_devices):
    """Compare new scan against known devices, generate alerts."""
    now = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    new_ips = {d["ip"] for d in new_devices}

    # Build MAC -> existing device lookup for Identity over Time
    mac_to_ip = {}
    for existing_ip, kd in app_data["known_devices"].items():
        m = kd.get("mac","")
        if m and m != "-":
            mac_to_ip[m.upper()] = existing_ip

    for d in new_devices:
        ip  = d["ip"]
        mac = (d.get("mac") or "").upper()
        label = app_data["labels"].get(ip, "")

        # --- Identity over Time: find device by MAC even if IP changed ---
        prev_ip = mac_to_ip.get(mac) if mac and mac != "-" else None
        if prev_ip and prev_ip != ip:
            # IP has changed — migrate identity
            old_entry = app_data["known_devices"].pop(prev_ip)
            prev_ips  = old_entry.get("previous_ips", [])
            if prev_ip not in prev_ips:
                prev_ips.append(prev_ip)
            old_entry["previous_ips"] = prev_ips[-10:]  # keep last 10
            old_entry["last_seen"]    = now
            old_entry["last_ip"]      = ip
            app_data["known_devices"][ip] = old_entry
            app_data["alerts"].append({
                "id": f"ip_change_{int(time.time())}_{mac.replace(':','_')}",
                "type": "ip_change",
                "severity": "info",
                "message": f"IP address changed: {d.get('vendor','device')} was {prev_ip}, now {ip}",
                "ip": ip, "prev_ip": prev_ip, "mac": mac,
                "vendor": d.get("vendor",""), "hostname": d.get("hostname",""),
                "time": now, "acknowledged": False
            })
            log_event(f"IP-WECHSEL  {prev_ip} -> {ip}  MAC:{mac}  [{d.get('vendor','')}]", "warn")
        elif ip not in app_data["known_devices"]:
            # Genuinely new device
            app_data["alerts"].append({
                "id": f"alert_{int(time.time())}_{ip.replace('.','_')}",
                "type": "new_device",
                "severity": "warning",
                "message": f"New device discovered: {ip} ({d.get('vendor','Unknown')})",
                "ip": ip, "vendor": d.get("vendor",""),
                "hostname": d.get("hostname",""),
                "time": now, "acknowledged": False
            })
            app_data["known_devices"][ip] = {
                "mac": mac, "vendor": d.get("vendor",""),
                "hostname": d.get("hostname",""),
                "first_seen": now, "last_seen": now,
                "previous_ips": [], "label": label
            }
        else:
            # Known device, same IP — just update
            kd = app_data["known_devices"][ip]
            kd["last_seen"] = now
            if mac and mac != "-" and not kd.get("mac"):
                kd["mac"] = mac  # enrich if we now have MAC
            if d.get("vendor","Unknown") != "Unknown" and not kd.get("vendor"):
                kd["vendor"] = d.get("vendor","")

        # CVE alert
        if d.get("cves"):
            worst = "UNKNOWN"
            if d.get("cve_details"):
                sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"UNKNOWN":4}
                worst = min(d["cve_details"], key=lambda x: sev_order.get(x.get("severity","UNKNOWN"),4)).get("severity","UNKNOWN")
            app_data["alerts"].append({
                "id": f"cve_{int(time.time())}_{ip.replace('.','_')}",
                "type": "cve_found",
                "severity": "critical" if worst in ("CRITICAL","HIGH") else "warning",
                "message": f"CVEs found on {ip}: {', '.join(d['cves'][:3])}{'...' if len(d['cves'])>3 else ''}",
                "ip": ip,
                "cves": d["cves"],
                "worst_severity": worst,
                "time": now,
                "acknowledged": False
            })

    # Keep only last 100 alerts
    app_data["alerts"] = app_data["alerts"][-100:]

    # Attach last_seen + label to device results
    for d in new_devices:
        ip = d["ip"]
        known = app_data["known_devices"].get(ip, {})
        d["first_seen"] = known.get("first_seen", now)
        d["last_seen"] = now
        d["label"] = app_data["labels"].get(ip, "")

    save_data()

def get_arp_table():
    """Read OS ARP cache: returns {ip: mac} dict. Works on Windows + Linux."""
    result = {}
    try:
        if os.name == "nt":  # Windows
            out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    ip  = parts[0].strip()
                    mac = parts[1].strip().replace("-", ":").upper()
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip) and re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", mac):
                        result[ip] = mac
        else:  # Linux/macOS
            out = subprocess.run(["arp", "-n"], capture_output=True, text=True, timeout=10).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    ip  = parts[0].strip()
                    mac = parts[2].strip().upper()
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip) and re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", mac):
                        result[ip] = mac
    except Exception as e:
        print(f"ARP table read failed: {e}")
    return result

def enrich_with_arp(devices):
    """Fill in missing MACs, vendor lookup (mac-vendor-lookup > OUI_DB), reverse DNS."""
    global _mac_lookup
    arp = get_arp_table()
    for d in devices:
        ip = d.get("ip","")
        # MAC from ARP table
        if (not d.get("mac") or d["mac"] == "-") and ip in arp:
            d["mac"] = arp[ip]
        # Vendor lookup — mac-vendor-lookup first, fallback to OUI_DB
        if d.get("mac") and d["mac"] != "-" and (not d.get("vendor") or d["vendor"] == "Unknown"):
            if HAS_MAC_VENDOR:
                try:
                    if _mac_lookup is None:
                        _mac_lookup = _MacLookup()
                    d["vendor"] = _mac_lookup.lookup(d["mac"])
                except Exception:
                    oui = d["mac"].replace(":","").upper()[:6]
                    d["vendor"] = OUI_DB.get(oui, "Unknown")
            else:
                oui = d["mac"].replace(":","").upper()[:6]
                d["vendor"] = OUI_DB.get(oui, "Unknown")
        # Reverse DNS — dnspython first, fallback to socket
        if not d.get("hostname") or d["hostname"] in ("-", "", "Unknown"):
            if HAS_DNSPYTHON:
                try:
                    rev = _dns_reversename.from_address(ip)
                    answers = _dns_resolver.resolve(rev, "PTR", lifetime=2)
                    d["hostname"] = str(answers[0]).rstrip(".")
                except Exception:
                    pass
            if not d.get("hostname") or d["hostname"] in ("-", "", "Unknown"):
                try:
                    d["hostname"] = socket.gethostbyaddr(ip)[0]
                except Exception:
                    pass
    return devices

# Minimal OUI prefix table for most common vendors
OUI_DB = {
    "001A2B":"Cisco","00505A":"Cisco","B8BE4D":"AVM","28C68E":"AVM","A4B1E9":"AVM",
    "DC0B34":"AVM","1C3950":"AVM","E0CB4E":"AVM","48BA4E":"AVM",
    "B827EB":"Raspberry Pi","DC:A6:32":"Raspberry Pi","E4:5F:01":"Raspberry Pi",
    "001B63":"Apple","3C0754":"Apple","F0DBF8":"Apple","A85C2C":"Apple",
    "000C29":"VMware","005056":"VMware","000569":"VMware",
    "00155D":"Microsoft","7C1E52":"Microsoft","28187C":"Microsoft",
    "001E58":"D-Link","1CAFF7":"D-Link","B0C554":"D-Link",
    "14D64D":"TP-Link","50C7BF":"TP-Link","A42BB0":"TP-Link","E84DD0":"TP-Link",
    "C46E1F":"Nintendo","002709":"Nintendo","0009BF":"Nintendo",
    "606BBD":"Amazon","FC65DE":"Amazon","74C246":"Amazon",
    "B4E62D":"Samsung","8C77B3":"Samsung","6C2B59":"Samsung",
    "001C55":"Sonos","5CAAFA":"Sonos","94:9F:3E":"Sonos",
    "9059C3":"Synology","001132":"Synology",
    "7085C2":"Intel","8086F2":"Intel","A4C3F0":"Intel","C8D9D2":"Intel",
    "B47C9C":"Dell","F48E38":"Dell","BCEE7B":"Dell","A4BADB":"Dell",
    "000C76":"Hikvision","4C11AE":"Hikvision",
    "3894ED":"Xiaomi","64B473":"Xiaomi","D4970B":"Xiaomi",
}


def port_mode_label(port_mode):
    return {
        "top1000": "STD",
        "iana": "HIGH",
        "iana_udp": "HIGH+",
        "deep": "DEEP",
        "udp": "UDP",
    }.get(port_mode, str(port_mode).upper())

def port_mode_title(port_mode):
    return {
        "top1000": "STD (TCP Top 1000 + LAN-UDP)",
        "iana": "HIGH (IANA TCP + LAN-UDP)",
        "iana_udp": "HIGH+ (All IANA TCP + UDP)",
        "deep": "DEEP (all TCP ports 1-65535)",
        "udp": "UDP (kritische Ports)",
    }.get(port_mode, str(port_mode).upper())

def add_scan_history(devices, port_mode="top1000"):
    """Store a summary of this scan in SQLite + memory."""
    now = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    mode_label = port_mode_label(port_mode)
    summary = {
        "time": now,
        "device_count": len(devices),
        "vuln_count": sum(1 for d in devices if d.get("cves")),
        "port_count": sum(len(d.get("ports",[])) for d in devices),
        "port_mode": mode_label,
        "devices": [{"ip": d["ip"], "hostname": d.get("hostname",""), "vendor": d.get("vendor",""),
                     "cve_count": len(d.get("cves",[])), "port_count": len(d.get("ports",[]))} for d in devices]
    }
    save_scan_history_db(summary)
    app_data["scan_history"].append(summary)
    app_data["scan_history"] = app_data["scan_history"][-50:]
    save_data()

# --- Scheduler ---


def scheduler_loop():
    while True:
        time.sleep(60)
        cfg = app_data.get("scheduler", {})
        if not cfg.get("enabled"):
            continue

        mode     = cfg.get("sched_mode", "interval")
        now      = datetime.now()
        last_run = cfg.get("last_run")
        should_run = False

        if mode == "interval":
            interval = cfg.get("interval_minutes", 60)
            if last_run:
                try:
                    last_dt = datetime.strptime(last_run, "%d.%m.%Y %H:%M:%S")
                    if (now - last_dt).total_seconds() >= interval * 60:
                        should_run = True
                except:
                    should_run = True
            else:
                should_run = True

        elif mode == "daily":
            sched_time = cfg.get("sched_time", "02:00")
            try:
                h, m = map(int, sched_time.split(":"))
                target = now.replace(hour=h, minute=m, second=0, microsecond=0)
                # Run if within 1 minute of target and not already run today
                if abs((now - target).total_seconds()) < 60:
                    if last_run:
                        last_dt = datetime.strptime(last_run, "%d.%m.%Y %H:%M:%S")
                        if last_dt.date() < now.date():
                            should_run = True
                    else:
                        should_run = True
            except:
                pass

        elif mode == "weekly":
            sched_time    = cfg.get("sched_time", "02:00")
            sched_weekdays = cfg.get("sched_weekdays", [1])  # default Monday
            try:
                h, m = map(int, sched_time.split(":"))
                target = now.replace(hour=h, minute=m, second=0, microsecond=0)
                weekday = now.weekday() + 1  # Mon=1 ... Sun=7 → convert to 0=Sun,1=Mon,...
                weekday_js = now.weekday() + 1 if now.weekday() < 6 else 0  # JS: 0=Sun
                if weekday_js in sched_weekdays and abs((now - target).total_seconds()) < 60:
                    if last_run:
                        last_dt = datetime.strptime(last_run, "%d.%m.%Y %H:%M:%S")
                        if last_dt.date() < now.date():
                            should_run = True
                    else:
                        should_run = True
            except:
                pass

        if should_run and not scan_state["running"]:
            net, _ = get_local_network()
            ranges    = cfg.get("ranges", [net])
            port_mode = cfg.get("port_mode", "top1000")
            print(f"[Scheduler] Auto-Scan startet ({mode}): {ranges} [{port_mode}]")

            def scheduled_run(ranges=ranges, port_mode=port_mode):
                if port_mode == "udp":
                    # UDP-Only Scan
                    targets = ranges  # scan the ranges for live hosts first
                    UDP_PORTS = "53,67,68,123,161,162,500,514,520,1194,4500,5060,5353,69"
                    log_event("─── SCHEDULER: UDP SCAN ───", "batch")
                    # Quick ping sweep first
                    try:
                        ping_args = [NMAP_BIN, "-sn", "-T4"] + ranges + ["-oX", "-"]
                        proc = subprocess.Popen(ping_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        out, _ = proc.communicate(timeout=120)
                        live = [h["ip"] for h in parse_nmap_xml(out)]
                    except:
                        live = []
                    for ip in live:
                        try:
                            args = [NMAP_BIN, "-sU", "-Pn", "--open", "-p", UDP_PORTS,
                                    "--script", "snmp-info,dns-recursion",
                                    "--script-timeout", "10s", "-T4",
                                    "--host-timeout", "60s", "-oX", "-", ip]
                            proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                            out, _ = proc.communicate(timeout=90)
                            devs = parse_nmap_xml(out)
                            for d in devs:
                                update_known_device(d)
                        except Exception as e:
                            log_event(f"UDP error {ip}: {e}", "warn")
                    log_event("─── UDP SCAN COMPLETE ───", "batch")
                else:
                    run_scan(ranges, False, True, True, port_mode)

            thread = threading.Thread(target=scheduled_run, daemon=True)
            thread.start()
            app_data["scheduler"]["last_run"] = now.strftime("%d.%m.%Y %H:%M:%S")
            save_data()

scheduler_thread = threading.Thread(target=scheduler_loop, daemon=True)
scheduler_thread.start()



# --- Auto-detect home network ---
def get_local_network():
    """Erkennt automatisch das lokale Netzwerk — netifaces wenn verfügbar."""
    if HAS_NETIFACES:
        try:
            gws = _netifaces.gateways()
            gw = gws.get("default", {}).get(_netifaces.AF_INET)
            if gw:
                iface = gw[1]
                addrs = _netifaces.ifaddresses(iface).get(_netifaces.AF_INET, [{}])[0]
                ip   = addrs.get("addr", "")
                mask = addrs.get("netmask", "255.255.255.0")
                if ip:
                    import ipaddress
                    net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                    return str(net), ip
        except Exception as e:
            print(f"netifaces fallback: {e}")
    # Fallback: socket trick
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.rsplit(".", 1)
        return f"{parts[0]}.0/24", local_ip
    except:
        return "192.168.1.0/24", "192.168.1.1"



# ═══════════════════════════════════════════════════════════════
# INFRASTRUCTURE SECURITY TEMPLATES — v1.0.0
# Docker · Kubernetes · Proxmox · ESXi · LXD · Rancher · Registry
# ═══════════════════════════════════════════════════════════════

import urllib.request, urllib.error, ssl, socket, json as _json

def _http_get(url, timeout=4):
    """Simple HTTP GET, returns (status_code, body_str) or (None, None)"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "VulnScan/1.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(4096).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return None, None

def _port_open(ip, port, timeout=2):
    try:
        s = socket.create_connection((ip, int(port)), timeout=timeout)
        s.close(); return True
    except Exception:
        return False

# ── Finding Builder ──────────────────────────────────────────────
def _finding(severity, tech, title, detail, remediation):
    return {"severity": severity, "tech": tech, "title": title,
            "detail": detail, "remediation": remediation}

# ── AUTO-DETECT ──────────────────────────────────────────────────
def auto_detect_infra(ip, open_ports):
    """Returns list of detected infra technologies for this host."""
    detected = []
    port_set = set(str(p) for p in open_ports)

    checks = [
        ("docker",      ["2375","2376","2377"]),
        ("kubernetes",  ["6443","10250","10255","2379","2380","8001"]),
        ("lxd",         ["8443"]),
        ("rancher",     ["6443"]),
        ("proxmox",     ["8006"]),
        ("esxi",        ["902","5900"]),
        ("nomad",       ["4646","4647","4648"]),
        ("registry",    ["5000","5050","8081","8082"]),
        ("portainer",   ["9000","9443"]),
        ("harbor",      ["80","443"]),
        ("grafana",     ["3000"]),
        ("prometheus",  ["9090","9091"]),
        ("jenkins",     ["8080","50000"]),
        ("gitlab",      ["80","443"]),
        ("zabbix",      ["10051","10050","80","443"]),
        ("checkmk",     ["80","443"]),
        ("minio",       ["9000","9001"]),
        ("truenas",     ["80","443"]),
        ("synology",    ["5000","5001"]),
        ("qnap",        ["8080","443"]),
        ("pbs",         ["8007"]),
        ("fortinet",    ["541","8443","443"]),
        ("paloalto",    ["3978","443"]),
        ("mikrotik",    ["8291","80","443"]),
    ]
    for tech, ports in checks:
        if port_set & set(ports):
            detected.append(tech)
    return list(set(detected))

# ── DOCKER ───────────────────────────────────────────────────────
def check_docker(ip, open_ports):
    findings = []
    # Unprotected API on 2375
    if _port_open(ip, 2375):
        code, body = _http_get(f"http://{ip}:2375/v1.41/info")
        if code == 200:
            findings.append(_finding(
                "KRITISCH", "Docker",
                'Docker API accessible without authentication (port 2375)',
                f"Unauthenticated REST API — full host control may be possible. Response: {body[:200]}",
                "Do not expose the Docker API without TLS and authentication. Configure local socket access in /etc/docker/daemon.json."
            ))
            # Check privileged containers
            c2, b2 = _http_get(f"http://{ip}:2375/v1.41/containers/json")
            if c2 == 200 and '"Privileged":true' in b2:
                findings.append(_finding(
                    "HIGH", "Docker",
                    "Privileged container running",
                    'At least one container uses --privileged; host escape may be possible',
                    "Run containers without --privileged and grant capabilities individually."
                ))
    # TLS API on 2376
    if _port_open(ip, 2376):
        findings.append(_finding(
            "INFO", "Docker",
            'Docker TLS API accessible (port 2376)',
            'Docker API uses TLS; verify certificate validation',
            "Ensure client certificate authentication is enabled"
        ))
    # Portainer
    for port in ["9000", "9443"]:
        if _port_open(ip, port):
            scheme = "https" if port == "9443" else "http"
            code, body = _http_get(f"{scheme}://{ip}:{port}/api/status")
            if code in (200, 401):
                findings.append(_finding(
                    "MEDIUM" if code == 401 else "HIGH",
                    "Portainer",
                    f"Portainer Web-UI erreichbar (Port {port})",
                    'Portainer accessible; review authentication and default credentials' if code == 200 else 'Portainer accessible; review authentication and default credentials',
                    'Set a strong password, enable MFA and restrict network exposure'
                ))
    return findings

# ── KUBERNETES ────────────────────────────────────────────────────
def check_kubernetes(ip, open_ports):
    findings = []
    # API Server
    if _port_open(ip, 6443):
        code, body = _http_get(f"https://{ip}:6443/api/v1/namespaces")
        if code == 200:
            findings.append(_finding(
                "KRITISCH", "Kubernetes",
                'Kubernetes API accessible without authentication (port 6443)',
                'Unauthenticated cluster-admin access may expose secrets, pods and nodes',
                'Enable RBAC and disable anonymous access with --anonymous-auth=false'
            ))
        elif code == 401:
            findings.append(_finding(
                "INFO", "Kubernetes",
                'Kubernetes API accessible with authentication (port 6443)',
                'Kubernetes authentication is enabled',
                'Review RBAC and network policies regularly'
            ))
    # etcd
    if _port_open(ip, 2379):
        code, body = _http_get(f"http://{ip}:2379/v2/keys")
        if code == 200:
            findings.append(_finding(
                "KRITISCH", "Kubernetes/etcd",
                'etcd accessible without authentication (port 2379)',
                'Kubernetes secrets may be readable in plaintext, enabling cluster compromise',
                'Enable etcd client certificate authentication and restrict access'
            ))
    # Kubelet
    if _port_open(ip, 10250):
        code, body = _http_get(f"https://{ip}:10250/pods")
        if code == 200:
            findings.append(_finding(
                "KRITISCH", "Kubernetes",
                'Kubelet API accessible without authentication (port 10250)',
                'Node command execution may be possible; running pods may be exposed',
                'Set --anonymous-auth=false and --authorization-mode=Webhook for Kubelet'
            ))
    # Dashboard
    if _port_open(ip, 8001):
        code, _ = _http_get(f"http://{ip}:8001/api/v1/namespaces/kubernetes-dashboard/services")
        if code == 200:
            findings.append(_finding(
                "HIGH", "Kubernetes",
                "Kubernetes Dashboard exponiert (Port 8001)",
                'kubectl proxy running; dashboard accessible without authentication',
                "Access the dashboard locally through kubectl proxy; do not expose it externally"
            ))
    return findings

# ── PROXMOX ───────────────────────────────────────────────────────
def check_proxmox(ip, open_ports):
    findings = []
    if _port_open(ip, 8006):
        code, body = _http_get(f"https://{ip}:8006/api2/json/version")
        if code == 200:
            try:
                data = _json.loads(body)
                version = data.get("data", {}).get("version", "unknown")
                findings.append(_finding(
                    "INFO", "Proxmox",
                    f"Proxmox VE {version} detected (Port 8006)",
                    f"Proxmox Web-UI erreichbar. Version: {version}",
                    'Keep Proxmox updated, enable MFA and restrict SSH access'
                ))
            except Exception:
                pass
        # Check unauthenticated API access
        code2, body2 = _http_get(f"https://{ip}:8006/api2/json/nodes")
        if code2 == 200 and "data" in (body2 or ""):
            findings.append(_finding(
                "KRITISCH", "Proxmox",
                'Proxmox API accessible without authentication',
                "Node list accessible without authentication",
                "Require Proxmox API authentication tickets and restrict port 8006 to the management VLAN"
            ))
        elif code2 == 401:
            findings.append(_finding(
                "INFO", "Proxmox",
                "Proxmox API authentication enabled",
                "401 Unauthorized — Authentication funktioniert korrekt",
                'Enable MFA for all administrator accounts'
            ))
        # HTTP statt HTTPS?
        code3, _ = _http_get(f"http://{ip}:8006")
        if code3 == 200:
            findings.append(_finding(
                "MEDIUM", "Proxmox",
                'Proxmox accessible over HTTP',
                'Web interface responds over unencrypted HTTP',
                "HTTP→HTTPS Redirect erzwingen in /etc/default/pveproxy"
            ))
    return findings

# ── ESXi / vSphere ────────────────────────────────────────────────
def check_esxi(ip, open_ports):
    findings = []
    if _port_open(ip, 443):
        code, body = _http_get(f"https://{ip}/sdk")
        if code in (200, 500) and body and ("VMware" in body or "vim" in body.lower()):
            findings.append(_finding(
                "INFO", "ESXi/vSphere",
                'ESXi web interface or SOAP API detected (port 443)',
                'VMware ESXi or vCenter accessible',
                'Keep ESXi updated, disable unnecessary SSH access and enable lockdown mode'
            ))
        # ESXiArgs / CVE-2021-21985 check
        code2, body2 = _http_get(f"https://{ip}/ui/")
        if code2 == 200 and body2 and "VMware" in body2:
            findings.append(_finding(
                "MEDIUM", "ESXi",
                "ESXi host interface accessible",
                'ESXi management interface directly accessible',
                'Restrict the management interface to a dedicated VLAN'
            ))
    if _port_open(ip, 902):
        findings.append(_finding(
            "MEDIUM", "ESXi",
            'VMware AuthD port open (902)',
            'VMware AuthD or remote console accessible on port 902',
            'Restrict port 902 to the management network'
        ))
    return findings

# ── LXD ───────────────────────────────────────────────────────────
def check_lxd(ip, open_ports):
    findings = []
    if _port_open(ip, 8443):
        code, body = _http_get(f"https://{ip}:8443/1.0")
        if code == 200:
            findings.append(_finding(
                "HIGH", "LXD",
                'LXD API accessible without a client certificate (port 8443)',
                'Unauthenticated LXD API access may enable privilege escalation to root',
                'Require TLS client certificates and disable unused remote LXD access'
            ))
        elif code == 403:
            findings.append(_finding(
                "INFO", "LXD",
                'LXD API accessible with authentication (port 8443)',
                "403 — Client certificate required",
                'Rotate certificates regularly'
            ))
    return findings

# ── CONTAINER REGISTRY ────────────────────────────────────────────
def check_registry(ip, open_ports):
    findings = []
    for port in ["5000", "5050", "8081", "8082"]:
        if not _port_open(ip, port): continue
        scheme = "https" if port in ("5050","8082") else "http"
        code, body = _http_get(f"{scheme}://{ip}:{port}/v2/")
        if code == 200:
            # List repositories without auth
            code2, body2 = _http_get(f"{scheme}://{ip}:{port}/v2/_catalog")
            if code2 == 200:
                try:
                    repos = _json.loads(body2).get("repositories", [])
                    findings.append(_finding(
                        "HIGH", "Container Registry",
                        f"Registry without authentication — {len(repos)} images readable (Port {port})",
                        f"Images: {', '.join(repos[:5])}{'...' if len(repos)>5 else ''}",
                        'Protect the registry with authentication and enable RBAC'
                    ))
                except Exception:
                    findings.append(_finding(
                        "HIGH", "Container Registry",
                        f"Registry accessible without authentication (Port {port})",
                        "Container registry API accessible without authentication",
                        'Require authentication and restrict registry network exposure'
                    ))
        elif code == 401:
            findings.append(_finding(
                "INFO", "Container Registry",
                f"Registry authentication enabled (Port {port})",
                "401 — Authentication required",
                'Rotate tokens and scan container images regularly'
            ))
    return findings

# ── RANCHER ───────────────────────────────────────────────────────
def check_rancher(ip, open_ports):
    findings = []
    for port in ["80", "443"]:
        if not _port_open(ip, port): continue
        scheme = "https" if port == "443" else "http"
        code, body = _http_get(f"{scheme}://{ip}:{port}/v3")
        if code == 200 and body and "rancher" in body.lower():
            findings.append(_finding(
                "HIGH", "Rancher",
                f"Rancher API accessible without authentication (Port {port})",
                "Rancher Kubernetes Management — unauthenticated API",
                'Set a Rancher administrator password, enable RBAC and restrict access to VPN users'
            ))
    return findings

# ── NOMAD ─────────────────────────────────────────────────────────
def check_nomad(ip, open_ports):
    findings = []
    if _port_open(ip, 4646):
        code, body = _http_get(f"http://{ip}:4646/v1/nodes")
        if code == 200:
            findings.append(_finding(
                "KRITISCH", "HashiCorp Nomad",
                'Nomad API accessible without authentication (port 4646)',
                "Nodes, jobs and secrets accessible without authentication",
                'Enable Nomad ACLs and TLS for all components'
            ))
    return findings

# ── GRAFANA ───────────────────────────────────────────────────────
def check_grafana(ip, open_ports):
    findings = []
    if _port_open(ip, 3000):
        code, body = _http_get(f"http://{ip}:3000/api/health")
        if code == 200:
            findings.append(_finding("MEDIUM","Grafana",'Grafana accessible (port 3000)',
                'Review Grafana default credentials and disable anonymous access','Review Grafana default credentials and disable anonymous access'))
            code2, body2 = _http_get(f"http://{ip}:3000/api/datasources")
            if code2 == 200:
                findings.append(_finding("HIGH","Grafana","Grafana data sources readable without authentication",
                    "Configured data sources, potentially including credentials, are visible","Require authentication: GF_AUTH_ANONYMOUS_ENABLED=false"))
    return findings

# ── PROMETHEUS ────────────────────────────────────────────────────
def check_prometheus(ip, open_ports):
    findings = []
    for port in [9090, 9091]:
        if _port_open(ip, port):
            code, body = _http_get(f"http://{ip}:{port}/-/healthy")
            if code == 200:
                findings.append(_finding("MEDIUM","Prometheus",f"Prometheus accessible (Port {port})",
                    "Metrics and targets visible without authentication; internal infrastructure may be exposed",
                    "Use an authenticated reverse proxy and restrict access to internal networks."))
    return findings

# ── JENKINS ───────────────────────────────────────────────────────
def check_jenkins(ip, open_ports):
    findings = []
    if _port_open(ip, 8080):
        code, body = _http_get(f"http://{ip}:8080/api/json")
        if code == 200:
            findings.append(_finding("HIGH","Jenkins",'Jenkins API accessible without authentication (port 8080)',
                "Jobs, build history or credentials visible without login",
                'Enable Jenkins security and configure authorization'))
    return findings

# ── MINIO ─────────────────────────────────────────────────────────
def check_minio(ip, open_ports):
    findings = []
    for port in [9000, 9001]:
        if _port_open(ip, port):
            code, body = _http_get(f"http://{ip}:{port}/minio/health/live")
            if code == 200:
                findings.append(_finding("MEDIUM","MinIO",f"MinIO erreichbar (Port {port})",
                    'Review MinIO default credentials',
                    'Change root credentials, restrict bucket access and enable TLS'))
    return findings

# ── SYNOLOGY ─────────────────────────────────────────────────────
def check_synology(ip, open_ports):
    findings = []
    for port, scheme in [("5000","http"),("5001","https")]:
        if _port_open(ip, int(port)):
            code, body = _http_get(f"{scheme}://{ip}:{port}/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query")
            if code == 200 and "SYNO" in body:
                findings.append(_finding("MEDIUM","Synology DSM",f"Synology DSM erreichbar (Port {port})",
                    'Review DSM default or empty administrator credentials',
                    'Rename the default administrator account, enable MFA and automatic blocking'))
    return findings

# ── TRUENAS ───────────────────────────────────────────────────────
def check_truenas(ip, open_ports):
    findings = []
    if _port_open(ip, 80) or _port_open(ip, 443):
        code, body = _http_get(f"https://{ip}/api/v1.0/system/info")
        if code == 200 and "TrueNAS" in body:
            findings.append(_finding("MEDIUM","TrueNAS","TrueNAS API accessible",
                'Review TrueNAS default or empty root credentials',
                'Set a root password, require SSH keys and enforce HTTPS'))
    return findings

# ── FORTINET ─────────────────────────────────────────────────────
def check_fortinet(ip, open_ports):
    findings = []
    for port in [443, 8443]:
        if _port_open(ip, port):
            code, body = _http_get(f"https://{ip}:{port}/remote/login")
            if code == 200 and ("FortiGate" in body or "Fortinet" in body or "fortigate" in body.lower()):
                findings.append(_finding("HIGH","Fortinet FortiGate",f"FortiGate SSL-VPN login reachable (port {port})",
                    'FortiGate detected; check applicability of CVE-2023-27997 and CVE-2022-40684',
                    'Update FortiOS to a supported fixed version and restrict SSL VPN access'))
    return findings

# ── MIKROTIK ─────────────────────────────────────────────────────
def check_mikrotik(ip, open_ports):
    findings = []
    if _port_open(ip, 8291):
        findings.append(_finding("MEDIUM","MikroTik",'MikroTik Winbox port open (8291)',
            'Winbox accessible; check applicability of CVE-2018-14847',
            'Update Winbox and restrict management access to trusted IP addresses'))
    if _port_open(ip, 80):
        code, body = _http_get(f"http://{ip}/")
        if code == 200 and ("MikroTik" in body or "routeros" in body.lower()):
            findings.append(_finding("MEDIUM","MikroTik",'MikroTik web interface accessible (port 80)',
                'Review RouterOS default or empty administrator credentials',
                'Set a strong password, require HTTPS and restrict management access'))
    return findings

# ── MAIN DISPATCHER ──────────────────────────────────────────────
def run_infra_templates(ip, open_ports, vendor="", os_info="", snmp_info=""):
    """
    Hauptfunktion — erkennt Infra-Technologien und führt alle
    passenden Security-Checks durch. Gibt Liste of findings zurück.
    """
    all_findings = []
    port_list = [str(p) for p in open_ports]
    detected = auto_detect_infra(ip, port_list)

    checkers = {
        "docker":      check_docker,
        "kubernetes":  check_kubernetes,
        "proxmox":     check_proxmox,
        "esxi":        check_esxi,
        "lxd":         check_lxd,
        "registry":    check_registry,
        "rancher":     check_rancher,
        "nomad":       check_nomad,
        "grafana":     check_grafana,
        "prometheus":  check_prometheus,
        "jenkins":     check_jenkins,
        "minio":       check_minio,
        "synology":    check_synology,
        "truenas":     check_truenas,
        "fortinet":    check_fortinet,
        "mikrotik":    check_mikrotik,
    }
    for tech in detected:
        fn = checkers.get(tech)
        if fn:
            try:
                results = fn(ip, port_list)
                all_findings.extend(results)
            except Exception:
                pass

    return all_findings, detected


# ═══════════════════════════════════════════════════════════════
# PYTHON SECURITY CHECKS — Phase 3 (100% Python, no extra tools)
# ═══════════════════════════════════════════════════════════════

import urllib.request
import urllib.error
import ssl
import socket
import concurrent.futures

# Optional enhanced tools (Stufe 1 upgrades)
try:
    import netifaces2 as _netifaces
    HAS_NETIFACES = True  # netifaces2 on Windows, netifaces on Linux
except ImportError:
    HAS_NETIFACES = False

try:
    import dns.resolver as _dns_resolver
    import dns.reversename as _dns_reversename
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    from mac_vendor_lookup import MacLookup as _MacLookup
    # Initialize lazily so importing the web app does not create an asyncio loop.
    _mac_lookup = None
    HAS_MAC_VENDOR = True
except ImportError:
    _mac_lookup = None
    HAS_MAC_VENDOR = False


from datetime import timezone

# --- HTTP Security Header Check ---
SECURITY_HEADERS = {
    "Strict-Transport-Security": ("MISSING HSTS",       "MEDIUM", 'HTTP Strict Transport Security is missing; HTTPS is not enforced by this header'),
    "X-Frame-Options":           ("MISSING X-Frame",    "LOW",    "No X-Frame-Options clickjacking protection header is set."),
    "X-Content-Type-Options":    ("MISSING X-CTO",      "LOW",    'MIME sniffing is not disabled'),
    "Content-Security-Policy":   ("MISSING CSP",        "MEDIUM", 'Content Security Policy is missing; review XSS protection'),
    "X-XSS-Protection":          ("MISSING XSS-Hdr",   "LOW",    "No legacy X-XSS-Protection header is set."),
    "Referrer-Policy":           ("MISSING Referrer",   "LOW",    'Referrer Policy is not configured'),
    "Permissions-Policy":        ("MISSING Perms",      "LOW",    'Permissions Policy is not configured'),
}

RISKY_HEADERS = {
    "Server":       ("INFO EXPOSED",  "LOW",    "Server banner discloses the software version."),
    "X-Powered-By": ("INFO EXPOSED",  "LOW",    "X-Powered-By discloses backend technology."),
    "X-AspNet-Version": ("INFO EXPOSED","LOW",  "ASP.NET Version exposed."),
}

# --- Exposed Path Check ---
EXPOSED_PATHS = [
    ("/",                  None,    None),
    ("/.env",              None,    ("EXPOSED .env",    "CRITICAL", 'Environment file publicly accessible; passwords or keys may be exposed')),
    ("/.git/HEAD",         "ref:",  ("EXPOSED .git",    "CRITICAL", 'Git repository publicly accessible; source code or secrets may be exposed')),
    ("/config.json",       None,    ("EXPOSED config",  "HIGH",     'Configuration file publicly accessible')),
    ("/wp-config.php",     None,    ("EXPOSED wp-cfg",  "HIGH",     'WordPress configuration accessible')),
    ("/phpinfo.php",       "PHP",   ("EXPOSED phpinfo", "HIGH",     "PHP information page publicly accessible; system details visible.")),
    ("/admin",             None,    ("EXPOSED /admin",  "MEDIUM",   "Administrator panel accessible.")),
    ("/admin/",            None,    None),
    ("/phpmyadmin",        None,    ("EXPOSED phpMyAdmin","HIGH",   'phpMyAdmin accessible; review database administration exposure')),
    ("/phpmyadmin/",       None,    None),
    ("/manager/html",      None,    ("EXPOSED Tomcat",  "HIGH",     "Tomcat Manager accessible.")),
    ("/wp-admin",          None,    ("EXPOSED WP-Admin","MEDIUM",   'WordPress administrator login accessible')),
    ("/login",             None,    ("INFO /login",     "LOW",      "Login page found.")),
    ("/setup",             None,    ("EXPOSED /setup",  "MEDIUM",   "Setup page accessible.")),
    ("/robots.txt",        None,    None),
    ("/backup",            None,    ("EXPOSED /backup", "HIGH",     'Backup directory accessible')),
    ("/backup.zip",        None,    ("EXPOSED backup",  "CRITICAL", 'Backup archive directly accessible')),
    ("/db_backup.sql",     None,    ("EXPOSED DB dump", "CRITICAL", 'Database dump directly accessible')),
    ("/.htpasswd",         None,    ("EXPOSED htpasswd","CRITICAL", "Password file accessible!")),
    ("/api",               None,    ("INFO /api",       "LOW",      "API endpoint accessible.")),
    ("/api/v1",            None,    None),
    ("/swagger-ui.html",   "swagger",("EXPOSED Swagger","MEDIUM",   "Swagger API documentation publicly accessible.")),
    ("/actuator",          None,    ("EXPOSED Actuator","HIGH",     'Spring Actuator accessible; internal information may be exposed')),
    ("/server-status",     "Apache",("EXPOSED mod_status","MEDIUM", 'Apache mod_status accessible')),
    ("/nginx_status",      None,    ("EXPOSED nginx",   "MEDIUM",   "Nginx status accessible.")),
]

# --- Default Credential Check ---
DEFAULT_CREDS = [
    # (path, username, password, check_string, name)
    ("/",                "admin",      "admin",      None,         "Default admin/admin"),
    ("/",                "admin",      "password",   None,         "Default admin/password"),
    ("/",                "admin",      "",           None,         "Default admin/(empty)"),
    ("/",                "root",       "root",       None,         "Default root/root"),
    ("/admin",           "admin",      "admin",      None,         "Admin admin/admin"),
    ("/login",           "admin",      "1234",       None,         "Default admin/1234"),
    # Fritz!Box
    ("/",                "",           "0000",       "fritzbox|fritz",  "FritzBox empty/0000"),
    # TP-Link
    ("/",                "admin",      "admin",      "tp-link|tplink",  "TP-Link admin/admin"),
    # Hikvision cameras
    ("/ISAPI/Security/userCheck", "admin", "12345",  None,         "Hikvision admin/12345"),
    # D-Link
    ("/",                "Admin",      "",           "d-link|dlink",    "D-Link Admin/(empty)"),
    # Ubiquiti
    ("/",                "ubnt",       "ubnt",       None,         "Ubiquiti ubnt/ubnt"),
    # Synology NAS
    ("/webman/login.cgi","admin",      "",           "synology|dsm",    "Synology admin/(empty)"),
]

def _http_get(url, timeout=4, verify_ssl=False):
    """Simple HTTP GET, returns (status_code, headers_dict, body_snippet)."""
    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VulnScan-Pro/1.0.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(512).decode("utf-8", errors="ignore")
            return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers) if e.headers else {}, ""
    except Exception:
        return None, {}, ""

def _http_post_basic(url, username, password, timeout=4):
    """Try HTTP Basic Auth."""
    import base64
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        creds = base64.b64encode(f"{username}:{password}".encode()).decode()
        req = urllib.request.Request(url, headers={
            "User-Agent": "VulnScan-Pro/1.0.0",
            "Authorization": f"Basic {creds}"
        })
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(256).decode("utf-8", errors="ignore")
            return resp.status, body
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return None, ""

def _ssl_check(ip, port=443, timeout=4):
    """Vollständiger SSL/TLS Check — Protokoll, Cipher, Zertifikat, bekannte Angriffe."""
    findings = []

    # Schwache Cipher-Namen
    WEAK_CIPHERS_RC4    = ["RC4"]
    WEAK_CIPHERS_DES    = ["DES-CBC", "DES-CBC3", "3DES", "TRIPLE"]
    WEAK_CIPHERS_EXPORT = ["EXP-", "EXPORT"]
    WEAK_CIPHERS_NULL   = ["NULL", "ANON"]
    WEAK_CIPHERS_MD5    = ["MD5"]
    BEAST_CIPHERS       = ["CBC"]  # CBC in TLS 1.0 → BEAST
    SWEET32_CIPHERS     = ["DES-CBC3", "3DES"]  # 64-bit block cipher

    def try_connect(protocol, ciphers=None):
        """Versuche Verbindung mit bestimmtem Protokoll/Cipher. Gibt (version, cipher_name, cert) zurück."""
        try:
            ctx = ssl.SSLContext(protocol)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if ciphers:
                ctx.set_ciphers(ciphers)
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                    return ssock.version(), ssock.cipher(), ssock.getpeercert()
        except Exception:
            return None, None, None

    def make_finding(name, severity, description, template_id):
        return {
            "name": name, "severity": severity, "description": description,
            "matched_at": f"https://{ip}:{port}",
            "source": "ssl-check", "template_id": template_id
        }

    # ── 1. Aktive Verbindung — Version + Cipher + Zertifikat ────────
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert   = ssock.getpeercert()
                cipher = ssock.cipher()  # (name, protocol, bits)
                proto  = ssock.version()

                # Zertifikat abgelaufen / läuft ab
                if cert:
                    import time
                    exp_str = cert.get("notAfter", "")
                    if exp_str:
                        exp_ts = ssl.cert_time_to_seconds(exp_str)
                        days_left = (exp_ts - time.time()) / 86400
                        if days_left < 0:
                            findings.append(make_finding(
                                "SSL CERTIFICATE EXPIRED", "CRITICAL",
                                f"Certificate expired {abs(int(days_left))} days ago.",
                                "ssl-expired"))
                        elif days_left < 14:
                            findings.append(make_finding(
                                "SSL CERTIFICATE EXPIRING", "HIGH",
                                f"Certificate expires in {int(days_left)} days.",
                                "ssl-expiring-critical"))
                        elif days_left < 30:
                            findings.append(make_finding(
                                "SSL CERTIFICATE EXPIRING SOON", "MEDIUM",
                                f"Certificate expires in {int(days_left)} days.",
                                "ssl-expiring"))

                # Aktives Protokoll
                if proto in ("SSLv2", "SSLv3"):
                    findings.append(make_finding(
                        f"CRITICAL PROTOCOL: {proto}", "CRITICAL",
                        f"{proto} is broken; POODLE attacks may be possible.",
                        "ssl-sslv3"))
                elif proto in ("TLSv1", "TLSv1.1"):
                    findings.append(make_finding(
                        f"DEPRECATED PROTOCOL: {proto}", "HIGH",
                        f"{proto} is insecure; BEAST attacks may be possible with TLS 1.0. Use TLS 1.2 or later.",
                        "ssl-tls10-11"))

                # Aktiver Cipher
                if cipher and cipher[0]:
                    cname = cipher[0].upper()
                    bits  = cipher[2] or 0
                    if any(w in cname for w in WEAK_CIPHERS_NULL):
                        findings.append(make_finding(
                            f"NULL CIPHER ACTIVE: {cipher[0]}", "CRITICAL",
                            'Connection without encryption is possible', "ssl-null-cipher"))
                    elif any(w in cname for w in WEAK_CIPHERS_EXPORT):
                        findings.append(make_finding(
                            f"EXPORT CIPHER: {cipher[0]}", "CRITICAL",
                            'Export cipher limited to 40/56 bits; FREAK attack may be possible', "ssl-export-cipher"))
                    elif any(w in cname for w in WEAK_CIPHERS_RC4):
                        findings.append(make_finding(
                            f"RC4 CIPHER: {cipher[0]}", "HIGH",
                            'RC4 is broken; statistical bias attacks may be possible', "ssl-rc4"))
                    elif any(w in cname for w in WEAK_CIPHERS_DES):
                        findings.append(make_finding(
                            f"3DES/SWEET32: {cipher[0]}", "HIGH",
                            '64-bit block cipher; SWEET32 attack may be possible with large data volumes', "ssl-sweet32"))
                    elif bits > 0 and bits < 128:
                        findings.append(make_finding(
                            f"WEAK KEY LENGTH: {bits} Bit", "HIGH",
                            f"Cipher {cipher[0]} uses only {bits} bits — insecure.", "ssl-weak-bits"))

    except Exception:
        return findings  # Port nicht erreichbar / kein SSL

    # ── 2. SSLv3 Support testen → POODLE ────────────────────────────
    try:
        ver, cph, _ = try_connect(ssl.PROTOCOL_SSLv23)
        if ver == "SSLv3":
            findings.append(make_finding(
                "SSLv3 ACTIVE — POODLE ANGRIFF", "CRITICAL",
                'Server accepts SSLv3; POODLE (CVE-2014-3566) may expose encrypted data',
                "ssl-poodle"))
    except Exception:
        pass

    # ── 3. TLS 1.0 → BEAST ──────────────────────────────────────────
    try:
        ctx10 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx10.check_hostname = False
        ctx10.verify_mode = ssl.CERT_NONE
        ctx10.minimum_version = ssl.TLSVersion.TLSv1
        ctx10.maximum_version = ssl.TLSVersion.TLSv1
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx10.wrap_socket(sock, server_hostname=ip) as ssock:
                cph = ssock.cipher()
                if cph and "CBC" in (cph[0] or "").upper():
                    findings.append(make_finding(
                        "TLS 1.0 + CBC — BEAST ANGRIFF", "HIGH",
                        'TLS 1.0 with CBC cipher enabled; BEAST (CVE-2011-3389) may be possible',
                        "ssl-beast"))
    except Exception:
        pass

    # ── 4. DH Parameter Größe → Logjam ──────────────────────────────
    try:
        ctx_dh = ssl.create_default_context()
        ctx_dh.check_hostname = False
        ctx_dh.verify_mode = ssl.CERT_NONE
        ctx_dh.set_ciphers("DHE:ECDHE")
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx_dh.wrap_socket(sock, server_hostname=ip) as ssock:
                cph = ssock.cipher()
                if cph and "DHE" in (cph[0] or "").upper() and (cph[2] or 0) < 2048:
                    findings.append(make_finding(
                        f"SCHWACHER DH-PARAMETER: {cph[2]} Bit", "HIGH",
                        f"Diffie-Hellman Parameter < 2048 Bit ({cph[2]} Bit). Logjam (CVE-2015-4000) may be possible.",
                        "ssl-logjam"))
    except Exception:
        pass

    # ── 5. RC4 Support testen ────────────────────────────────────────
    try:
        ver, cph, _ = try_connect(ssl.PROTOCOL_TLS_CLIENT, "RC4")
        if ver and cph:
            findings.append(make_finding(
                "RC4 CIPHER UNTERSTÜTZT", "HIGH",
                "Server accepts RC4, which is cryptographically broken.",
                "ssl-rc4-support"))
    except Exception:
        pass

    return findings


def _check_smtp(ip, port=25, timeout=5):
    """SMTP Security Check — Open Relay, StartTLS, STARTTLS-Downgrade."""
    findings = []
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        banner = s.recv(1024).decode("utf-8", errors="ignore")

        # EHLO
        s.sendall(b"EHLO vulnscan-scanner.local\r\n")
        resp = s.recv(2048).decode("utf-8", errors="ignore")

        # StartTLS verfügbar?
        has_starttls = "STARTTLS" in resp.upper()
        if not has_starttls:
            findings.append({
                "name": "SMTP — STARTTLS FEHLT", "severity": "MEDIUM",
                "description": f"SMTP port {port} does not support STARTTLS. Email may be transmitted without encryption.",
                "matched_at": f"smtp://{ip}:{port}", "source": "smtp-check", "template_id": "smtp-no-starttls"
            })

        # Open Relay Test
        s.sendall(b"MAIL FROM:<test@example.com>\r\n")
        r1 = s.recv(512).decode("utf-8", errors="ignore")
        s.sendall(b"RCPT TO:<external@gmail.com>\r\n")
        r2 = s.recv(512).decode("utf-8", errors="ignore")
        if r2.startswith("2"):
            findings.append({
                "name": "SMTP OPEN RELAY", "severity": "CRITICAL",
                "description": f"SMTP server accepts external recipients without authentication and may be abused for spam or phishing.",
                "matched_at": f"smtp://{ip}:{port}", "source": "smtp-check", "template_id": "smtp-open-relay"
            })

        s.sendall(b"QUIT\r\n")
        s.close()
    except Exception:
        pass
    return findings


def _check_rdp(ip, port=3389, timeout=4):
    """RDP Security Check — NLA, Verschlüsselung."""
    findings = []
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        # RDP Connection Request
        pkt = bytes([
            0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03,
            0x00, 0x00, 0x00
        ])
        s.sendall(pkt)
        resp = s.recv(1024)
        s.close()

        if resp and len(resp) > 10:
            # Protokoll-Flags prüfen
            if len(resp) >= 19:
                proto_flags = resp[15] if len(resp) > 15 else 0
                if proto_flags & 0x01 == 0:
                    findings.append({
                        "name": "RDP — NLA NICHT ERZWUNGEN", "severity": "MEDIUM",
                        "description": 'RDP accepts connections without Network Level Authentication; credentials may be exposed before authentication',
                        "matched_at": f"rdp://{ip}:{port}", "source": "rdp-check", "template_id": "rdp-no-nla"
                    })
            findings.append({
                "name": "RDP PORT OFFEN", "severity": "LOW",
                "description": f"RDP port {port} accessible. Review brute-force protection and applicability of BlueKeep (CVE-2019-0708).",
                "matched_at": f"rdp://{ip}:{port}", "source": "rdp-check", "template_id": "rdp-exposed"
            })
    except Exception:
        pass
    return findings


def _check_ssh_algos(ip, port=22, timeout=4):
    """SSH Security Check — Version, Algorithmen."""
    findings = []
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        banner = s.recv(256).decode("utf-8", errors="ignore").strip()
        s.close()

        if banner:
            # SSH Version
            if "SSH-1" in banner:
                findings.append({
                    "name": "SSH VERSION 1 ACTIVE", "severity": "CRITICAL",
                    "description": f"SSH-1 ist komplett gebrochen. Banner: {banner[:60]}",
                    "matched_at": f"ssh://{ip}:{port}", "source": "ssh-check", "template_id": "ssh-v1"
                })
            # Version Banner exposure
            if len(banner) > 10:
                findings.append({
                    "name": f"SSH BANNER: {banner[:60]}", "severity": "LOW",
                    "description": 'SSH banner discloses a software version that can aid vulnerability identification',
                    "matched_at": f"ssh://{ip}:{port}", "source": "ssh-check", "template_id": "ssh-banner"
                })
    except Exception:
        pass
    return findings


def _check_db_exposed(ip, port, db_name, timeout=3):
    """Prüft ob Datenbank-Port ohne Auth erreichbar ist."""
    findings = []
    try:
        s = socket.create_connection((ip, int(port)), timeout=timeout)
        banner = s.recv(256)
        s.close()
        if banner:
            findings.append({
                "name": f"{db_name} PORT OFFEN", "severity": "HIGH",
                "description": f"{db_name} port {port} directly accessible. Review authentication and firewall rules.",
                "matched_at": f"{db_name.lower()}://{ip}:{port}", "source": "db-check",
                "template_id": f"db-exposed-{db_name.lower()}"
            })
    except Exception:
        pass
    return findings


def run_python_checks(device):
    """Run all Python security checks against a single device. Returns list of findings."""
    ip = device["ip"]
    open_ports = [p["port"] for p in device.get("ports", [])]
    services   = {p["port"]: p.get("service","") for p in device.get("ports", [])}
    findings = []

    # Determine which ports/protocols to check
    http_ports  = [p for p in open_ports if p in ("80","8080","8008","8888","8000","81","8181","8089","8081")]
    https_ports = [p for p in open_ports if p in ("443","8443","8444","4443","8089")]

    if not http_ports and not https_ports:
        return findings

    def check_http(port, scheme):
        base = f"{scheme}://{ip}:{port}"
        port_findings = []

        # 1. Security Headers
        status, headers, body = _http_get(base, timeout=4)
        if status is not None:
            hdrs_lower = {k.lower(): v for k, v in headers.items()}
            for hdr, (name, sev, desc) in SECURITY_HEADERS.items():
                if hdr.lower() not in hdrs_lower:
                    port_findings.append({
                        "name": name, "severity": sev, "description": desc,
                        "matched_at": base, "source": "header-check",
                        "template_id": f"missing-header-{hdr.lower()}"
                    })
            for hdr, (name, sev, desc) in RISKY_HEADERS.items():
                if hdr.lower() in hdrs_lower:
                    val = hdrs_lower[hdr.lower()]
                    port_findings.append({
                        "name": f"{name}: {val[:40]}",
                        "severity": sev, "description": desc,
                        "matched_at": base, "source": "header-check",
                        "template_id": f"exposed-header-{hdr.lower()}"
                    })

        # 2. Exposed Paths
        for path, body_check, finding_info in EXPOSED_PATHS:
            if finding_info is None:
                continue
            url = f"{base}{path}"
            st, hdrs2, body2 = _http_get(url, timeout=3)
            if st in (200, 301, 302, 403):
                if body_check and body_check.lower() not in body2.lower():
                    continue
                name, sev, desc = finding_info
                port_findings.append({
                    "name": name, "severity": sev, "description": desc,
                    "matched_at": url, "source": "path-check",
                    "template_id": f"exposed-path",
                })

        # 3. Default Credentials (Basic Auth only, no form login)
        for path, user, pw, body_hint, cred_name in DEFAULT_CREDS:
            url = f"{base}{path}"
            if body_hint:
                # Only test if body hint matches earlier response
                st0, _, b0 = _http_get(url, timeout=3)
                if not b0 or body_hint.split("|")[0] not in b0.lower():
                    continue
            st_auth, body_auth = _http_post_basic(url, user, pw, timeout=3)
            if st_auth in (200, 302) and st_auth != 401:
                port_findings.append({
                    "name": f"DEFAULT CREDENTIALS: {cred_name}",
                    "severity": "CRITICAL",
                    "description": f"Default credentials accepted! User={user} Pass={pw} — change immediately!",
                    "matched_at": url, "source": "default-creds",
                    "template_id": "default-credentials",
                })
                break  # One is enough

        return port_findings

    # Run checks in parallel per port
    tasks = [(p, "http") for p in http_ports] + [(p, "https") for p in https_ports]
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        futures = {ex.submit(check_http, p, s): (p, s) for p, s in tasks}
        for fut in concurrent.futures.as_completed(futures, timeout=30):
            try:
                findings.extend(fut.result())
            except Exception:
                pass

    # 4. SSL Check on all HTTPS ports
    for port in https_ports:
        try:
            findings.extend(_ssl_check(ip, int(port)))
        except Exception:
            pass

    # 5. SMTP Check
    for port in [p for p in open_ports if p in ("25","465","587","2525")]:
        try:
            findings.extend(_check_smtp(ip, int(port)))
        except Exception:
            pass

    # 6. RDP Check
    if "3389" in open_ports:
        try:
            findings.extend(_check_rdp(ip, 3389))
        except Exception:
            pass

    # 7. SSH Check
    for port in [p for p in open_ports if p in ("22","2222","22222")]:
        try:
            findings.extend(_check_ssh_algos(ip, int(port)))
        except Exception:
            pass

    # 8. Datenbank-Ports offen?
    db_ports = {
        "3306": "MySQL", "5432": "PostgreSQL", "1433": "MSSQL",
        "1521": "OracleDB", "27017": "MongoDB", "6379": "Redis",
        "5984": "CouchDB", "9200": "Elasticsearch"
    }
    for port, db_name in db_ports.items():
        if port in open_ports:
            try:
                findings.extend(_check_db_exposed(ip, port, db_name))
            except Exception:
                pass

    # Deduplicate by template_id + matched_at
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("template_id",""), f.get("matched_at",""))
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SNMP WALK — läuft wenn Port 161/udp offen, liefert Interfaces + VLANs
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def snmp_walk_device(ip, community="public", timeout=5):
    """
    SNMP Walk gegen ein Gerät. Probiert community strings.
    Liest: SysDescr, Interfaces, IP-Adressen, Routing-Tabelle, Bridge-MIB (VLANs).
    Gibt dict zurück oder None wenn kein SNMP.
    """
    try:
        from pysnmp.hlapi import (
            getCmd, nextCmd, SnmpEngine, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity
        )
    except ImportError:
        return None  # pysnmp not installed

    communities = [community, "public", "private", "read", "snmp"]
    engine = SnmpEngine()
    result = {}

    for comm in communities:
        try:
            # Test: SysDescr (1.3.6.1.2.1.1.1.0)
            err_ind, err_stat, _, var_binds = next(
                getCmd(engine, CommunityData(comm), UdpTransportTarget((ip, 161), timeout=timeout, retries=1),
                       ContextData(), ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")))
            )
            if err_ind or err_stat:
                continue
            result["community"] = comm
            result["sys_descr"] = str(var_binds[0][1]) if var_binds else ""
            break
        except Exception:
            continue

    if "community" not in result:
        return None  # kein SNMP erreichbar

    comm = result["community"]

    # SysName (1.3.6.1.2.1.1.5.0)
    try:
        _, _, _, vb = next(getCmd(engine, CommunityData(comm),
            UdpTransportTarget((ip, 161), timeout=timeout, retries=1),
            ContextData(), ObjectType(ObjectIdentity("1.3.6.1.2.1.1.5.0"))))
        result["sys_name"] = str(vb[0][1]) if vb else ""
    except Exception:
        pass

    # Interfaces (1.3.6.1.2.1.2.2.1.2 = ifDescr)
    interfaces = []
    try:
        for err_ind, err_stat, _, vb in nextCmd(
            engine, CommunityData(comm),
            UdpTransportTarget((ip, 161), timeout=timeout, retries=1),
            ContextData(), ObjectType(ObjectIdentity("1.3.6.1.2.1.2.2.1.2")),
            lexicographicMode=False
        ):
            if err_ind or err_stat:
                break
            for oid, val in vb:
                interfaces.append(str(val))
    except Exception:
        pass
    result["interfaces"] = interfaces[:32]  # max 32

    # IP-Adressen der Interfaces (1.3.6.1.2.1.4.20.1.1)
    ip_addrs = []
    try:
        for err_ind, err_stat, _, vb in nextCmd(
            engine, CommunityData(comm),
            UdpTransportTarget((ip, 161), timeout=timeout, retries=1),
            ContextData(), ObjectType(ObjectIdentity("1.3.6.1.2.1.4.20.1.1")),
            lexicographicMode=False
        ):
            if err_ind or err_stat:
                break
            for oid, val in vb:
                addr = str(val)
                if addr not in ("0.0.0.0", "127.0.0.1"):
                    ip_addrs.append(addr)
    except Exception:
        pass
    result["ip_addresses"] = ip_addrs[:16]

    return result


def run_snmp_enrichment(devices):
    """Läuft nach Port scan — enriches Devices mit SNMP-Daten wenn Port 161 offen."""
    enriched = 0
    for d in devices:
        ports = d.get("ports", [])
        has_snmp = any(p.get("port") == "161" for p in ports)
        if not has_snmp:
            continue
        ip = d.get("ip", "")
        log_event(f"  SNMP-Walk  {ip}  ...", "info")
        snmp_data = snmp_walk_device(ip)
        if snmp_data:
            d["snmp"] = snmp_data
            iface_count = len(snmp_data.get("interfaces", []))
            ip_count    = len(snmp_data.get("ip_addresses", []))
            sys_name    = snmp_data.get("sys_name", "")
            log_event(
                f"  SNMP  {ip}  {sys_name}  {iface_count} Interfaces  {ip_count} IPs",
                "found"
            )
            enriched += 1
        else:
            log_event(f"  SNMP  {ip}  access denied (community string incorrect or filtered)", "warn")
    return devices, enriched


def run_all_python_checks(devices, progress_cb=None):
    """Run Python checks against all devices with open HTTP/HTTPS ports."""
    targets = [d for d in devices if any(
        p["port"] in ("80","443","8080","8443","8181","8089","8000","8008","8888","8081","81")
        for p in d.get("ports", [])
    )]
    if not targets:
        return devices

    total = len(targets)
    done = [0]

    def check_device(dev):
        hits = run_python_checks(dev)
        done[0] += 1
        if progress_cb:
            progress_cb(done[0], total, dev["ip"])
        return dev["ip"], hits

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futures = [ex.submit(check_device, d) for d in targets]
        for fut in concurrent.futures.as_completed(futures, timeout=120):
            try:
                ip, hits = fut.result()
                for dev in devices:
                    if dev["ip"] == ip:
                        dev.setdefault("nuclei_findings", [])
                        dev["nuclei_findings"].extend(hits)
                        # Promote CRITICAL/HIGH findings as alert
                        for h in hits:
                            if h["severity"] in ("CRITICAL","HIGH") and h.get("template_id","").startswith(("default-cred","exposed-path","ssl-exp")):
                                if h.get("template_id","").startswith("default-cred"):
                                    dev.setdefault("cves", [])  # not a CVE but flag it
                        break
            except Exception:
                pass
    return devices

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# GERÄTE-KLASSIFIZIERUNG — leitet device_type aus Vendor+OS+Hostname+Ports ab
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Hostname-Patterns die ein Gerät eindeutig identifizieren
HOSTNAME_PATTERNS = [
    # (regex, type_key, label, icon, priority)
    (r"^pixel[-_]?\d+", "mobile", "Smartphone (Google Pixel)", "📱", 10),
    (r"^iphone", "mobile", "Smartphone (Apple iPhone)", "📱", 10),
    (r"^ipad", "tablet", "Tablet (Apple iPad)", "📱", 10),
    (r"^samsung", "mobile", "Smartphone (Samsung)", "📱", 12),
    (r"^huawei[-_]", "mobile", "Smartphone (Huawei)", "📱", 12),
    (r"^oneplus", "mobile", "Smartphone (OnePlus)", "📱", 12),
    (r"^xiaomi[-_]?\d*", "mobile", "Smartphone (Xiaomi)", "📱", 12),
    (r"^mi-?\w*phone", "mobile", "Smartphone (Xiaomi)", "📱", 12),
    (r"^redmi", "mobile", "Smartphone (Redmi)", "📱", 12),

    (r"^macbook", "workstation", "Laptop (MacBook)", "💻", 20),
    (r"^imac", "workstation", "Desktop (iMac)", "💻", 20),
    (r"^desktop[-_]", "workstation", "Windows Workstation", "💻", 20),
    (r"^laptop[-_]", "workstation", "Laptop", "💻", 20),
    (r"^win[-_]?\d", "workstation", "Windows-PC", "💻", 22),
    (r"^pc[-_]\w", "workstation", "PC", "💻", 22),
    (r"^po[-_]\w", "workstation", "Workstation (Office)", "💻", 22),

    (r"fritz\.repeater", "ap", "WLAN-Repeater (FRITZ!Repeater)", "📶", 14),
    (r"^fritz", "router", "FRITZ!Box device", "📡", 14),
    (r"^re\d+", "ap", "Wi-Fi range extender (TP-Link RE)", "📶", 14),
    (r"^speedport", "router", "Speedport (Telekom)", "📡", 15),
    (r"^vodafone[-_]", "router", "Vodafone-Router", "📡", 15),
    (r"^easybox", "router", "EasyBox (Vodafone)", "📡", 15),
    (r"^router", "router", "Router", "📡", 15),
    (r"^gateway", "router", "Gateway", "📡", 15),
    (r"^ap[-_]", "ap", "Access Point", "📶", 15),

    (r"doorbell", "doorbell", "Smart doorbell", "🔔", 18),
    (r"camera|cam[-_]", "camera", "IP camera", "📷", 18),
    (r"^cam\d", "camera", "IP camera", "📷", 18),
    (r"^c\d{3}\.", "camera", "TP-Link Tapo Kamera", "📷", 18),  # C210, C310

    (r"^tado", "smart_home", "Smart heating controller (tado)", "🌡", 18),
    (r"^homematic|^hmip", "smart_home", "Smart-Home-Zentrale (Homematic)", "🏠", 18),
    (r"^hue[-_]?bridge|^philips[-_]hue", "smart_home", "Philips Hue Bridge", "💡", 18),
    (r"^shelly", "smart_home", "Shelly Smart-Switch", "🏠", 18),
    (r"^sonos", "media", "Sonos Lautsprecher", "🔊", 18),
    (r"^echo|alexa", "media", "Amazon Echo / Alexa", "🔊", 18),
    (r"^chromecast", "media", "Chromecast", "📺", 18),
    (r"^appletv|apple-tv", "media", "Apple TV", "📺", 18),
    (r"^firetv|fire-?tv", "media", "Amazon Fire TV", "📺", 18),
    (r"^smarttv|samsung-?tv|lg-?tv", "media", "Smart TV", "📺", 18),

    (r"^printer|hp[-_]?print|canon[-_]?print|epson[-_]?print|brother[-_]", "printer", "Printer", "🖨", 16),

    (r"^nas|synology|qnap|truenas", "nas", "NAS", "💾", 16),
    (r"^proxmox|^esxi|^vmware|^xen", "vm_host", "VM-Host", "⚙", 16),
    (r"^dc[-_]|^pdc|^bdc|domain-?controller", "dc", "Domain Controller", "🏛", 16),
    (r"^firewall|^fw[-_]|^pfsense|^opnsense", "firewall", "Firewall", "🛡", 12),
]

# Vendor-Patterns die NUR den Gerätetyp setzen (OS bleibt wenn erkannt)
VENDOR_HARD_OVERRIDES = {
    # AVM → FRITZ!Box (Router)
    "avm":           ("router", "FRITZ!Box / AVM", "📡"),
    "fritz":         ("router", "FRITZ!Box", "📡"),
    # tado → Smart heating controller
    "tado":          ("smart_home", "tado° Heating bridge", "🌡"),
    # Homematic
    "eq-3":          ("smart_home", "Smart-Home (eQ-3 / Homematic)", "🏠"),
    "elv":           ("smart_home", "Smart-Home (ELV/eQ-3)", "🏠"),
    # Lumi = Aqara/Xiaomi Smart Home
    "lumi":          ("smart_home", "Aqara/Xiaomi Smart-Home", "🏠"),
    "xiaomi":        ("smart_home", "Xiaomi Smart-Home", "🏠"),  # kann auch Smartphone sein, Hostname checkt vorher
    # Shelly
    "shelly":        ("smart_home", "Shelly Smart-Switch", "🏠"),
    "allterco":      ("smart_home", "Shelly (Allterco)", "🏠"),
    # Philips Hue
    "philips lighting": ("smart_home", "Philips Hue", "💡"),
    "signify":       ("smart_home", "Philips Hue (Signify)", "💡"),
    # Sonos
    "sonos":         ("media", "Sonos Lautsprecher", "🔊"),
    # Apple devices
    "apple":         ("apple", "Apple device", "🍎"),  # weiter klassifizieren über Hostname/OS
    # Google Nest
    "nest labs":     ("smart_home", "Google Nest", "🏠"),
    "google":        ("media", "Google device", "🟢"),
    # Smart Doorbell
    "ring llc":      ("doorbell", "Ring Doorbell", "🔔"),
    "lumi united":   ("doorbell", "Aqara Doorbell/Sensor", "🔔"),
    # TP-Link variants
    "tp-link":       ("router", "TP-Link Router/AP", "📡"),
    # IP-Cameras
    "hikvision":     ("camera", "Hikvision IP camera", "📷"),
    "dahua":         ("camera", "Dahua IP camera", "📷"),
    "axis":          ("camera", "Axis IP camera", "📷"),
    "reolink":       ("camera", "Reolink IP camera", "📷"),
    "eufy":          ("camera", "Eufy IP camera", "📷"),
    # Laptop-Hersteller (OEM-MACs)
    "lcfc":          ("workstation", "Laptop (Lenovo-OEM)", "💻"),
    "compal":        ("workstation", "Laptop (Compal-OEM)", "💻"),
    "quanta":        ("workstation", "Laptop (Quanta-OEM)", "💻"),
    "wistron":       ("workstation", "Laptop (Wistron-OEM)", "💻"),
    "pegatron":      ("workstation", "PC (Pegatron-OEM)", "💻"),
    "asustek":       ("workstation", "ASUS PC/Laptop", "💻"),
    "dell":          ("workstation", "Dell PC/Laptop", "💻"),
    "lenovo":        ("workstation", "Lenovo PC/Laptop", "💻"),
    "hp inc":        ("workstation", "HP PC/Laptop", "💻"),
    "hewlett packard":("workstation", "HP PC/Laptop", "💻"),
    "acer":          ("workstation", "Acer PC/Laptop", "💻"),
    "msi":           ("workstation", "MSI PC/Laptop", "💻"),
    "microsoft":     ("workstation", "Microsoft Surface", "💻"),
    "intel corporate":("workstation", "PC (Intel WiFi-Chip)", "💻"),
    # Drucker
    "canon":         ("printer", "Canon printer", "🖨"),
    "epson seiko":   ("printer", "Epson printer", "🖨"),
    "brother":       ("printer", "Brother printer", "🖨"),
    "ricoh":         ("printer", "Ricoh printer", "🖨"),
    "kyocera":       ("printer", "Kyocera printer", "🖨"),
    "samsung electronics co": ("mobile", "Samsung device", "📱"),  # könnte auch TV sein, Hostname entscheidet
    # NAS
    "synology":      ("nas", "Synology NAS", "💾"),
    "qnap":          ("nas", "QNAP NAS", "💾"),
    "buffalo":       ("nas", "Buffalo NAS", "💾"),
}

# Vendor-Patterns die anzeigen "OS detection ist Müll, ignorier sie"
# Wenn nmap eine OS rät die NICHT zum Vendor passt, verwerfen
VENDOR_OS_SUSPICIOUS = {
    "tado":          ("Cisco", "HP ProCurve", "Switch"),
    "eq-3":          ("Cisco", "HP ProCurve", "Switch"),
    "lumi":          ("Cisco", "HP ProCurve", "Switch"),
    "philips lighting": ("Cisco", "HP ProCurve", "Switch"),
    "shelly":        ("Cisco", "HP ProCurve", "Switch"),
}


def _hostname_classify(hostname):
    """Return (type, label, icon, priority) from hostname match or None."""
    if not hostname:
        return None
    import re as _re
    name = hostname.lower().strip()
    # strip .fritz.box, .local etc. for matching
    short = _re.sub(r"\.(fritz\.box|local|lan|home)$", "", name)
    for pattern, type_key, label, icon, priority in HOSTNAME_PATTERNS:
        if _re.search(pattern, short):
            return (type_key, label, icon, priority)
    return None


def _vendor_classify(vendor):
    """Return (type, label, icon) from vendor map or None."""
    if not vendor:
        return None
    vlow = vendor.lower().strip()
    for key, mapping in VENDOR_HARD_OVERRIDES.items():
        if key in vlow:
            return mapping
    return None


def _is_os_suspicious(vendor, os_name):
    """Return True if nmap's OS guess obviously contradicts the MAC vendor."""
    if not vendor or not os_name:
        return False
    vlow = vendor.lower()
    for vkey, bad_tokens in VENDOR_OS_SUSPICIOUS.items():
        if vkey in vlow:
            return any(t.lower() in os_name.lower() for t in bad_tokens)
    return False


DEVICE_TYPE_RULES = [
    # (type_key, label_de, icon, priority, match_fn)
    # priority: niedrig = stärker (wird zuerst geprüft)

    # ── Netzwerk-Infrastruktur ──────────────────────────────────────
    ("firewall",  "Firewall",       "🛡",  10, lambda v,o,p,s: any(x in v for x in
        ["Fortinet","FortiGate","Palo Alto","pfSense","OPNsense","Sophos","Checkpoint","Check Point","Barracuda","SonicWall","Cisco ASA","Juniper SRX"]) or
        any(x in o for x in ["pfSense","OPNsense","FortiOS","PAN-OS","ScreenOS"])),

    ("router",    "Router",         "📡", 15, lambda v,o,p,s: any(x in v for x in
        ["Cisco","MikroTik","Ubiquiti","AVM","FRITZ","Netgear","TP-Link","D-Link","ASUS","Linksys","Zyxel","Huawei","Juniper"]) or
        any(x in o for x in ["RouterOS","IOS","JunOS","VxWorks","OpenWrt","DD-WRT"]) or
        ({"80","443","22","23"}.issubset(s) and len(p) < 10)),

    ("switch",    "Switch",         "🔀", 20, lambda v,o,p,s: any(x in v for x in
        ["Cisco","HP","Aruba","Juniper","Extreme","Brocade","Netgear","D-Link","TP-Link","Dell EMC","Huawei"]) and
        "161" in s and len([x for x in p if x.get("service","") in ("snmp","snmp-trap","lldp")]) > 0),

    ("ap",        "Access Point",   "📶", 25, lambda v,o,p,s: any(x in v for x in
        ["Ubiquiti","Aruba","Ruckus","Aerohive","Meraki","Cisco AIR","EnGenius","Zyxel NWA"]) or
        any(x in o for x in ["ArubaOS","UniFi","AireOS"])),

    # ── Server ─────────────────────────────────────────────────────
    ("dc",        "Domain Controller","🏛", 30, lambda v,o,p,s: "445" in s and "88" in s and "389" in s),

    ("server",    "Server",         "🖥", 35, lambda v,o,p,s: any(x in o for x in
        ["Windows Server","Ubuntu Server","Debian","CentOS","Red Hat","RHEL","Rocky","AlmaLinux","FreeBSD","ESXi","Proxmox","TrueNAS","NAS"]) or
        any(x in s for x in ["22","3306","5432","1433","3389","5985","5986","8443","8080","9200"]) and
        not any(x in o for x in ["Android","iOS","macOS","Windows 10","Windows 11"])),

    ("nas",       "NAS",            "💾", 32, lambda v,o,p,s: any(x in v for x in
        ["Synology","QNAP","Buffalo","Seagate","Western Digital","NETGEAR ReadyNAS"]) or
        any(x in o for x in ["DSM","QTS","TrueNAS","FreeNAS","NAS4Free"])),

    ("vm_host",   "VM-Host",        "⚙",  33, lambda v,o,p,s: any(x in o for x in
        ["ESXi","vSphere","Proxmox","Hyper-V","XenServer"]) or
        any(x in v for x in ["VMware","Proxmox"])),

    # ── Drucker / Scanner ──────────────────────────────────────────
    ("printer",   "Printer",        "🖨", 40, lambda v,o,p,s: any(x in v for x in
        ["HP","Hewlett-Packard","Canon","Epson","Brother","Ricoh","Kyocera","Lexmark","Xerox","Konica","OKI","Samsung Print","Sharp"]) or
        any(x in o for x in ["HP-ChaiSOE","Epson","Canon","Kyocera"]) or
        "9100" in s or ("515" in s and "631" in s)),

    # ── Client-Devices ──────────────────────────────────────────────
    ("phone",     "IP-Telefon",     "📞", 45, lambda v,o,p,s: any(x in v for x in
        ["Cisco","Polycom","Yealink","Snom","Grandstream","Avaya","Mitel","Gigaset"]) and
        any(x in s for x in ["5060","5061","2000","2001"]) or
        any(x in o for x in ["VxWorks","RTOS"]) and "5060" in s),

    ("mobile",    "Smartphone/tablet","📱",50, lambda v,o,p,s: any(x in o for x in
        ["Android","iOS","iPadOS"]) or
        any(x in v for x in ["Apple","Samsung","Xiaomi","Huawei","OnePlus"])),

    ("workstation","Workstation",   "💻", 55, lambda v,o,p,s: any(x in o for x in
        ["Windows 10","Windows 11","Windows 7","Windows 8","macOS","Mac OS X"]) or
        any(x in v for x in ["Apple","Dell","HP","Lenovo","Acer","Asus","Microsoft Surface"])),

    # ── IoT / Sonstiges ───────────────────────────────────────────
    ("camera",    "IP-Kamera",      "📷", 60, lambda v,o,p,s: any(x in v for x in
        ["Hikvision","Dahua","Axis","Hanwha","Vivotek","Bosch Security","Pelco"]) or
        any(x in o for x in ["Hikvision","Dahua","Axis ARTPEC"]) or
        "554" in s),  # RTSP

    ("iot",       "IoT device",      "📟", 65, lambda v,o,p,s: any(x in v for x in
        ["Espressif","Arduino","Raspberry Pi","Shelly","Sonos","Philips Hue","Belkin","TP-Link Tapo","Tuya"]) or
        any(x in o for x in ["FreeRTOS","ThreadX","VxWorks","Contiki","RIOT"])),

    ("unknown",   "Unknown",      "❓", 99, lambda v,o,p,s: True),  # Fallback
]


# Type-Label-Icon-Lookup für neue Typen
NEW_TYPE_LABELS = {
    "smart_home": ("Smart-Home",    "🏠"),
    "doorbell":   ("Smart doorbell", "🔔"),
    "media":      ("Media device",   "🔊"),
    "tablet":     ("Tablet",        "📱"),
    "apple":      ("Apple device",   "🍎"),
}


def classify_device(device):
    """
    Leitet device_type aus Vendor, OS, Hostname und offenen Ports ab.
    Reihenfolge: 1) Hostname (am eindeutigsten) 2) Vendor-Hard-Override 3) Regeln 4) Fallback.
    Setzt device["device_type"], device["device_label"], device["device_icon"].
    """
    vendor   = (device.get("vendor") or "").strip()
    os_name  = (device.get("os")     or "").strip()
    hostname = (device.get("hostname") or "").strip()
    ports    = device.get("ports", [])
    port_set = {str(p.get("port","")) for p in ports}

    # OS-Sanity-Check: wenn Vendor klar IoT/Smart-Home ist und nmap "Cisco SLM2008" rät → OS verwerfen
    if _is_os_suspicious(vendor, os_name):
        device["os_suspicious"] = os_name
        device["os"] = "Unknown"
        os_name = "Unknown"

    # SNMP SysDescr kann Gerättyp verraten
    snmp = device.get("snmp", {})
    sys_descr = (snmp.get("sys_descr") or "").lower()
    if "switch" in sys_descr:
        vendor  = vendor  or "Network"
        os_name = os_name or "Switch"
    elif "router" in sys_descr or "gateway" in sys_descr:
        os_name = os_name or "Router"
    elif "firewall" in sys_descr:
        os_name = os_name or "Firewall"
    elif "printer" in sys_descr or "print" in sys_descr:
        os_name = os_name or "Printer"
    elif "camera" in sys_descr or "ipc" in sys_descr:
        os_name = os_name or "Camera"

    # 1. Hostname-Pattern-Match (höchste Priorität — sehr eindeutig wenn Treffer)
    hn_hit = _hostname_classify(hostname)
    if hn_hit:
        type_key, label, icon, _prio = hn_hit
        device["device_type"]  = type_key
        device["device_label"] = label
        device["device_icon"]  = icon
        return device

    # 2. Vendor-Hard-Override (eindeutige Vendor-Patterns wie tado, eq-3, etc.)
    ven_hit = _vendor_classify(vendor)
    if ven_hit:
        type_key, label, icon = ven_hit
        device["device_type"]  = type_key
        device["device_label"] = label
        device["device_icon"]  = icon
        return device

    # 3. Regel-basiert (alte Logik mit DEVICE_TYPE_RULES)
    for type_key, label, icon, priority, match_fn in sorted(DEVICE_TYPE_RULES, key=lambda x: x[3]):
        try:
            if match_fn(vendor, os_name, ports, port_set):
                device["device_type"]  = type_key
                device["device_label"] = label
                device["device_icon"]  = icon
                return device
        except Exception:
            continue

    device["device_type"]  = "unknown"
    device["device_label"] = "Unknown"
    device["device_icon"]  = "❓"
    return device


def enrich_device_banner(device):
    """
    HTTP Banner Check — ergänzt nmap-Erkennung durch gezielte HTTP-GETs
    auf bekannte Gerät-spezifische Pfade. Überschreibt vendor/os nur wenn
    sicherer erkannt als bisher.
    """
    ip = device.get("ip", "")
    port_set = {str(p.get("port","")).split("/")[0] for p in device.get("ports", [])}

    # Nur wenn HTTP/HTTPS Ports offen
    http_ports = []
    for p, s in [("80","http"),("443","https"),("8080","http"),("8443","https"),
                 ("5000","http"),("5001","https"),("8006","https"),("8007","https"),
                 ("9000","http"),("3000","http"),("9090","http")]:
        if p in port_set:
            http_ports.append((p, s))
    if not http_ports:
        return device

    # Bekannte Erkennungs-Signaturen: (pfad, suchbegriff, vendor, os, device_type)
    SIGNATURES = [
        # NAS
        ("/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query", "SYNO",
            "Synology", "DSM", "nas"),
        ("/cgi-bin/authLogin.cgi",            "QNAP",
            "QNAP", "QTS", "nas"),
        ("/api/v1.0/system/info",             "TrueNAS",
            "iXsystems", "TrueNAS", "nas"),
        ("/index.php",                         "ReadyNAS",
            "NETGEAR", "ReadyNAS", "nas"),
        # Virtualisierung
        ("/api2/json/version",                "proxmox",
            "Proxmox", "Proxmox VE", "vm_host"),
        ("/ui/",                               "VMware ESXi",
            "VMware", "ESXi", "vm_host"),
        # Router / Firewall
        ("/remote/login",                      "FortiGate",
            "Fortinet", "FortiOS", "firewall"),
        ("/dana-na/auth/url_default/welcome.cgi","Pulse Secure",
            "Ivanti", "Pulse Secure", "firewall"),
        ("/",                                  "FRITZ!Box",
            "AVM", "Fritz!OS", "router"),
        ("/",                                  "MikroTik",
            "MikroTik", "RouterOS", "router"),
        ("/",                                  "OpenWrt",
            "OpenWrt", "OpenWrt", "router"),
        # Monitoring
        ("/api/health",                        "Grafana",
            "Grafana Labs", "Grafana", "server"),
        ("/-/healthy",                         "Prometheus",
            "Prometheus", "Prometheus", "server"),
        ("/api/json",                          "Jenkins",
            "Jenkins", "Jenkins", "server"),
        # Container
        ("/v1.41/info",                        "Docker",
            "Docker", "Docker Engine", "server"),
        ("/api/v1/namespaces",                 "Kubernetes",
            "Kubernetes", "k8s", "server"),
        # Drucker
        ("/hp/device/this.LCDispatcher",       "HP",
            "HP", "HP Printer", "printer"),
        ("/cgi-bin/dynamic/printer/PrinterStatus.html", "Canon",
            "Canon", "Canon Printer", "printer"),
        # Checkmk / Zabbix
        ("/check_mk/",                         "Checkmk",
            "Checkmk", "Checkmk", "server"),
        ("/zabbix/",                           "Zabbix",
            "Zabbix", "Zabbix", "server"),
    ]

    for port, scheme in http_ports[:3]:  # max 3 Ports prüfen
        for path, keyword, vendor, os_name, dev_type in SIGNATURES:
            try:
                url = f"{scheme}://{ip}:{port}{path}"
                code, body = _http_get(url, timeout=3)
                if code and body and keyword.lower() in body.lower():
                    # Nur überschreiben wenn aktuell unknown oder weniger spezifisch
                    cur_type = device.get("device_type", "unknown")
                    if cur_type in ("unknown", "server") or device.get("vendor","") == "Unknown":
                        device["vendor"]      = vendor
                        device["os"]          = os_name
                        device["device_type"] = dev_type
                        device["banner_match"] = f"{keyword} at {path}"
                        classify_device(device)  # neu klassifizieren
                    return device
            except Exception:
                continue
    return device



def parse_nmap_xml(xml_output):
    """Parst nmap XML-Output und extrahiert Gerätedaten."""
    import xml.etree.ElementTree as ET
    devices = []
    
    try:
        root = ET.fromstring(xml_output)
        for host in root.findall("host"):
            if host.find("status").get("state") != "up":
                continue
            
            # IP
            addr = host.find("address[@addrtype='ipv4']")
            ip = addr.get("addr") if addr is not None else "?"
            
            # MAC + Hersteller
            mac_el = host.find("address[@addrtype='mac']")
            mac = mac_el.get("addr", "-") if mac_el is not None else "-"
            raw_vendor = mac_el.get("vendor", "Unknown") if mac_el is not None else "Unknown"
            # Fix encoding artifacts (nmap OUI DB uses latin-1 sometimes)
            try:
                vendor = raw_vendor.encode("latin-1").decode("utf-8")
            except Exception:
                vendor = raw_vendor.encode("utf-8", errors="replace").decode("utf-8")
            
            # Hostname
            hostnames = host.find("hostnames")
            hostname = "-"
            if hostnames is not None:
                hn = hostnames.find("hostname")
                if hn is not None:
                    hostname = hn.get("name", "-")
            
            # OS detection
            os_name = "Unknown"
            osmatch = host.find(".//osmatch")
            if osmatch is not None:
                os_name = osmatch.get("name", "Unknown")
            
            # Ports
            ports = []
            cves = []
            for port in host.findall(".//port"):
                state_el = port.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                
                portid = port.get("portid")
                protocol = port.get("protocol", "tcp")
                service_el = port.find("service")
                service = service_el.get("name", "?") if service_el is not None else "?"
                product = service_el.get("product", "") if service_el is not None else ""
                version = service_el.get("version", "") if service_el is not None else ""
                
                # CVE + NSE Script findings aus Port-Scripts
                port_cves = []
                port_scripts = {}
                for script in port.findall(".//script"):
                    script_id     = script.get("id", "")
                    script_output = script.get("output", "")
                    found = re.findall(r"CVE-\d{4}-\d{4,}", script_output)
                    port_cves.extend(found)
                    cves.extend(found)
                    # Collect interesting script outputs
                    if script_id in ("http-title", "http-auth", "ftp-anon",
                                     "telnet-encryption", "dns-recursion",
                                     "smb-security-mode", "smb-vuln-ms17-010",
                                     "ssl-cert", "ssl-enum-ciphers", "snmp-info",
                                     "banner"):
                        port_scripts[script_id] = script_output.strip()[:300]

                # Banner Status — aktiv genutzt oder nur offen?
                full_product = f"{product} {version}".strip()
                if full_product:
                    banner_status = "active"    # Service antwortet mit Banner
                elif service and service not in ("?", "unknown", "tcpwrapped"):
                    banner_status = "open"      # Port offen, Service erkannt aber kein Banner
                elif service == "tcpwrapped":
                    banner_status = "filtered"  # Firewall/Wrapper blockt
                else:
                    banner_status = "unknown"   # Offen aber nichts erkennbar

                port_scripts[f"_banner_status"] = banner_status

                # Extra-Info: beste verfügbare Zusatzinfo für Anzeige
                extra_info = ""
                if port_scripts.get("http-title"):
                    t = port_scripts["http-title"].replace("\n"," ").strip()
                    extra_info = f"Titel: {t[:80]}"
                elif port_scripts.get("banner"):
                    b = port_scripts["banner"].replace("\n"," ").strip()
                    extra_info = f"Banner: {b[:80]}"
                elif port_scripts.get("ssl-cert"):
                    sc = port_scripts["ssl-cert"]
                    # Extract subject CN
                    import re as _re
                    m = _re.search(r"commonName=([^\s/,]+)", sc)
                    if m:
                        extra_info = f"SSL: {m.group(1)[:60]}"
                elif port_scripts.get("smb-security-mode"):
                    smb = port_scripts["smb-security-mode"].replace("\n"," ").strip()
                    extra_info = f"SMB: {smb[:80]}"

                ports.append({
                    "port":          int(portid) if portid and portid.isdigit() else portid,
                    "protocol":      protocol,
                    "service":       service,
                    "product":       full_product,
                    "extra_info":    extra_info,
                    "cves":          list(set(port_cves)),
                    "scripts":       port_scripts,
                    "banner_status": banner_status,
                })
            
            # Host-level NSE scripts (e.g. smb-vuln-ms17-010)
            host_scripts = {}
            for hs in host.findall(".//hostscript/script"):
                sid = hs.get("id","")
                sout = hs.get("output","").strip()[:300]
                if sid:
                    host_scripts[sid] = sout
                    found = re.findall(r"CVE-\d{4}-\d{4,}", sout)
                    cves.extend(found)

            dev = {
                "ip":           ip,
                "mac":          mac,
                "vendor":       vendor,
                "hostname":     hostname,
                "os":           os_name,
                "ports":        ports,
                "cves":         list(set(cves)),
                "host_scripts": host_scripts,
                "status":       "up"
            }
            classify_device(dev)
            enrich_device_banner(dev)
            devices.append(dev)
    except Exception as e:
        print(f"XML Parse Error: {e}")
    
    return devices


# --- NVD API Enrichment ---
import urllib.request
import urllib.error


def discover_networks():
    """Liest die lokale Routing-Tabelle aus und findet alle erreichbaren Netzwerke."""
    import platform, subprocess, re
    networks = []
    seen = set()

    try:
        if platform.system() == "Windows":
            out = subprocess.check_output("route print -4", shell=True, text=True, timeout=5)
            # Parse Windows route print: "  192.168.1.0    255.255.255.0    ..."
            for line in out.splitlines():
                m = re.match(r"\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    net_ip, mask = m.group(1), m.group(2)
                    try:
                        net = ipaddress.IPv4Network(f"{net_ip}/{mask}", strict=False)
                        # Skip host routes, loopback, multicast, too-large nets
                        if (net.prefixlen >= 8 and net.prefixlen <= 30
                            and not net.is_loopback
                            and not net.is_multicast
                            and not str(net).startswith("0.")
                            and str(net) not in seen):
                            seen.add(str(net))
                            networks.append(str(net))
                    except:
                        pass
        else:
            out = subprocess.check_output(["ip", "route"], text=True, timeout=5)
            for line in out.splitlines():
                m = re.match(r"(\d+\.\d+\.\d+\.\d+/\d+)", line)
                if m:
                    try:
                        net = ipaddress.IPv4Network(m.group(1), strict=False)
                        if (net.prefixlen >= 8 and net.prefixlen <= 30
                            and not net.is_loopback
                            and not net.is_multicast
                            and str(net) not in seen):
                            seen.add(str(net))
                            networks.append(str(net))
                    except:
                        pass
    except Exception as e:
        print(f"Route discovery error: {e}")

    # Always include current network as fallback
    base_net, _ = get_local_network()
    if base_net not in seen:
        networks.insert(0, base_net)

    # Deduplicate - remove subnets already covered by supernet
    final = []
    net_objs = []
    for n in networks:
        try:
            net_objs.append(ipaddress.IPv4Network(n))
        except:
            pass
    for net in net_objs:
        covered = any(net != other and net.subnet_of(other) for other in net_objs)
        if not covered:
            final.append(str(net))

    return final if final else [base_net]


# ═══════════════════════════════════════════════════════════════
# OLLAMA AI EMPFEHLUNGEN — mistral:7b lokal, offline
# ═══════════════════════════════════════════════════════════════

OLLAMA_URL  = "http://localhost:11434"
OLLAMA_MODEL = "mistral"
_ollama_available = None  # wird beim ersten Aufruf gecheckt

def _check_ollama():
    """Prüft ob Ollama lokal läuft. Cached das Ergebnis."""
    global _ollama_available
    if _ollama_available is not None:
        return _ollama_available
    try:
        import urllib.request
        r = urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=2)
        _ollama_available = r.status == 200
    except Exception:
        _ollama_available = False
    return _ollama_available

def _ollama_ask(prompt, timeout=30):
    """Sendet Prompt an Ollama, gibt Text-Antwort zurück."""
    import urllib.request, json as _json
    try:
        payload = _json.dumps({
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.3, "num_predict": 300}
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{OLLAMA_URL}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = _json.loads(r.read().decode("utf-8"))
            return data.get("response", "").strip()
    except Exception as e:
        return None

def _build_ai_prompt(device):
    """Erstellt den Prompt für ein Gerät with CVEs."""
    ip       = device.get("ip","?")
    hostname = device.get("hostname","-")
    vendor   = device.get("vendor","Unknown")
    os_name  = device.get("os","Unknown")
    dtype    = device.get("device_label","Unknown")
    cves     = device.get("cve_details", [])
    ports    = [f"{p.get('port','?')}/{p.get('service','?')}" for p in device.get("ports",[])[:8]]

    cve_lines = ""
    for c in cves[:5]:
        cve_id  = c.get("id","?")
        score   = c.get("score","?")
        sev     = c.get("severity","?")
        desc    = c.get("description","")[:120]
        cve_lines += f"- {cve_id} (CVSS {score}, {sev}): {desc}\n"

    prompt = f"""You are an IT security expert. Analyze this network device and provide a brief, specific recommendation in English. Do not invent firmware versions, fixes or confirmed exploitation. State uncertainty explicitly.

Device: {ip} ({hostname})
Vendor: {vendor}
Operating system: {os_name}
Device type: {dtype}
Open ports: {', '.join(ports)}

Identified vulnerabilities (CVEs):
{cve_lines if cve_lines else "No CVEs found."}

Task: Give exactly two or three specific recommendations:
1. Is current firmware or an update available from the vendor? (Yes/No/Unknown)
2. What specific action should the administrator take? (e.g. "replace the router if required", "update Apache: apt upgrade apache2")
3. How urgent is the action? (Immediately/This week/This month)

Respond briefly and directly without introductory text."""

    return prompt

def enrich_ai_recommendations(devices):
    """
    Ollama AI recommendationen für Devices with CVEs.
    Läuft nur wenn Ollama lokal verfügbar ist.
    Graceful fallback wenn not installed.
    """
    if not _check_ollama():
        log_event("  AI recommendations: Ollama unavailable (optional)", "info")
        return devices

    # Nur Devices with CVEs analysieren
    targets = [d for d in devices if d.get("cves") or d.get("cve_details")]
    if not targets:
        return devices

    log_event(f"─── AI ANALYSIS: {len(targets)} device(s) via Ollama ({OLLAMA_MODEL}) ───", "batch")
    scan_state["status"] = f"AI recommendationen ({OLLAMA_MODEL})..."

    for i, dev in enumerate(targets):
        if scan_state.get("cancel_requested"):
            break
        ip = dev.get("ip","?")
        pct = int((i+1) / max(len(targets),1) * 100)
        log_event(f"  KI ({i+1}/{len(targets)}) {ip}  (AI Analyse {pct}%)", "info")

        prompt = _build_ai_prompt(dev)
        response = _ollama_ask(prompt, timeout=45)

        if response:
            dev["ai_recommendation"] = response
            # Kurz ins Log
            short = response.replace("\n"," ")[:120]
            log_event(f"  AI ✓ {ip}  → {short}...", "found")
        else:
            dev["ai_recommendation"] = None

    log_event(f"─── AI ANALYSIS COMPLETE ───", "batch")
    return devices


def _cve_cache_init():
    """Ensure cve_cache table exists. Called lazily."""
    try:
        with db_connect() as con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS cve_cache (
                    cve_id           TEXT PRIMARY KEY,
                    score            REAL,
                    severity         TEXT,
                    description      TEXT,
                    vector           TEXT,
                    source           TEXT,
                    kev              INTEGER DEFAULT 0,
                    kev_date_added   TEXT,
                    epss_score       REAL,
                    epss_percentile  REAL,
                    exploit_refs     TEXT,
                    fetched_at       TEXT
                )
            """)
            # Add columns to existing tables (idempotent migration)
            for col, typ in [("kev","INTEGER DEFAULT 0"), ("kev_date_added","TEXT"),
                              ("epss_score","REAL"), ("epss_percentile","REAL"),
                              ("exploit_refs","TEXT")]:
                try:
                    con.execute(f"ALTER TABLE cve_cache ADD COLUMN {col} {typ}")
                except Exception:
                    pass  # column exists
            # KEV catalog table (separate)
            con.execute("""
                CREATE TABLE IF NOT EXISTS kev_catalog (
                    cve_id        TEXT PRIMARY KEY,
                    vendor        TEXT,
                    product       TEXT,
                    date_added    TEXT,
                    due_date      TEXT,
                    required_action TEXT,
                    short_description TEXT
                )
            """)
            con.execute("""
                CREATE TABLE IF NOT EXISTS kev_meta (
                    k TEXT PRIMARY KEY,
                    v TEXT
                )
            """)
    except Exception:
        pass


def _cve_cache_get(cve_id):
    """Return cached CVE dict (incl. KEV/EPSS/exploits) or None."""
    try:
        with db_connect() as con:
            con.row_factory = sqlite3.Row
            r = con.execute("SELECT * FROM cve_cache WHERE cve_id=?", (cve_id,)).fetchone()
        if not r:
            return None
        try:
            exploits = json.loads(r["exploit_refs"]) if r["exploit_refs"] else []
        except Exception:
            exploits = []
        return {"id": r["cve_id"], "score": r["score"],
                "severity": r["severity"] or "UNKNOWN",
                "description": r["description"] or "",
                "vector": r["vector"] or "", "source": r["source"] or "cache",
                "kev": bool(r["kev"]) if "kev" in r.keys() else False,
                "kev_date_added": r["kev_date_added"] if "kev_date_added" in r.keys() else None,
                "epss_score": r["epss_score"] if "epss_score" in r.keys() else None,
                "epss_percentile": r["epss_percentile"] if "epss_percentile" in r.keys() else None,
                "exploits": exploits}
    except Exception:
        return None


def _cve_cache_set(cve_id, data):
    """Store CVE data in cache (including KEV/EPSS/exploit enrichment)."""
    try:
        import datetime as _dt
        with db_connect() as con:
            con.execute(
                "INSERT OR REPLACE INTO cve_cache "
                "(cve_id, score, severity, description, vector, source, "
                " kev, kev_date_added, epss_score, epss_percentile, exploit_refs, fetched_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (cve_id, data.get("score"), data.get("severity"), data.get("description",""),
                 data.get("vector",""), data.get("source",""),
                 1 if data.get("kev") else 0,
                 data.get("kev_date_added"),
                 data.get("epss_score"), data.get("epss_percentile"),
                 json.dumps(data.get("exploits", [])),
                 _dt.datetime.now().isoformat(timespec="seconds"))
            )
    except Exception:
        pass


# ════════════════════════════════════════════════════════════════════
# KEV (CISA Known Exploited Vulnerabilities) — daily-refresh catalog
# ════════════════════════════════════════════════════════════════════
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_REFRESH_INTERVAL_SEC = 24 * 60 * 60   # daily

def _kev_should_refresh():
    """True if catalog is older than refresh interval or empty."""
    try:
        with db_connect() as con:
            r = con.execute("SELECT v FROM kev_meta WHERE k='last_updated'").fetchone()
            if not r:
                return True
            import datetime as _dt
            last = _dt.datetime.fromisoformat(r[0])
            age = (_dt.datetime.now() - last).total_seconds()
            return age > KEV_REFRESH_INTERVAL_SEC
    except Exception:
        return True


def _kev_load_catalog(force=False):
    """Download CISA KEV catalog into local DB. Idempotent, daily-refresh."""
    _cve_cache_init()
    if not force and not _kev_should_refresh():
        return None  # already current
    try:
        req = urllib.request.Request(KEV_URL, headers={"User-Agent":"VulnScan-Pro/1.0.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return 0
        import datetime as _dt
        with db_connect() as con:
            con.execute("DELETE FROM kev_catalog")
            for v in vulns:
                con.execute(
                    "INSERT OR REPLACE INTO kev_catalog "
                    "(cve_id, vendor, product, date_added, due_date, required_action, short_description) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (v.get("cveID",""), v.get("vendorProject",""), v.get("product",""),
                     v.get("dateAdded",""), v.get("dueDate",""),
                     v.get("requiredAction",""), v.get("shortDescription",""))
                )
            con.execute("INSERT OR REPLACE INTO kev_meta (k,v) VALUES ('last_updated', ?)",
                        (_dt.datetime.now().isoformat(timespec="seconds"),))
            con.execute("INSERT OR REPLACE INTO kev_meta (k,v) VALUES ('count', ?)", (str(len(vulns)),))
        return len(vulns)
    except Exception as e:
        print(f"KEV load failed: {e}")
        return None


def _kev_check(cve_id):
    """Return KEV-info dict if CVE is in catalog, else None."""
    try:
        with db_connect() as con:
            con.row_factory = sqlite3.Row
            r = con.execute("SELECT * FROM kev_catalog WHERE cve_id=?", (cve_id,)).fetchone()
        if not r:
            return None
        return {"kev": True, "kev_date_added": r["date_added"],
                "kev_vendor": r["vendor"], "kev_product": r["product"],
                "kev_action": r["required_action"]}
    except Exception:
        return None


# ════════════════════════════════════════════════════════════════════
# EPSS (Exploit Prediction Scoring System) — first.org batch API
# ════════════════════════════════════════════════════════════════════
def _epss_fetch_batch(cve_ids):
    """Fetch EPSS scores for up to 100 CVEs in one call. Returns dict cve_id → {epss_score, epss_percentile}."""
    if not cve_ids:
        return {}
    result = {}
    # API supports comma-separated, ~100 per request safely
    batch_size = 80
    for i in range(0, len(cve_ids), batch_size):
        chunk = cve_ids[i:i+batch_size]
        try:
            url = "https://api.first.org/data/v1/epss?cve=" + ",".join(chunk)
            req = urllib.request.Request(url, headers={"User-Agent":"VulnScan-Pro/1.0.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
            for row in data.get("data", []):
                cid = row.get("cve","")
                if cid:
                    try:
                        result[cid] = {
                            "epss_score":      float(row.get("epss", 0)),
                            "epss_percentile": float(row.get("percentile", 0)),
                        }
                    except (TypeError, ValueError):
                        pass
        except Exception as e:
            print(f"EPSS batch failed: {e}")
    return result


# ════════════════════════════════════════════════════════════════════
# Exploit-References from CIRCL response
# ════════════════════════════════════════════════════════════════════
EXPLOIT_HOSTS = ("exploit-db.com", "packetstormsecurity.com",
                 "metasploit", "rapid7.com/db", "0day.today")
EXPLOIT_GITHUB_KEYWORDS = ("exploit", "poc", "metasploit", "0day", "cve-")

def _extract_exploit_refs(circl_data):
    """Pull URLs from CIRCL response that point to known exploit databases."""
    if not isinstance(circl_data, dict):
        return []
    refs = circl_data.get("references", []) or []
    exploits = []
    for r in refs:
        url = r if isinstance(r, str) else (r.get("url","") if isinstance(r, dict) else "")
        if not url:
            continue
        low = url.lower()
        label = None
        if "exploit-db.com" in low:
            label = "ExploitDB"
        elif "metasploit" in low or "rapid7.com/db" in low:
            label = "Metasploit"
        elif "packetstorm" in low:
            label = "PacketStorm"
        elif "0day" in low:
            label = "0day"
        elif "github.com" in low and any(k in low for k in EXPLOIT_GITHUB_KEYWORDS):
            label = "GitHub PoC"
        if label:
            exploits.append({"label": label, "url": url})
    return exploits


def _fetch_cve_vulnerability_circl(cve_id):
    """Try the new CIRCL Vulnerability-Lookup service at vulnerability.circl.lu.
    Returns enriched dict (with exploits if available) or None.
    """
    # Try multiple endpoint shapes that CIRCL has used in different versions
    endpoints = [
        f"https://vulnerability.circl.lu/api/vulnerability/{cve_id}",
        f"https://vulnerability.circl.lu/api/cve/{cve_id}",
    ]
    for url in endpoints:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "VulnScan-Pro/1.0.0"})
            with urllib.request.urlopen(req, timeout=6) as resp:
                raw = resp.read().decode()
            if not raw.strip():
                continue
            data = json.loads(raw)
            if not data or not isinstance(data, dict):
                continue
            # Format 1: MITRE cvelistv5 nested format (containers.cna.metrics + descriptions)
            score, severity, vector, desc = None, "UNKNOWN", "", ""
            containers = data.get("containers", {})
            cna = containers.get("cna", {}) if isinstance(containers, dict) else {}
            if cna:
                descs = cna.get("descriptions", []) or []
                for d in descs:
                    if isinstance(d, dict) and d.get("lang","").lower().startswith("en"):
                        desc = (d.get("value") or "")[:200]
                        break
                metrics = cna.get("metrics", []) or []
                for m in metrics:
                    if not isinstance(m, dict): continue
                    for key in ("cvssV4_0","cvssV3_1","cvssV3_0","cvssV2"):
                        if key in m and isinstance(m[key], dict):
                            cvss = m[key]
                            score = cvss.get("baseScore") or cvss.get("score")
                            severity = (cvss.get("baseSeverity") or "").upper() or severity
                            vector = cvss.get("vectorString","")
                            if score:
                                break
                    if score:
                        break

            # Format 2: legacy CIRCL flat format (summary + cvss3 + cvss)
            if score is None:
                desc = desc or (data.get("summary") or data.get("Description") or "")[:200]
                if isinstance(data.get("cvss3"), dict):
                    score = data["cvss3"].get("baseScore") or data["cvss3"].get("score")
                    severity = (data["cvss3"].get("baseSeverity") or "").upper() or severity
                    vector = data["cvss3"].get("vectorString","")
                elif data.get("cvss3") is not None:
                    score = data.get("cvss3")
                if score is None and data.get("cvss"):
                    score = data.get("cvss")
                    vector = data.get("cvss-vector", "")

            # Format 3: NVD-style nested
            if score is None and "cve" in data:
                cve_data = data["cve"]
                desc = desc or next((x["value"][:200] for x in cve_data.get("descriptions", [])
                                     if x.get("lang","").lower().startswith("en")), "")
                for mk in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    metrics = cve_data.get("metrics", {}).get(mk, [])
                    if metrics:
                        cvss = metrics[0].get("cvssData", {})
                        score = cvss.get("baseScore")
                        severity = (cvss.get("baseSeverity") or "UNKNOWN").upper()
                        vector = cvss.get("vectorString","")
                        break

            # Derive severity from score if still UNKNOWN
            if severity == "UNKNOWN" and isinstance(score, (int, float)):
                if   score >= 9.0: severity = "CRITICAL"
                elif score >= 7.0: severity = "HIGH"
                elif score >= 4.0: severity = "MEDIUM"
                elif score >  0:   severity = "LOW"

            # Need at least score OR desc
            if score is None and not desc:
                continue

            # Extract exploit refs (combined data) — try CIRCL legacy field AND MITRE refs
            exploits = _extract_exploit_refs(data)
            cna_refs = cna.get("references", []) or [] if cna else []
            if cna_refs:
                # Build a synthetic dict to reuse the extractor
                exploits += _extract_exploit_refs({"references": cna_refs})

            return {"id": cve_id,
                    "score": float(score) if score is not None else None,
                    "severity": severity, "vector": vector or "",
                    "description": desc, "source": "CIRCL-VL", "exploits": exploits}
        except Exception:
            continue
    return None


def _fetch_cve_circl(cve_id):
    """Try CIRCL legacy (cve.circl.lu) — fallback after vulnerability.circl.lu."""
    try:
        url = f"https://cve.circl.lu/api/cve/{cve_id}"
        req = urllib.request.Request(url, headers={"User-Agent": "VulnScan-Pro/1.0.0"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            raw = resp.read().decode()
        if not raw.strip():
            return None
        data = json.loads(raw)
        if not data or not isinstance(data, dict):
            return None
        score, severity, vector = None, "UNKNOWN", ""
        desc = (data.get("summary") or data.get("Description") or "")[:200]
        if isinstance(data.get("cvss3"), dict):
            score = data["cvss3"].get("score") or data["cvss3"].get("baseScore")
            severity = (data["cvss3"].get("baseSeverity") or "").upper() or severity
            vector = data["cvss3"].get("vectorString","")
        elif data.get("cvss3"):
            score = data.get("cvss3")
        if score is None and data.get("cvss"):
            score = data.get("cvss")
            vector = data.get("cvss-vector", "")
        if severity == "UNKNOWN" and isinstance(score, (int, float)):
            if score >= 9.0: severity = "CRITICAL"
            elif score >= 7.0: severity = "HIGH"
            elif score >= 4.0: severity = "MEDIUM"
            elif score > 0: severity = "LOW"
        if score is None and not desc:
            return None
        exploits = _extract_exploit_refs(data)
        return {"id": cve_id, "score": float(score) if score is not None else None,
                "severity": severity, "vector": vector or "", "description": desc,
                "source": "CIRCL", "exploits": exploits}
    except Exception:
        return None


def _fetch_cve_nvd(cve_id):
    """NVD fallback (rate-limited, no API key — slower)."""
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        req = urllib.request.Request(url, headers={"User-Agent": "VulnScan-Pro/1.0.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode())
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        cve_data = vulns[0]["cve"]
        score, severity, vector = None, "UNKNOWN", ""
        for mk in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metrics = cve_data.get("metrics", {}).get(mk, [])
            if metrics:
                cvss     = metrics[0].get("cvssData", {})
                score    = cvss.get("baseScore")
                severity = (cvss.get("baseSeverity") or metrics[0].get("baseSeverity") or "UNKNOWN").upper()
                vector   = cvss.get("vectorString", "")
                break
        desc = next((x["value"][:200] for x in cve_data.get("descriptions", []) if x.get("lang") == "en"), "")
        return {"id": cve_id, "score": score,
                "severity": severity, "vector": vector, "description": desc,
                "source": "NVD"}
    except Exception:
        return None


def fetch_cve_data(cve_id):
    """Get CVE data from cache → vulnerability.circl.lu → CIRCL legacy → NVD. Returns dict."""
    cached = _cve_cache_get(cve_id)
    if cached and cached.get("score") is not None:
        return cached
    # NEW: vulnerability.circl.lu (better coverage, MITRE-format)
    d = _fetch_cve_vulnerability_circl(cve_id)
    if d and d.get("score") is not None:
        _cve_cache_set(cve_id, d)
        return d
    # Legacy CIRCL
    d = _fetch_cve_circl(cve_id)
    if d and d.get("score") is not None:
        _cve_cache_set(cve_id, d)
        return d
    # NVD fallback (slow due to rate-limit)
    d = _fetch_cve_nvd(cve_id)
    if d and d.get("score") is not None:
        _cve_cache_set(cve_id, d)
        return d
    # Stub: no source had data
    stub = {"id": cve_id, "score": None, "severity": "UNKNOWN",
            "description": "No public CVE data found (possibly too new, reserved or withdrawn)",
            "vector": "", "source": "none"}
    return stub


def enrich_cves_nvd(devices):
    """CVE enrichment: CIRCL (primary) + NVD (fallback) + KEV + EPSS + Cache + Exploits."""
    _cve_cache_init()
    all_cves = set()
    for d in devices:
        for cve in d.get("cves", []):
            all_cves.add(cve)
    if not all_cves:
        return devices

    all_cves = list(all_cves)
    scan_state["status"] = f"CVE enrichment: {len(all_cves)} CVE(s)..."
    scan_state["progress"] = 85
    log_event(f"─── CVE ENRICHMENT: {len(all_cves)} CVEs (CIRCL + NVD + KEV + EPSS) ───", "batch")

    # 1. KEV catalog (daily-refresh — usually no-op)
    n_kev = _kev_load_catalog()
    if n_kev:
        log_event(f"  KEV catalog updated: {n_kev} actively exploited CVEs", "info")

    # 2. EPSS batch fetch for all CVEs in one go
    log_event(f"  EPSS enrichment running (1 batch request for {len(all_cves)} CVEs)...", "info")
    epss_map = _epss_fetch_batch(all_cves)
    log_event(f"  EPSS: {len(epss_map)} CVEs with exploitation probability", "info")

    cve_cache = {}
    done_count = [0]
    lock = threading.Lock()
    with lock:
        _nvd_slot = len(scan_state["log_events"])
        log_event(f"  CVE scan 0/{len(all_cves)}  0%", "info")

    sources_used = {"cache": 0, "CIRCL-VL": 0, "CIRCL": 0, "NVD": 0, "none": 0}
    kev_hits = [0]
    exploit_hits = [0]

    def fetch_one(cve_id):
        # try cache first
        cached = _cve_cache_get(cve_id)
        if cached and cached.get("score") is not None:
            result = cached
            result["source"] = "cache"
        else:
            result = fetch_cve_data(cve_id)

        # KEV check
        kev_info = _kev_check(cve_id)
        if kev_info:
            result.update(kev_info)
            kev_hits[0] += 1
        else:
            result.setdefault("kev", False)

        # EPSS attach
        ep = epss_map.get(cve_id)
        if ep:
            result["epss_score"] = ep["epss_score"]
            result["epss_percentile"] = ep["epss_percentile"]

        # Track exploit refs from CIRCL
        if result.get("exploits"):
            exploit_hits[0] += 1

        # Save enriched record back to cache
        _cve_cache_set(cve_id, result)

        with lock:
            cve_cache[cve_id] = result
            src = result.get("source") or "none"
            sources_used[src] = sources_used.get(src, 0) + 1
            done_count[0] += 1
            n = done_count[0]
            total_n = len(all_cves)
            pct = int((n / max(total_n, 1)) * 100)
            scan_state["progress"] = int(85 + (n / total_n) * 13)
            kev_tag = " 🔥KEV" if result.get("kev") else ""
            scan_state["status"]   = f"CVE {n}/{total_n}: {cve_id} [{src}]{kev_tag}"
            log_update_at(_nvd_slot, f"  CVE scan {n}/{total_n}  {pct}%", "info")

    for cve_id in all_cves:
        if scan_state.get("cancel_requested"):
            break
        t = threading.Thread(target=fetch_one, args=(cve_id,))
        t.start()
        t.join(timeout=12)
        time.sleep(0.2)

    summary = ", ".join(f"{k}={v}" for k, v in sources_used.items() if v > 0)
    log_event(f"─── CVE enrichment complete: {len(cve_cache)} enriched ({summary}) · 🔥KEV={kev_hits[0]} · 💥Exploits={exploit_hits[0]} ───", "batch")

    # Attach enriched data to devices
    for d in devices:
        d["cve_details"] = []
        for cve_id in d.get("cves", []):
            if cve_id in cve_cache:
                d["cve_details"].append(cve_cache[cve_id])
        # Priority sort: KEV > EPSS × CVSS
        def _priority(cv):
            base = cv.get("score") or 0
            epss = cv.get("epss_score") or 0
            kev_boost = 100 if cv.get("kev") else 0
            return -(kev_boost + base + (epss * 10))
        d["cve_details"].sort(key=_priority)

    return devices


def run_scan(ranges, enable_cve=False, enable_nvd=True, enable_os=True, port_mode='top1000', enable_nuclei=False, enable_infra=False):
    """Führt den nmap-Scan durch."""
    global scan_state
    scan_state["running"] = True
    scan_state["results"] = []
    scan_state["progress"] = 5
    scan_state["status"] = "Starting scan..."
    scan_state["log_events"] = []
    scan_state["log_seq"] = 0
    scan_state["os_disabled_runtime"] = False  # reset auto-disable flag
    log_event(f"Scan started  >>  {', '.join(ranges)}", "info")

    # ── DHCP-Server Discovery (einmalig beim Scan-Start) ──────────────
    log_event("DHCP discovery — searching for DHCP servers on the network...", "info")
    try:
        r_dhcp = subprocess.run(
            [NMAP_BIN, "--script", "broadcast-dhcp-discover", "-e", "any",
             "--script-timeout", "10s", "-oX", "-"],
            capture_output=True, text=True, timeout=15
        )
        # Parse DHCP results from script output
        dhcp_servers = []
        for line in r_dhcp.stdout.split("\n"):
            if "Server Identifier" in line or "serverIdentifier" in line:
                parts = line.strip().split()
                if parts:
                    ip = parts[-1]
                    dhcp_servers.append(ip)
        if dhcp_servers:
            for srv in dhcp_servers:
                log_event(f"  DHCP SERVER  {srv}", "found")
            scan_state["dhcp_servers"] = dhcp_servers
        else:
            log_event("  DHCP discovery: no server found (broadcast may be blocked)", "info")
    except Exception as e:
        log_event(f"  DHCP discovery failed: {e}", "warn")

    all_devices = []
    
    scan_state["cancel_requested"] = False
    for i, network_range in enumerate(ranges):
        if scan_state.get('cancel_requested'):
            scan_state['status'] = 'Scan cancelled'
            break
        scan_state["status"] = f"Scanning {network_range} ..."
        scan_state["progress"] = int(10 + (i / len(ranges)) * 80)
        
        try:
            # Phase 1: Host Discovery — mehrere Methoden, erste die Hosts findet gewinnt
            import xml.etree.ElementTree as ET

            def parse_live_hosts(xml_out):
                hosts = []
                try:
                    root = ET.fromstring(xml_out)
                    for host in root.findall("host"):
                        st = host.find("status")
                        if st is not None and st.get("state") == "up":
                            addr = host.find("address[@addrtype='ipv4']")
                            if addr is not None:
                                hosts.append(addr.get("addr"))
                except:
                    pass
                return hosts

            import sys as _sys
            _is_windows = _sys.platform.startswith("win") or os.name == "nt"
            if _is_windows:
                # Windows ohne Admin: kein ARP/ICMP raw — TCP-basierte Discovery
                discovery_methods = [
                    [NMAP_BIN, "-sn", "-PS80,443,22,8080,3389", "-T4", "-oX", "-", network_range],
                    [NMAP_BIN, "-sn", "-PA80,443", "-T4", "-oX", "-", network_range],
                    [NMAP_BIN, "-sn", "-Pn", "-T4", "-oX", "-", network_range],
                ]
            else:
                discovery_methods = [
                    [NMAP_BIN, "-sn", "-PR", "-T4", "--min-rate", "200", "-oX", "-", network_range],
                    [NMAP_BIN, "-sn", "-PE", "-PS80,443,22,8080", "-T4", "-oX", "-", network_range],
                    [NMAP_BIN, "-sn", "-PE", "-T4", "-oX", "-", network_range],
                    [NMAP_BIN, "-sn", "-Pn", "-T4", "-oX", "-", network_range],
                ]

            live_hosts = []
            for method in discovery_methods:
                scan_state["status"] = f"Host discovery ({method[2]}) in {network_range}..."
                log_event(f"Host discovery {method[2]}  in  {network_range}...", "info")
                try:
                    r = subprocess.run(method, capture_output=True, text=True, timeout=60)
                    hosts = parse_live_hosts(r.stdout)
                    if hosts:
                        live_hosts = hosts
                        print(f"Discovery via {method[2]}: {len(hosts)} Hosts")
                        break
                except Exception as e:
                    print(f"Discovery method {method[2]} failed: {e}")
                    log_event(f"Discovery {method[2]} failed, trying the next method...", "warn")
                    continue

            if not live_hosts:
                scan_state["status"] = f"No hosts in {network_range} found"
                log_event(f"No hosts in {network_range} found", "warn")
                continue

            # Log each discovered host
            log_event(f"─── {len(live_hosts)} HOSTS ONLINE ───", "batch")
            for h in live_hosts:
                log_event(f"  ONLINE   {h}", "found")
            log_event(f"─── STARTING PORT SCAN ({"STD" if port_mode=="top1000" else "HIGH" if port_mode=="iana" else "HIGH+" if port_mode=="iana_udp" else "DEEP"}) ───", "batch")

            host_list = " | ".join(live_hosts)
            scan_state["status"]           = f"{len(live_hosts)} hosts found — Starting port scan..."
            scan_state["discovery_hosts"]  = live_hosts
            time.sleep(0.5)

            # Discovery hat Hosts acknowledged — direkt uebernehmen (kein separater Health-Check)
            confirmed = list(live_hosts)
            log_event(f"─── ALL {len(confirmed)} HOSTS ARE BEING SCANNED ───", "batch")

            base_pct = int(10 + (i / len(ranges)) * 30)
            scan_state["progress"] = base_pct

            # --- Mode-specific batch config ---
            # LAN-relevante UDP-Ports (fix für alle Modi außer DEEP/iana_udp)
            LAN_UDP = "53,67,68,123,137,138,161,162,500,1900,4500,5353,5355"
            udp_port_args = []  # default: kein separater UDP-Pass
            if port_mode == "deep":
                host_timeout     = "0"
                batch_py_timeout = 3600
                port_args        = ["-p", "1-65535"]
                udp_port_args    = ["-sU", "--top-ports", "100"]  # DEEP: UDP Top 100
                timing, min_rate, retries = "-T3", "50", "1"
                PARALLL         = 2
                batch_size       = 1
            elif port_mode in ("iana", "iana_udp"):
                host_timeout     = "0"
                batch_py_timeout = 1200 if enable_cve else 600
                iana_data        = get_iana_port_lists()
                tcp_ports        = iana_data.get("tcp_ports", [])
                # iana_udp = IANA TCP+UDP kombiniert; iana = nur TCP + feste LAN-UDP
                if port_mode == "iana_udp":
                    udp_ports    = iana_data.get("udp_ports", [])
                    scan_ports   = sorted(set(tcp_ports + udp_ports))
                    iana_str     = ",".join(str(p) for p in scan_ports)
                    port_args    = ["-sS", "-sU", "-p", iana_str]
                    log_event(f"  IANA list: {len(tcp_ports)} TCP + {len(udp_ports)} UDP-ports loaded", "info")
                else:
                    iana_str     = ",".join(str(p) for p in sorted(set(tcp_ports)))
                    port_args    = ["-p", iana_str]
                    udp_port_args = []  # HIGH: no UDP
                    log_event(f"  IANA list: {len(tcp_ports)} TCP-ports loaded (no UDP)", "info")
                timing, min_rate, retries = ("-T4","120","1") if enable_cve else ("-T4","250","1")
                PARALLL       = 2 if port_mode == "iana_udp" else (3 if enable_cve else 4)
                batch_size     = max(1, len(confirmed) // max(1, PARALLL))
            else:  # top1000 (STD) — TCP Top 1000 + feste LAN-UDP
                host_timeout     = "0"
                batch_py_timeout = 500 if enable_cve else 180
                port_args        = ["--top-ports", "1000"]
                udp_port_args    = ["-sU", "-p", LAN_UDP]  # fix LAN-UDP statt Top 1000 UDP
                timing, min_rate, retries = ("-T4","200","1") if enable_cve else ("-T4","500","1")
                PARALLL         = 3 if enable_cve else 4
                batch_size       = max(1, len(confirmed) // PARALLL)

            # --- 1 Host per Worker, Queue mit max PARALLL gleichzeitig ---
            port_range_pct = int(65 / len(ranges))
            start_pct      = base_pct
            total_hosts    = len(confirmed)

            scan_state["status"]     = f"{total_hosts} Hosts, max {PARALLL} parallel..."
            scan_state["hosts_done"]  = 0
            scan_state["hosts_total"] = total_hosts
            scan_state["progress"] = start_pct
            log_event(f"─── PORT SCAN {'STD' if port_mode=='top1000' else 'HIGH' if port_mode=='iana' else 'HIGH+' if port_mode=='iana_udp' else 'DEEP'}  {total_hosts} Hosts  max {PARALLL}x parallel ───", "batch")

            # Realistic per-host time estimate for progress display
            if port_mode == "deep":
                host_est_secs = 600     # deep: 65535 ports, can take 10min
            elif port_mode in ("iana", "iana_udp"):
                host_est_secs = 120 if enable_cve else 60
            else:  # top1000
                host_est_secs = 60 if enable_cve else 25

            completed = [0]
            lock      = threading.Lock()
            sem       = threading.Semaphore(PARALLL)

            def scan_host(idx, host):
                if scan_state.get("cancel_requested"):
                    return
                with sem:
                    with lock:
                        _slot  = len(scan_state["log_events"])
                        log_event(f"  START  ({idx+1}/{total_hosts})  {host}  (Discovery 0%)", "info")
                    ht_args = ["--host-timeout", host_timeout] if host_timeout != "0" else []
                    # Root/Admin-Detection: -sS (SYN) braucht raw sockets = root/admin.
                    # Ohne root liefert nmap still leeres XML → Scan wirkt "kaputt".
                    # Fallback: -sT (Connect-Scan) funktioniert als beliebiger User.
                    import sys
                    is_windows = sys.platform.startswith("win") or os.name == "nt"
                    try:
                        is_root = (not is_windows) and hasattr(os, "geteuid") and os.geteuid() == 0
                    except Exception:
                        is_root = False
                    if is_windows or not is_root:
                        scan_type = ["-sT"]
                    else:
                        scan_type = ["-sS"]
                    args = [NMAP_BIN] + scan_type + ["-sV", "-Pn",
                            timing, "--min-rate", min_rate, "--max-retries", retries,
                            "-oX", "-"] + ht_args + port_args
                    # Auto-disable -O if a previous host hit a raw-socket / QUITTING error
                    use_os = enable_os and not scan_state.get("os_disabled_runtime")
                    if use_os:
                        args += ["-O", "--osscan-guess", "--osscan-limit"]
                    if enable_cve:
                        args += ["--script", "vuln,banner,http-title,ssl-cert,smb-security-mode", "--script-timeout", "60s"]
                    else:
                        # Targeted NSE scripts — safe scripts work on all platforms
                        nse_safe = [
                            # HTTP
                            "http-title",
                            "http-auth",
                            "http-methods",
                            # SSL/TLS — safe (keine raw sockets)
                            "ssl-cert",
                            "ssl-enum-ciphers",
                            # DNS
                            "dns-recursion",
                            # SNMP
                            "snmp-info",
                            # FTP
                            "ftp-anon",
                            # Telnet
                            "telnet-encryption",
                            # NetBIOS
                            "nbstat",
                            # SMTP
                            "smtp-commands",
                            # SSH
                            "ssh-auth-methods",
                            "ssh2-enum-algos",
                        ]
                        # Privileged scripts — nur auf Linux/Mac mit Root oder Windows mit Npcap+Admin
                        nse_privileged = [
                            # SMB
                            "smb-security-mode",
                            "smb-vuln-ms17-010",
                            "smb-protocols",
                            "smb2-security-mode",
                            "smb-enum-shares",
                            # SSL/TLS vuln (braucht raw sockets)
                            "ssl-poodle",
                            "ssl-heartbleed",
                            "ssl-dh-params",
                            "ssl-ccs-injection",
                            "sslv2",
                            "tls-ticketbleed",
                            # SSH
                            "sshv1",
                            # SMTP
                            "smtp-open-relay",
                            # RDP
                            "rdp-enum-encryption",
                            "rdp-vuln-ms12-020",
                            # MySQL / MSSQL
                            "mysql-empty-password",
                            "mysql-info",
                            "ms-sql-empty-password",
                            "ms-sql-info",
                            # FTP
                            "ftp-bounce",
                        ]
                        if is_windows:
                            nse_scripts = ",".join(nse_safe)
                        else:
                            nse_scripts = ",".join(nse_safe + nse_privileged)
                        args += ["--script", nse_scripts, "--script-timeout", "30s"]
                    args += [host]
                    stop_evt   = threading.Event()
                    t_start    = time.time()
                    _hi        = idx
                    _h         = host
                    _total     = total_hosts
                    _timeout   = batch_py_timeout
                    _host_est  = host_est_secs

                    def timer_progress(slot=_slot, hi=_hi, h=_h, total=_total, timeout=_timeout,
                                       ev=stop_evt, ts=t_start, lk=lock, comp=completed,
                                       sp=start_pct, prng=port_range_pct, host_est=_host_est):
                        def _host_phase(p):
                            if p < 20:  return f"Discovery {p}%"
                            if p < 80:  return f"Port scan {p}%"
                            return      f"Service detection {p}%"
                        while not ev.wait(timeout=1):
                            elapsed = time.time() - ts
                            with lk:
                                n_done = comp[0]
                            # Per-host % based on realistic estimate, capped at 95
                            pct = min(95, int((elapsed / max(host_est, 1)) * 100))
                            log_update_at(slot, f"  START  ({hi+1}/{total})  {h}  ({_host_phase(pct)})", "info")
                            # Smooth global progress: interpolate current host between n_done and n_done+1
                            host_frac = pct / 100.0
                            smooth_done = n_done + host_frac
                            global_pct = int(sp + (smooth_done / max(total, 1)) * prng)
                            scan_state["progress"] = min(global_pct, sp + prng - 1)

                    threading.Thread(target=timer_progress, daemon=True).start()
                    try:
                        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        stdout_data, stderr_data = proc.communicate(timeout=batch_py_timeout)
                        devs = parse_nmap_xml(stdout_data)
                        # Silent-fail detection: nmap lief durch ohne Exception,
                        # aber weder Hosts-up noch Ports → vermutlich Privileg-/Setup-Problem.
                        if not devs:
                            hint = ""
                            err = (stderr_data or "").strip()
                            errL = err.lower()
                            out  = (stdout_data or "")
                            outL = out.lower()
                            xml_bytes = len(out)
                            exit_code = proc.returncode if proc.returncode is not None else -1
                            if "requires privileges" in errL or "requires root" in errL or "operation not permitted" in errL:
                                hint = "Nmap requires root/administrator privileges"
                            elif "wpcap.dll" in errL or "npcap" in errL or "no permission to scan" in errL:
                                hint = "Npcap is missing or inactive (Windows) — https://npcap.com/#download install"
                            elif "failed to open" in errL and ("raw socket" in errL or "ethernet device" in errL or "dnet:" in errL):
                                hint = "raw socket error (often OS detection -O on Windows without the correct Npcap)"
                                # Auto-disable -O for the rest of this scan so other hosts still scan
                                if not scan_state.get("os_disabled_runtime"):
                                    scan_state["os_disabled_runtime"] = True
                                    log_event("  ⚙  OS detection automatically disabled for remaining hosts (raw socket unavailable)", "warn")
                            elif "failed to determine route" in errL or "failed to determine route" in outL:
                                hint = "Routing issue - check the interface or gateway"
                            elif "0 hosts up" in outL and 'status="up"' not in outL:
                                hint = "Nmap reports 0 hosts up - check the firewall or interface"
                            elif scan_type == ["-sT"] and not is_root and not is_windows:
                                hint = "Connect scan without root - some ports may not be visible"
                            elif xml_bytes < 100:
                                hint = f"Nmap returned very little output ({xml_bytes} bytes) — process may be blocked or terminated"
                            elif exit_code != 0:
                                hint = f"nmap exit={exit_code}"
                            else:
                                hint = "no matching pattern - see diagnostics"
                            log_event(f"  ⚠  Nmap ran but returned no result for {host} ({hint})", "warn")
                            # Verbatim stderr aus nmap (max 300 Zeichen) für Diagnose
                            if err:
                                log_event(f"     stderr: {err[:300]}", "warn")
                            # Verbatim erste Zeile mit Routing-/Warnungs-Hinweis aus stdout
                            for ln in out.splitlines():
                                lnL = ln.lower()
                                if any(k in lnL for k in ["warning", "failed", "nsock", "error", "could not"]):
                                    log_event(f"     stdout: {ln.strip()[:300]}", "warn")
                                    break
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        stop_evt.set()
                        log_event(f"  TIMEOUT ({idx+1}/{total_hosts})  {host}", "warn")
                        devs = []
                    except Exception as e:
                        stop_evt.set()
                        log_event(f"  ERROR ({idx+1}/{total_hosts})  {host}: {e}", "warn")
                        devs = []
                    stop_evt.set()  # stops timer immediately

                    # ── UDP-Pass (STD: Top 1000, DEEP: Top 100) ──────────────────
                    if udp_port_args and not scan_state.get("cancel_requested"):
                        try:
                            udp_args_full = [NMAP_BIN, "-Pn", timing, "--min-rate", min_rate,
                                             "-oX", "-"] + udp_port_args + [host]
                            proc_udp = subprocess.Popen(udp_args_full, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                            udp_stdout, _ = proc_udp.communicate(timeout=120)
                            udp_devs = parse_nmap_xml(udp_stdout)
                            if udp_devs and devs:
                                # Merge UDP ports into TCP result
                                udp_ports = udp_devs[0].get("ports", [])
                                if udp_ports:
                                    devs[0]["ports"] = devs[0].get("ports", []) + udp_ports
                                    log_event(f"  UDP  {host}  {len(udp_ports)} UDP port(s) found", "info")
                        except Exception as e:
                            log_event(f"  UDP scan {host} Error: {e}", "warn")
                    with lock:
                        completed[0] += 1
                        done = completed[0]
                        if not devs:
                            devs = [{
                                "ip": host, "mac": "-", "vendor": "Unknown", "hostname": "-",
                                "os": "Unknown", "status": "up", "ports": [], "cves": [],
                                "cve_details": [], "nuclei_findings": [],
                                "first_seen": datetime.now().strftime("%d.%m.%Y %H:%M"),
                                "last_seen":  datetime.now().strftime("%d.%m.%Y %H:%M"),
                            }]
                        all_devices.extend(devs)
                        scan_state["results"]  = list(all_devices)
                        scan_state["progress"] = int(start_pct + (done / total_hosts) * port_range_pct)
                        scan_state["status"]   = f"{done}/{total_hosts} hosts completed..."
                        scan_state["hosts_done"] = done
                        d      = devs[0]
                        ip     = d.get("ip", host)
                        ports  = len(d.get("ports", []))
                        cves   = len(d.get("cves", []))
                        hn     = d.get("hostname","") or ""
                        hn     = f"  {hn}" if hn and hn != "-" else ""
                        vendor = d.get("vendor","") or ""
                        vendor = f"  [{vendor[:20]}]" if vendor and vendor != "Unknown" else ""
                        _num = idx + 1
                        if cves > 0:
                            log_update_at(_slot, f"  DONE ({_num}/{total_hosts})  {ip}{hn}{vendor}   {ports} Ports  !! {cves} CVE(s)  100%", "cve")
                        elif ports > 0:
                            log_update_at(_slot, f"  DONE ({_num}/{total_hosts})  {ip}{hn}{vendor}   {ports} Ports  100%", "found")
                        else:
                            log_update_at(_slot, f"  DONE ({_num}/{total_hosts})  {ip}{hn}{vendor}   online, no ports  100%", "found")

            workers = [threading.Thread(target=scan_host, args=(i, h)) for i, h in enumerate(confirmed)]
            for t in workers: t.daemon = True; t.start()
            for t in workers: t.join(timeout=batch_py_timeout + 30)

            # Sicherheitsnetz: falls ein Worker komplett crashte
            scanned_ips = {d["ip"] for d in all_devices}
            for h in confirmed:
                if h not in scanned_ips:
                    all_devices.append({
                        "ip": h, "mac": "-", "vendor": "Unknown", "hostname": "-",
                        "os": "Unknown", "status": "up", "ports": [], "cves": [],
                        "cve_details": [], "nuclei_findings": [],
                        "first_seen": datetime.now().strftime("%d.%m.%Y %H:%M"),
                        "last_seen":  datetime.now().strftime("%d.%m.%Y %H:%M"),
                    })
                    log_event(f"  FALLBACK  {h}  Worker-Timeout", "warn")
            scan_state["results"] = list(all_devices)
            scan_state["progress"] = int(start_pct + port_range_pct)  # ~75%
            
        except subprocess.TimeoutExpired:
            scan_state["status"] = f"Timeout for {network_range}"
        except Exception as e:
            scan_state["status"] = f"Error: {str(e)}"
            print(f"Scan Error: {e}")
    
    # Phase 2.4: SNMP Walk — Devices mit Port 161 anreichern
    snmp_candidates = [d for d in all_devices if any(p.get("port") == "161" for p in d.get("ports", []))]
    if snmp_candidates:
        scan_state["status"] = f"SNMP-Walk: {len(snmp_candidates)} device(s) with port 161..."
        scan_state["progress"] = 75
        log_event(f"─── SNMP WALK: {len(snmp_candidates)} device(s) ───", "batch")
        all_devices, snmp_count = run_snmp_enrichment(all_devices)
        log_event(f"─── SNMP enrichment complete: {snmp_count} enriched ───", "batch")

    # Phase 2.5: ARP enrichment — 76%
    scan_state["progress"] = 76
    scan_state["status"] = "Reading ARP table..."
    all_devices = enrich_with_arp(all_devices)
    log_event(f"ARP enrichment complete — {sum(1 for d in all_devices if d.get('mac') and d['mac'] != '-')} MAC addresses known", "batch")

    # Phase 3: Python Security Checks — 78→83%
    if enable_nuclei and not scan_state.get("cancel_requested"):
        http_targets = [d for d in all_devices if any(
            p["port"] in ("80","443","8080","8443","8181","8089","8000","8008","8888","8081","81")
            for p in d.get("ports", [])
        )]
        if http_targets:
            scan_state["status"] = f"Security checks: HTTP headers, TLS, paths, default credentials..."
            scan_state["progress"] = 78

            def _progress(done, total, ip):
                pct = int(78 + (done / max(total,1)) * 5)
                scan_state["progress"] = pct
                scan_state["status"] = f"Security-Check {done}/{total}: {ip}"
                scan_state["results"] = list(all_devices)

            all_devices = run_all_python_checks(all_devices, progress_cb=_progress)
            n_hits = sum(len(d.get("nuclei_findings",[])) for d in all_devices)
            scan_state["status"] = f"Security checks complete — {n_hits} findings"
            scan_state["results"] = list(all_devices)
        else:
            scan_state["status"] = "No HTTP ports — security checks skipped"
    scan_state["progress"] = 84

    # Phase 3.5: Infrastructure Security Templates — 84→85%
    infra_targets = [d for d in all_devices if d.get("ports")]
    # enable_infra kommt als Funktionsargument
    if enable_infra and infra_targets:
        scan_state["status"] = "Infrastructure Security Templates..."
        log_event(f"─── INFRA TEMPLATES: {len(infra_targets)} check hosts ───", "batch")
        infra_total = len(infra_targets)
        infra_found = 0
        for i_idx, dev in enumerate(infra_targets):
            if scan_state.get("cancel_requested"): break
            ip        = dev.get("ip","")
            open_ports = [p["port"].split("/")[0] for p in dev.get("ports",[])]
            vendor    = dev.get("vendor","")
            os_info   = dev.get("os","")
            snmp_info = dev.get("snmp_info","")
            pct_i     = int((i_idx+1) / max(infra_total,1) * 100)
            log_event(f"  INFRA  ({i_idx+1}/{infra_total})  {ip}  checking... ({pct_i}%)", "info")
            try:
                findings, detected = run_infra_templates(ip, open_ports, vendor, os_info, snmp_info)
            except Exception as e:
                log_event(f"  INFRA  {ip}  Error: {e}", "warn")
                continue
            if detected:
                dev["infra_tech"]     = detected
                dev["infra_findings"] = findings
                sev_counts = {}
                for f in findings:
                    s = f.get("severity","INFO")
                    sev_counts[s] = sev_counts.get(s,0) + 1
                summary = " · ".join(f"{v}x {k}" for k,v in sev_counts.items() if v > 0) or "no findings"
                log_event(f"  INFRA  ({i_idx+1}/{infra_total})  {ip}  [{', '.join(detected)}]  {summary}  ({pct_i}%)", "cve" if sev_counts.get("KRITISCH",0) > 0 else "found" if sev_counts.get("HIGH",0) > 0 else "info")
                infra_found += len(findings)
            else:
                log_event(f"  INFRA  ({i_idx+1}/{infra_total})  {ip}  no infrastructure detected  ({pct_i}%)", "info")
        log_event(f"─── INFRA TEMPLATES complete: {infra_found} findings ───", "batch")
    scan_state["progress"] = 85

    # Phase 4: NVD CVE enrichment — 85→92%
    scan_state["status"] = "Querying CVE database (NVD)..."
    scan_state["progress"] = 85
    if enable_nvd:
        all_devices = enrich_cves_nvd(all_devices)
    else:
        scan_state['status'] = 'NVD enrichment skipped'

    # Sort devices: CVE + Nuclei findings first
    all_devices.sort(key=lambda d: (
        -(len(d.get("cves",[])) + len(d.get("nuclei_findings",[])))
    ))

    # Attach first_seen, previous_ips from known_devices to results
    for d in all_devices:
        kd = app_data["known_devices"].get(d["ip"], {})
        d["first_seen"]    = kd.get("first_seen", datetime.now().strftime("%d.%m.%Y %H:%M"))
        d["previous_ips"]  = kd.get("previous_ips", [])
        d["label"]         = app_data["labels"].get(d["ip"], "")

    # Complete — sofort UI updaten
    vuln_count = sum(1 for d in all_devices if d.get("cves"))
    scan_state["results"]   = all_devices
    scan_state["progress"]  = 100
    scan_state["running"]   = False
    scan_state["last_scan"] = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    scan_state["status"]    = f"Complete — {len(all_devices)} device(s), {vuln_count} with CVEs"
    log_event(f"─── SCAN COMPLETE: {len(all_devices)} devices, {vuln_count} with CVEs ───", "batch")

    # Blocklists-Check: prüfen, ob gefundene Hosts auf Blacklists stehen
    try:
        bl_hits = 0
        for d in all_devices:
            ip = d.get("ip")
            if not ip:
                continue
            matches = ip_in_blacklist(ip)
            if matches:
                bl_hits += 1
                feeds = ", ".join(sorted({m["feed"] for m in matches}))
                log_ev("critical", "alert",
                       f"Blocklists-Hit: {ip} ({d.get('hostname') or '-'}) in {feeds}",
                       event_type="blacklist_hit", host=ip,
                       data={"matches": matches})
        if bl_hits:
            log_event(f"─── Blocklists: {bl_hits} host(s) matched blocklists! ───", "warn")
    except Exception as _e:
        log_event(f"Blocklist check failed: {_e}", "warn")

    # Alerts + DB speichern im Hintergrund — blockiert UI nicht
    def _save_bg():
        try:
            check_alerts(all_devices)
            add_scan_history(all_devices, port_mode)
            app_data["last_scan_results"] = all_devices
            app_data["last_scan_time"]    = scan_state["last_scan"]
            app_data["last_scan_mode"]    = port_mode
            scan_state["last_mode"]       = port_mode
            save_data()
            new_alerts = sum(1 for a in app_data["alerts"] if not a["acknowledged"])
            scan_state["status"] = f"Complete — {len(all_devices)} devices, {vuln_count} with CVEs, {new_alerts} Alerts"
        except Exception as e:
            print(f"BG save error: {e}")
    threading.Thread(target=_save_bg, daemon=True).start()

# --- Routes ---
@app.route("/")
def index():
    with open(os.path.join(os.path.dirname(__file__), "index.html"), encoding="utf-8") as f:
        return f.read(), 200, {"Content-Type": "text/html; charset=utf-8"}

@app.route("/api/network-info")
def network_info():
    net, local_ip = get_local_network()
    iana_data = get_iana_port_lists()
    tcp_count = len(iana_data.get("tcp_ports", []))
    udp_count = len(iana_data.get("udp_ports", []))
    return jsonify({
        "network": net,
        "local_ip": local_ip,
        "iana_tcp_count": tcp_count,
        "iana_udp_count": udp_count,
        "iana_total_count": tcp_count + udp_count,
        "iana_last_updated": iana_data.get("last_updated")
    })

@app.route("/api/scan", methods=["POST"])
def start_scan():
    global scan_state
    if scan_state["running"]:
        return jsonify({"error": "Scan already running"}), 400
    
    data = request.json or {}
    ranges = data.get("ranges", [])
    enable_cve    = data.get("cve", False)
    enable_nvd    = data.get("nvd", True)
    enable_os     = data.get("os", True)
    port_mode     = data.get("port_mode", "top1000")
    enable_nuclei = data.get("nuclei", False)
    enable_infra  = data.get("infra", False)
    
    if not ranges:
        net, _ = get_local_network()
        ranges = [net]
    
    thread = threading.Thread(target=run_scan, args=(ranges, enable_cve, enable_nvd, enable_os, port_mode, enable_nuclei, enable_infra))
    thread.daemon = True
    thread.start()
    
    return jsonify({"status": "gestartet", "ranges": ranges})

@app.route("/api/status")
def get_status():
    return jsonify({
        "running": scan_state["running"],
        "progress": scan_state["progress"],
        "status": scan_state["status"],
        "last_scan": scan_state["last_scan"],
        "last_mode": scan_state.get("last_mode", "top1000"),
        "device_count": len(scan_state["results"]),
        "log_seq": scan_state.get("log_seq", 0),
        "hosts_done": scan_state.get("hosts_done", 0),
        "hosts_total": scan_state.get("hosts_total", 0),
    })

@app.route("/api/scan-log")
def get_scan_log():
    events = scan_state.get("log_events", [])
    return jsonify({"events": events, "total": len(events), "seq": scan_state.get("log_seq", 0)})

@app.route("/api/results")
def get_results():
    return jsonify(scan_state["results"])







@app.route("/api/scan/cancel", methods=["POST"])
def cancel_scan():
    global scan_state
    scan_state["cancel_requested"] = True
    scan_state["status"] = "Cancellation requested..."
    return jsonify({"ok": True})


@app.route("/api/scan/udp", methods=["POST"])
def start_udp_scan():
    """UDP scan auf bekannte kritische Ports gegen alle bekannten Hosts."""
    if scan_state.get("running"):
        return jsonify({"error": "Scan already running"}), 409

    data   = request.json or {}
    # Use known devices or provided IPs
    targets = data.get("targets") or list(app_data.get("known_devices", {}).keys())
    if not targets:
        return jsonify({"error": "No targets — run a TCP scan first"}), 400

    UDP_PORTS = "53,67,68,123,161,162,500,514,520,1194,4500,5060,5353,69"

    def run_udp():
        scan_state["running"]  = True
        scan_state["status"]   = "UDP scan running..."
        scan_state["progress"] = 0
        log_event("─── UDP SCAN STARTED ───", "batch")
        results = {}
        for i, ip in enumerate(targets):
            if scan_state.get("cancel_requested"):
                break
            try:
                log_event(f"  UDP  {ip}  ({i+1}/{len(targets)})", "info")
                args = [NMAP_BIN, "-sU", "-Pn", "--open",
                        "-p", UDP_PORTS,
                        "--script", "snmp-info,dns-recursion",
                        "--script-timeout", "10s",
                        "-T4", "--host-timeout", "60s",
                        "-oX", "-", ip]
                proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                out, _ = proc.communicate(timeout=90)
                devs = parse_nmap_xml(out)
                if devs and devs[0].get("ports"):
                    results[ip] = devs[0]["ports"]
                    log_event(f"  UDP  {ip}  {len(devs[0]['ports'])} open UDP ports", "found")
                    # Merge into known devices
                    kd = app_data.get("known_devices", {}).get(ip)
                    if kd is not None:
                        existing = [p for p in kd.get("ports", []) if p.get("protocol") != "udp"]
                        udp_ports = [dict(p, protocol="udp") for p in devs[0]["ports"]]
                        kd["ports"] = existing + udp_ports
                        kd["udp_scanned"] = datetime.now().strftime("%d.%m.%Y %H:%M")
            except Exception as e:
                log_event(f"  UDP  {ip}  Error: {e}", "warn")
            scan_state["progress"] = int((i+1) / len(targets) * 100)

        save_data()
        scan_state["running"]  = False
        scan_state["status"]   = f"UDP scan complete — {len(results)} hosts with open UDP ports"
        scan_state["progress"] = 100
        log_event(f"─── UDP SCAN COMPLETE: {len(results)} hosts with UDP ports ───", "batch")

    scan_state["cancel_requested"] = False
    threading.Thread(target=run_udp, daemon=True).start()
    return jsonify({"ok": True})



@app.route("/api/scan/clear", methods=["POST"])
def clear_scan():
    """Loescht die letzten Scan-Ergebnisse."""
    scan_state["results"] = []
    scan_state["last_scan"] = None
    scan_state["status"] = "Ready"
    scan_state["progress"] = 0
    app_data["last_scan_results"] = []
    app_data["last_scan_time"] = None
    save_data()
    return jsonify({"ok": True})

@app.route("/api/discover-networks")
def discover_networks_route():
    """Returns all reachable networks from routing table."""
    nets = discover_networks()
    return jsonify({"networks": nets})


@app.route("/api/alerts")
def get_alerts():
    alerts = sorted(app_data["alerts"], key=lambda a: a.get("time",""), reverse=True)
    return jsonify(alerts)

@app.route("/api/alerts/<alert_id>/ack", methods=["POST"])
def ack_alert(alert_id):
    for a in app_data["alerts"]:
        if a["id"] == alert_id:
            a["acknowledged"] = True
    save_data()
    return jsonify({"ok": True})

@app.route("/api/alerts/ack-all", methods=["POST"])
def ack_all():
    for a in app_data["alerts"]:
        a["acknowledged"] = True
    save_data()
    return jsonify({"ok": True})

@app.route("/api/history")
def get_history():
    return jsonify(list(reversed(app_data["scan_history"])))

@app.route("/api/known-devices")
def get_known_devices():
    """All devices ever seen — merged with current scan results.
    Re-runs classify_device on every load so stale DB data benefits from latest rules.
    """
    current_ips = {d["ip"] for d in scan_state.get("results", [])}
    current_map = {d["ip"]: d for d in scan_state.get("results", [])}
    devices = []
    for ip, kd in app_data["known_devices"].items():
        if ip in current_map:
            d = dict(current_map[ip])
            d["online"] = True
        else:
            d = {
                "ip": ip, "mac": kd.get("mac",""), "vendor": kd.get("vendor",""),
                "hostname": kd.get("hostname",""), "os": "", "ports": [], "cves": [],
                "label": kd.get("label",""), "first_seen": kd.get("first_seen",""),
                "last_seen": kd.get("last_seen",""), "online": False
            }
        # Re-classify on every load — applies latest rules to stale data
        try:
            classify_device(d)
        except Exception:
            pass
        devices.append(d)
    # Sort: online first, then by IP
    devices.sort(key=lambda d: (not d.get("online"), [int(x) for x in d["ip"].split(".") if x.isdigit()]))
    return jsonify(devices)

@app.route("/api/labels", methods=["GET"])
def get_labels():
    return jsonify(app_data["labels"])

@app.route("/api/labels", methods=["POST"])
def set_label():
    data = request.json or {}
    ip = data.get("ip")
    label = data.get("label", "").strip()
    if ip:
        app_data["labels"][ip] = label
        if ip in app_data["known_devices"]:
            app_data["known_devices"][ip]["label"] = label
        save_data()
    return jsonify({"ok": True})

@app.route("/api/scheduler", methods=["GET"])
def get_scheduler():
    return jsonify(app_data["scheduler"])

@app.route("/api/scheduler", methods=["POST"])
def set_scheduler():
    data = request.json or {}
    app_data["scheduler"]["enabled"]          = data.get("enabled", False)
    app_data["scheduler"]["interval_minutes"] = int(data.get("interval_minutes", 60))
    app_data["scheduler"]["port_mode"]        = data.get("port_mode", "top1000")
    app_data["scheduler"]["sched_mode"]       = data.get("sched_mode", "interval")
    app_data["scheduler"]["sched_time"]       = data.get("sched_time", "02:00")
    app_data["scheduler"]["sched_weekdays"]   = data.get("sched_weekdays", [1])
    app_data["scheduler"]["sched_udp"]        = data.get("sched_udp", False)
    if "ranges" in data:
        app_data["scheduler"]["ranges"] = data["ranges"]
    save_data()
    return jsonify(app_data["scheduler"])

@app.route("/api/reports/max", methods=["POST"])
def set_max_reports():
    data = request.get_json(silent=True) or {}
    n = max(1, min(20, int(data.get("max", 3))))
    app_data["max_reports"] = n
    return jsonify({"max": n})

@app.route("/api/reports")
def list_reports():
    """List saved PDF reports up to max_reports limit."""
    try:
        limit = app_data.get("max_reports", 3)
        with db_connect() as con:
            rows = con.execute("SELECT id, created_at, label FROM saved_reports ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return jsonify([{"id": r["id"], "created_at": r["created_at"], "label": r["label"]} for r in rows])
    except:
        return jsonify([])

@app.route("/api/reports/<int:report_id>")
def download_report(report_id):
    """Download a saved PDF report by ID."""
    try:
        with db_connect() as con:
            row = con.execute("SELECT label, pdf_data FROM saved_reports WHERE id=?", (report_id,)).fetchone()
        if not row:
            return jsonify({"error": "Report not found"}), 404
        from flask import send_file
        fname = f"vulnscan-report-{report_id}.pdf"
        return send_file(io.BytesIO(row["pdf_data"]), mimetype='application/pdf',
                         as_attachment=True, download_name=fname)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/reports/<int:report_id>", methods=["DELETE"])
def delete_report(report_id):
    try:
        with db_connect() as con:
            con.execute("DELETE FROM saved_reports WHERE id=?", (report_id,))
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/report")
def generate_report():
    """Generates a PDF security report from the last scan."""
    try:
        return _generate_report_impl("en")
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        try:
            log_ev("error", "system", f"PDF-Report Error: {type(e).__name__}: {str(e)[:200]}",
                   event_type="pdf_report_error", data={"traceback": tb[:1500]})
        except Exception:
            pass
        print("=" * 60, "\nPDF REPORT ERROR:\n", tb, "\n", "=" * 60)
        return jsonify({
            "error": f"Could not generate PDF: {type(e).__name__}: {str(e)[:200]}",
            "hint": "See the Logs tab and terminal window for details.",
        }), 500


def english_output(value):
    """Normalize application-generated labels, including legacy scan labels."""
    if not isinstance(value, str):
        return value
    if not hasattr(english_output, "mapping"):
        from pathlib import Path
        english_output.mapping = json.loads((Path(__file__).parent / "static" / "english-strings.json").read_text(encoding="utf-8"))
    return english_output.mapping.get(value, value)


@app.after_request
def normalize_english_response(response):
    if response.is_json:
        def walk(value):
            if isinstance(value, dict):
                return {key: walk(item) for key, item in value.items()}
            if isinstance(value, list):
                return [walk(item) for item in value]
            return english_output(value)
        payload = response.get_json(silent=True)
        if payload is not None:
            response.set_data(app.json.dumps(walk(payload)))
    return response


def _generate_report_impl(lang="en"):
    """Generate a PDF security report in German or English."""
    lang = "en"
    labels = {'report': ('Network Security Report', 'Network Security Report'), 'created': ('Generated', 'Generated'), 'port_mode': ('Port profile', 'Port profile'), 'risk_assessment': ('Risk assessment', 'Risk assessment'), 'devices': ('DEVICES', 'DEVICES'), 'without_cves': ('NO CVEs', 'NO CVEs'), 'with_cves': ('WITH CVEs', 'WITH CVEs'), 'open_ports': ('OPEN PORTS', 'OPEN PORTS'), 'no_cves_notice': ('No known CVEs were identified in this scan. This does not prove that the network is secure.', 'No known CVEs were identified in this scan. This does not prove that the network is secure.'), 'scan_time': ('Scan time', 'Scan time'), 'device_word': ('devices', 'devices'), 'open_ports_word': ('open ports', 'open ports'), 'recommendation': ('Recommendation', 'Recommendation'), 'update_isolate': ('Update firmware, review ports, and isolate affected devices.', 'Update firmware, review ports, and isolate affected devices.'), 'action1': ('Immediately update firmware and software on affected devices.', 'Immediately update firmware and software on affected devices.'), 'action2': ('Isolate affected devices in a separate VLAN.', 'Isolate affected devices in a separate VLAN.'), 'action3': ('Review open ports and close those that are not required.', 'Review open ports and close those that are not required.'), 'action4': ('Check the CVE details in the NVD database (links below).', 'Check the CVE details in the NVD database (links below).'), 'found_devices': ('Discovered devices (by VLAN/subnet)', 'Discovered devices (by VLAN/subnet)'), 'hosts': ('hosts', 'hosts'), 'online': ('online', 'online'), 'with_cves_lower': ('with CVEs', 'with CVEs'), 'ip': ('IP', 'IP'), 'hostname': ('Hostname', 'Hostname'), 'vendor': ('Vendor', 'Vendor'), 'os': ('OS', 'OS'), 'type': ('Type', 'Type'), 'ports': ('Ports', 'Ports'), 'risk': ('Risk', 'Risk'), 'unknown': ('Unknown', 'Unknown'), 'no_cve': ('No CVE', 'No CVE'), 'safe': ('No finding', 'No finding'), 'network_topology': ('Network topology', 'Network topology'), 'symbol': ('Symbol', 'Symbol'), 'meaning': ('Meaning', 'Meaning'), 'gateway_router': ('Gateway / router', 'Gateway / router'), 'device_no_cves': ('Device without CVEs', 'Device without CVEs'), 'device_with_cves': ('Device with CVEs', 'Device with CVEs'), 'cve_details': ('CVE details and action plan', 'CVE details and action plan'), 'sorted_severity': ('Sorted by severity (CRITICAL first)', 'Sorted by severity (CRITICAL first)'), 'port_status_explanation': ('Port status explanation:', 'Port status explanation:'), 'status': ('Status', 'Status'), 'recommendation_col': ('Recommendation', 'Recommendation'), 'active': ('Active', 'Active'), 'open_review': ('Open - review', 'Open - review'), 'filtered': ('Filtered', 'Filtered'), 'unknown_q': ('Unknown', 'Unknown'), 'service_active': ('Service responds with a banner; it appears to be in use.', 'Service responds with a banner; it appears to be in use.'), 'active_action': ('Keep enabled. Check for updates regularly.', 'Keep enabled. Check for updates regularly.'), 'open_unconfirmed': ('Port is open, but no service banner was detected. It may be unused.', 'Port is open, but no service banner was detected. It may be unused.'), 'check_disable': ('Check whether it is needed. If not, disable the port or service.', 'Check whether it is needed. If not, disable the port or service.'), 'firewall_filtered': ('Port is blocked by a firewall or wrapper. Direct access is not available.', 'Port is blocked by a firewall or wrapper. Direct access is not available.'), 'firewall_ok': ('The firewall protects this port. Document the rule.', 'The firewall protects this port. Document the rule.'), 'nmap_unknown': ('Nmap could not identify a service.', 'Nmap could not identify a service.'), 'manual_check': ('Manually check whether the port is required.', 'Manually check whether the port is required.'), 'port': ('Port', 'Port'), 'proto': ('Proto', 'Proto'), 'service': ('Service', 'Service'), 'product_version': ('Product / version', 'Product / version'), 'what_to_do': ('What to do', 'What to do'), 'check_needed': ('Check whether this service is required. If not, disable it.', 'Check whether this service is required. If not, disable it.'), 'vulnerabilities_found': ('Vulnerabilities found:', 'Vulnerabilities found:'), 'update_vendor': ('Update the device firmware and software. Check the vendor website for current updates. Isolate the device from the rest of the network until it is updated.', 'Update the device firmware and software. Check the vendor website for current updates. Isolate the device from the rest of the network until it is updated.'), 'cve_id': ('CVE ID', 'CVE ID'), 'score': ('Score', 'Score'), 'severity': ('Severity', 'Severity'), 'kev': ('KEV', 'KEV'), 'epss': ('EPSS', 'EPSS'), 'description': ('Description', 'Description'), 'active_kev': ('ACTIVE', 'ACTIVE'), 'nvd_missing': ('NVD data unavailable', 'NVD data unavailable'), 'authorized': ('For authorized use on networks you own or are permitted to assess.', 'For authorized use on networks you own or are permitted to assess.'), 'nuclei_findings': ('Nuclei findings', 'Nuclei findings'), 'template_name': ('Template / name', 'Template / name'), 'match_url': ('Matched URL', 'Matched URL')}
    def tr(key):
        de, en = labels.get(key, (key, key))
        return en if lang == "en" else de

    _mode_map = {"top1000": port_mode_title("top1000"), "iana": port_mode_title("iana"), "iana_udp": port_mode_title("iana_udp"), "deep": port_mode_title("deep")}
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
    _ReportParagraph = Paragraph
    def Paragraph(text, *args, **kwargs):
        return _ReportParagraph(english_output(text), *args, **kwargs)
    from reportlab.graphics.shapes import Drawing, Circle, Line, String, Rect, Polygon
    from reportlab.graphics import renderPDF
    from reportlab.platypus.flowables import HRFlowable
    import math
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    import io
    from datetime import datetime

    devices = scan_state.get("results", [])
    if not devices:
        devices = list(app_data.get("known_devices", {}).values())
    buf = io.BytesIO()

    PAGE_W, PAGE_H = A4
    doc = SimpleDocTemplate(buf, pagesize=A4,
        leftMargin=1.8*cm, rightMargin=1.8*cm, topMargin=1.5*cm, bottomMargin=1.5*cm)

    # --- Color palette (print-friendly) ---
    # PDF - print-friendly with website accent colors
    C_BG    = colors.white
    # --- Customer-tauglich: schwarzer Text, Corporate-Navy-Blau, dezente Akzente ---
    C_CARD  = colors.HexColor("#f5f7fa")   # very light gray
    C_CARD2 = colors.HexColor("#fafbfc")   # alternating row even lighter
    C_BLUE  = colors.HexColor("#1e3a8a")   # corporate navy blue (Tailwind blue-900)
    C_BLUE2 = colors.HexColor("#3b82f6")   # secondary blue (Tailwind blue-500)
    C_GREEN = colors.HexColor("#15803d")   # subtle green (dark)
    C_RED   = colors.HexColor("#b91c1c")   # subtle red (dark)
    C_WARN  = colors.HexColor("#b45309")   # subtle amber (dark)
    C_YELL  = colors.HexColor("#a16207")
    C_TEXT  = colors.HexColor("#111827")   # near-black (Tailwind gray-900)
    C_MUTED = colors.HexColor("#6b7280")   # gray (Tailwind gray-500)
    C_BOR   = colors.HexColor("#d1d5db")   # light gray border (Tailwind gray-300)
    C_SURF  = colors.HexColor("#f9fafb")   # surface (Tailwind gray-50)
    C_CRIT  = colors.HexColor("#991b1b")   # dark red
    C_HIGH  = colors.HexColor("#b91c1c")
    C_MED   = colors.HexColor("#b45309")
    C_LOW   = colors.HexColor("#a16207")

    # --- Styles ---
    title_style = ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=22,
        textColor=C_BLUE, spaceAfter=2, alignment=TA_LEFT)
    sub_style   = ParagraphStyle("sub",   fontName="Helvetica", fontSize=9,
        textColor=C_MUTED, spaceAfter=2)
    h2_style    = ParagraphStyle("h2",    fontName="Helvetica-Bold", fontSize=12,
        textColor=C_BLUE, spaceBefore=18, spaceAfter=8)
    h3_style    = ParagraphStyle("h3",    fontName="Helvetica-Bold", fontSize=10,
        textColor=C_TEXT, spaceBefore=10, spaceAfter=4)
    body_style  = ParagraphStyle("body",  fontName="Helvetica", fontSize=9,
        textColor=C_TEXT, spaceAfter=3, leading=14)
    red_style   = ParagraphStyle("red",   fontName="Helvetica-Bold", fontSize=9,
        textColor=C_RED, spaceAfter=3)
    warn_style  = ParagraphStyle("warn",  fontName="Helvetica-Bold", fontSize=9,
        textColor=C_WARN, spaceAfter=3)
    ok_style    = ParagraphStyle("ok",    fontName="Helvetica", fontSize=9,
        textColor=C_GREEN, spaceAfter=3)
    label_style = ParagraphStyle("label", fontName="Helvetica", fontSize=8,
        textColor=C_MUTED, spaceAfter=1)
    value_style = ParagraphStyle("value", fontName="Helvetica-Bold", fontSize=14,
        textColor=C_TEXT, spaceAfter=0)

    story = []

    # ── HEADER BLOCK ──────────────────────────────────────────
    scan_ts = scan_state.get("last_scan", datetime.now().strftime("%d.%m.%Y %H:%M:%S"))
    total   = len(devices)
    vuln    = [d for d in devices if d.get("cves") or d.get("cve_details") or d.get("nuclei_findings")]
    safe    = total - len(vuln)
    ports_total = sum(len(d.get("ports", [])) for d in devices)
    cve_total   = sum(len(d.get("cves",  [])) for d in devices)

    # Header bar drawing
    hdr = Drawing(PAGE_W - 3.6*cm, 60)
    hdr.add(Rect(0, 0, PAGE_W - 3.6*cm, 60,
        fillColor=colors.HexColor("#eff6ff"), strokeColor=C_BLUE, strokeWidth=1.5, rx=4, ry=4))
    hdr.add(Rect(0, 0, 6, 60,
        fillColor=C_BLUE, strokeColor=None, rx=3, ry=3))
    hdr.add(String(20, 36, "VulnScan Pro", fontSize=18, fontName="Helvetica-Bold",
        fillColor=C_BLUE))
    hdr.add(String(20, 22, f"{tr('report')}  |  (c) 2026 VulnScan Pro  |  ", fontSize=8,
        fillColor=C_MUTED))
    _mode_label = _mode_map.get(scan_state.get("last_mode","top1000"), "STD")
    # Split label: "STD" in normal, "(nmap Top 1000)" in orange
    _mode_parts = _mode_label.split(" ", 1)
    _mode_main  = _mode_parts[0]
    _mode_sub   = " " + _mode_parts[1] if len(_mode_parts) > 1 else ""
    _prefix     = f"{tr('created')}: {scan_ts}  |  {tr('port_mode')}: "
    hdr.add(String(20, 10, _prefix, fontSize=8, fillColor=C_MUTED))
    hdr.add(String(20 + len(_prefix)*4.2, 10, _mode_main, fontSize=8, fillColor=C_TEXT))
    hdr.add(String(20 + len(_prefix)*4.2 + len(_mode_main)*4.8, 10, _mode_sub, fontSize=8, fillColor=colors.HexColor("#e6a817")))
    # Risk indicator top right
    risk_color = C_RED if vuln else C_GREEN
    risk_text  = (f"{len(vuln)} devices with CVEs" if lang == "en" else f"{len(vuln)} device(s) with CVEs") if vuln else ("No finding identified" if lang == "en" else "No finding identified")
    hdr.add(String(PAGE_W - 3.6*cm - 10, 36, risk_text, fontSize=10,
        fontName="Helvetica-Bold", fillColor=risk_color, textAnchor="end"))
    story.append(hdr)
    story.append(Spacer(1, 12))

    # ── KPI CARDS ROW ─────────────────────────────────────────
    kpi_w = (PAGE_W - 3.6*cm) / 4 - 4
    kpis = [
        (tr("devices"),       str(total),        C_BLUE),
        (tr("without_cves"),     str(safe),         C_GREEN),
        (tr("with_cves"),      str(len(vuln)),    C_RED if vuln else C_MUTED),
        (tr("open_ports"),  str(ports_total),  C_WARN if ports_total else C_MUTED),
    ]
    kpi_row = Drawing(PAGE_W - 3.6*cm, 55)
    x = 0
    for label, val, col in kpis:
        kpi_row.add(Rect(x, 0, kpi_w, 55, fillColor=C_CARD, strokeColor=C_BOR, strokeWidth=0.8, rx=3, ry=3))
        kpi_row.add(Rect(x, 0, kpi_w, 3, fillColor=col, strokeColor=None))
        kpi_row.add(String(x + kpi_w/2, 28, val, fontSize=18, fontName="Helvetica-Bold",
            fillColor=col, textAnchor="middle"))
        kpi_row.add(String(x + kpi_w/2, 10, label, fontSize=7,
            fillColor=C_MUTED, textAnchor="middle"))
        x += kpi_w + 5
    story.append(kpi_row)
    story.append(Spacer(1, 16))

    # ── RISIKOBEWERTUNG ──────────────────────────────────────
    story.append(Paragraph(tr("risk_assessment"), h2_style))

    # Worst CVE severity
    all_sevs = []
    for d in devices:
        for cv in d.get("cve_details", []):
            all_sevs.append(cv.get("severity", "UNKNOWN"))
    sev_rank = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"UNKNOWN":0}
    worst_sev = max(all_sevs, key=lambda s: sev_rank.get(s,0)) if all_sevs else None
    sev_col_map = {"CRITICAL":C_CRIT,"HIGH":C_HIGH,"MEDIUM":C_MED,"LOW":C_LOW}

    if not vuln:
        risk_draw = Drawing(PAGE_W - 3.6*cm, 40)
        risk_draw.add(Rect(0,0, PAGE_W-3.6*cm, 40, fillColor=colors.HexColor("#eaf5ea"),
            strokeColor=C_GREEN, strokeWidth=1, rx=3, ry=3))
        risk_draw.add(String(14, 22, "✓  " + tr("no_cves_notice"), fontSize=10,
            fontName="Helvetica-Bold", fillColor=C_GREEN))
        risk_draw.add(String(14, 10, f"{tr('scan_time')}: {scan_ts}  |  {total} {tr('device_word')}  |  {ports_total} {tr('open_ports_word')}",
            fontSize=8, fillColor=C_MUTED))
        story.append(risk_draw)
    else:
        wc = sev_col_map.get(worst_sev, C_WARN) if worst_sev else C_WARN
        risk_draw = Drawing(PAGE_W - 3.6*cm, 40)
        risk_draw.add(Rect(0,0, PAGE_W-3.6*cm, 40, fillColor=colors.HexColor("#fdf0ee"),
            strokeColor=wc, strokeWidth=1.5, rx=3, ry=3))
        risk_draw.add(String(14, 22, (f"!  {len(vuln)} device(s) with CVEs — Highest severity: {worst_sev or 'UNKNOWN'}" if lang == "en" else f"!  {len(vuln)} device(s) with CVEs — Hoechste Kritikalitaet: {worst_sev or 'UNKNOWN'}"),
            fontSize=10, fontName="Helvetica-Bold", fillColor=wc))
        risk_draw.add(String(14, 10, f"{tr('recommendation')}: {tr('update_isolate')}",
            fontSize=8, fillColor=C_MUTED))
        story.append(risk_draw)

        # Action items as compact table
        story.append(Spacer(1, 8))
        actions = [
            ["1.", tr("action1")],
            ["2.", tr("action2")],
            ["3.", tr("action3")],
            ["4.", tr("action4")],
        ]
        act_tbl = Table(actions, colWidths=[0.6*cm, PAGE_W-3.6*cm-0.6*cm])
        act_tbl.setStyle(TableStyle([
            ("TEXTCOLOR",(0,0),(0,-1), wc),
            ("TEXTCOLOR",(1,0),(1,-1), C_TEXT),
            ("FONTNAME", (0,0),(-1,-1),"Helvetica"),
            ("FONTSIZE", (0,0),(-1,-1), 9),
            ("TOPPADDING",(0,0),(-1,-1),2),
            ("BOTTOMPADDING",(0,0),(-1,-1),2),
        ]))
        story.append(act_tbl)
    story.append(Spacer(1, 12))

    # ── DEVICE TABLE — grouped by VLAN/subnet ─────────────────────
    story.append(Paragraph(tr("found_devices"), h2_style))

    # Group devices by /24 subnet
    subnets = {}
    for d in devices:
        parts = d["ip"].split(".")
        subnet = ".".join(parts[:3]) + ".0/24"
        subnets.setdefault(subnet, []).append(d)

    col_w = [2.6*cm, 3.4*cm, 3.0*cm, 2.5*cm, 2.4*cm, 1.3*cm, 1.8*cm]
    th_s = ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=8, textColor=C_BLUE)
    td_s   = ParagraphStyle("td",  fontName="Helvetica",      fontSize=8, textColor=C_TEXT,  leading=10)
    td_sm  = ParagraphStyle("tds", fontName="Helvetica",      fontSize=7, textColor=C_MUTED, leading=9)
    td_b   = ParagraphStyle("tdb", fontName="Helvetica-Bold", fontSize=8, textColor=C_TEXT,  leading=10)
    subnet_hdr_style = ParagraphStyle("snhdr", fontName="Helvetica-Bold", fontSize=11, textColor=C_BLUE,
                                       spaceBefore=10, spaceAfter=4)
    subnet_meta_style = ParagraphStyle("snmeta", fontName="Helvetica", fontSize=8, textColor=C_MUTED,
                                        spaceAfter=4)

    # Sort subnets by IP, then devices within each by CVEs+IP
    for subnet, sn_devices in sorted(subnets.items()):
        sn_devices_sorted = sorted(sn_devices, key=lambda x: (len(x.get("cves",[])) == 0, x["ip"]))
        sn_online    = sum(1 for d in sn_devices if d.get("online", True))
        sn_with_cves = sum(1 for d in sn_devices if d.get("cves"))
        sn_total_ports = sum(len(d.get("ports", [])) for d in sn_devices)
        story.append(Paragraph((f"Subnet: {subnet}" if lang == "en" else f"Subnetz: {subnet}"), subnet_hdr_style))
        meta_line = (f"{len(sn_devices)} hosts &nbsp;·&nbsp; {sn_online} online &nbsp;·&nbsp; {sn_with_cves} with CVEs &nbsp;·&nbsp; {sn_total_ports} open ports" if lang == "en" else f"{len(sn_devices)} Hosts &nbsp;·&nbsp; {sn_online} online &nbsp;·&nbsp; {sn_with_cves} with CVEs &nbsp;·&nbsp; {sn_total_ports} offene Ports")
        story.append(Paragraph(meta_line, subnet_meta_style))

        hdr_row = [
            Paragraph("<b>"+tr("ip")+"</b>",        th_s),
            Paragraph("<b>"+tr("hostname")+"</b>",   th_s),
            Paragraph("<b>"+tr("vendor")+"</b>", th_s),
            Paragraph("<b>"+tr("os")+"</b>",         th_s),
            Paragraph("<b>"+tr("type")+"</b>",        th_s),
            Paragraph("<b>"+tr("ports")+"</b>",      th_s),
            Paragraph("<b>"+tr("risk")+"</b>",     th_s),
        ]
        rows = [hdr_row]

        for d in sn_devices_sorted:
            cve_count  = len(d.get("cves", []))
            port_count = len(d.get("ports", []))
            dev_label = english_output(d.get("device_label", "Unknown"))
            dev_icon  = ""  # Built-in PDF fonts do not support emoji icons.
            worst = None
            for cv in d.get("cve_details", []):
                s = cv.get("severity","UNKNOWN")
                if worst is None or sev_rank.get(s,0) > sev_rank.get(worst,0):
                    worst = s
            # KEV-flag boost for risk text
            kev_hit = any(cv.get("kev") for cv in d.get("cve_details", []))
            if cve_count:
                risk_col = sev_col_map.get(worst, C_WARN)
                kev_tag = " KEV" if kev_hit else ""
                risk_txt = f"{worst or 'CVE'}{kev_tag} ({cve_count})"
            elif port_count:
                risk_col = C_MUTED
                risk_txt = tr("no_cve")
            else:
                risk_col = C_GREEN
                risk_txt = tr("safe")
            ip_hex = "ff3b3b" if cve_count else "00e5ff"
            ip_col = C_RED if cve_count else C_BLUE

            rows.append([
                Paragraph(f'<font color="#{ip_hex}">{d["ip"]}</font>',
                    ParagraphStyle("td", fontName="Helvetica-Bold", fontSize=8, textColor=ip_col)),
                Paragraph(d.get("hostname") or "-", td_sm),
                Paragraph(english_output(d.get("vendor") or "-"),   td_sm),
                Paragraph(english_output(d.get("os") or tr("unknown")), td_sm),
                Paragraph(f"{dev_icon} {dev_label}",
                    ParagraphStyle("td", fontName="Helvetica", fontSize=7, textColor=C_TEXT, leading=9)),
                Paragraph(str(port_count),
                    ParagraphStyle("td", fontName="Helvetica-Bold", fontSize=9, textColor=C_WARN if port_count else C_MUTED)),
                Paragraph(risk_txt,
                    ParagraphStyle("td", fontName="Helvetica-Bold", fontSize=8, textColor=risk_col)),
            ])

        dev_table = Table(rows, colWidths=col_w, repeatRows=1)
        ts = TableStyle([
            ("BACKGROUND",   (0,0),(-1,0),  colors.HexColor("#eff6ff")),
            ("LINEBELOW",    (0,0),(-1,0),  1, C_BLUE),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_CARD, C_CARD2]),
            ("GRID",         (0,0),(-1,-1), 0.3, C_BOR),
            ("LEFTPADDING",  (0,0),(-1,-1), 6),
            ("RIGHTPADDING", (0,0),(-1,-1), 6),
            ("TOPPADDING",   (0,0),(-1,-1), 5),
            ("BOTTOMPADDING",(0,0),(-1,-1), 5),
            ("VALIGN",       (0,0),(-1,-1), "MIDDLE"),
        ])
        for i, d in enumerate(sn_devices_sorted, 1):
            if d.get("cves"):
                ts.add("LINEAFTER",  (0,i),(0,i), 2, C_RED)
                ts.add("LINEBEFORE", (0,i),(0,i), 3, C_RED)
        dev_table.setStyle(ts)
        story.append(dev_table)
        story.append(Spacer(1, 8))

    story.append(Spacer(1, 8))

    # Network Map
    story.append(HRFlowable(width="100%", thickness=1, color=C_BOR, spaceAfter=0))
    story.append(Paragraph(tr("network_topology"), h2_style))

    map_w, map_h = 480, 220
    d = Drawing(map_w, map_h)

    # Dark background
    d.add(Rect(0, 0, map_w, map_h, fillColor=colors.HexColor("#f0f5f9"), strokeColor=colors.HexColor("#b0c4d4"), strokeWidth=1))

    # Find gateway (lowest IP or .1)
    sorted_devs = sorted(devices, key=lambda x: [int(p) for p in x["ip"].split(".")])
    gateway = sorted_devs[0] if sorted_devs else None
    others  = sorted_devs[1:] if len(sorted_devs) > 1 else []

    cx, cy = map_w // 2, map_h // 2  # center

    # Draw spokes to each device
    n = len(others)
    for i, dev in enumerate(others):
        angle = (2 * math.pi * i / max(n, 1)) - math.pi / 2
        r = min(map_w, map_h) * 0.38
        nx = cx + r * math.cos(angle)
        ny = cy + r * math.sin(angle)
        has_cve = bool(dev.get("cves"))
        line_col = colors.HexColor("#ff3b3b") if has_cve else colors.HexColor("#1a3a4a")
        d.add(Line(cx, cy, nx, ny, strokeColor=line_col, strokeWidth=0.8))

    # Draw device nodes
    for i, dev in enumerate(others):
        angle = (2 * math.pi * i / max(n, 1)) - math.pi / 2
        r = min(map_w, map_h) * 0.38
        nx = cx + r * math.cos(angle)
        ny = cy + r * math.sin(angle)
        has_cve = bool(dev.get("cves"))
        col = colors.HexColor("#ff3b3b") if has_cve else colors.HexColor("#ff9500")
        d.add(Circle(nx, ny, 6, fillColor=colors.HexColor("#0d1520"), strokeColor=col, strokeWidth=1.5))
        label = (dev.get("label") or dev.get("hostname") or dev["ip"])[:14]
        d.add(String(nx, ny - 14, label, fontSize=6, fillColor=colors.HexColor("#4a6680"), textAnchor="middle"))
        d.add(String(nx, ny - 21, dev["ip"], fontSize=5, fillColor=colors.HexColor("#2a4a60"), textAnchor="middle"))

    # Gateway node (center)
    if gateway:
        d.add(Circle(cx, cy, 12, fillColor=colors.HexColor("#003344"), strokeColor=colors.HexColor("#00e5ff"), strokeWidth=2))
        gw_label = (gateway.get("label") or gateway.get("hostname") or gateway["ip"])[:16]
        d.add(String(cx, cy - 18, gw_label, fontSize=7, fillColor=colors.HexColor("#00e5ff"), textAnchor="middle"))
        d.add(String(cx, cy + 4, "GW", fontSize=6, fillColor=colors.HexColor("#00e5ff"), textAnchor="middle"))

    story.append(d)

    # Legend
    legend_data = [[tr("symbol"), tr("meaning")]]
    legend_data.append(["Cyan circle (center)" if lang == "en" else "Cyan Kreis (Mitte)", tr("gateway_router")])
    legend_data.append(["Orange circle" if lang == "en" else "Orange Kreis", tr("device_no_cves")])
    legend_data.append(["Red line / node" if lang == "en" else "Rote Linie / Knoten", tr("device_with_cves")])
    leg_tbl = Table(legend_data, colWidths=[5*cm, 12.4*cm])
    leg_tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0,0),(-1,0),  colors.HexColor("#eff6ff")),
        ("TEXTCOLOR",   (0,0),(-1,0),  C_BLUE),
        ("FONTNAME",    (0,0),(-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",    (0,0),(-1,-1), 8),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, C_SURF]),
        ("TEXTCOLOR",   (0,1),(-1,-1), C_MUTED),
        ("GRID",        (0,0),(-1,-1), 0.4, C_BOR),
        ("LEFTPADDING", (0,0),(-1,-1), 5),
        ("TOPPADDING",  (0,0),(-1,-1), 3),
        ("BOTTOMPADDING",(0,0),(-1,-1),3),
    ]))
    story.append(Spacer(1, 6))
    story.append(leg_tbl)
    story.append(Spacer(1, 14))

    # CVE Details with CVSS
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    sev_colors = {
        "CRITICAL": colors.HexColor("#ff3b3b"),
        "HIGH":     colors.HexColor("#ff6b35"),
        "MEDIUM":   colors.HexColor("#ff9500"),
        "LOW":      colors.HexColor("#ffcc00"),
        "UNKNOWN":  colors.HexColor("#4a6680"),
    }

    if vuln:
        story.append(HRFlowable(width="100%", thickness=1, color=C_BOR, spaceAfter=0))
        story.append(Paragraph(tr("cve_details"), h2_style))
        story.append(Paragraph("Potential matches; ordered by exploitation priority and severity. Confirm product, component and affected version before remediation.", sub_style))

        # ── PORT-STATUS LEGENDE ─────────────────────────────────
        legend_title = ParagraphStyle("lt2", fontName="Helvetica-Bold", fontSize=8,
            textColor=C_BLUE, spaceBefore=10, spaceAfter=4)
        story.append(Paragraph(tr("port_status_explanation"), legend_title))
        legend_rows = [
            ["✔ " + tr("active"),           colors.HexColor("#e8f5e9"), colors.HexColor("#1a6e1a"),
             tr("service_active"),
             "→ " + tr("active_action")],
            ["■ " + tr("open_review"),  colors.HexColor("#fff3e0"), colors.HexColor("#b85c00"),
             tr("open_unconfirmed"),
             "→ " + tr("check_disable")],
            ["■ " + tr("filtered"),       colors.HexColor("#f0f4f8"), colors.HexColor("#5a6a7a"),
             tr("firewall_filtered"),
             "→ " + tr("firewall_ok")],
            ["? " + tr("unknown_q"),       colors.HexColor("#f5f5f5"), colors.HexColor("#8a8a8a"),
             tr("nmap_unknown"),
             "→ " + tr("manual_check")],
        ]
        leg_data = [[
            Paragraph(tr("status"),     ParagraphStyle("lh", fontName="Helvetica-Bold", fontSize=7.5, textColor=C_BLUE)),
            Paragraph(tr("meaning"),  ParagraphStyle("lh", fontName="Helvetica-Bold", fontSize=7.5, textColor=C_BLUE)),
            Paragraph(tr("recommendation_col"), ParagraphStyle("lh", fontName="Helvetica-Bold", fontSize=7.5, textColor=C_BLUE)),
        ]]
        row_colors_leg = [colors.HexColor("#eff6ff")]
        for label, bg, fg, bedeutung, empf in legend_rows:
            leg_data.append([
                Paragraph(label,    ParagraphStyle("ll", fontName="Helvetica-Bold", fontSize=7.5, textColor=fg)),
                Paragraph(bedeutung, ParagraphStyle("lb", fontName="Helvetica", fontSize=7.5, textColor=C_TEXT)),
                Paragraph(empf,     ParagraphStyle("le", fontName="Helvetica", fontSize=7.5, textColor=C_MUTED)),
            ])
            row_colors_leg.append(bg)
        leg_table = Table(leg_data, colWidths=[3.0*cm, 8.0*cm, 6.4*cm])
        leg_ts = [
            ("FONTSIZE",      (0,0), (-1,-1), 7.5),
            ("GRID",          (0,0), (-1,-1), 0.3, C_BOR),
            ("LEFTPADDING",   (0,0), (-1,-1), 5),
            ("TOPPADDING",    (0,0), (-1,-1), 3),
            ("BOTTOMPADDING", (0,0), (-1,-1), 3),
            ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ]
        for ri, bg in enumerate(row_colors_leg):
            leg_ts.append(("BACKGROUND", (0, ri), (-1, ri), bg))
        leg_table.setStyle(TableStyle(leg_ts))
        story.append(leg_table)
        story.append(Spacer(1, 14))
        story.append(Spacer(1, 8))

        # Sort devices by worst CVE score
        def worst_score(dev):
            details = dev.get("cve_details", [])
            if details and details[0].get("score"):
                return -(details[0]["score"])
            return 0
        vuln_sorted = sorted(vuln, key=worst_score)

        for d in vuln_sorted:
            details = sorted(d.get("cve_details", []), key=lambda cv: (not bool(cv.get("kev")), -float(cv.get("score") or 0)))
            worst = details[0].get("severity", "UNKNOWN") if details else "UNKNOWN"
            worst_col = sev_colors.get(worst, C_MUTED)

            hdr_style = ParagraphStyle("devhdr", fontName="Helvetica-Bold", fontSize=10,
                textColor=worst_col, spaceBefore=12, spaceAfter=4)
            story.append(Paragraph(
                f"{d['ip']}  |  {d.get('hostname','-')}  |  {d.get('vendor','-')}",
                hdr_style))

            if d.get("ports"):
                # Port-Tabelle mit Banner-Status
                # Einheitliche Status-Labels und PDF-taugliche Farben (heller Hintergrund!)
                BS_LABEL = {
                    "active":   "✔ " + tr("active"),
                    "open":     "■ " + tr("open_review"),
                    "filtered": "■ " + tr("filtered"),
                    "unknown":  "? " + tr("unknown_q"),
                }
                BS_COLOR = {
                    "active":   colors.HexColor("#1a6e1a"),
                    "open":     colors.HexColor("#b85c00"),
                    "filtered": colors.HexColor("#5a6a7a"),  # grau = neutral
                    "unknown":  colors.HexColor("#8a8a8a"),
                }
                BS_BG = {
                    "active":   colors.HexColor("#e8f5e9"),
                    "open":     colors.HexColor("#fff3e0"),
                    "filtered": colors.HexColor("#f0f4f8"),  # hellgrau = neutral
                    "unknown":  colors.HexColor("#f5f5f5"),
                }

                def get_bs(p):
                    """Bestimmt banner_status — robust auch für alte Scan-Daten."""
                    bs = p.get("banner_status")
                    if bs in ("active","open","filtered","unknown"):
                        return bs
                    # Fallback: aus product/service ableiten
                    product = (p.get("product") or "").strip()
                    service = (p.get("service") or "").strip()
                    if product:
                        return "active"
                    if service in ("tcpwrapped",):
                        return "filtered"
                    if service and service != "?":
                        return "open"
                    return "unknown"

                port_rows = [[
                    Paragraph(tr("port"),            ParagraphStyle("ph", fontName="Helvetica-Bold", fontSize=8, textColor=C_BLUE)),
                    Paragraph(tr("proto"),           ParagraphStyle("ph", fontName="Helvetica-Bold", fontSize=8, textColor=C_BLUE)),
                    Paragraph(tr("service"),         ParagraphStyle("ph", fontName="Helvetica-Bold", fontSize=8, textColor=C_BLUE)),
                    Paragraph(tr("product_version"), ParagraphStyle("ph", fontName="Helvetica-Bold", fontSize=8, textColor=C_BLUE)),
                    Paragraph("Status",          ParagraphStyle("ph", fontName="Helvetica-Bold", fontSize=8, textColor=C_BLUE)),
                ]]
                row_bgs = [colors.HexColor("#eff6ff")]  # header bg
                for p in d["ports"]:
                    bs    = get_bs(p)
                    bscol = BS_COLOR.get(bs, C_MUTED)
                    row_bgs.append(BS_BG.get(bs, C_SURF))
                    proto = p.get("protocol", "tcp").upper()
                    if proto == "UDP":
                        proto_para = Paragraph(proto, ParagraphStyle("pu", fontName="Helvetica-Bold", fontSize=8, textColor=colors.HexColor("#b85c00")))
                    else:
                        proto_para = Paragraph(proto, ParagraphStyle("pt", fontName="Helvetica", fontSize=8, textColor=C_MUTED))
                    port_rows.append([
                        Paragraph(str(p.get("port","")),     ParagraphStyle("pt", fontName="Helvetica-Bold", fontSize=8, textColor=C_BLUE)),
                        proto_para,
                        Paragraph(p.get("service","?"),      ParagraphStyle("pt", fontName="Helvetica", fontSize=8, textColor=C_TEXT)),
                        Paragraph(p.get("product","") or "—", ParagraphStyle("pt", fontName="Helvetica", fontSize=7, textColor=C_MUTED)),
                        Paragraph(BS_LABEL.get(bs,"?"),      ParagraphStyle("pt", fontName="Helvetica-Bold", fontSize=8, textColor=bscol)),
                    ])

                pt = Table(port_rows, colWidths=[1.4*cm, 1.6*cm, 3.0*cm, 8.4*cm, 3.0*cm], repeatRows=1)
                ts = [
                    ("BACKGROUND",    (0,0), (-1,0),  colors.HexColor("#eff6ff")),
                    ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
                    ("FONTSIZE",      (0,0), (-1,-1), 8),
                    ("GRID",          (0,0), (-1,-1), 0.3, C_BOR),
                    ("LEFTPADDING",   (0,0), (-1,-1), 5),
                    ("TOPPADDING",    (0,0), (-1,-1), 3),
                    ("BOTTOMPADDING", (0,0), (-1,-1), 3),
                    ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
                ]
                for row_i, bg in enumerate(row_bgs):
                    ts.append(("BACKGROUND", (0, row_i), (-1, row_i), bg))
                pt.setStyle(TableStyle(ts))
                story.append(pt)
                story.append(Spacer(1, 6))

            # Kundenfreundliche Massnahmen
            if lang == "en":
                port_advice = {
                    135: ("Windows RPC", "Required internally for Windows services. Do not expose it externally."),
                    139: ("Windows file sharing (NetBIOS)", "Legacy file-sharing protocol. Allow only on trusted internal networks; never expose it externally."),
                    445: ("Windows file sharing (SMB)", "A common attack target. Ensure this port is not reachable from the internet."),
                    22: ("SSH remote access", "Allows remote access. Disable password login and use SSH keys."),
                    23: ("Telnet", "Insecure legacy protocol. Disable it and use SSH instead."),
                    21: ("FTP file transfer", "Transfers data without encryption. Replace it with SFTP or FTPS."),
                    80: ("Unencrypted web server", "Serves web pages without encryption. Use HTTPS on port 443."),
                    443: ("Encrypted web server", "Encrypted web access. Renew its certificate regularly."),
                    8080: ("Alternative web server", "Often used for development or administration. Check whether it is required."),
                    8443: ("Alternative HTTPS", "A second encrypted web interface. Check whether it is required."),
                    3389: ("Windows remote access (RDP)", "A common attack target. Restrict access to VPN; never expose it directly to the internet."),
                    5900: ("VNC remote access", "Remote desktop access. Restrict it to a trusted internal network or VPN."),
                    53: ("DNS name resolution", "Translates domain names to IP addresses. Expected when the device is a router or DNS server."),
                    5060: ("VoIP (SIP)", "Used for IP telephony. Protect it from unauthorized use and toll fraud."),
                    161: ("SNMP network monitoring", "Network monitoring service. Change default community strings."),
                    1433: ("Microsoft SQL database", "Database server. Never expose it directly to the internet; use strong credentials."),
                    3306: ("MySQL database", "Database server. Restrict access to trusted internal hosts and use strong credentials."),
                    5432: ("PostgreSQL database", "Database server. Restrict access to trusted internal hosts and use strong credentials."),
                    27017: ("MongoDB database", "Can be exposed without authentication. Secure it immediately."),
                    6379: ("Redis database", "May lack authentication. Secure it immediately."),
                    5000: ("Application server", "Often a development server or app interface. Check whether it is required in production."),
                    8181: ("Administration interface", "Restrict the admin interface to trusted internal hosts and use strong credentials."),
                    16992: ("Intel AMT remote management", "Intel remote management feature. Disable it in BIOS if it is not used."),
                    7070: ("Media streaming service", "Check whether this service is required."),
                }
            ports_list = d.get("ports", [])
            story.append(Spacer(1, 6))
            story.append(Paragraph(tr("what_to_do"), ParagraphStyle("mhdr", fontName="Helvetica-Bold", fontSize=9, textColor=C_BLUE, spaceBefore=4)))

            # Per-port advice
            shown_advice = set()
            for p in ports_list:
                pnum = p.get("port")
                svc  = p.get("service","")
                if pnum in port_advice and pnum not in shown_advice:
                    shown_advice.add(pnum)
                    pname, advice = port_advice[pnum]
                    story.append(Paragraph(
                        f"<b>Port {pnum} ({pname}):</b> {advice}" if lang == "de" else f"<b>Port {pnum} ({pname}):</b> {advice}",
                        ParagraphStyle("padv", fontName="Helvetica", fontSize=8, textColor=C_TEXT, leading=11, leftIndent=8, spaceBefore=2)))
                elif pnum not in shown_advice:
                    shown_advice.add(pnum)
                    story.append(Paragraph(
                        f"<b>Port {pnum} ({svc or tr('unknown')}):</b> {tr('check_needed')}",
                        ParagraphStyle("padv", fontName="Helvetica", fontSize=8, textColor=C_MUTED, leading=11, leftIndent=8, spaceBefore=2)))

            # CVE general advice
            if d.get("cves"):
                story.append(Paragraph(
                    f"<b>{tr('vulnerabilities_found')}</b> {tr('update_vendor')}",
                    ParagraphStyle("cveadv", fontName="Helvetica", fontSize=8, textColor=C_TEXT, leading=11, leftIndent=8, spaceBefore=2)))
            story.append(Spacer(1, 8))

            # CVE table
            if details:
                # Welcher Port ist of welchem CVE betroffen?
                port_cve_map = {}
                for p in d.get("ports", []):
                    for cve_id in p.get("cves", []):
                        port_cve_map[cve_id] = f"{p.get('port','?')}/{p.get('protocol','tcp')}"

                cve_rows = [[
                    Paragraph(tr("cve_id"),    ParagraphStyle("ch", fontName="Helvetica-Bold", fontSize=8, textColor=C_BLUE)),
                    Paragraph(tr("score"),     ParagraphStyle("ch", fontName="Helvetica-Bold", fontSize=8, textColor=C_BLUE)),
                    Paragraph(tr("severity"),   ParagraphStyle("ch", fontName="Helvetica-Bold", fontSize=8, textColor=C_BLUE)),
                    Paragraph("Port",      ParagraphStyle("ch", fontName="Helvetica-Bold", fontSize=8, textColor=C_BLUE)),
                    Paragraph(tr("kev"),       ParagraphStyle("ch", fontName="Helvetica-Bold", fontSize=8, textColor=C_BLUE)),
                    Paragraph(tr("epss"),      ParagraphStyle("ch", fontName="Helvetica-Bold", fontSize=8, textColor=C_BLUE)),
                    Paragraph(tr("description"), ParagraphStyle("ch", fontName="Helvetica-Bold", fontSize=8, textColor=C_BLUE)),
                ]]
                row_bgs_cve = [colors.HexColor("#eff6ff")]
                for cv in details:
                    sev       = cv.get("severity", "UNKNOWN")
                    score_str = f"{cv['score']:.1f}" if cv.get("score") else "?"
                    desc      = (cv.get("description") or "")[:100]
                    if len(cv.get("description","")) > 100:
                        desc += "..."
                    port_ref  = port_cve_map.get(cv["id"], "—")
                    sev_col   = sev_colors.get(sev, C_MUTED)
                    sev_bg    = {
                        "CRITICAL": colors.HexColor("#fef2f2"),
                        "HIGH":     colors.HexColor("#fff7ed"),
                        "MEDIUM":   colors.HexColor("#fffbeb"),
                        "LOW":      colors.HexColor("#f0f9ff"),
                    }.get(sev, colors.white)
                    # KEV row gets soft red background (subtle, not blaring)
                    if cv.get("kev"):
                        sev_bg = colors.HexColor("#fee2e2")
                    row_bgs_cve.append(sev_bg)
                    # KEV cell
                    kev_txt = tr("active_kev") if cv.get("kev") else "—"
                    kev_col = C_RED if cv.get("kev") else C_MUTED
                    # EPSS cell
                    if cv.get("epss_score") is not None:
                        epss_pct = int((cv["epss_score"] or 0) * 100)
                        epss_txt = f"{epss_pct}%"
                        if epss_pct >= 50:
                            epss_col = C_RED
                        elif epss_pct >= 20:
                            epss_col = C_WARN
                        elif epss_pct >= 5:
                            epss_col = C_BLUE
                        else:
                            epss_col = C_MUTED
                    else:
                        epss_txt = "—"
                        epss_col = C_MUTED
                    cve_rows.append([
                        Paragraph('<link href="https://www.cve.org/CVERecord?id=' + cv["id"] + '">' + cv["id"] + '</link>',   ParagraphStyle("cv", fontName="Helvetica-Bold", fontSize=8, textColor=sev_col)),
                        Paragraph(score_str,  ParagraphStyle("cv", fontName="Helvetica-Bold", fontSize=8, textColor=sev_col)),
                        Paragraph(sev,        ParagraphStyle("cv", fontName="Helvetica-Bold", fontSize=8, textColor=sev_col)),
                        Paragraph(port_ref,   ParagraphStyle("cv", fontName="Courier",        fontSize=8, textColor=C_BLUE)),
                        Paragraph(kev_txt,    ParagraphStyle("cv", fontName="Helvetica-Bold", fontSize=8, textColor=kev_col)),
                        Paragraph(epss_txt,   ParagraphStyle("cv", fontName="Helvetica-Bold", fontSize=8, textColor=epss_col)),
                        Paragraph(desc,       ParagraphStyle("cv", fontName="Helvetica",      fontSize=7.5, textColor=C_TEXT)),
                    ])

                cve_tbl = Table(cve_rows, colWidths=[3.5*cm, 1.3*cm, 1.9*cm, 1.8*cm, 1.5*cm, 1.4*cm, 6.0*cm], repeatRows=1)
                cve_ts_list = [
                    ("FONTSIZE",      (0,0), (-1,-1), 8),
                    ("GRID",          (0,0), (-1,-1), 0.4, C_BOR),
                    ("LEFTPADDING",   (0,0), (-1,-1), 5),
                    ("RIGHTPADDING",  (0,0), (-1,-1), 5),
                    ("TOPPADDING",    (0,0), (-1,-1), 4),
                    ("BOTTOMPADDING", (0,0), (-1,-1), 4),
                    ("VALIGN",        (0,0), (-1,-1), "TOP"),
                ]
                for row_i, bg in enumerate(row_bgs_cve):
                    cve_ts_list.append(("BACKGROUND", (0, row_i), (-1, row_i), bg))
                cve_tbl.setStyle(TableStyle(cve_ts_list))
                story.append(cve_tbl)
            else:
                for cve in d.get("cves",[]):
                    story.append(Paragraph(f"  {cve}  ({tr('nvd_missing')})", red_style))

            # Nuclei findings
            nuclei_hits = d.get("nuclei_findings", [])
            if nuclei_hits:
                story.append(Paragraph(f"{tr('nuclei_findings')} ({len(nuclei_hits)}):", h3_style))
                nuc_data = [[tr("severity"), tr("template_name"), tr("match_url"), "CVSS"]]
                for nf in nuclei_hits:
                    sev = nf.get("severity","?")
                    nuc_data.append([
                        sev,
                        Paragraph((nf.get("name") or nf.get("template_id",""))[:60], body_style),
                        Paragraph((nf.get("matched_at",""))[:50], body_style),
                        str(nf.get("cvss_score","")) or "-",
                    ])
                nuc_tbl = Table(nuc_data, colWidths=[1.5*cm, 7*cm, 6*cm, 1.5*cm])
                nuc_tbl.setStyle(TableStyle([
                    ("BACKGROUND",  (0,0),(-1,0), colors.HexColor("#eff6ff")),
                    ("TEXTCOLOR",   (0,0),(-1,0), C_BLUE),
                    ("FONTNAME",    (0,0),(-1,0), "Helvetica-Bold"),
                    ("FONTSIZE",    (0,0),(-1,-1), 7),
                    ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, C_CARD]),
                    ("TEXTCOLOR",   (0,1),(-1,-1), C_TEXT),
                    ("GRID",        (0,0),(-1,-1), 0.4, C_BOR),
                    ("VALIGN",      (0,0),(-1,-1), "TOP"),
                    ("TOPPADDING",  (0,0),(-1,-1), 3),
                    ("BOTTOMPADDING",(0,0),(-1,-1), 3),
                ]))
                for row_i, nf in enumerate(nuclei_hits, 1):
                    sev = nf.get("severity","UNKNOWN")
                    col = sev_colors.get(sev, C_MUTED)
                    nuc_tbl.setStyle(TableStyle([("TEXTCOLOR",(0,row_i),(0,row_i),col),("FONTNAME",(0,row_i),(0,row_i),"Helvetica-Bold")]))
                story.append(nuc_tbl)
                story.append(Spacer(1,4))

    # Footer
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BOR, spaceAfter=6))
    story.append(Paragraph(f"\xa9 2026   |  VulnScan Pro  |  {tr('authorized')}", sub_style))

    doc.build(story)
    buf.seek(0)
    pdf_bytes = buf.read()

    # Save report to DB (max 10)
    try:
        created_at = datetime.now().strftime("%d.%m.%Y %H:%M")
        device_count = len(devices)
        label = (f"{created_at} · {device_count} devices" if lang == "en" else f"{created_at} · {device_count} Devices")
        with db_connect() as con:
            con.execute("INSERT INTO saved_reports (created_at, label, pdf_data) VALUES (?,?,?)",
                        (created_at, label, pdf_bytes))
            # Keep max 10
            con.execute("""DELETE FROM saved_reports WHERE id NOT IN
                          (SELECT id FROM saved_reports ORDER BY id DESC LIMIT ?)""",
                        (app_data.get("max_reports", 3),))
    except Exception as e:
        print(f"Failed to save report: {e}")

    from flask import send_file
    return send_file(io.BytesIO(pdf_bytes), mimetype='application/pdf',
        as_attachment=True, download_name=f'vulnscan-report-{lang}.pdf')





@app.route("/api/nvd-key", methods=["GET","POST","DELETE"])
def nvd_key_route():
    if request.method == "GET":
        k = get_nvd_api_key()
        if k:
            masked = k[:8] + "****" + k[-4:]
            return jsonify({"set": True, "masked": masked})
        return jsonify({"set": False})
    elif request.method == "POST":
        key = (request.json or {}).get("key","").strip()
        if key:
            set_nvd_api_key(key)
        return jsonify({"ok": True})
    else:  # DELETE
        try:
            with db_connect() as con:
                con.execute("DELETE FROM scheduler WHERE key='nvd_api_key'")
        except: pass
        return jsonify({"ok": True})


@app.route("/api/syscheck")
def syscheck():
    """Checks versions of updatable dependencies and local port-list state."""
    import subprocess, sys, importlib.metadata
    result = {}

    result["python"] = {
        "name": "Python",
        "current": sys.version.split()[0],
        "ok": True,
        "info": os.path.basename(sys.executable)
    }

    try:
        out = subprocess.check_output([NMAP_BIN, "--version"], text=True, timeout=5)
        ver = re.search(r"Nmap version ([\d.]+)", out)
        result["nmap"] = {"name": "nmap", "current": ver.group(1) if ver else "?", "ok": True, "info": "nmap.org"}
    except Exception as e:
        result["nmap"] = {"name": "nmap", "current": "not found", "ok": False, "info": str(e)}

    packages = ["flask", "reportlab", "dnspython", "netifaces2", "mac-vendor-lookup"]
    for pkg in packages:
        try:
            current = importlib.metadata.version(pkg)
            result[pkg] = {"name": pkg, "current": current, "ok": True, "latest": None, "info": ""}
        except Exception:
            result[pkg] = {"name": pkg, "current": "not installed", "ok": False, "latest": None, "info": f"pip install {pkg}"}

    for pkg in packages:
        try:
            out = subprocess.check_output(
                [sys.executable, "-m", "pip", "index", "versions", pkg],
                text=True, stderr=subprocess.DEVNULL, timeout=10
            )
            m = re.search(r"Available versions: ([\d.]+)", out)
            if m and pkg in result:
                latest = m.group(1)
                result[pkg]["latest"] = latest
                result[pkg]["update_available"] = (latest != result[pkg]["current"])
        except Exception:
            result[pkg]["update_available"] = False

    import sqlite3 as _sq
    try:
        db_size = os.path.getsize(DB_FILE) // 1024 if os.path.exists(DB_FILE) else 0
        with db_connect() as con:
            n_dev   = con.execute("SELECT COUNT(*) FROM known_devices").fetchone()[0]
            n_scans = con.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
            n_alrt  = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        result["sqlite"] = {
            "name": "SQLite database",
            "current": f"{_sq.sqlite_version}",
            "ok": True,
            "info": f"{db_size} KB  ·  {n_dev} Devices  ·  {n_scans} Scans  ·  {n_alrt} Alerts"
        }
    except Exception as e:
        result["sqlite"] = {"name": "SQLite database", "current": "Error", "ok": False, "info": str(e)}

    local_data = get_iana_port_lists()
    local_tcp = len(local_data.get("tcp_ports", []))
    local_udp = len(local_data.get("udp_ports", []))
    local_ver = local_data.get("last_updated") or "local snapshot"
    checked_at = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    result["portlists"] = {
        "name": "Port lists (IANA)",
        "current": f"{local_ver}",
        "ok": True,
        "latest": local_ver,
        "info": f"Local: TCP {local_tcp} · UDP {local_udp} · Total {local_tcp + local_udp} · Checked {checked_at}",
        "update_available": False
    }

    try:
        remote = _fetch_iana_registry(timeout=8)
        remote_ver = remote.get("last_updated") or "online verfuegbar"
        remote_tcp = len(remote.get("tcp_ports", []))
        remote_udp = len(remote.get("udp_ports", []))
        needs_update = remote_ver != local_ver or remote_tcp != local_tcp or remote_udp != local_udp
        result["portlists"].update({
            "latest": remote_ver,
            "remote_info": f"Remote: TCP {remote_tcp} · UDP {remote_udp} · Total {remote_tcp + remote_udp}",
            "update_available": needs_update
        })
    except Exception as e:
        result["portlists"].update({
            "latest": None,
            "remote_info": f"Online check failed: {e}"
        })

    return jsonify(result)

@app.route("/api/update", methods=["POST"])
def do_update():
    """Installs/upgrades Python packages and refreshes port lists."""
    import subprocess, sys
    req = request.json or {}
    packages = req.get("packages", ["flask", "reportlab", "dnspython", "netifaces2", "mac-vendor-lookup"])
    results = {}
    for pkg in packages:
        if pkg == "portlists":
            try:
                data = get_iana_port_lists(force_refresh=True)
                results[pkg] = {
                    "ok": True,
                    "message": f"IANA port lists updated: TCP {len(data.get('tcp_ports', []))}, UDP {len(data.get('udp_ports', []))}, Updated {data.get('last_updated') or 'Snapshot'}"
                }
            except Exception as e:
                results[pkg] = {"ok": False, "message": str(e)}
            continue
        try:
            out = subprocess.check_output(
                [sys.executable, "-m", "pip", "install", "--upgrade", pkg],
                text=True, stderr=subprocess.STDOUT, timeout=60
            )
            m = re.search(r"Successfully installed.*?" + pkg + r"-([\d.]+)", out)
            ver = m.group(1) if m else "updated"
            results[pkg] = {"ok": True, "message": f"Updated to {ver}"}
        except subprocess.CalledProcessError as e:
            results[pkg] = {"ok": False, "message": e.output[:200]}
        except Exception as e:
            results[pkg] = {"ok": False, "message": str(e)}
    return jsonify(results)


# ────────────────────────────────────────────────────────────────
# LOGS API — central event store (scan, scheduler, alerts, system)
# ────────────────────────────────────────────────────────────────
_LOG_SEVERITIES = ("info", "warn", "error", "critical")
_LOG_SOURCES    = ("scan", "scheduler", "alert", "traffic", "system", "user")


def _build_logs_where(args):
    """Build WHERE clause and params from query args."""
    where, params = [], []
    sev = (args.get("severity") or "").strip().lower()
    if sev and sev in _LOG_SEVERITIES:
        where.append("severity = ?"); params.append(sev)
    src = (args.get("source") or "").strip().lower()
    if src and src in _LOG_SOURCES:
        where.append("source = ?"); params.append(src)
    host = (args.get("host") or "").strip()
    if host:
        where.append("host LIKE ?"); params.append(f"%{host}%")
    since = (args.get("from") or "").strip()
    if since:
        where.append("ts >= ?"); params.append(since)
    until = (args.get("to") or "").strip()
    if until:
        where.append("ts <= ?"); params.append(until)
    q = (args.get("search") or "").strip()
    if q:
        where.append("(message LIKE ? OR event_type LIKE ?)")
        params += [f"%{q}%", f"%{q}%"]
    return (" WHERE " + " AND ".join(where)) if where else "", params


@app.route("/api/logs")
def api_logs_list():
    """List events with optional filters.
    Query: severity, source, host, from, to, search, limit (default 200), offset.
    """
    try:
        limit  = max(1, min(2000, int(request.args.get("limit", 200))))
    except Exception:
        limit = 200
    try:
        offset = max(0, int(request.args.get("offset", 0)))
    except Exception:
        offset = 0
    where, params = _build_logs_where(request.args)
    with db_connect() as con:
        con.row_factory = sqlite3.Row
        total = con.execute(f"SELECT COUNT(*) AS c FROM events{where}", params).fetchone()["c"]
        rows = con.execute(
            f"SELECT id, ts, severity, source, event_type, host, message "
            f"FROM events{where} ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        ).fetchall()
    return jsonify({
        "total": total, "limit": limit, "offset": offset,
        "events": [dict(r) for r in rows]
    })


@app.route("/api/logs/stats")
def api_logs_stats():
    """Summary counts per severity/source + total."""
    where, params = _build_logs_where(request.args)
    with db_connect() as con:
        con.row_factory = sqlite3.Row
        sev_rows = con.execute(
            f"SELECT severity, COUNT(*) AS c FROM events{where} GROUP BY severity",
            params).fetchall()
        src_rows = con.execute(
            f"SELECT source, COUNT(*) AS c FROM events{where} GROUP BY source",
            params).fetchall()
        total = con.execute(f"SELECT COUNT(*) AS c FROM events{where}", params).fetchone()["c"]
    return jsonify({
        "total":     total,
        "severity": {r["severity"]: r["c"] for r in sev_rows},
        "source":   {r["source"]:   r["c"] for r in src_rows},
    })


@app.route("/api/logs", methods=["DELETE"])
def api_logs_clear():
    """Delete events matching filter (or all if none)."""
    where, params = _build_logs_where(request.args)
    with db_connect() as con:
        cur = con.execute(f"DELETE FROM events{where}", params)
        deleted = cur.rowcount or 0
    log_ev("info", "system", f"Logs deleted: {deleted} entries", event_type="logs_clear")
    return jsonify({"deleted": deleted})


@app.route("/api/logs/export/csv")
def api_logs_export_csv():
    """CSV export of current filtered result set."""
    import csv, io
    where, params = _build_logs_where(request.args)
    with db_connect() as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            f"SELECT ts, severity, source, event_type, host, message FROM events{where} "
            f"ORDER BY id DESC LIMIT 50000", params
        ).fetchall()
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(["timestamp", "severity", "source", "event_type", "host", "message"])
    for r in rows:
        w.writerow([r["ts"], r["severity"], r["source"], r["event_type"], r["host"], r["message"]])
    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = 'attachment; filename="vulnscan-logs.csv"'
    return resp


@app.route("/api/logs/export/syslog")
def api_logs_export_syslog():
    """RFC-3164-style syslog export (plain text)."""
    import io
    where, params = _build_logs_where(request.args)
    prio_map = {"info": 14, "warn": 12, "error": 11, "critical": 10}  # facility=1 (user)
    with db_connect() as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            f"SELECT ts, severity, source, host, message FROM events{where} "
            f"ORDER BY id ASC LIMIT 50000", params
        ).fetchall()
    buf = io.StringIO()
    host_default = "vulnscan"
    for r in rows:
        pri = prio_map.get(r["severity"], 14)
        # try to parse ts; fall back to raw
        try:
            from datetime import datetime as _dt
            dt = _dt.fromisoformat(r["ts"])
            ts = dt.strftime("%b %d %H:%M:%S")
        except Exception:
            ts = r["ts"]
        tag = "vulnscan-" + (r["source"] or "sys")
        h = r["host"] or host_default
        buf.write(f"<{pri}>{ts} {h} {tag}: {r['message']}\n")
    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"] = "text/plain; charset=utf-8"
    resp.headers["Content-Disposition"] = 'attachment; filename="vulnscan-logs.log"'
    return resp


@app.route("/api/logs/export/pdf")
def api_logs_export_pdf():
    """PDF export of current filtered log — executive summary + detail table."""
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib import colors as _c
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas as _canvas
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    import io as _io
    from datetime import datetime as _dt

    where, params = _build_logs_where(request.args)
    with db_connect() as con:
        con.row_factory = sqlite3.Row
        stats = {
            "total": con.execute(f"SELECT COUNT(*) AS c FROM events{where}", params).fetchone()["c"],
        }
        sev_rows = con.execute(
            f"SELECT severity, COUNT(*) AS c FROM events{where} GROUP BY severity", params
        ).fetchall()
        stats["severity"] = {r["severity"]: r["c"] for r in sev_rows}
        rows = con.execute(
            f"SELECT ts, severity, source, event_type, host, message "
            f"FROM events{where} ORDER BY id DESC LIMIT 2000", params
        ).fetchall()

    buf = _io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4),
                            leftMargin=12*mm, rightMargin=12*mm,
                            topMargin=14*mm,  bottomMargin=12*mm)
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"],
                        fontName="Helvetica-Bold", fontSize=16,
                        textColor=_c.HexColor("#0b3954"))
    small = ParagraphStyle("sm", parent=styles["BodyText"], fontSize=8,
                           textColor=_c.HexColor("#555555"))
    story = []
    story.append(Paragraph("VulnScan Pro — Log Report", h1))
    story.append(Paragraph(
        f"Erstellt: {_dt.now().strftime('%Y-%m-%d %H:%M:%S')}  ·  "
        f"Total entries: <b>{stats['total']}</b>  ·  "
        f"CRITICAL: {stats['severity'].get('critical',0)}  ·  "
        f"ERROR: {stats['severity'].get('error',0)}  ·  "
        f"WARN: {stats['severity'].get('warn',0)}  ·  "
        f"INFO: {stats['severity'].get('info',0)}",
        small))
    story.append(Spacer(1, 6*mm))

    # table
    data = [["Timestamp", "Sev", "Source", "Host", "Event", "Message"]]
    sev_color = {
        "critical": _c.HexColor("#b00020"),
        "error":    _c.HexColor("#d9480f"),
        "warn":     _c.HexColor("#c98a00"),
        "info":     _c.HexColor("#1b7f3a"),
    }
    row_styles = []
    for i, r in enumerate(rows, start=1):
        sev = r["severity"] or "info"
        data.append([
            (r["ts"] or "")[:19],
            sev.upper(),
            r["source"] or "",
            r["host"] or "",
            r["event_type"] or "",
            (r["message"] or "")[:220],
        ])
        row_styles.append(("TEXTCOLOR", (1, i), (1, i), sev_color.get(sev, _c.black)))

    tbl = Table(data, colWidths=[32*mm, 16*mm, 22*mm, 30*mm, 30*mm, 140*mm], repeatRows=1)
    ts = [
        ("BACKGROUND", (0,0), (-1,0), _c.HexColor("#0b3954")),
        ("TEXTCOLOR",  (0,0), (-1,0), _c.white),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 7.5),
        ("VALIGN",     (0,0), (-1,-1), "TOP"),
        ("GRID",       (0,0), (-1,-1), 0.25, _c.HexColor("#cccccc")),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [_c.white, _c.HexColor("#f5f7fa")]),
        ("FONTNAME",   (1,1), (1,-1), "Helvetica-Bold"),
    ] + row_styles
    tbl.setStyle(TableStyle(ts))
    story.append(tbl)

    doc.build(story)
    buf.seek(0)
    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"] = "application/pdf"
    resp.headers["Content-Disposition"] = 'attachment; filename="vulnscan-logs.pdf"'
    return resp


# ────────────────────────────────────────────────────────────────
# BLACKLIST API
# ────────────────────────────────────────────────────────────────
@app.route("/api/blacklist/feeds")
def api_bl_feeds():
    """List all feeds with counts."""
    with db_connect() as con:
        con.row_factory = sqlite3.Row
        rows = con.execute("""
            SELECT id, name, url, format, enabled, is_custom,
                   last_updated, entry_count, last_error
            FROM blacklist_feeds ORDER BY is_custom ASC, name ASC
        """).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/blacklist/feeds", methods=["POST"])
def api_bl_feeds_add():
    """Add a custom feed. Body: {name, url, format?}"""
    b = request.json or {}
    name = (b.get("name") or "").strip()
    url  = (b.get("url") or "").strip()
    fmt  = (b.get("format") or "netset").strip()
    if not name or not url:
        return jsonify({"error": "name and url required"}), 400
    if fmt not in ("netset", "plain", "spamhaus"):
        fmt = "netset"
    try:
        with db_connect() as con:
            con.execute(
                "INSERT INTO blacklist_feeds (name, url, format, enabled, is_custom) "
                "VALUES (?, ?, ?, 1, 1)",
                (name, url, fmt)
            )
            fid = con.execute("SELECT id FROM blacklist_feeds WHERE name=?", (name,)).fetchone()[0]
        log_ev("info", "user", f"Blocklists-Feed added: {name}", event_type="blacklist_add")
        return jsonify({"id": fid, "ok": True})
    except sqlite3.IntegrityError:
        return jsonify({"error": "name already exists"}), 409


@app.route("/api/blacklist/feeds/<int:fid>", methods=["PATCH"])
def api_bl_feed_toggle(fid):
    """Enable/disable a feed. Body: {enabled: bool}"""
    b = request.json or {}
    enabled = 1 if b.get("enabled") else 0
    with db_connect() as con:
        con.execute("UPDATE blacklist_feeds SET enabled=? WHERE id=?", (enabled, fid))
    _bl_refresh_index()
    return jsonify({"ok": True, "enabled": bool(enabled)})


@app.route("/api/blacklist/feeds/<int:fid>", methods=["DELETE"])
def api_bl_feed_delete(fid):
    """Delete a feed (and its entries via CASCADE)."""
    with db_connect() as con:
        row = con.execute("SELECT name, is_custom FROM blacklist_feeds WHERE id=?", (fid,)).fetchone()
        if not row:
            return jsonify({"error": "not found"}), 404
        # Don't let users delete the default (preloaded) feeds — reset instead
        if not row[1]:
            con.execute("DELETE FROM blacklist_entries WHERE feed_id=?", (fid,))
            con.execute("UPDATE blacklist_feeds SET enabled=0, last_updated='', entry_count=0, last_error='' WHERE id=?", (fid,))
            _bl_refresh_index()
            return jsonify({"ok": True, "reset": True, "message": "Default feed entries cleared (feed kept)."})
        con.execute("DELETE FROM blacklist_feeds WHERE id=?", (fid,))
    _bl_refresh_index()
    log_ev("info", "user", f"Blocklists-Feed deleted: {row[0]}", event_type="blacklist_delete")
    return jsonify({"ok": True, "deleted": True})


@app.route("/api/blacklist/feeds/<int:fid>/update", methods=["POST"])
def api_bl_feed_update(fid):
    """Fetch & refresh one feed."""
    count, err = _bl_update_feed(fid)
    if err:
        return jsonify({"ok": False, "error": err, "count": count}), 200
    return jsonify({"ok": True, "count": count})


@app.route("/api/blacklist/update-all", methods=["POST"])
def api_bl_update_all():
    """Update every enabled feed."""
    with db_connect() as con:
        fids = [r[0] for r in con.execute(
            "SELECT id FROM blacklist_feeds WHERE enabled=1 AND is_custom=0"
        ).fetchall()]
        # Custom feeds also get refreshed if enabled
        fids += [r[0] for r in con.execute(
            "SELECT id FROM blacklist_feeds WHERE enabled=1 AND is_custom=1"
        ).fetchall()]
    results = {}
    for fid in fids:
        c, e = _bl_update_feed(fid)
        results[str(fid)] = {"count": c, "error": e}
    return jsonify({"ok": True, "results": results})


@app.route("/api/blacklist/custom")
def api_bl_custom_list():
    """List manual/custom entries (feed_id IS NULL)."""
    with db_connect() as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT id, ip_or_net, notes, added_at FROM blacklist_entries "
            "WHERE feed_id IS NULL ORDER BY id DESC"
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/blacklist/custom", methods=["POST"])
def api_bl_custom_add():
    """Add a custom entry. Body: {ip_or_net, notes?}"""
    import ipaddress as _ipa, datetime as _dt
    b = request.json or {}
    val = (b.get("ip_or_net") or "").strip()
    notes = (b.get("notes") or "").strip()
    if not val:
        return jsonify({"error": "ip_or_net required"}), 400
    try:
        if "/" in val:
            _ipa.ip_network(val, strict=False)
        else:
            _ipa.ip_address(val)
    except Exception:
        return jsonify({"error": f"invalid IP/CIDR: {val}"}), 400
    with db_connect() as con:
        con.execute(
            "INSERT INTO blacklist_entries (ip_or_net, feed_id, notes, added_at) "
            "VALUES (?, NULL, ?, ?)",
            (val, notes, _dt.datetime.now().isoformat(timespec="seconds"))
        )
    _bl_refresh_index()
    log_ev("info", "user", f"Blocklists-Custom added: {val}", event_type="blacklist_custom_add", host=val)
    return jsonify({"ok": True})


@app.route("/api/blacklist/custom/<int:eid>", methods=["DELETE"])
def api_bl_custom_delete(eid):
    with db_connect() as con:
        con.execute("DELETE FROM blacklist_entries WHERE id=? AND feed_id IS NULL", (eid,))
    _bl_refresh_index()
    return jsonify({"ok": True})


@app.route("/api/blacklist/lookup/<ip>")
def api_bl_lookup(ip):
    """Check if a single IP matches any enabled blacklist."""
    matches = ip_in_blacklist(ip)
    return jsonify({"ip": ip, "blacklisted": bool(matches), "matches": matches})


@app.route("/api/blacklist/stats")
def api_bl_stats():
    """Summary: total entries, by feed."""
    with db_connect() as con:
        con.row_factory = sqlite3.Row
        total_enabled = con.execute("""
            SELECT COUNT(*) AS c FROM blacklist_entries e
            LEFT JOIN blacklist_feeds f ON e.feed_id = f.id
            WHERE (f.enabled=1) OR (e.feed_id IS NULL)
        """).fetchone()["c"]
        total_all = con.execute("SELECT COUNT(*) AS c FROM blacklist_entries").fetchone()["c"]
        custom = con.execute(
            "SELECT COUNT(*) AS c FROM blacklist_entries WHERE feed_id IS NULL"
        ).fetchone()["c"]
        enabled_feeds = con.execute(
            "SELECT COUNT(*) AS c FROM blacklist_feeds WHERE enabled=1"
        ).fetchone()["c"]
    return jsonify({
        "entries_enabled": total_enabled,
        "entries_total":   total_all,
        "entries_custom":  custom,
        "feeds_enabled":   enabled_feeds,
    })


# ════════════════════════════════════════════════════════════════════
# TRAFFIC MONITOR — process-to-connection mapping (Sniffnet-style)
# ════════════════════════════════════════════════════════════════════
#
# Polls psutil.net_connections() every TRAFFIC_POLL_SEC and aggregates
# connections by (process_name, remote_ip, remote_port, protocol).
# Auto-checks each new remote IP against the blacklist. Hits → critical
# event in the Logs tab.
#
# Privacy: collector is opt-in (start/stop via UI). No data is sent
# anywhere; everything stays local in this Flask process.
# ────────────────────────────────────────────────────────────────────

try:
    import psutil  # noqa: F401
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

TRAFFIC_POLL_SEC = 2.0

_traffic_state = {
    "running":          False,
    "thread":           None,
    "started_at":       None,
    "polls":            0,
    "last_poll_at":     None,
    "last_error":       "",
    "connections":      {},   # key: (proc, pid, raddr, rport, proto) → dict
    "process_cache":    {},   # pid → name  (cleared periodically)
    "blacklist_hits":   set(),# remote IPs we've already alerted on (dedup)
    "lock":             threading.Lock(),
}


def _proc_name_for_pid(pid):
    """Cached lookup of process name."""
    if pid is None or pid < 0:
        return "?"
    cache = _traffic_state["process_cache"]
    if pid in cache:
        return cache[pid]
    if not _HAS_PSUTIL:
        return "?"
    try:
        p = psutil.Process(pid)
        name = p.name() or "?"
        # On Linux, try cmdline[0] for more detail
        try:
            cmd = p.cmdline()
            if cmd:
                base = os.path.basename(cmd[0])
                if base and base != name:
                    name = base
        except Exception:
            pass
    except Exception:
        name = "?"
    cache[pid] = name
    return name


def _is_external(ip):
    """Return True if IP is public (not loopback/private/link-local)."""
    if not ip:
        return False
    try:
        import ipaddress as _ipa
        a = _ipa.ip_address(ip)
        if a.is_loopback or a.is_private or a.is_link_local or a.is_multicast:
            return False
        return True
    except Exception:
        return False


def _traffic_poll_once():
    """Single poll cycle: fetch connections, aggregate, blacklist-check."""
    if not _HAS_PSUTIL:
        return
    try:
        conns = psutil.net_connections(kind="inet")
    except (PermissionError, psutil.AccessDenied):
        _traffic_state["last_error"] = "Access denied — full visibility requires sufficient capture permissions"
        return
    except Exception as e:
        _traffic_state["last_error"] = str(e)[:200]
        return

    _traffic_state["last_error"] = ""
    now = time.time()
    new_blacklist_ips = []

    with _traffic_state["lock"]:
        active_keys = set()
        for c in conns:
            if not c.raddr:
                continue
            raddr_ip   = c.raddr.ip if hasattr(c.raddr, "ip") else c.raddr[0]
            raddr_port = c.raddr.port if hasattr(c.raddr, "port") else c.raddr[1]
            laddr_ip   = (c.laddr.ip if hasattr(c.laddr, "ip") else c.laddr[0]) if c.laddr else "-"
            laddr_port = (c.laddr.port if hasattr(c.laddr, "port") else c.laddr[1]) if c.laddr else 0
            proto      = "TCP" if c.type == 1 else "UDP" if c.type == 2 else str(c.type)
            pid        = c.pid
            pname      = _proc_name_for_pid(pid)
            status     = (c.status or "?")
            external   = _is_external(raddr_ip)
            key = (pname, pid or -1, raddr_ip, raddr_port, proto)
            active_keys.add(key)
            entry = _traffic_state["connections"].get(key)
            if entry is None:
                entry = {
                    "process":   pname,
                    "pid":       pid or 0,
                    "laddr":     f"{laddr_ip}:{laddr_port}",
                    "raddr_ip":  raddr_ip,
                    "raddr":     f"{raddr_ip}:{raddr_port}",
                    "rport":     raddr_port,
                    "proto":     proto,
                    "status":    status,
                    "external":  external,
                    "first_seen": now,
                    "last_seen":  now,
                    "blacklist": None,
                    "poll_count": 1,
                }
                _traffic_state["connections"][key] = entry
                # Blocklists check (only for external IPs, only once per IP)
                if external and raddr_ip not in _traffic_state["blacklist_hits"]:
                    try:
                        matches = ip_in_blacklist(raddr_ip)
                        if matches:
                            entry["blacklist"] = matches
                            new_blacklist_ips.append((pname, pid, raddr_ip, raddr_port, matches))
                            _traffic_state["blacklist_hits"].add(raddr_ip)
                    except Exception:
                        pass
            else:
                entry["last_seen"] = now
                entry["status"]    = status
                entry["poll_count"] += 1

        # Mark stale entries (not seen this poll) — keep for 60s for "recently closed"
        stale_cutoff = now - 60
        for k, e in list(_traffic_state["connections"].items()):
            if k not in active_keys and e["last_seen"] < stale_cutoff:
                _traffic_state["connections"].pop(k, None)

        _traffic_state["polls"] += 1
        _traffic_state["last_poll_at"] = now

    # Emit blacklist-hit events OUTSIDE the lock to avoid DB-lock contention
    for pname, pid, ip, port, matches in new_blacklist_ips:
        feeds = ", ".join(sorted({m["feed"] for m in matches}))
        try:
            log_ev("critical", "traffic",
                   f"Traffic-Blocklists-Hit: {pname} (pid={pid}) → {ip}:{port} in {feeds}",
                   event_type="traffic_blacklist_hit", host=ip,
                   data={"process": pname, "pid": pid, "port": port, "matches": matches})
        except Exception:
            pass


def _traffic_loop():
    """Background polling loop."""
    while _traffic_state["running"]:
        _traffic_poll_once()
        # Sleep in small chunks to react quickly to stop signal
        for _ in range(int(TRAFFIC_POLL_SEC * 10)):
            if not _traffic_state["running"]:
                return
            time.sleep(0.1)


def _traffic_start():
    if not _HAS_PSUTIL:
        return False, "psutil is not installed — pip install psutil"
    if _traffic_state["running"]:
        return True, "already running"
    _traffic_state["running"]    = True
    _traffic_state["started_at"] = time.time()
    _traffic_state["polls"]      = 0
    _traffic_state["last_error"] = ""
    t = threading.Thread(target=_traffic_loop, daemon=True, name="TrafficCollector")
    _traffic_state["thread"] = t
    t.start()
    try:
        log_ev("info", "traffic", "Traffic monitor started", event_type="traffic_start")
    except Exception:
        pass
    return True, "gestartet"


def _traffic_stop():
    if not _traffic_state["running"]:
        return True, "was not running"
    _traffic_state["running"] = False
    t = _traffic_state.get("thread")
    if t:
        t.join(timeout=3)
    try:
        log_ev("info", "traffic", "Traffic monitor stopped", event_type="traffic_stop")
    except Exception:
        pass
    return True, "gestoppt"


@app.route("/api/traffic/status")
def api_traffic_status():
    return jsonify({
        "available":      _HAS_PSUTIL,
        "running":        _traffic_state["running"],
        "started_at":     _traffic_state["started_at"],
        "polls":          _traffic_state["polls"],
        "last_poll_at":   _traffic_state["last_poll_at"],
        "last_error":     _traffic_state["last_error"],
        "active_count":   len(_traffic_state["connections"]),
        "poll_interval":  TRAFFIC_POLL_SEC,
        "is_root":        bool(hasattr(os, "geteuid") and os.geteuid() == 0),
    })


@app.route("/api/traffic/start", methods=["POST"])
def api_traffic_start():
    ok, msg = _traffic_start()
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/traffic/stop", methods=["POST"])
def api_traffic_stop():
    ok, msg = _traffic_stop()
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/traffic")
def api_traffic_list():
    """Current snapshot of tracked connections. Filters: process, external_only, blacklisted_only, search."""
    proc_f       = (request.args.get("process") or "").strip().lower()
    external_f   = request.args.get("external_only") in ("1", "true", "True")
    blacklist_f  = request.args.get("blacklisted_only") in ("1", "true", "True")
    search       = (request.args.get("search") or "").strip().lower()
    with _traffic_state["lock"]:
        entries = list(_traffic_state["connections"].values())
    out = []
    for e in entries:
        if proc_f and proc_f not in (e.get("process") or "").lower():
            continue
        if external_f and not e.get("external"):
            continue
        if blacklist_f and not e.get("blacklist"):
            continue
        if search and search not in (e.get("process","") + " " + e.get("raddr","")).lower():
            continue
        # serialize matches (lookup format)
        bl = e.get("blacklist") or []
        out.append({
            "process":   e["process"],
            "pid":       e["pid"],
            "laddr":     e["laddr"],
            "raddr":     e["raddr"],
            "raddr_ip":  e["raddr_ip"],
            "rport":     e["rport"],
            "proto":     e["proto"],
            "status":    e["status"],
            "external":  e["external"],
            "blacklist": [{"feed": m.get("feed"), "match_kind": m.get("match_kind")} for m in bl],
            "first_seen": e["first_seen"],
            "last_seen":  e["last_seen"],
            "poll_count": e["poll_count"],
        })
    # Sort: blacklist hits first, then external, then most recent
    out.sort(key=lambda x: (
        0 if x["blacklist"] else 1,
        0 if x["external"] else 1,
        -x["last_seen"],
    ))
    return jsonify(out)


@app.route("/api/traffic/stats")
def api_traffic_stats():
    """Aggregate stats: active total, processes, external, blacklist hits, top talkers."""
    with _traffic_state["lock"]:
        entries = list(_traffic_state["connections"].values())
    now = time.time()
    active = [e for e in entries if (now - e["last_seen"]) < 5]
    external = [e for e in entries if e["external"]]
    bl_hit = [e for e in entries if e["blacklist"]]
    procs = {}
    for e in entries:
        p = e["process"]
        procs[p] = procs.get(p, 0) + 1
    top_procs = sorted(procs.items(), key=lambda x: -x[1])[:10]
    return jsonify({
        "total":           len(entries),
        "active":          len(active),
        "external":        len(external),
        "blacklist_hits":  len(bl_hit),
        "unique_procs":    len(procs),
        "top_procs":       [{"process": p, "count": c} for p, c in top_procs],
    })


@app.route("/api/traffic/clear", methods=["POST"])
def api_traffic_clear():
    """Clear the in-memory connection table (does NOT stop the collector)."""
    with _traffic_state["lock"]:
        _traffic_state["connections"].clear()
        _traffic_state["blacklist_hits"].clear()
        _traffic_state["process_cache"].clear()
    return jsonify({"ok": True})




if __name__ == "__main__":
    import sys
    is_root = hasattr(os, 'geteuid') and os.geteuid() == 0
    is_win  = sys.platform.startswith("win") or os.name == "nt"
    priv = "root" if is_root else ("Windows" if is_win else "user")
    port = int(os.environ.get("VULNSCAN_PORT", "5000"))
    print(f"🔍 VulnScan Pro v1.0.0 running at http://127.0.0.1:{port}")
    if not NMAP_FOUND:
        print("⚠ nmap.exe not found — please install: https://nmap.org/download.html")
    try:
        log_ev("info", "system",
               f"VulnScan Pro v1.0.0 started · nmap={NMAP_BIN} · privileges: {priv}",
               event_type="app_start")
    except Exception:
        pass
    app.run(host="127.0.0.1", port=port, debug=False)
