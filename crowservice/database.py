import sqlite3, json
from pathlib import Path
from datetime import datetime, timezone

DB_PATH=Path("results/crowservice.db")

def connect():
    DB_PATH.parent.mkdir(parents=True,exist_ok=True)
    c=sqlite3.connect(DB_PATH)
    c.row_factory=sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.executescript("""
    CREATE TABLE IF NOT EXISTS scans(
      id INTEGER PRIMARY KEY, started_utc TEXT NOT NULL, target_count INTEGER,
      port_count INTEGER, note TEXT
    );
    CREATE TABLE IF NOT EXISTS hosts(
      id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      host TEXT NOT NULL, resolved_ips TEXT, reverse_dns TEXT
    );
    CREATE TABLE IF NOT EXISTS services(
      id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      host TEXT NOT NULL, port INTEGER NOT NULL, state TEXT, service TEXT,
      banner TEXT, product TEXT, version TEXT, os_hint TEXT, details_json TEXT
    );
    CREATE TABLE IF NOT EXISTS vulnerabilities(
      id INTEGER PRIMARY KEY, service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
      cve_id TEXT, cvss REAL, severity TEXT, published TEXT, description TEXT, source TEXT
    );
    CREATE TABLE IF NOT EXISTS web_audits(
      id INTEGER PRIMARY KEY, created_utc TEXT NOT NULL, host TEXT NOT NULL,
      url TEXT NOT NULL, status_code INTEGER, grade TEXT, score INTEGER,
      data_json TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS lookups(
      id INTEGER PRIMARY KEY, created_utc TEXT NOT NULL, kind TEXT NOT NULL,
      query TEXT NOT NULL, data_json TEXT NOT NULL
    );
    """)
    c.commit()
    return c

def save_scan(rows, host_data, vuln_by_service, ports_count, note=""):
    c=connect()
    cur=c.execute("INSERT INTO scans(started_utc,target_count,port_count,note) VALUES(?,?,?,?)",
                  (datetime.now(timezone.utc).isoformat(),len(host_data),ports_count,note))
    scan_id=cur.lastrowid
    for h in host_data:
        c.execute("INSERT INTO hosts(scan_id,host,resolved_ips,reverse_dns) VALUES(?,?,?,?)",
                  (scan_id,h["host"],json.dumps(h.get("resolved_ips",[])),h.get("reverse_dns","")))
    for row in rows:
        cur=c.execute("""INSERT INTO services(scan_id,host,port,state,service,banner,product,version,os_hint,details_json)
        VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (scan_id,row["host"],row["port"],row["state"],row["service"],row["banner"],row["product"],
         row["version"],row["os_hint"],json.dumps(row,ensure_ascii=False)))
        sid=cur.lastrowid
        for v in vuln_by_service.get((row["host"],row["port"]),{}).get("items",[]):
            c.execute("""INSERT INTO vulnerabilities(service_id,cve_id,cvss,severity,published,description,source)
            VALUES(?,?,?,?,?,?,?)""",(sid,v.get("cve_id"),v.get("cvss"),v.get("severity"),
            v.get("published"),v.get("description"),v.get("source","NVD")))
    c.commit(); c.close()
    return scan_id

def save_lookup(kind,query,data):
    c=connect()
    c.execute("INSERT INTO lookups(created_utc,kind,query,data_json) VALUES(?,?,?,?)",
              (datetime.now(timezone.utc).isoformat(),kind,query,json.dumps(data,ensure_ascii=False)))
    c.commit(); c.close()

def recent_scans(limit=30):
    c=connect(); rows=c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?",(limit,)).fetchall(); c.close()
    return [dict(x) for x in rows]

def services_for_scan(scan_id):
    c=connect(); rows=c.execute("SELECT * FROM services WHERE scan_id=? ORDER BY host,port",(scan_id,)).fetchall(); c.close()
    return [dict(x) for x in rows]

def recent_lookups(limit=30):
    c=connect(); rows=c.execute("SELECT * FROM lookups ORDER BY id DESC LIMIT ?",(limit,)).fetchall(); c.close()
    return [dict(x) for x in rows]

def db_summary():
    c=connect()
    out={}
    for table in ("scans","hosts","services","vulnerabilities","lookups","web_audits"):
        out[table]=c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    c.close(); return out


def save_web_audit(data):
    c=connect()
    c.execute("INSERT INTO web_audits(created_utc,host,url,status_code,grade,score,data_json) VALUES(?,?,?,?,?,?,?)",
              (datetime.now(timezone.utc).isoformat(),data.get("host",""),data.get("url",""),
               data.get("status_code"),data.get("grade"),data.get("score"),
               json.dumps(data,ensure_ascii=False)))
    c.commit(); c.close()

def recent_web_audits(limit=30):
    c=connect()
    rows=c.execute("SELECT id,created_utc,host,url,status_code,grade,score FROM web_audits ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
    c.close()
    return [dict(x) for x in rows]
