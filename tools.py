"""
Investigation tools exposed to the Nemotron agent.

TelemetryDB wraps a pandas DataFrame of security events and exposes a handful
of query functions. TOOL_SCHEMAS describes them in OpenAI function-calling
format so the model can pick which ones to call.

Expected (flexible) columns: timestamp, host, user, event_type, pid, ppid,
process, parent_process, command_line, image_path, file_path, file_hash,
dest_ip, dest_port, domain, task_name, registry_key, registry_value ...
Missing columns are simply treated as empty.
"""
from __future__ import annotations

import io
import ipaddress
import json
from typing import Any

import pandas as pd

MAX_ROWS = 40  # cap what we send back to the model per tool call

# ---------------------------------------------------------------------------
# Mock threat intelligence (a real build would hit VirusTotal / AbuseIPDB etc.)
# ---------------------------------------------------------------------------
THREAT_INTEL_IPS = {
    "185.220.101.47": {"verdict": "malicious", "confidence": 95, "country": "DE", "asn": "AS205100 F3 Netze",
                       "tags": ["tor-exit-node", "cobalt-strike-c2", "malware-distribution"],
                       "reports": 412, "last_seen": "2026-09-17"},
    "45.155.205.233": {"verdict": "malicious", "confidence": 88, "country": "RU", "asn": "AS49505 Selectel",
                       "tags": ["data-exfiltration", "bulletproof-hosting"], "reports": 97, "last_seen": "2026-09-15"},
}
THREAT_INTEL_DOMAINS = {
    "cdn-update-status.com": {"verdict": "malicious", "registered": "2026-09-11", "registrar": "NameSilo",
                              "tags": ["newly-registered", "typosquat", "c2"], "notes": "Registered 7 days ago; mimics CDN naming."},
}
THREAT_INTEL_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
        "verdict": "malicious", "detections": "41/72", "family": "PowerShell/Downloader.Agent",
        "first_seen": "2026-09-12", "tags": ["dropper", "stage2-loader"]},
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08": {
        "verdict": "malicious", "detections": "29/72", "family": "W97M/Downloader.Emotet-like",
        "first_seen": "2026-09-16", "tags": ["maldoc", "vba-macro", "autoopen"]},
}
KNOWN_GOOD_DOMAINS = ("microsoft.com", "office365.com", "office.com", "live.com", "google.com", "github.com",
                      "windowsupdate.com", "azure.com", "msftconnecttest.com")

STRING_COLS = ["host", "user", "event_type", "process", "parent_process", "command_line", "command_line_decoded",
               "image_path", "file_path", "file_hash", "dest_ip", "domain", "resolved_ip", "task_name", "task_action",
               "registry_key", "registry_value_name", "registry_value", "protocol", "action"]
PERSISTENCE_TYPES = {"scheduled_task", "registry_set", "service_install", "wmi_subscription", "startup_folder"}
PERSISTENCE_KEYWORDS = ["\\run", "runonce", "schtasks", "sc.exe", "new-service", "startup", "winlogon", "userinit",
                        "image file execution", "wmi", "eventconsumer", "hklm\\system\\currentcontrolset\\services"]


class TelemetryDB:
    def __init__(self, df: pd.DataFrame):
        df = df.copy()
        df.columns = [str(c).strip().lower().replace(" ", "_") for c in df.columns]
        # normalize a few common alternative column names
        renames = {"eventtype": "event_type", "type": "event_type", "hostname": "host", "computer": "host",
                   "username": "user", "processname": "process", "image": "process", "parentimage": "parent_process",
                   "commandline": "command_line", "processid": "pid", "parentprocessid": "ppid",
                   "destinationip": "dest_ip", "destinationport": "dest_port", "targetfilename": "file_path",
                   "utctime": "timestamp", "time": "timestamp", "@timestamp": "timestamp"}
        df = df.rename(columns={k: v for k, v in renames.items() if k in df.columns and v not in df.columns})
        for col in ["timestamp", "event_type", "host", "pid", "ppid", "process", "parent_process"]:
            if col not in df.columns:
                df[col] = ""
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
        df = df.sort_values("timestamp", kind="stable").reset_index(drop=True)
        if "event_id" not in df.columns:
            df.insert(0, "event_id", range(1, len(df) + 1))
        for col in ("pid", "ppid", "dest_port"):
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce").astype("Int64")
        # stringify everything else, NaN -> ""
        for col in df.columns:
            if col not in ("timestamp", "pid", "ppid", "dest_port", "event_id"):
                df[col] = df[col].astype("string").fillna("")
        self.df = df

    # loading
    @classmethod
    def from_file(cls, path_or_buffer, name: str | None = None) -> "TelemetryDB":
        name = (name or str(path_or_buffer)).lower()
        if name.endswith(".csv"):
            return cls(pd.read_csv(path_or_buffer))
        if hasattr(path_or_buffer, "read"):
            raw = path_or_buffer.read()
            text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
        else:
            text = open(path_or_buffer, encoding="utf-8").read()
        text = text.strip()
        if text.startswith("["):
            data = json.loads(text)
        else:  # JSON lines
            data = [json.loads(line) for line in text.splitlines() if line.strip()]
        if isinstance(data, dict):  # {"events": [...]} style
            data = next((v for v in data.values() if isinstance(v, list)), [])
        return cls(pd.json_normalize(data))

    # helpers
    def _rows(self, sub: pd.DataFrame, limit: int = MAX_ROWS) -> dict[str, Any]:
        total = len(sub)
        out = []
        for rec in sub.head(limit).to_dict(orient="records"):
            clean = {}
            for k, v in rec.items():
                if v is None or v == "" or (not isinstance(v, str) and pd.isna(v)):
                    continue
                if isinstance(v, pd.Timestamp):
                    v = v.strftime("%Y-%m-%d %H:%M:%S")
                elif hasattr(v, "item"):
                    v = v.item()
                clean[k] = v
            out.append(clean)
        res = {"count": total, "events": out}
        if total > limit:
            res["note"] = f"Showing first {limit} of {total} events. Narrow your query to see the rest."
        return res

    def _match(self, sub: pd.DataFrame, col: str, value) -> pd.DataFrame:
        if value in (None, "") or col not in sub.columns:
            return sub
        if col in ("pid", "ppid", "dest_port"):
            return sub[sub[col] == int(value)]
        return sub[sub[col].str.contains(str(value), case=False, regex=False, na=False)]

    # tools
    def get_overview(self) -> dict:
        df = self.df
        procs = df[df.event_type == "process_start"]
        parent_child = (procs.groupby(["parent_process", "process"]).size().sort_values(ascending=False).head(25)
                        .reset_index().values.tolist()) if len(procs) else []
        return {
            "total_events": len(df),
            "time_range": [str(df.timestamp.min()), str(df.timestamp.max())],
            "hosts": df.host.value_counts().to_dict(),
            "users": df.user.value_counts().to_dict() if "user" in df else {},
            "event_types": df.event_type.value_counts().to_dict(),
            "parent_child_pairs": [{"parent": p, "child": c, "count": int(n)} for p, c, n in parent_child],
            "external_ips": sorted({ip for ip in df.get("dest_ip", pd.Series(dtype=str)) if ip and not _is_private(ip)}),
            "domains": sorted({d for d in df.get("domain", pd.Series(dtype=str)) if d}),
            "hint": "Look for unusual parent->child pairs (e.g. Office apps spawning shells), "
                    "unknown external IPs, and persistence event types.",
        }

    def search_events(self, query: str, event_type: str = "", host: str = "", limit: int = MAX_ROWS) -> dict:
        sub = self._match(self.df, "event_type", event_type)
        sub = self._match(sub, "host", host)
        if query:
            cols = [c for c in STRING_COLS if c in sub.columns]
            mask = pd.Series(False, index=sub.index)
            for c in cols:
                mask |= sub[c].str.contains(query, case=False, regex=False, na=False)
            sub = sub[mask]
        return self._rows(sub, min(int(limit or MAX_ROWS), 100))

    def get_process_tree(self, process_name: str = "", pid: int | None = None, host: str = "") -> dict:
        procs = self.df[self.df.event_type == "process_start"]
        procs = self._match(procs, "host", host)
        seeds = procs
        if pid is not None and pid != "":
            seeds = procs[procs.pid == int(pid)]
        elif process_name:
            seeds = self._match(procs, "process", process_name)
        if seeds.empty:
            return {"error": f"No process_start events for {process_name or pid}. Try search_events."}
        by_pid = {int(r.pid): r for r in procs.itertuples() if pd.notna(r.pid)}
        children: dict[int, list] = {}
        for r in procs.itertuples():
            if pd.notna(r.ppid):
                children.setdefault(int(r.ppid), []).append(r)

        def node(r):
            return {"time": r.timestamp.strftime("%H:%M:%S") if pd.notna(r.timestamp) else "", "pid": int(r.pid),
                    "ppid": int(r.ppid) if pd.notna(r.ppid) else None, "process": r.process,
                    "command_line": getattr(r, "command_line", "")}

        trees = []
        for seed in seeds.head(5).itertuples():
            ancestors = []
            cur = seed
            seen = set()
            while pd.notna(cur.ppid) and int(cur.ppid) in by_pid and int(cur.ppid) not in seen:
                seen.add(int(cur.ppid))
                cur = by_pid[int(cur.ppid)]
                ancestors.insert(0, node(cur))
            if not ancestors and pd.notna(seed.ppid):
                ancestors.append({"pid": int(seed.ppid), "process": getattr(seed, "parent_process", "?"),
                                  "note": "parent start event not in dataset"})

            def descend(r, depth):
                out = []
                for ch in children.get(int(r.pid), []):
                    if depth > 6:
                        break
                    n = node(ch)
                    n["depth"] = depth
                    out.append(n)
                    out.extend(descend(ch, depth + 1))
                return out

            trees.append({"host": seed.host, "ancestors": ancestors, "process": node(seed),
                          "descendants": descend(seed, 1)})
        return {"trees": trees}

    def get_process_events(self, process_name: str = "", pid: int | None = None, host: str = "") -> dict:
        sub = self._match(self.df, "host", host)
        if pid not in (None, ""):
            sub = sub[(sub.pid == int(pid)) | (sub.ppid == int(pid))]
        elif process_name:
            sub = sub[sub.process.str.contains(process_name, case=False, regex=False, na=False)
                      | sub.parent_process.str.contains(process_name, case=False, regex=False, na=False)]
        return self._rows(sub)

    def get_network_connections(self, process_name: str = "", dest_ip: str = "", host: str = "",
                                external_only: bool = False) -> dict:
        sub = self.df[self.df.event_type.isin(["network_connect", "dns_query"])]
        sub = self._match(sub, "process", process_name)
        sub = self._match(sub, "dest_ip", dest_ip)
        sub = self._match(sub, "host", host)
        if external_only and "dest_ip" in sub.columns:
            sub = sub[~sub.dest_ip.map(_is_private)]
        res = self._rows(sub)
        if "dest_ip" in sub.columns:
            res["unique_destinations"] = (sub[sub.dest_ip != ""].groupby(["dest_ip", "process"]).size()
                                          .reset_index(name="connections").to_dict(orient="records"))
        return res

    def get_file_events(self, process_name: str = "", path_contains: str = "", host: str = "") -> dict:
        sub = self.df[self.df.event_type.str.startswith("file_")]
        sub = self._match(sub, "process", process_name)
        sub = self._match(sub, "file_path", path_contains)
        sub = self._match(sub, "host", host)
        return self._rows(sub)

    def get_persistence_events(self, host: str = "") -> dict:
        df = self._match(self.df, "host", host)
        mask = df.event_type.isin(PERSISTENCE_TYPES)
        for col in ("command_line", "registry_key", "task_action"):
            if col in df.columns:
                low = df[col].str.lower()
                mask |= low.map(lambda s: any(k in s for k in PERSISTENCE_KEYWORDS))
        return self._rows(df[mask])

    def get_events_in_window(self, start: str, end: str, host: str = "") -> dict:
        s, e = pd.to_datetime(start, utc=True), pd.to_datetime(end, utc=True)
        sub = self.df[(self.df.timestamp >= s) & (self.df.timestamp <= e)]
        return self._rows(self._match(sub, "host", host), 60)

    def lookup_ip(self, ip: str) -> dict:
        ip = ip.strip()
        if _is_private(ip):
            return {"ip": ip, "verdict": "internal", "note": "Private / RFC1918 address - internal network."}
        intel = THREAT_INTEL_IPS.get(ip)
        if intel:
            return {"ip": ip, **intel, "source": "Demo Threat Intelligence (simulated for demo)"}
        return {"ip": ip, "verdict": "unknown", "confidence": 0, "reports": 0,
                "note": "No threat intel hits. Likely benign SaaS/CDN if paired with a known-good domain."}

    def lookup_domain(self, domain: str) -> dict:
        d = domain.strip().lower()
        if d in THREAT_INTEL_DOMAINS:
            return {"domain": d, **THREAT_INTEL_DOMAINS[d], "source": "Demo Threat Intelligence (simulated for demo)"}
        if any(d.endswith(g) for g in KNOWN_GOOD_DOMAINS):
            return {"domain": d, "verdict": "benign", "note": "Well-known vendor domain."}
        return {"domain": d, "verdict": "unknown"}

    def lookup_hash(self, file_hash: str) -> dict:
        h = file_hash.strip().lower()
        intel = THREAT_INTEL_HASHES.get(h)
        if intel:
            return {"hash": h, **intel, "source": "Demo Threat Intelligence (simulated for demo)"}
        return {"hash": h, "verdict": "unknown", "detections": "0/72"}

    # dispatch
    def call(self, name: str, args: dict) -> Any:
        fn = getattr(self, name, None)
        if fn is None or name.startswith("_") or name not in TOOL_NAMES:
            return {"error": f"Unknown tool '{name}'. Available: {sorted(TOOL_NAMES)}"}
        try:
            return fn(**{k: v for k, v in (args or {}).items() if v is not None})
        except TypeError as e:
            return {"error": f"Bad arguments for {name}: {e}"}
        except Exception as e:  # keep the agent loop alive
            return {"error": f"{type(e).__name__}: {e}"}


def _is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Agent investigation tools
# Schemas use NVIDIA NIM's OpenAI-compatible function-calling format.
# ---------------------------------------------------------------------------
def _tool(name, desc, props=None, required=()):
    return {"type": "function", "function": {"name": name, "description": desc,
            "parameters": {"type": "object", "properties": props or {}, "required": list(required)}}}


HOST = {"type": "string", "description": "Optional hostname filter"}
PROC = {"type": "string", "description": "Process name substring, e.g. 'powershell'"}

TOOL_SCHEMAS = [
    _tool("get_overview", "Dataset summary: hosts, users, event type counts, parent->child process pairs, "
          "external IPs and domains. ALWAYS call this first to orient yourself."),
    _tool("search_events", "Full-text search across all fields (process names, command lines, paths, IPs, "
          "registry keys...). Optionally filter by event_type and host.",
          {"query": {"type": "string", "description": "Substring to search for (case-insensitive)"},
           "event_type": {"type": "string", "description": "Optional: process_start, network_connect, dns_query, "
                          "file_create, file_modify, scheduled_task, registry_set, ..."},
           "host": HOST, "limit": {"type": "integer", "description": "Max rows (default 40)"}}, ["query"]),
    _tool("get_process_tree", "Ancestors and descendants of a process (by name or PID) from process_start events. "
          "Use to see what spawned a process and what it spawned.",
          {"process_name": PROC, "pid": {"type": "integer", "description": "Exact PID"}, "host": HOST}),
    _tool("get_process_events", "Every event generated by a process (by name or PID) or its direct children: "
          "network, files, registry, tasks.",
          {"process_name": PROC, "pid": {"type": "integer"}, "host": HOST}),
    _tool("get_network_connections", "network_connect and dns_query events, optionally filtered by process, "
          "destination IP or host. Includes per-destination connection counts.",
          {"process_name": PROC, "dest_ip": {"type": "string"}, "host": HOST,
           "external_only": {"type": "boolean", "description": "Only non-private destinations"}}),
    _tool("get_file_events", "file_create / file_modify / file_delete events filtered by process and/or path substring.",
          {"process_name": PROC, "path_contains": {"type": "string", "description": "Path substring, e.g. '.ps1' or 'AppData'"},
           "host": HOST}),
    _tool("get_persistence_events", "Scheduled tasks, Run-key registry writes, service installs, WMI subscriptions "
          "and commands that look like persistence.", {"host": HOST}),
    _tool("get_events_in_window", "All events between two timestamps (ISO format) - useful to see everything that "
          "happened around a suspicious event.",
          {"start": {"type": "string", "description": "e.g. 2026-09-18 10:31:00"},
           "end": {"type": "string", "description": "e.g. 2026-09-18 10:35:00"}, "host": HOST}, ["start", "end"]),
    _tool("lookup_ip", "Demo threat-intel (simulated) reputation for an IP address.", {"ip": {"type": "string"}}, ["ip"]),
    _tool("lookup_domain", "Demo threat-intel (simulated) registration / reputation info for a domain.",
          {"domain": {"type": "string"}}, ["domain"]),
    _tool("lookup_hash", "Demo threat-intel (simulated) reputation for a file hash (SHA256/MD5).",
          {"file_hash": {"type": "string"}}, ["file_hash"]),
]
TOOL_NAMES = {t["function"]["name"] for t in TOOL_SCHEMAS}


if __name__ == "__main__":  # quick test
    db = TelemetryDB.from_file("data/sample_telemetry.json")
    print(json.dumps(db.get_overview(), indent=1, default=str)[:1500])
    print(json.dumps(db.get_process_tree(process_name="WINWORD"), indent=1, default=str)[:1500])
