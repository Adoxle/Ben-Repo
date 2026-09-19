"""
Streamlit UI: upload logs -> watch Nemotron investigate live -> read the incident report.

    streamlit run app.py
"""
import html
import json
import os
import re
from pathlib import Path

import streamlit as st

from agent import DEFAULT_MODEL, make_client, run_investigation
from tools import TelemetryDB

st.set_page_config(page_title="AI Security Log Investigator", page_icon="🛡️", layout="wide")

NVIDIA_GREEN = "#76B900"
st.markdown(f"""
<style>
.nv-badge {{ display:inline-block; background:{NVIDIA_GREEN}; color:#000; font-weight:700;
             padding:5px 14px; border-radius:6px; font-size:1.1rem; letter-spacing:.3px; }}
.nv-model {{ color:#9aa0a6; font-family:monospace; font-size:.85rem; margin-left:12px; }}
.trace-tool {{ color:#8b949e; font-size:.78rem; font-family:monospace; margin:-6px 0 4px 1.7rem; }}
.trace-detail {{ color:#c9d1d9; font-size:.92rem; margin:0 0 2px 1.7rem; }}
.sum-label {{ color:#8b949e; font-size:.72rem; letter-spacing:.08em; text-transform:uppercase; }}
.sum-value {{ font-size:1.45rem; font-weight:700; line-height:1.3; }}
.sum-card {{ border:1px solid #30363d; border-radius:8px; padding:10px 14px; background:rgba(255,255,255,.02); }}
</style>""", unsafe_allow_html=True)

TI_TOOLS = {"lookup_ip", "lookup_domain", "lookup_hash"}
OFFICE_APPS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "onenote.exe"}
SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
          "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}
TI_NOTE = "Threat intelligence enrichment: simulated for demo"

# sidebar
with st.sidebar:
    st.header("Settings")
    api_key = st.text_input("NVIDIA API key", value=os.getenv("NVIDIA_API_KEY", ""), type="password",
                            help="From build.nvidia.com. Or put NVIDIA_API_KEY in a .env file.")
    model = st.text_input("Nemotron model", value=DEFAULT_MODEL)
    max_steps = st.slider("Max agent steps", 6, 30, 18)
    focus = st.text_area("Analyst hint (optional)", placeholder="e.g. Focus on host WS-042", height=80)
    st.divider()
    st.markdown("**Tools available to the agent**")
    st.code("\n".join(["get_overview", "search_events", "get_process_tree", "get_process_events",
                       "get_network_connections", "get_file_events", "get_persistence_events",
                       "get_events_in_window", "lookup_ip", "lookup_domain", "lookup_hash"]), language="text")
    st.caption(f"{TI_NOTE} (lookup_ip / lookup_domain / lookup_hash use a local demo table).")

# header / branding
st.title("🛡️ AI Security Log Investigator")
st.markdown(f'<span class="nv-badge">Powered by NVIDIA Nemotron 3</span>'
            f'<span class="nv-model">{html.escape(model)}</span>', unsafe_allow_html=True)
st.caption("Nemotron acts as an autonomous DFIR agent: it decides which evidence to pull, calls Python tools "
           "against your telemetry, correlates the results and writes the incident report.")

#  data input
col_a, col_b = st.columns([3, 1])
with col_a:
    uploaded = st.file_uploader("Upload telemetry (JSON, JSONL or CSV)", type=["json", "jsonl", "csv"])
with col_b:
    st.write("")
    st.write("")
    use_sample = st.button("📂 Use sample dataset", width="stretch")

if uploaded is not None:
    st.session_state.db = TelemetryDB.from_file(uploaded, uploaded.name)
    st.session_state.source = uploaded.name
    st.session_state.pop("trace", None)
    st.session_state.pop("report", None)
elif use_sample:
    sample = Path("data/sample_telemetry.json")
    if not sample.exists():
        st.error("Sample not found. Run `python make_sample_data.py` first.")
    else:
        st.session_state.db = TelemetryDB.from_file(str(sample))
        st.session_state.source = sample.name
        st.session_state.pop("trace", None)
        st.session_state.pop("report", None)

db: TelemetryDB | None = st.session_state.get("db")
if db is None:
    st.info("Upload a log file or load the sample dataset to begin.")
    st.stop()

# dataset summary
df = db.df
span_min = int((df.timestamp.max() - df.timestamp.min()).total_seconds() // 60) if len(df) else 0
m1, m2, m3, m4 = st.columns(4)
m1.metric("Events", len(df))
m2.metric("Hosts", df.host.nunique())
m3.metric("Event Types", df.event_type.nunique())
m4.metric("Time Span", f"{span_min} min")
with st.expander(f"Preview events from `{st.session_state.source}`", expanded=False):
    st.dataframe(df.astype(str), width="stretch", height=240)

#  primary CTA
run = st.button("🔍 Investigate with Nemotron", type="primary", width="stretch", disabled=not api_key)
if not api_key:
    st.warning("Enter your NVIDIA API key in the sidebar.")


#  trace rendering
def describe_call(name: str, args: dict) -> str:
    """Short human label for a tool call - derived from the call itself, not model reasoning."""
    a = args or {}
    target = a.get("process_name") or (f"PID {a['pid']}" if a.get("pid") else "") or a.get("host") or ""
    tail = f" of {target}" if target else ""
    if name == "get_overview":
        return "Analyzing dataset overview"
    if name == "search_events":
        return f"Searching events for “{a.get('query', '')}”" + (f" ({a['event_type']})" if a.get("event_type") else "")
    if name == "get_process_tree":
        return "Reconstructing process tree" + (f" for {target}" if target else "")
    if name == "get_process_events":
        return "Examining process activity" + tail
    if name == "get_network_connections":
        return "Examining network activity" + tail
    if name == "get_file_events":
        return "Examining file activity" + (f" ({a['path_contains']})" if a.get("path_contains") else tail)
    if name == "get_persistence_events":
        return "Examining persistence mechanisms" + (f" on {a['host']}" if a.get("host") else "")
    if name == "get_events_in_window":
        return f"Reviewing events between {a.get('start', '?')} and {a.get('end', '?')}"
    if name in TI_TOOLS:
        key = a.get("ip") or a.get("domain") or (str(a.get("file_hash", ""))[:16] + "…")
        return f"Checking threat intelligence for {key}"
    return f"Running {name}"


def describe_result(name: str, res) -> list[str]:
    """Concise observable outcomes derived from structured tool results."""
    if not isinstance(res, dict):
        return ["Evidence received"]
    if "error" in res:
        return [f"No results — {str(res['error'])[:90]}"]
    if name == "get_overview":
        lines = [f"Dataset overview analyzed — {res.get('total_events')} events across {len(res.get('hosts', {}))} hosts"]
        sus = [f"{p['parent']} → {p['child']}" for p in res.get("parent_child_pairs", [])
               if str(p['parent']).lower() in OFFICE_APPS and str(p['child']).lower() in SHELLS]
        if sus:
            lines.append("Suspicious Office → shell relationship identified: " + ", ".join(sus))
        return lines
    if name in TI_TOOLS:
        key = res.get("ip") or res.get("domain") or (str(res.get("hash", ""))[:16] + "…")
        extra = res.get("family") or ", ".join(res.get("tags", [])[:3])
        return [f"Verdict: {str(res.get('verdict', 'unknown')).upper()} for {key}"
                + (f" ({extra})" if extra else "") + " · Demo Threat Intelligence"]
    if name == "get_process_tree":
        trees = res.get("trees", [])
        n = sum(len(t.get("descendants", [])) for t in trees)
        root = trees[0]["process"]["process"] if trees else "?"
        return [f"Process tree reconstructed — {root} with {n} descendant process(es)"]
    count = res.get("count")
    noun = {"search_events": "matching events", "get_process_events": "process events",
            "get_network_connections": "network events", "get_file_events": "file events",
            "get_persistence_events": "persistence events", "get_events_in_window": "events in window"}.get(name, "events")
    line = f"{count} {noun} retrieved" if count is not None else "Evidence received"
    if name == "get_network_connections" and res.get("unique_destinations"):
        line += f" · {len({d['dest_ip'] for d in res['unique_destinations']})} unique destination(s)"
    return [line]


class Trace:
    """Renders investigation events as observable actions. Never shows model chain-of-thought."""

    def __init__(self, box):
        self.box, self.cur = box, None

    def add(self, ev: dict):
        t = ev["type"]
        if t == "thought":
            return
        if t == "tool_call":
            self.cur = self.box.container()
            args = ", ".join(f"{k}={json.dumps(v)}" for k, v in ev["args"].items())
            self.cur.markdown(f"🔎 **{html.escape(describe_call(ev['name'], ev['args']))}**")
            self.cur.markdown(f'<div class="trace-tool">Tool: {html.escape(ev["name"])}({html.escape(args)})</div>',
                              unsafe_allow_html=True)
        elif t == "tool_result":
            c = self.cur or self.box.container()
            for line in describe_result(ev["name"], ev["result"]):
                c.markdown(f'<div class="trace-detail">✓ {html.escape(line)}</div>', unsafe_allow_html=True)
            with c.expander("Evidence", expanded=False):
                if ev["name"] in TI_TOOLS:
                    st.caption(TI_NOTE)
                st.json(ev["result"], expanded=1)
        elif t == "retry":
            self.box.caption(f"⚠️ {ev['content']}")
        elif t == "error":
            self.box.error(ev["content"])
        elif t == "final":
            self.box.markdown("✅ **Investigation complete**")


#  report summary
def _section(report: str, title: str) -> str:
    m = re.search(rf"^##\s*{re.escape(title)}\s*$\n(.*?)(?=^##\s|\Z)", report, re.S | re.M)
    return m.group(1).strip() if m else ""


def summarize_report(report: str, db: TelemetryDB) -> dict:
    """Compact summary from the report's fixed sections + names that exist in the dataset."""
    verdict_line = next((l.strip(" -*") for l in _section(report, "Verdict").splitlines() if l.strip()), "")
    low = verdict_line.lower()
    if "no malicious" in low:
        verdict, color = "No Incident", "#3fb950"
    elif "critical" in low:
        verdict, color = "Critical Incident", "#f85149"
    elif "high" in low:
        verdict, color = "High-Severity Incident", "#f85149"
    elif "medium" in low:
        verdict, color = "Medium-Severity Incident", "#d29922"
    elif "low" in low:
        verdict, color = "Low-Severity Activity", "#8b949e"
    elif "suspicious" in low:
        verdict, color = "Suspicious Activity", "#d29922"
    elif "incident" in low:
        verdict, color = "Incident Detected", "#f85149"
    else:
        verdict, color = (verdict_line[:40] or "See report"), "#8b949e"

    def present(names, text):
        return [n for n in names if n and re.search(rf"(?<![\w-]){re.escape(str(n))}(?![\w-])", text)]

    assets = _section(report, "Affected Assets")
    hosts = present(db.df.host.unique(), assets) or present(db.df.host.unique(), report)
    users = [u for u in db.df.user.unique() if str(u).upper() != "SYSTEM"] if "user" in db.df else []
    users = present(users, assets) or present(users, report)

    mitre = _section(report, "MITRE ATT&CK Mapping")
    techniques = set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", mitre or report))
    ioc_sec = _section(report, "Indicators of Compromise")
    iocs = [l for l in ioc_sec.splitlines() if re.match(r"^\s*(?:[-*•]|\d+[.)])\s+\S", l)]
    return {"verdict": verdict, "color": color,
            "host": ", ".join(hosts[:2]) if hosts else "—",
            "user": ", ".join(users[:2]) if users else "—",
            "techniques": str(len(techniques)) if techniques else "—",
            "iocs": str(len(iocs)) if iocs else "—"}


def render_summary(s: dict):
    cards = [("Verdict", s["verdict"], s["color"]), ("Affected Host", s["host"], None),
             ("Affected User", s["user"], None), ("ATT&CK Techniques", s["techniques"], None), ("IOCs", s["iocs"], None)]
    for col, (label, value, color) in zip(st.columns(len(cards)), cards):
        style = f' style="color:{color}"' if color else ""
        col.markdown(f'<div class="sum-card"><div class="sum-label">{html.escape(label)}</div>'
                     f'<div class="sum-value"{style}>{html.escape(str(value))}</div></div>', unsafe_allow_html=True)


# run
if run:
    st.session_state.trace = []
    st.session_state.report = None
    client = make_client(api_key)
    tool_calls = 0
    with st.status("Investigation Trace — Nemotron is investigating…", expanded=True) as status:
        tr = Trace(st.container())
        for ev in run_investigation(db, model=model, client=client, max_steps=max_steps, user_focus=focus):
            st.session_state.trace.append(ev)
            if ev["type"] == "tool_call":
                tool_calls += 1
                status.update(label=f"Investigation Trace — step {ev['step']}: {describe_call(ev['name'], ev['args'])}")
            elif ev["type"] == "final":
                st.session_state.report = ev["content"]
            tr.add(ev)
        if st.session_state.report is not None:
            status.update(label=f"Investigation Trace — complete · {tool_calls} tool calls chosen by Nemotron",
                          state="complete", expanded=True)
        else:
            status.update(label="Investigation Trace — ended without a report", state="error")
elif st.session_state.get("trace"):
    n = sum(1 for e in st.session_state.trace if e["type"] == "tool_call")
    with st.status(f"Investigation Trace — complete · {n} tool calls chosen by Nemotron",
                   state="complete", expanded=False):
        tr = Trace(st.container())
        for ev in st.session_state.trace:
            tr.add(ev)

#  results
if st.session_state.get("report"):
    st.divider()
    st.subheader("Incident Summary")
    render_summary(summarize_report(st.session_state.report, db))
    st.caption(TI_NOTE)
    st.markdown(st.session_state.report)
    st.download_button("⬇️ Download report (Markdown)", st.session_state.report,
                       file_name="incident_report.md", mime="text/markdown")
