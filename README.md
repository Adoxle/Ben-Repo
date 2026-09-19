# 🛡️ AI Security Log Investigator (NVIDIA Nemotron)

Hackathon prototype. Upload Windows endpoint telemetry (JSON / CSV) and **NVIDIA Nemotron
investigates it as an agent**: it decides what to look at, calls Python tools against the data,
reads the evidence, pivots, and finally writes an incident report with a timeline and MITRE ATT&CK mapping.

```
LOGS -> Nemotron -> decides what to investigate -> calls Python tools -> receives evidence
     -> calls more tools -> correlates -> INCIDENT TIMELINE + FINDINGS
```

## Quick start

```powershell
# 1. deps
python -m pip install -r requirements.txt

# 2. API key (free at https://build.nvidia.com)
copy .env.example .env      # then paste your NVIDIA_API_KEY into .env

# 3. sample data (a macro-doc -> PowerShell -> C2 -> persistence attack chain + benign noise)
python make_sample_data.py

# 4a. CLI - watch the agent think and call tools
python investigate.py data/sample_telemetry.json

# 4b. Web UI
python -m streamlit run app.py
```

## Files

| File | What it does |
|---|---|
| `tools.py` | `TelemetryDB` (pandas over the log file) + the tools Nemotron can call + their JSON schemas |
| `agent.py` | The agent loop: send tools to Nemotron, execute whatever it calls, feed results back, repeat until it writes the report |
| `investigate.py` | CLI runner, prints the live trace and saves `report.md` |
| `app.py` | Streamlit UI: upload -> live investigation trace -> rendered report |
| `make_sample_data.py` | Generates `data/sample_telemetry.{json,csv}` |

## Tools the agent has

`get_overview` · `search_events` · `get_process_tree` · `get_process_events` · `get_network_connections` ·
`get_file_events` · `get_persistence_events` · `get_events_in_window` · `lookup_ip` · `lookup_domain` · `lookup_hash`

Threat-intel lookups are **mocked** with a small local table (see the top of `tools.py`).
Swapping in VirusTotal / AbuseIPDB is a ~10 line change if you want it.

## Log format

Flat list of events (JSON array, JSON lines, or CSV). Recognised columns (all optional except `timestamp`
and `event_type`):

```
timestamp, host, user, event_type, pid, ppid, process, parent_process, command_line, image_path,
file_path, file_hash, dest_ip, dest_port, domain, task_name, task_action, registry_key, registry_value
```

`event_type` values used by the tools: `process_start`, `network_connect`, `dns_query`, `file_create`,
`file_modify`, `file_delete`, `scheduled_task`, `registry_set`, `service_install`.
Common Sysmon-style column names (`Image`, `ParentImage`, `CommandLine`, `UtcTime`, ...) are auto-mapped.

## Model

Default: `nvidia/nemotron-3-super-120b-a12b` via the NVIDIA NIM OpenAI-compatible endpoint.
Change with `NEMOTRON_MODEL` in `.env`, the `--model` flag, or the sidebar. Any Nemotron model that
supports tool calling works (e.g. `nvidia/llama-3.1-nemotron-ultra-253b-v1`). If a model emits
`<TOOLCALL>` tags as text instead of structured tool calls, the loop parses those too.

Transient API failures (HTTP 500/502/503/504, connection errors, timeouts) are retried up to 3 times
with 1s / 2s / 4s backoff, resending the same full conversation so the investigation never restarts.
Permanent errors (400/401/403/404) are not retried.


## To access it, its on http://localhost:8501/