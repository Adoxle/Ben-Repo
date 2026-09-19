"""
Nemotron investigation agent.

run_investigation() is a generator that yields step dicts so the CLI and the
Streamlit UI can both render the investigation live:

  {"type": "thought",     "step": n, "content": "..."}
  {"type": "tool_call",   "step": n, "name": "...", "args": {...}}
  {"type": "tool_result", "step": n, "name": "...", "result": {...}}
  {"type": "final",       "step": n, "content": "<markdown report>"}
  {"type": "retry",       "step": n, "content": "[NVIDIA API] Temporary server error (500). Retrying in 1s... (1/3)"}
  {"type": "error",       "content": "..."}
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Iterator

from dotenv import load_dotenv
from openai import APIConnectionError, APIStatusError, OpenAI

from tools import TOOL_SCHEMAS, TelemetryDB

load_dotenv()

DEFAULT_MODEL = os.getenv("NEMOTRON_MODEL", "nvidia/nemotron-3-super-120b-a12b")
BASE_URL = os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")
MAX_STEPS = int(os.getenv("MAX_STEPS", "18"))

# Retry policy for transient NVIDIA API failures
RETRYABLE_STATUS = {500, 502, 503, 504}
MAX_RETRIES = 3
RETRY_DELAYS = (1, 2, 4)  # seconds, exponential backoff
_sleep = time.sleep  # injectable for tests

SYSTEM_PROMPT = """You are an autonomous security incident investigator (a senior SOC / DFIR analyst).
A dataset of Windows endpoint telemetry has been loaded. You can NOT see it directly - you must investigate
it by calling the provided tools, examining the evidence they return, and deciding what to look at next.

Investigation method:
1. Call get_overview first to orient yourself.
2. Form hypotheses from anomalies (Office/browser apps spawning shells, encoded/obfuscated commands, LOLBins,
   unknown external IPs, newly registered domains, files dropped in AppData/Temp, scheduled tasks, Run keys,
   discovery commands like whoami/net/nltest, lsass access, large outbound transfers).
3. Pivot on every lead: process tree -> process events -> network -> files -> persistence -> threat intel.
   Follow the chain until you reach the root cause AND the last observed attacker action.
4. Rule things out too: some activity is benign (admins running PowerShell, Windows Update tasks). Say why.
5. Only state facts you have seen in tool results. Cite timestamps, PIDs, paths, IPs exactly.
6. Do not stop early. Keep calling tools until the full attack chain is evidenced. Typically 8-14 tool calls.
7. lookup_ip / lookup_domain / lookup_hash return SIMULATED demo threat intelligence. In the report refer to it
   as "demo threat intelligence" and never attribute verdicts to VirusTotal, AbuseIPDB or any live feed.

When you have enough evidence, STOP calling tools and write the final report in Markdown using EXACTLY these
sections:

# Incident Report
## Verdict
(one line: INCIDENT DETECTED / SUSPICIOUS ACTIVITY / NO MALICIOUS ACTIVITY FOUND, plus severity Critical/High/Medium/Low)
## Executive Summary
(3-5 sentences a manager can read)
## Attack Timeline
| Time | Host | Process (PID) | Event | Why it matters |
## Attack Chain Narrative
(step-by-step story: initial access -> execution -> C2 -> persistence -> discovery -> credential access -> exfil...)
## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique | Evidence |
## Indicators of Compromise
(IPs, domains, hashes, file paths, task names, registry keys - as a bulleted list)
## Affected Assets
(hosts, users, processes)
## Benign Activity Ruled Out
(ONLY activity you actually examined with tools and determined to be benign - e.g. an admin's interactive
PowerShell session, known vendor/SaaS traffic, legitimate Windows Update tasks - with the evidence and the reason.
Never list malicious or suspicious activity in this section.)
## Recommended Actions
(prioritized containment / eradication / recovery steps)
"""

TOOLCALL_RE = re.compile(r"<TOOLCALL>(.*?)</TOOLCALL>", re.S | re.I)
THINK_RE = re.compile(r"<think>(.*?)</think>", re.S | re.I)


def make_client(api_key: str | None = None, base_url: str | None = None) -> OpenAI:
    key = api_key or os.getenv("NVIDIA_API_KEY")
    if not key:
        raise RuntimeError("NVIDIA_API_KEY not set. Copy .env.example to .env and add your key from build.nvidia.com")
    # max_retries=0: we handle retries ourselves below so the trace is visible and predictable
    return OpenAI(api_key=key, base_url=base_url or BASE_URL, max_retries=0)


def _transient_reason(e: Exception) -> str | None:
    """Return a short description if the error is worth retrying, else None."""
    if isinstance(e, APIStatusError):
        return f"Temporary server error ({e.status_code})" if e.status_code in RETRYABLE_STATUS else None
    if isinstance(e, APIConnectionError):  # includes APITimeoutError
        return f"Connection error ({type(e).__name__})"
    return None


def _chat_with_retry(client: OpenAI, step: int, **kwargs) -> Iterator[dict]:
    """Generator: yields 'retry' trace events, returns the response (use via `yield from`).
    Resends the exact same request (full message/tool history) on transient failures.
    Raises the last error if the failure is permanent or retries are exhausted."""
    for attempt in range(MAX_RETRIES + 1):
        try:
            return client.chat.completions.create(**kwargs)
        except Exception as e:
            reason = _transient_reason(e)
            if reason is None or attempt == MAX_RETRIES:
                raise
            delay = RETRY_DELAYS[attempt]
            yield {"type": "retry", "step": step,
                   "content": f"[NVIDIA API] {reason}. Retrying in {delay}s... ({attempt + 1}/{MAX_RETRIES})"}
            _sleep(delay)


def _fallback_tool_calls(content: str) -> list[dict]:
    """Some Nemotron builds emit <TOOLCALL>[{"name":..., "arguments":{...}}]</TOOLCALL> as text
    instead of structured tool_calls. Parse that so the loop still works."""
    calls = []
    for m in TOOLCALL_RE.finditer(content or ""):
        try:
            data = json.loads(m.group(1))
        except json.JSONDecodeError:
            continue
        for i, c in enumerate(data if isinstance(data, list) else [data]):
            args = c.get("arguments", c.get("parameters", {}))
            calls.append({"id": f"call_fb_{len(calls)}_{i}", "type": "function",
                          "function": {"name": c.get("name", ""),
                                       "arguments": args if isinstance(args, str) else json.dumps(args)}})
    return calls


def _split_thought(content: str) -> tuple[str, str]:
    """Return (thought, visible_text) - pulls <think> blocks out of the content."""
    content = content or ""
    thoughts = " ".join(t.strip() for t in THINK_RE.findall(content))
    visible = THINK_RE.sub("", content)
    visible = TOOLCALL_RE.sub("", visible).strip()
    return thoughts, visible


def run_investigation(db: TelemetryDB, model: str = DEFAULT_MODEL, client: OpenAI | None = None,
                      max_steps: int = MAX_STEPS, user_focus: str = "") -> Iterator[dict]:
    client = client or make_client()
    task = ("Investigate the loaded telemetry dataset for signs of compromise. "
            "Use the tools to gather evidence, then produce the incident report.")
    if user_focus:
        task += f"\n\nAnalyst note / focus: {user_focus}"
    messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": task}]

    for step in range(1, max_steps + 1):
        try:
            resp = yield from _chat_with_retry(
                client, step, model=model, messages=messages, tools=TOOL_SCHEMAS, tool_choice="auto",
                temperature=0.2, top_p=0.9, max_tokens=4096,
            )
        except Exception as e:
            yield {"type": "error", "step": step, "content": f"{type(e).__name__}: {e}"}
            return

        msg = resp.choices[0].message
        content = msg.content or ""
        # Some reasoning models put thoughts in a separate field
        reasoning = getattr(msg, "reasoning_content", None) or getattr(msg, "reasoning", None) or ""
        thought, visible = _split_thought(content)
        thought = (reasoning + " " + thought).strip()

        tool_calls = [tc.model_dump() for tc in (msg.tool_calls or [])] or _fallback_tool_calls(content)

        if thought or (visible and tool_calls):
            yield {"type": "thought", "step": step, "content": (thought + "\n" + visible).strip()}

        if not tool_calls:
            if len(visible) < 200 and step < 3:
                # model answered without investigating - push it to use tools
                messages.append({"role": "assistant", "content": visible})
                messages.append({"role": "user", "content": "You must investigate using the tools before "
                                 "reporting. Start with get_overview."})
                continue
            yield {"type": "final", "step": step, "content": visible}
            return

        messages.append({"role": "assistant", "content": visible or None, "tool_calls": tool_calls})

        for tc in tool_calls:
            name = tc["function"]["name"]
            try:
                args = json.loads(tc["function"]["arguments"] or "{}")
            except json.JSONDecodeError:
                args = {}
            yield {"type": "tool_call", "step": step, "name": name, "args": args}
            result = db.call(name, args)
            yield {"type": "tool_result", "step": step, "name": name, "result": result}
            messages.append({"role": "tool", "tool_call_id": tc["id"], "name": name,
                             "content": json.dumps(result, default=str)})

    # Ran out of steps: force the report with whatever evidence we have
    messages.append({"role": "user", "content": "You have reached the tool-call budget. Using ONLY the evidence "
                     "gathered so far, write the final Incident Report now in the required format."})
    try:
        resp = yield from _chat_with_retry(client, max_steps + 1, model=model, messages=messages,
                                           temperature=0.2, max_tokens=4096)
        _, visible = _split_thought(resp.choices[0].message.content or "")
        yield {"type": "final", "step": max_steps + 1, "content": visible}
    except Exception as e:
        yield {"type": "error", "content": f"{type(e).__name__}: {e}"}
