"""
Offline smoke test - no API key needed.
  python smoke_test.py
Checks every tool on JSON + CSV input, then drives agent.run_investigation with a fake
LLM client that uses structured tool_calls, the <TOOLCALL> text fallback, and a final report.
"""
import json
from types import SimpleNamespace

from agent import run_investigation
from tools import TOOL_NAMES, TelemetryDB

# tools
calls = [
    ("get_overview", {}),
    ("search_events", {"query": "powershell"}),
    ("search_events", {"query": "update.ps1", "event_type": "file_create", "host": "WS-042"}),
    ("get_process_tree", {"process_name": "WINWORD"}),
    ("get_process_tree", {"pid": 4488}),
    ("get_process_tree", {"process_name": "nonexistent.exe"}),
    ("get_process_events", {"process_name": "powershell", "host": "WS-042"}),
    ("get_process_events", {"pid": 4488}),
    ("get_network_connections", {"process_name": "powershell"}),
    ("get_network_connections", {"external_only": True, "dest_ip": "185.220"}),
    ("get_file_events", {"path_contains": "AppData"}),
    ("get_persistence_events", {}),
    ("get_persistence_events", {"host": "WS-042"}),
    ("get_events_in_window", {"start": "2026-09-18 10:31:00", "end": "2026-09-18 10:32:00", "host": "WS-042"}),
    ("lookup_ip", {"ip": "185.220.101.47"}),
    ("lookup_ip", {"ip": "10.0.0.5"}),
    ("lookup_domain", {"domain": "cdn-update-status.com"}),
    ("lookup_hash", {"file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}),
    ("bogus_tool", {}),
    ("search_events", {"query": "x", "bad_arg": 1}),
]
for path in ("data/sample_telemetry.json", "data/sample_telemetry.csv"):
    db = TelemetryDB.from_file(path)
    assert len(db.df) == 148, len(db.df)
    for name, args in calls:
        res = db.call(name, args)
        json.dumps(res, default=str)  # must be serializable
        expect_err = name == "bogus_tool" or "bad_arg" in args or args.get("process_name") == "nonexistent.exe"
        assert ("error" in res) == expect_err, (path, name, args, res)
    assert db.call("get_persistence_events", {})["count"] >= 3
    assert db.call("get_process_tree", {"process_name": "WINWORD"})["trees"][0]["descendants"][0]["process"] == "powershell.exe"
    print(f"[ok] {len(calls)} tool calls on {path}")

# agent loop with fake client
class FakeToolCall:
    def __init__(self, i, name, args):
        self.id, self.type = f"call_{i}", "function"
        self.function = SimpleNamespace(name=name, arguments=json.dumps(args))

    def model_dump(self):
        return {"id": self.id, "type": self.type,
                "function": {"name": self.function.name, "arguments": self.function.arguments}}


def fake_resp(content=None, tool_calls=None):
    msg = SimpleNamespace(content=content, tool_calls=tool_calls, reasoning_content=None)
    return SimpleNamespace(choices=[SimpleNamespace(message=msg)])


SCRIPT = [
    fake_resp("<think>Let me orient first.</think>", [FakeToolCall(1, "get_overview", {})]),
    fake_resp('WINWORD spawning PowerShell is suspicious.<TOOLCALL>[{"name":"get_process_tree",'
              '"arguments":{"process_name":"WINWORD"}},{"name":"lookup_ip","arguments":{"ip":"185.220.101.47"}}]</TOOLCALL>'),
    fake_resp("# Incident Report\n## Verdict\nINCIDENT DETECTED - Critical\n..."),
]


class FakeClient:
    def __init__(self):
        self.i = 0
        self.seen_messages = None
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self, **kw):
        self.seen_messages = kw["messages"]
        assert "tools" in kw and len(kw["tools"]) == len(TOOL_NAMES)
        r = SCRIPT[self.i]
        self.i += 1
        return r


db = TelemetryDB.from_file("data/sample_telemetry.json")
fc = FakeClient()
events = list(run_investigation(db, model="fake", client=fc))
types = [e["type"] for e in events]
assert types == ["thought", "tool_call", "tool_result", "thought", "tool_call", "tool_result",
                 "tool_call", "tool_result", "final"], types
assert events[0]["content"] == "Let me orient first."
assert events[4]["name"] == "get_process_tree" and events[6]["name"] == "lookup_ip"
assert events[7]["result"]["verdict"] == "malicious"
assert events[-1]["content"].startswith("# Incident Report")
# conversation history must be well-formed: every tool msg follows an assistant msg with matching ids
msgs = fc.seen_messages
tool_ids = {m["tool_call_id"] for m in msgs if m["role"] == "tool"}
call_ids = {tc["id"] for m in msgs if m["role"] == "assistant" for tc in (m.get("tool_calls") or [])}
assert tool_ids == call_ids and len(tool_ids) == 3, (tool_ids, call_ids)
print(f"[ok] agent loop: {len(events)} events, {len(tool_ids)} tool calls, final report produced")

# retry behaviour
import openai
import agent as agent_mod
try:
    import httpx2 as httpx  # openai>=3 ships its own httpx fork
except ImportError:
    import httpx


def http_err(status):
    req = httpx.Request("POST", "https://integrate.api.nvidia.com/v1/chat/completions")
    resp = httpx.Response(status, request=req)
    cls = {500: openai.InternalServerError, 502: openai.InternalServerError, 503: openai.InternalServerError,
           400: openai.BadRequestError, 401: openai.AuthenticationError, 404: openai.NotFoundError}[status]
    return cls(f"HTTP {status}", response=resp, body=None)


def conn_err():
    return openai.APIConnectionError(request=httpx.Request("POST", "https://integrate.api.nvidia.com/v1"))


def timeout_err():
    return openai.APITimeoutError(request=httpx.Request("POST", "https://integrate.api.nvidia.com/v1"))


class FlakyClient:
    """Raises the queued errors first, then serves SCRIPT. Records every messages list it was sent."""
    def __init__(self, errors):
        self.errors, self.i, self.calls = list(errors), 0, []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self, **kw):
        self.calls.append([dict(m) for m in kw["messages"]])
        if self.errors:
            raise self.errors.pop(0)
        r = SCRIPT[self.i]
        self.i += 1
        return r


sleeps = []
agent_mod._sleep = lambda s: sleeps.append(s)

# (a) 500, 503, connection error, timeout -> retried, investigation continues from the same history
sleeps.clear()
fc = FlakyClient([http_err(500), http_err(503), conn_err()])
events = list(run_investigation(db, model="fake", client=fc))
retries = [e for e in events if e["type"] == "retry"]
assert len(retries) == 3, retries
assert retries[0]["content"] == "[NVIDIA API] Temporary server error (500). Retrying in 1s... (1/3)", retries[0]
assert "(503)" in retries[1]["content"] and "2s" in retries[1]["content"]
assert "Connection error" in retries[2]["content"] and "4s" in retries[2]["content"]
assert sleeps == [1, 2, 4], sleeps
assert events[-1]["type"] == "final", events[-1]
# the 4 attempts of step 1 all sent the identical (system+user) history -> no restart, no duplication
assert fc.calls[0] == fc.calls[1] == fc.calls[2] == fc.calls[3] and len(fc.calls[0]) == 2
assert "nvapi" not in json.dumps(retries) and "Authorization" not in json.dumps(retries)
print("[ok] transient errors retried with 1/2/4s backoff, history preserved")

# (b) transient error mid-investigation (after tool results) resends the full tool history
sleeps.clear()
fc = FlakyClient([])
fc.errors_after_first = True
orig_create = fc.create
state = {"n": 0}

def create_mid(**kw):
    state["n"] += 1
    if state["n"] == 2:  # first request after get_overview result
        fc.calls.append([dict(m) for m in kw["messages"]])
        raise timeout_err()
    return orig_create(**kw)

fc.chat.completions.create = create_mid
events = list(run_investigation(db, model="fake", client=fc))
assert [e["type"] for e in events].count("retry") == 1
assert events[-1]["type"] == "final"
assert fc.calls[1] == fc.calls[2] and fc.calls[1][-1]["role"] == "tool"  # retried with tool result intact
assert sleeps == [1]
print("[ok] mid-investigation timeout retried with full tool history")

# (c) retries exhausted -> error event, exactly 4 attempts, no crash
sleeps.clear()
fc = FlakyClient([http_err(500)] * 4)
events = list(run_investigation(db, model="fake", client=fc))
assert [e["type"] for e in events] == ["retry", "retry", "retry", "error"], [e["type"] for e in events]
assert len(fc.calls) == 4 and sleeps == [1, 2, 4]
print("[ok] retries exhausted after 3 -> error event")

# (d) permanent client errors are NOT retried
for status in (400, 401, 404):
    sleeps.clear()
    fc = FlakyClient([http_err(status)])
    events = list(run_investigation(db, model="fake", client=fc))
    assert [e["type"] for e in events] == ["error"] and len(fc.calls) == 1 and sleeps == [], (status, events)
    assert str(status) in events[0]["content"]
print("[ok] 400/401/404 not retried")

# real openai client shape
from openai import OpenAI
c = OpenAI(api_key="test", base_url="http://localhost:1/v1")
assert callable(c.chat.completions.create)
print("[ok] openai client API surface present")
print("\nALL SMOKE TESTS PASSED")

# Test complete