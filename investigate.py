"""
CLI runner: watch Nemotron investigate a log file from the terminal.

    python investigate.py data/sample_telemetry.json
    python investigate.py mylogs.csv --model nvidia/llama-3.1-nemotron-ultra-253b-v1 --out report.md
"""
import argparse
import json
import sys

from agent import DEFAULT_MODEL, run_investigation
from tools import TelemetryDB


def main():
    ap = argparse.ArgumentParser(description="AI Security Log Investigator (NVIDIA Nemotron)")
    ap.add_argument("path", help="JSON / JSONL / CSV telemetry file")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--out", default="report.md", help="Where to save the markdown report")
    ap.add_argument("--focus", default="", help="Optional analyst hint, e.g. 'look at host WS-042'")
    ap.add_argument("--max-steps", type=int, default=18)
    args = ap.parse_args()

    db = TelemetryDB.from_file(args.path)
    print(f"[+] loaded {len(db.df)} events from {args.path}")
    print(f"[+] model: {args.model}\n")

    report = None
    for ev in run_investigation(db, model=args.model, max_steps=args.max_steps, user_focus=args.focus):
        t = ev["type"]
        if t == "thought":
            print(f"\n[step {ev['step']}] THINKING: {ev['content'][:600]}")
        elif t == "tool_call":
            print(f"\n[step {ev['step']}] >> {ev['name']}({json.dumps(ev['args'])})")
        elif t == "tool_result":
            preview = json.dumps(ev["result"], default=str)
            count = ev["result"].get("count") if isinstance(ev["result"], dict) else None
            print(f"   << {'count=' + str(count) + ' ' if count is not None else ''}{preview[:300]}{'...' if len(preview) > 300 else ''}")
        elif t == "final":
            report = ev["content"]
            print("\n" + "=" * 78 + "\n" + report + "\n" + "=" * 78)
        elif t == "retry":
            print(f"\n{ev['content']}")
        elif t == "error":
            print(f"\n[!] ERROR: {ev['content']}", file=sys.stderr)

    if report:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"\n[+] report saved to {args.out}")


if __name__ == "__main__":
    main()
