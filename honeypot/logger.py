import json
import os
from datetime import datetime

def log_event(session_id, event, data, log_dir="logs/sessions"):
    """
    Log events in structured JSONL format.
    Each line = one event.
    """
    os.makedirs(log_dir, exist_ok=True)
    path = os.path.join(log_dir, f"{session_id}.jsonl")

    entry = {
        "time": datetime.utcnow().isoformat() + "Z",
        "event": event,
        "data": data
    }

    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")


def log_command_event(session_id, username, hostname, cwd, command, output, log_dir="logs/sessions"):
    """
    Specialized logger for commands.
    Stores input + output + environment (user, host, cwd).
    """
    os.makedirs(log_dir, exist_ok=True)
    path = os.path.join(log_dir, f"{session_id}.jsonl")

    entry = {
        "time": datetime.utcnow().isoformat() + "Z",
        "event": "command",
        "user": username,
        "host": hostname,
        "cwd": cwd,
        "input": command,
        "output": output
    }

    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")

def log_session_summary(session_id, username, hostname, start_time, end_time, commands, log_dir="logs/sessions"):
    """
    Logs a session summary at the end of each session.
    Includes metadata for ML analysis.
    """
    os.makedirs(log_dir, exist_ok=True)
    path = os.path.join(log_dir, f"{session_id}_summary.json")

    suspicious_keywords = ["wget", "curl", "nc", "chmod", "ssh", "scp", "python", "perl"]
    suspicious_hits = [cmd for cmd in commands if any(k in cmd for k in suspicious_keywords)]

    summary = {
        "session_id": session_id,
        "user": username,
        "host": hostname,
        "start_time": start_time.isoformat() + "Z",
        "end_time": end_time.isoformat() + "Z",
        "duration_sec": (end_time - start_time).total_seconds(),
        "total_commands": len(commands),
        "suspicious_commands": suspicious_hits,
        "suspicious_count": len(suspicious_hits),
    }

    with open(path, "w") as f:
        json.dump(summary, f, indent=2)
