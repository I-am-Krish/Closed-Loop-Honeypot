import json
import os
from datetime import datetime

def log_event(session_id, event, data, log_dir="logs/sessions"):
    os.makedirs(log_dir, exist_ok=True)
    path = os.path.join(log_dir, f"{session_id}.jsonl")
    entry = {
        "time": datetime.utcnow().isoformat() + "Z",
        "event": event,
        "data": data
    }
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")
