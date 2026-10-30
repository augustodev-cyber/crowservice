import json
from pathlib import Path

def load():
    path = Path("config/settings.json")
    return json.loads(path.read_text(encoding="utf-8"))
