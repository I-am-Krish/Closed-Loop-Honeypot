import yaml
import asyncio
from server import start_server

def load_config(path="config/honeypot.yml"):
    with open(path, "r") as f:
        return yaml.safe_load(f)

if __name__ == "__main__":
    config = load_config()
    try:
        asyncio.run(start_server(config))
    except KeyboardInterrupt:
        print("\n🛑 Honeypot stopped.")