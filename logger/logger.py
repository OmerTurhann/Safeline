#!/usr/bin/env python3

import sys
import json
import time
import requests
from datetime import date
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

if len(sys.argv) != 3:
    print("Usage: ./logger.py <zincsearch_url> <log_dir>")
    sys.exit(1)

server, log_dir = sys.argv[1:]
zinc_url = f"{server}/api/_bulkv2"
zinc_auth = ("admin", "admin")
headers = {"Content-Type": "application/x-ndjson"}

print(f"[📡] ZincSearch URL: {zinc_url} - Watching dir: {log_dir}")

def parse_file(file_path):
    try:
        with open(file_path, "r") as f:
            data = json.load(f)

        if "transaction" not in data:
            print(f"[!] No transaction in {file_path}")
            return

        tx = data["transaction"]
        log_entry = {
            "id": tx.get("id"),
            "timestamp": tx.get("timestamp"),
            "unix_timestamp": tx.get("unix_timestamp"),
            "client_ip": tx.get("client_ip"),
            "client_port": tx.get("client_port"),
            "host_ip": tx.get("host_ip"),
            "host_port": tx.get("host_port"),
            "server_id": tx.get("server_id"),
            "request_method": tx["request"].get("method"),
            "request_uri": tx["request"].get("uri"),
            "request_protocol": tx["request"].get("protocol"),
            "request_http_version": tx["request"].get("http_version"),
            "request_headers": dict([k.lower(), ", ".join(vs)] for k, vs in tx["request"]["headers"].items()),
            "request_body": tx["request"].get("body"),
            "response_http_version": tx["response"].get("protocol"),
            "response_status": tx["response"].get("status"),
            "response_headers": dict([k.lower(), ", ".join(vs)] for k, vs in tx["response"]["headers"].items()),
            "response_body": tx["response"].get("body"),
            "producer": tx.get("producer", {}),
            "rulesets": ", ".join(tx.get("producer", {}).get("rulesets", [])),
            "messages": [m.get("message") for m in tx.get("messages", []) if m.get("message")]
        }

        index_name = "coraza_" + str(date.today()).replace("-", "")
        messages = " ".join(log_entry.get("messages", [])).lower()
        if "sql" in messages or "injection" in messages:
            index_name = "coraza_sql_injection"

        ndjson = f'{{"index":{{"_index":"{index_name}"}}}}\n{json.dumps(log_entry)}\n'
        res = requests.post(zinc_url, auth=zinc_auth, data=ndjson, headers=headers)

        if res.status_code == 200:
            print(f"[✅] {index_name} → ZincSearch")
        else:
            print(f"[❌] ZincSearch error [{res.status_code}]: {res.text}")
    except Exception as e:
        print(f"[!] Error parsing file {file_path}: {e}")

class LogHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        if event.src_path.endswith(".json"):
            time.sleep(0.1)
            parse_file(event.src_path)

if __name__ == "__main__":
    path = Path(log_dir)
    if not path.exists() or not path.is_dir():
        print(f"[🛑] Directory {log_dir} not found!")
        sys.exit(1)

    observer = Observer()
    observer.schedule(LogHandler(), log_dir, recursive=False)
    observer.start()
    print("[🚀] Logger started.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
