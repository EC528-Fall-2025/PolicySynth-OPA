import base64, json, os, time
from typing import Any, Dict

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def now_ts() -> int:
    return int(time.time())

def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)

def ok(body: Dict[str, Any]): return {"statusCode": 200, "body": json.dumps(body)}
def err(msg: str, code: int = 500): return {"statusCode": code, "body": json.dumps({"error": msg})}
