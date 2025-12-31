from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import pathlib
import shutil
import subprocess
import time
from collections import deque
from typing import Any, Deque, Dict, Tuple

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# Все переменные можно также задать в вашем окружении.
#
# ДЕФОЛТЫ:
#   ANYGRAM_API_KEY = "changethis123"    # ВАШ АПИ КЛЮЧ СОФТА (ИСПОЛЬЗУЕТСЯ ДЛЯ ПОДПИСИ ВЕБХУКОВ)
#   DEFAULT_PORT = 4545                  # ПОРТ НА КОТОРОМ ПОДНЯТЬ ВЕБХУК-СЕРВЕР
#   DEFAULT_BIND_ALL = False             # Если False -> 127.0.0.1, если True -> 0.0.0.0
#   DEFAULT_SSL_SELF_SIGNED = True       # ВКЛЮЧИТЬ HTTPS НА САМОПОДПИСНОМ СЕРТИФИКАТЕ (ГЕНЕРИРУЕТСЯ АВТОМАТИЧЕСКИ)
#   DEFAULT_SSL_DIR = "data/webhook_ssl" # КУДА СОХРАНЯТЬ СГЕНЕРИРОВАННЫЕ СЕРТИФИКАТЫ
#   DEFAULT_WINDOW_SEC = 200             # ОКНО ВАЛИДНОСТИ ПОДПИСИ (СЕК)
#
# ПЕРЕМЕННЫЕ ОКРУЖЕНИЯ (НЕОБЯЗАТЕЛЬНО):
#   ANYGRAM_WEBHOOK_PORT, ANYGRAM_WEBHOOK_HOST, ANYGRAM_WEBHOOK_BIND_ALL
#   ANYGRAM_WEBHOOK_SSL_SELF_SIGNED, ANYGRAM_WEBHOOK_SSL_CERT, ANYGRAM_WEBHOOK_SSL_KEY, ANYGRAM_WEBHOOK_SSL_DIR
#   ANYGRAM_WEBHOOK_SECRET, ANYGRAM_WEBHOOK_WINDOW_SEC

DEFAULT_WINDOW_SEC = 200
DEFAULT_PORT = 4545
ANYGRAM_API_KEY = "changethis123"
DEFAULT_SSL_DIR = "data/webhook_ssl"
DEFAULT_SSL_SELF_SIGNED = False
DEFAULT_BIND_ALL = False


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name, "")
    if not raw:
        return default
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except Exception:
        value = default
    if value < minimum:
        return default
    return value


def _env_str(name: str, default: str = "") -> str:
    return str(os.getenv(name, default) or "").strip()


WEBHOOK_WINDOW_SEC = _env_int("ANYGRAM_WEBHOOK_WINDOW_SEC", DEFAULT_WINDOW_SEC)
WEBHOOK_SECRET = _env_str("ANYGRAM_WEBHOOK_SECRET", ANYGRAM_API_KEY)
WEBHOOK_PORT = _env_int("ANYGRAM_WEBHOOK_PORT", DEFAULT_PORT)
WEBHOOK_BIND_ALL = _env_bool("ANYGRAM_WEBHOOK_BIND_ALL", DEFAULT_BIND_ALL)
WEBHOOK_HOST = _env_str("ANYGRAM_WEBHOOK_HOST", "") or ("0.0.0.0" if WEBHOOK_BIND_ALL else "127.0.0.1")
WEBHOOK_SSL_SELF_SIGNED = _env_bool("ANYGRAM_WEBHOOK_SSL_SELF_SIGNED", DEFAULT_SSL_SELF_SIGNED)
WEBHOOK_SSL_CERT = _env_str("ANYGRAM_WEBHOOK_SSL_CERT", "")
WEBHOOK_SSL_KEY = _env_str("ANYGRAM_WEBHOOK_SSL_KEY", "")
WEBHOOK_SSL_DIR = pathlib.Path(_env_str("ANYGRAM_WEBHOOK_SSL_DIR", DEFAULT_SSL_DIR)).resolve()

app = FastAPI()

_recent_ids: Dict[str, int] = {}
_recent_queue: Deque[Tuple[int, str]] = deque()
_recent_lock = asyncio.Lock()


def _get_window_sec() -> int:
    return WEBHOOK_WINDOW_SEC


def _get_secret() -> str:
    return WEBHOOK_SECRET


def _get_port() -> int:
    return WEBHOOK_PORT


def _ssl_paths() -> tuple[str | None, str | None]:
    if WEBHOOK_SSL_CERT and WEBHOOK_SSL_KEY:
        cert = pathlib.Path(WEBHOOK_SSL_CERT).expanduser()
        key = pathlib.Path(WEBHOOK_SSL_KEY).expanduser()
        if cert.exists() and key.exists():
            return str(cert), str(key)
        if not WEBHOOK_SSL_SELF_SIGNED:
            return None, None
    if not WEBHOOK_SSL_SELF_SIGNED:
        return None, None

    try:
        WEBHOOK_SSL_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        return None, None

    cert_path = WEBHOOK_SSL_DIR / "cert.pem"
    key_path = WEBHOOK_SSL_DIR / "key.pem"
    if cert_path.exists() and key_path.exists():
        return str(cert_path), str(key_path)
    if _generate_self_signed(cert_path, key_path):
        return str(cert_path), str(key_path)
    return None, None


def _generate_self_signed(cert_path: pathlib.Path, key_path: pathlib.Path) -> bool:
    try:
        from datetime import datetime, timedelta
        import ipaddress
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Anygram Webhooks"),
        ])
        san = x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=3650))
            .add_extension(san, critical=False)
            .sign(key, hashes.SHA256())
        )
        key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        cert_path.write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )
        return True
    except Exception:
        pass

    openssl = shutil.which("openssl")
    if not openssl:
        return False
    try:
        cmd = [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            "3650",
            "-subj",
            "/CN=Anygram Webhooks",
        ]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return cert_path.exists() and key_path.exists()
    except Exception:
        return False


def _expected_signature(secret: str, ts: int, req_id: str) -> str:
    msg = f"{ts}:{req_id}"
    return hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()


def _purge_old(now: int, window_sec: int) -> None:
    while _recent_queue and now - _recent_queue[0][0] > window_sec:
        old_ts, old_id = _recent_queue.popleft()
        if _recent_ids.get(old_id) == old_ts:
            del _recent_ids[old_id]


def _count_items(value: Any) -> int:
    try:
        return len(value) if value is not None else 0
    except Exception:
        return -1


def _print_payload(payload: Dict[str, Any]) -> None:
    event = payload.get("event")
    task = payload.get("task") or {}
    task_id = task.get("id")
    status = task.get("status")
    module_id = task.get("module_id")
    print(f"[anygram_hooks] event={event} task_id={task_id} status={status} module_id={module_id}")

    task_results = task.get("results") if isinstance(task, dict) and "results" in task else payload.get("results")
    if task_results is not None:
        print(f"[anygram_hooks] results_count={_count_items(task_results)}")

    task_logs = task.get("logs") if isinstance(task, dict) and "logs" in task else payload.get("logs")
    if task_logs is not None:
        print(f"[anygram_hooks] logs_count={_count_items(task_logs)}")

    task_chunks = task.get("chunks") if isinstance(task, dict) and "chunks" in task else payload.get("chunks")
    if task_chunks is not None:
        print(f"[anygram_hooks] chunks_count={_count_items(task_chunks)}")
    if isinstance(task, dict):
        if "completed_chunks" in task:
            print(f"[anygram_hooks] completed_chunks={_count_items(task.get('completed_chunks'))}")
        if "error_chunks" in task:
            print(f"[anygram_hooks] error_chunks={_count_items(task.get('error_chunks'))}")
        if "in_progress_chunks" in task:
            print(f"[anygram_hooks] in_progress_chunks={_count_items(task.get('in_progress_chunks'))}")

    if isinstance(task, dict) and ("used_account_paths" in task or "not_used_account_paths" in task):
        used = _count_items(task.get("used_account_paths"))
        not_used = _count_items(task.get("not_used_account_paths"))
        print(f"[anygram_hooks] paths_used={used} paths_not_used={not_used}")
    elif "paths" in payload:
        paths = payload.get("paths") or {}
        used = _count_items(paths.get("used"))
        not_used = _count_items(paths.get("not_used"))
        print(f"[anygram_hooks] paths_used={used} paths_not_used={not_used}")


@app.post("/anygram_hooks")
async def anygram_hooks(request: Request) -> JSONResponse:
    headers = request.headers
    ts_raw = headers.get("x-anygram-timestamp")
    req_id = headers.get("x-anygram-request-id")
    sig = headers.get("x-anygram-signature")

    if not ts_raw or not req_id or not sig:
        return JSONResponse({"ok": False, "error": "missing_headers"}, status_code=400)

    try:
        ts = int(ts_raw)
    except Exception:
        return JSONResponse({"ok": False, "error": "bad_timestamp"}, status_code=400)

    window_sec = _get_window_sec()
    now = int(time.time())
    if abs(now - ts) > window_sec:
        return JSONResponse({"ok": False, "error": "timestamp_out_of_window"}, status_code=401)

    expected = _expected_signature(_get_secret(), ts, req_id)
    if not hmac.compare_digest(expected, sig):
        return JSONResponse({"ok": False, "error": "bad_signature"}, status_code=401)

    async with _recent_lock:
        _purge_old(now, window_sec)
        if req_id in _recent_ids:
            return JSONResponse({"ok": False, "error": "duplicate_request_id"}, status_code=409)
        _recent_ids[req_id] = ts
        _recent_queue.append((ts, req_id))

    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "bad_json"}, status_code=400)
    if isinstance(payload, dict):
        _print_payload(payload)
    else:
        print(f"[anygram_hooks] payload_type={type(payload).__name__}")

    return JSONResponse({"ok": True})


if __name__ == "__main__":
    try:
        import uvicorn
    except Exception as exc:
        print(f"[anygram_hooks] uvicorn missing: {exc}")
        raise
    certfile, keyfile = _ssl_paths()
    uvicorn.run(
        app,
        host=WEBHOOK_HOST,
        port=_get_port(),
        log_level="info",
        ssl_certfile=certfile,
        ssl_keyfile=keyfile,
    )
