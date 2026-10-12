from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .apply import ApplyManager, count_changes
from .audit import read_audit, write_audit
from .config import panel_settings
from .diagnostics import run_diagnostics
from .host_client import HostHelperClient
from .models import ConfigResponse, EXTERNAL_INTERFACE, HOST_HELPER_COMMAND, INTERNAL_GATEWAY, INTERNAL_INTERFACE, INTERNAL_SUBNET, PANEL_LISTEN, PROTECTED_PORTS_TEXT, PUBLIC_IP
from .nftgen import generate_nft, safety_checks
from .security import COOKIE, issue_token, require_mutation_access
from .storage import StateConflict, Storage
from .validation import RuleValidationError, validate_rule_list


BASE = Path(__file__).resolve().parent
app = FastAPI(title="PVE Port Forward Manager", version=__version__)
allowed_hosts = [host.strip() for host in os.environ.get("PVE_PORTFW_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1]").split(",") if host.strip()]
app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")
mutations = [Depends(require_mutation_access)]


@app.middleware("http")
async def security_headers(request: Request, call_next):
    size = request.headers.get("content-length")
    if size and (not size.isdigit() or int(size) > 2 * 1024 * 1024):
        return JSONResponse(status_code=413, content={"detail": "Request too large (maximum 2 MiB)"})
    # Bound streamed/chunked requests too, rather than trusting Content-Length alone.
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        chunks, total = [], 0
        async for chunk in request.stream():
            total += len(chunk)
            if total > 2 * 1024 * 1024:
                return JSONResponse(status_code=413, content={"detail": "Request too large (maximum 2 MiB)"})
            chunks.append(chunk)
        request._body = b"".join(chunks)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


def storage() -> Storage:
    return Storage()


def host_client() -> HostHelperClient:
    return HostHelperClient()


def apply_manager() -> ApplyManager:
    return ApplyManager(storage(), host_client())


@app.exception_handler(RuleValidationError)
async def validation_exception_handler(_: Request, exc: RuleValidationError):
    return JSONResponse(status_code=422, content={"detail": exc.errors})


@app.exception_handler(StateConflict)
async def conflict_exception_handler(_: Request, exc: StateConflict):
    return JSONResponse(status_code=409, content={"detail": str(exc)})


@app.exception_handler(ValueError)
async def data_exception_handler(_: Request, exc: ValueError):
    return JSONResponse(status_code=422, content={"detail": str(exc)})


@app.exception_handler(OSError)
async def storage_exception_handler(_: Request, exc: OSError):
    return JSONResponse(status_code=503, content={"detail": "Cannot access panel storage. Check its permissions, disk space and service journal."})


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/api/session")
def session(request: Request, response: Response):
    token = issue_token()
    response.set_cookie(COOKIE, token, httponly=True, samesite="strict", secure=request.url.scheme == "https")
    return {"csrfToken": token}


@app.get("/api/config")
def get_config():
    return ConfigResponse(previewMode=getattr(app.state, "preview_mode", False), publicIp=PUBLIC_IP, externalInterface=EXTERNAL_INTERFACE, internalInterface=INTERNAL_INTERFACE,
                          internalSubnet=INTERNAL_SUBNET, gateway=INTERNAL_GATEWAY,
                          protectedPorts=PROTECTED_PORTS_TEXT, webListen=PANEL_LISTEN, hostHelperCommand=HOST_HELPER_COMMAND)


@app.get("/api/rules")
def get_rules(response: Response):
    store = storage()
    with store.transaction():
        rules = store.load_rules()
        response.headers["ETag"] = f'"{store.rules_revision()}"'
        return [rule.model_dump() for rule in rules]


@app.put("/api/rules", dependencies=mutations)
def put_rules(rules: list[dict], response: Response, if_match: str | None = Header(default=None)):
    store = storage()
    with store.transaction():
        store.check_revision(if_match)
        saved = store.save_rules(rules)
        store.write_generated_nft(generate_nft(saved))
        write_audit("save-rules", {"count": len(saved), "applied": False}, store)
        response.headers["ETag"] = f'"{store.rules_revision()}"'
        return [rule.model_dump() for rule in saved]


@app.post("/api/rules/import", dependencies=mutations)
def import_rules(response: Response, payload: Any = Body(...), if_match: str | None = Header(default=None)):
    store = storage()
    with store.transaction():
        store.check_revision(if_match)
        # Validation completes before any existing file is changed.
        raw = payload.get("rules") if isinstance(payload, dict) else payload
        saved = validate_rule_list(raw)
        store.backup_current_files("pre-import")
        saved = store.save_rules(saved)
        store.write_generated_nft(generate_nft(saved))
        write_audit("import-rules", {"count": len(saved), "applied": False}, store)
        response.headers["ETag"] = f'"{store.rules_revision()}"'
        return [rule.model_dump() for rule in saved]


@app.get("/api/rules/export")
def export_rules():
    return [rule.model_dump() for rule in storage().load_rules()]


@app.get("/api/nft-preview", response_class=PlainTextResponse)
def nft_preview():
    return generate_nft(storage().load_rules())


@app.get("/api/nft-safety-checks")
def nft_safety_checks():
    return [check.model_dump() for check in safety_checks(generate_nft(storage().load_rules()))]


@app.post("/api/preview", dependencies=mutations)
def draft_preview(rules: list[dict]):
    validated = validate_rule_list(rules)
    store = storage()
    baseline = []
    if store.paths.last_confirmed_rules_json.exists():
        baseline = json.loads(store.paths.last_confirmed_rules_json.read_text(encoding="utf-8"))
    nft = generate_nft(validated)
    return {"nft": nft, "safetyChecks": [check.model_dump() for check in safety_checks(nft)],
            "changedRules": count_changes([rule.model_dump() for rule in validated], baseline),
            "baseline": "last confirmed snapshot" if store.paths.last_confirmed_rules_json.exists() else "empty draft baseline"}


@app.post("/api/dry-run", dependencies=mutations)
def dry_run(payload: dict = Body(default={})):
    result = apply_manager().dry_run(payload.get("revision"))
    return JSONResponse(status_code=200 if result.ok else 503, content=result.model_dump())


@app.post("/api/apply", dependencies=mutations)
def apply_rules(payload: dict = Body(default={})):
    result = apply_manager().apply(payload.get("revision"))
    return JSONResponse(status_code=200 if result.ok else 503, content=result.model_dump())


@app.post("/api/confirm", dependencies=mutations)
def confirm():
    return apply_manager().confirm().model_dump(mode="json")


@app.post("/api/rollback", dependencies=mutations)
def rollback():
    result = apply_manager().rollback()
    return JSONResponse(status_code=200 if result.ok else 503, content=result.model_dump())


@app.get("/api/apply-status")
def apply_status():
    return apply_manager().status()


@app.get("/api/preflight")
def preflight():
    checks = []
    try:
        settings = panel_settings()
        checks.append({"label": "Panel network configuration", "status": "ok", "detail": f"{settings.externalInterface} → {settings.internalInterface} / {settings.internalSubnet}", "scope": "panel"})
    except ValueError as exc:
        checks.append({"label": "Panel network configuration", "status": "error", "detail": str(exc), "suggestion": "Correct the panel systemd environment settings.", "scope": "panel"})
        settings = None
    client = host_client()
    result = client.run("status", timeout=15)
    try:
        host = ApplyManager.parse_host(result)
        checks.append({"label": "Restricted SSH helper", "status": "ok", "detail": "Protocol v2 host helper responded.", "scope": "host"})
        match = settings is not None and host.get("settings") == settings.to_dict()
        checks.append({"label": "Panel / Host configuration", "status": "ok" if match else "error", "detail": "Network settings match." if match else "Panel and host helper settings differ.", "suggestion": "Update the CT environment and /etc/pve-portfw-host-helper/config manually to the same values.", "scope": "host"})
        diag = client.run("diagnostics", timeout=30)
        if diag.returncode:
            raise ValueError(diag.stderr or "Host preflight failed")
        details = json.loads(diag.stdout)
        if not isinstance(details, list):
            raise ValueError("Host diagnostics did not return a checks array")
        checks += details
    except ValueError as exc:
        checks.append({"label": "Restricted SSH helper", "status": "error", "detail": str(exc), "cause": "The key, host address, forced command, sudo policy or helper version may be incorrect.", "suggestion": "Follow the SSH troubleshooting steps and check the host key fingerprint before trusting a new key.", "scope": "host"})
    return {"ready": all(item["status"] != "error" for item in checks), "checks": checks}


@app.get("/api/diagnostics")
def diagnostics():
    results = run_diagnostics(storage().load_rules(), host_client())
    return [result.model_dump() for result in results]


@app.get("/api/backups")
def backups():
    return [backup.model_dump() for backup in storage().list_backups()]


@app.post("/api/backups/{backup_id}/restore", dependencies=mutations)
def restore_backup(backup_id: str):
    try:
        rules = apply_manager().restore_backup(backup_id)
    except StateConflict:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return [rule.model_dump() for rule in rules]


@app.get("/api/audit-log")
def audit_log():
    return read_audit(storage=storage())
