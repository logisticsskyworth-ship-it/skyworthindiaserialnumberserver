"""
Serial Number Consolidator - Server
Skyworth India Electronics - Warehouse Operations

Exposes core.py's database logic over a small HTTP API so the desktop
client app can be run by team members anywhere (not just on one shared
network drive) while all data lands in one place.

Run locally with:
    uvicorn main:app --host 0.0.0.0 --port 8000

Deploy: see README_DEPLOY.md
"""
import os
import secrets
import sqlite3
import tempfile
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse
from pydantic import BaseModel

import core

app = FastAPI(title="Serial Number Consolidator API")

# ---------------------------------------------------------------------------
# Session tokens live in memory. That's fine for this internal tool - if the
# server restarts, everyone just logs in again (a few seconds).
# ---------------------------------------------------------------------------
SESSIONS = {}  # token -> {"id":.., "username":.., "role":..}


def db_conn():
    return sqlite3.connect(core.get_db_path())


def current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not logged in.")
    token = authorization.split(" ", 1)[1]
    user = SESSIONS.get(token)
    if not user:
        raise HTTPException(status_code=401, detail="Session expired - please log in again.")
    return user


def require_admin(user):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin account required.")


@app.on_event("startup")
def startup():
    core.init_db()


# --- Auth ---

class LoginBody(BaseModel):
    username: str
    password: str


@app.post("/login")
def login(body: LoginBody):
    conn = db_conn()
    try:
        user = core.verify_user(conn, body.username, body.password)
    finally:
        conn.close()
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password.")
    token = secrets.token_hex(24)
    SESSIONS[token] = user
    return {"token": token, "id": user["id"], "username": user["username"], "role": user["role"]}


class PasswordBody(BaseModel):
    password: str


@app.post("/verify-admin-password")
def verify_admin_password(body: PasswordBody, authorization: Optional[str] = Header(None)):
    current_user(authorization)  # must be logged in
    conn = db_conn()
    try:
        ok = core.verify_any_admin_password(conn, body.password)
    finally:
        conn.close()
    return {"ok": ok}


# --- Invoices (batch details / quantity limits) ---

class InvoiceBody(BaseModel):
    invoice_number: str
    quantity: Optional[int] = None
    model: str = ""
    vehicle_number: str = ""
    customer_name: str = ""
    entry_date: str = ""
    storage_location: str = ""
    warehouse: str = ""


@app.post("/invoices")
def upsert_invoice(body: InvoiceBody, authorization: Optional[str] = Header(None)):
    current_user(authorization)
    conn = db_conn()
    try:
        core.upsert_invoice(conn, body.invoice_number, quantity=body.quantity, model=body.model,
                             vehicle_number=body.vehicle_number, customer_name=body.customer_name,
                             entry_date=body.entry_date, storage_location=body.storage_location,
                             warehouse=body.warehouse)
    finally:
        conn.close()
    return {"ok": True}


@app.get("/invoices/{invoice_number}")
def get_invoice(invoice_number: str, authorization: Optional[str] = Header(None)):
    current_user(authorization)
    conn = db_conn()
    try:
        inv = core.get_invoice(conn, invoice_number)
        used = core.count_for_invoice(conn, invoice_number)
    finally:
        conn.close()
    return {"invoice": inv, "used": used}


# --- Records (manual entry) ---

class RecordBody(BaseModel):
    serial_number: str
    model: str = ""
    invoice_number: str = ""
    vehicle_number: str = ""
    customer_name: str = ""
    entry_date: str = ""
    storage_location: str = ""
    warehouse: str = ""
    sheet_name: str = "Manual Entry"
    source: str = "manual"


@app.post("/records")
def add_record(body: RecordBody, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    conn = db_conn()
    try:
        status, info = core.add_record(
            conn, body.serial_number, model=body.model, invoice_number=body.invoice_number,
            sheet_name=body.sheet_name, source=body.source, added_by=user["username"],
            vehicle_number=body.vehicle_number, customer_name=body.customer_name,
            entry_date=body.entry_date, storage_location=body.storage_location,
            warehouse=body.warehouse,
        )
    finally:
        conn.close()
    return {"status": status, "info": info}


@app.delete("/records/{record_id}")
def delete_record(record_id: int, admin_password: Optional[str] = None,
                   authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    conn = db_conn()
    try:
        if user["role"] != "admin":
            if not admin_password or not core.verify_any_admin_password(conn, admin_password):
                raise HTTPException(status_code=403, detail="Admin authorization required.")
        core.delete_record(conn, record_id)
    finally:
        conn.close()
    return {"ok": True}


# --- Excel upload ---

@app.post("/upload-excel")
async def upload_excel(file: UploadFile = File(...), authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    contents = await file.read()
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as tmp:
            tmp.write(contents)
            tmp_path = tmp.name
        conn = db_conn()
        try:
            summary = core.import_excel_file(conn, tmp_path, source_label=file.filename,
                                               added_by=user["username"])
        finally:
            conn.close()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not process '{file.filename}': {e}")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)
    return summary


# --- Duplicates review ---

@app.get("/duplicates")
def get_duplicates(authorization: Optional[str] = Header(None)):
    current_user(authorization)
    conn = db_conn()
    try:
        rows = core.get_pending_duplicates(conn)
    finally:
        conn.close()
    return {"rows": rows}


class ResolveBody(BaseModel):
    action: str  # discard | replace | keep_both
    admin_password: Optional[str] = None


@app.post("/duplicates/{dup_id}/resolve")
def resolve_duplicate(dup_id: int, body: ResolveBody, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    conn = db_conn()
    try:
        if user["role"] != "admin":
            if not body.admin_password or not core.verify_any_admin_password(conn, body.admin_password):
                raise HTTPException(status_code=403, detail="Admin authorization required to resolve a duplicate.")
        core.resolve_duplicate(conn, dup_id, body.action)
    finally:
        conn.close()
    return {"ok": True}


# --- Search / stats / export ---

@app.get("/search")
def search_master(q: str = "", date_from: str = "", date_to: str = "",
                   authorization: Optional[str] = Header(None)):
    current_user(authorization)
    conn = db_conn()
    try:
        rows = core.search_master(conn, query=q, date_from=date_from, date_to=date_to)
    finally:
        conn.close()
    return {"rows": rows}


@app.get("/stats")
def stats(authorization: Optional[str] = Header(None)):
    current_user(authorization)
    conn = db_conn()
    try:
        active = core.count_active(conn)
        pending = core.count_pending_duplicates(conn)
    finally:
        conn.close()
    return {"active": active, "pending": pending}


@app.get("/export")
def export(q: str = "", date_from: str = "", date_to: str = "",
           authorization: Optional[str] = Header(None)):
    current_user(authorization)
    conn = db_conn()
    tmp_path = None
    try:
        tmp_path = os.path.join(tempfile.gettempdir(), f"export_{secrets.token_hex(8)}.xlsx")
        core.export_master(conn, tmp_path, query=q, date_from=date_from, date_to=date_to)
    finally:
        conn.close()
    filename = f"Serial_Numbers_Export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    return FileResponse(tmp_path, filename=filename,
                         media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


# --- Admin: users ---

@app.get("/users")
def list_users(authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    require_admin(user)
    conn = db_conn()
    try:
        rows = core.list_users(conn)
    finally:
        conn.close()
    return {"rows": rows}


class CreateUserBody(BaseModel):
    username: str
    password: str
    role: str = "user"


@app.post("/users")
def create_user(body: CreateUserBody, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    require_admin(user)
    conn = db_conn()
    try:
        try:
            core.create_user(conn, body.username, body.password, role=body.role)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    finally:
        conn.close()
    return {"ok": True}


class ResetPasswordBody(BaseModel):
    new_password: str


@app.post("/users/{username}/reset-password")
def reset_password(username: str, body: ResetPasswordBody, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    require_admin(user)
    conn = db_conn()
    try:
        core.reset_password(conn, username, body.new_password)
    finally:
        conn.close()
    return {"ok": True}


class ActiveBody(BaseModel):
    active: bool


@app.post("/users/{username}/active")
def set_user_active(username: str, body: ActiveBody, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    require_admin(user)
    conn = db_conn()
    try:
        core.set_user_active(conn, username, body.active)
    finally:
        conn.close()
    return {"ok": True}


@app.get("/")
def health():
    return {"status": "ok", "app": "Serial Number Consolidator API"}


# --- Model / Warehouse lookup lists ---

@app.get("/models")
def get_models(authorization: Optional[str] = Header(None)):
    current_user(authorization)
    conn = db_conn()
    try:
        rows = core.list_models(conn)
    finally:
        conn.close()
    return {"rows": rows}


class NameBody(BaseModel):
    name: str


@app.post("/models")
def post_model(body: NameBody, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    require_admin(user)
    conn = db_conn()
    try:
        core.add_model(conn, body.name)
    finally:
        conn.close()
    return {"ok": True}


@app.get("/warehouses")
def get_warehouses(authorization: Optional[str] = Header(None)):
    current_user(authorization)
    conn = db_conn()
    try:
        rows = core.list_warehouses(conn)
    finally:
        conn.close()
    return {"rows": rows}


@app.post("/warehouses")
def post_warehouse(body: NameBody, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    require_admin(user)
    conn = db_conn()
    try:
        core.add_warehouse(conn, body.name)
    finally:
        conn.close()
    return {"ok": True}


@app.post("/lookup-lists/import")
async def import_lookup_lists(file: UploadFile = File(...), authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    require_admin(user)
    contents = await file.read()
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as tmp:
            tmp.write(contents)
            tmp_path = tmp.name
        conn = db_conn()
        try:
            summary = core.import_lookup_lists(conn, tmp_path)
        finally:
            conn.close()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not process '{file.filename}': {e}")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)
    return summary
