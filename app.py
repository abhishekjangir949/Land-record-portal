import csv
import io
import os
import random
import time
import uuid
from functools import wraps
from pathlib import Path
from flask import (
    Flask,
    Response,
    jsonify,
    render_template,
    request,
    send_from_directory,
    session,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from db import UPLOAD_DIR, get_db, init_db, normalize_phone
from ocr_engine import (
    CORE_FIELDS,
    calculate_health_score,
    compute_sha256,
    parse_land_fields,
    run_ocr_on_file,
)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "land-record-portal-secret-2026")
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024

ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tif", ".tiff", ".pdf"}


def log_audit(user_email: str, action: str, details: str = ""):
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_logs (user_email, action, details) VALUES (?, ?, ?)",
        (user_email or "anonymous", action, details),
    )
    conn.commit()
    conn.close()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"ok": False, "error": "Unauthorized. Please login first."}), 401
        return fn(*args, **kwargs)

    return wrapper


def _find_existing_parcel(conn, fields: dict, exclude_id=None):
    khasra = (fields.get("khasra_number") or "").strip().lower()
    survey = (fields.get("survey_number") or "").strip().lower()
    village = (fields.get("village_name") or "").strip().lower()
    parcel_key = khasra or survey

    if not parcel_key:
        return None

    rows = conn.execute("SELECT * FROM land_records ORDER BY id ASC").fetchall()
    for r in rows:
        if exclude_id is not None and r["id"] == exclude_id:
            continue
        r_parcel = ((r["khasra_number"] or "").strip().lower()) or ((r["survey_number"] or "").strip().lower())
        r_village = (r["village_name"] or "").strip().lower()
        if r_parcel == parcel_key and ((not village or not r_village) or (r_village == village)):
            return r
    return None


def _detect_conflict(conn, fields: dict, exclude_id=None):
    khasra = (fields.get("khasra_number") or "").strip().lower()
    survey = (fields.get("survey_number") or "").strip().lower()
    village = (fields.get("village_name") or "").strip().lower()
    owner = (fields.get("owner_name") or "").strip().lower()

    parcel_key = khasra or survey
    if not parcel_key or not owner:
        return None

    rows = conn.execute("SELECT * FROM land_records ORDER BY id ASC").fetchall()
    for r in rows:
        if exclude_id is not None and r["id"] == exclude_id:
            continue
        r_parcel = ((r["khasra_number"] or "").strip().lower()) or ((r["survey_number"] or "").strip().lower())
        r_village = (r["village_name"] or "").strip().lower()
        r_owner = (r["owner_name"] or "").strip().lower()

        same_parcel = r_parcel == parcel_key
        same_village = (not village or not r_village) or (r_village == village)
        if same_parcel and same_village and r_owner and r_owner != owner:
            return r["id"]
    return None


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/me")
def api_me():
    uid = session.get("user_id")
    if not uid:
        return jsonify({"authenticated": False})
    conn = get_db()
    user = conn.execute(
        "SELECT id, full_name, email, phone, role FROM users WHERE id = ?", (uid,)
    ).fetchone()
    conn.close()
    if not user:
        session.clear()
        return jsonify({"authenticated": False})
    return jsonify({"authenticated": True, "user": dict(user)})


@app.route("/api/auth/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True) or {}
    full_name = (data.get("full_name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    phone = normalize_phone(data.get("phone") or "")
    password = data.get("password") or ""
    role = (data.get("role") or "officer").strip().lower()
    if role not in ("officer", "reviewer", "admin"):
        role = "officer"

    if len(full_name) < 2:
        return jsonify({"ok": False, "error": "Please enter your full name."}), 400
    if "@" not in email or "." not in email:
        return jsonify({"ok": False, "error": "Please enter a valid email address."}), 400
    if len(phone) != 10:
        return jsonify({"ok": False, "error": "Please enter a valid 10-digit mobile number."}), 400
    if len(password) < 6:
        return jsonify({"ok": False, "error": "Password must be at least 6 characters long."}), 400

    conn = get_db()
    existing = conn.execute(
        "SELECT id FROM users WHERE email = ? OR phone = ?", (email, phone)
    ).fetchone()
    if existing:
        conn.close()
        return jsonify({"ok": False, "error": "Email or mobile number already registered."}), 409

    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users (full_name, email, phone, password_hash, role) VALUES (?, ?, ?, ?, ?)",
        (full_name, email, phone, generate_password_hash(password), role),
    )
    user_id = cur.lastrowid
    conn.commit()
    conn.close()

    session["user_id"] = user_id
    session["user_email"] = email
    log_audit(email, "REGISTER", f"New user registered: {full_name} ({role})")
    return jsonify({
        "ok": True,
        "user": {
            "id": user_id,
            "full_name": full_name,
            "email": email,
            "phone": phone,
            "role": role,
        },
    })


@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    identifier = (data.get("identifier") or "").strip()
    password = data.get("password") or ""
    keep_signed_in = bool(data.get("keep_signed_in"))

    if not identifier or not password:
        return jsonify({"ok": False, "error": "Please enter Email/Mobile and Password."}), 400

    conn = get_db()
    if "@" in identifier:
        user = conn.execute("SELECT * FROM users WHERE email = ?", (identifier.lower(),)).fetchone()
    else:
        user = conn.execute(
            "SELECT * FROM users WHERE phone = ?", (normalize_phone(identifier),)
        ).fetchone()
    conn.close()

    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"ok": False, "error": "Invalid credentials. Check Email/Mobile or Password."}), 401

    session.permanent = keep_signed_in
    session["user_id"] = user["id"]
    session["user_email"] = user["email"]
    log_audit(user["email"], "LOGIN", "User logged into Land Record Intelligence Portal")

    return jsonify({
        "ok": True,
        "user": {
            "id": user["id"],
            "full_name": user["full_name"],
            "email": user["email"],
            "phone": user["phone"],
            "role": user["role"],
        },
    })


@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    email = session.get("user_email", "")
    session.clear()
    if email:
        log_audit(email, "LOGOUT", "User logged out")
    return jsonify({"ok": True})


@app.route("/api/auth/forgot-password", methods=["POST"])
def api_forgot_password():
    data = request.get_json(silent=True) or {}
    identifier = (data.get("identifier") or "").strip()
    if not identifier:
        return jsonify({"ok": False, "error": "Enter your registered Email or Mobile Number."}), 400

    conn = get_db()
    if "@" in identifier:
        user = conn.execute("SELECT * FROM users WHERE email = ?", (identifier.lower(),)).fetchone()
    else:
        user = conn.execute(
            "SELECT * FROM users WHERE phone = ?", (normalize_phone(identifier),)
        ).fetchone()

    if not user:
        conn.close()
        return jsonify({"ok": False, "error": "No account found with this Email or Mobile Number."}), 404

    otp_code = f"{random.randint(100000, 999999)}"
    expires_at = time.time() + 600
    conn.execute(
        "INSERT INTO password_otps (identifier, user_email, otp_code, expires_at) VALUES (?, ?, ?, ?)",
        (identifier, user["email"], otp_code, expires_at),
    )
    conn.commit()
    conn.close()

    log_audit(user["email"], "OTP_SENT", f"Password reset OTP generated: {otp_code}")
    return jsonify({
        "ok": True,
        "message": f"6-digit OTP sent to {user['email']} / {user['phone']}.",
        "demo_otp": otp_code,
        "masked_email": user["email"],
    })


@app.route("/api/auth/verify-otp", methods=["POST"])
def api_verify_otp():
    data = request.get_json(silent=True) or {}
    identifier = (data.get("identifier") or "").strip()
    otp_code = (data.get("otp") or "").strip()

    conn = get_db()
    row = conn.execute(
        """SELECT * FROM password_otps
           WHERE identifier = ? AND otp_code = ? AND used = 0
           ORDER BY id DESC LIMIT 1""",
        (identifier, otp_code),
    ).fetchone()

    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "Invalid OTP. Please check and try again."}), 400
    if time.time() > row["expires_at"]:
        conn.close()
        return jsonify({"ok": False, "error": "OTP expired. Please request a new OTP."}), 400

    conn.execute("UPDATE password_otps SET verified = 1 WHERE id = ?", (row["id"],))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": "OTP verified! Now set your new password."})


@app.route("/api/auth/reset-password", methods=["POST"])
def api_reset_password():
    data = request.get_json(silent=True) or {}
    identifier = (data.get("identifier") or "").strip()
    otp_code = (data.get("otp") or "").strip()
    new_password = data.get("new_password") or ""

    if len(new_password) < 6:
        return jsonify({"ok": False, "error": "New password must be at least 6 characters."}), 400

    conn = get_db()
    row = conn.execute(
        """SELECT * FROM password_otps
           WHERE identifier = ? AND otp_code = ? AND verified = 1 AND used = 0
           ORDER BY id DESC LIMIT 1""",
        (identifier, otp_code),
    ).fetchone()

    if not row or time.time() > row["expires_at"]:
        conn.close()
        return jsonify({"ok": False, "error": "OTP session invalid or expired."}), 400

    conn.execute(
        "UPDATE users SET password_hash = ? WHERE email = ?",
        (generate_password_hash(new_password), row["user_email"]),
    )
    conn.execute("UPDATE password_otps SET used = 1 WHERE id = ?", (row["id"],))
    conn.commit()
    conn.close()

    log_audit(row["user_email"], "PASSWORD_RESET", "Password updated via OTP verification")
    return jsonify({"ok": True, "message": "Password reset successful! You can now login."})


@app.route("/api/records", methods=["GET"])
@login_required
def api_list_records():
    q = (request.args.get("q") or "").strip().lower()
    status_filter = (request.args.get("status") or "").strip()
    conn = get_db()
    rows = conn.execute("SELECT * FROM land_records ORDER BY id DESC").fetchall()
    logs = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 25").fetchall()
    conn.close()

    records = []
    for r in rows:
        item = dict(r)
        if status_filter and status_filter != "ALL" and item.get("status") != status_filter:
            continue
        if q:
            haystack = " ".join([
                str(item.get("owner_name", "")),
                str(item.get("survey_number", "")),
                str(item.get("khasra_number", "")),
                str(item.get("account_number", "")),
                str(item.get("village_name", "")),
                str(item.get("tehsil", "")),
                str(item.get("district", "")),
                str(item.get("original_filename", "")),
            ]).lower()
            if q not in haystack:
                continue
        records.append(item)

    total = len(rows)
    verified = sum(1 for r in rows if r["status"] in ("Verified", "Final Submitted"))
    submitted = sum(1 for r in rows if r["status"] == "Final Submitted")
    flagged = sum(
        1 for r in rows
        if r["duplicate_of_id"] is not None or r["conflict_with_id"] is not None
    )
    avg_score = round(sum(r["health_score"] for r in rows) / total, 1) if total else 0

    return jsonify({
        "ok": True,
        "records": records,
        "audit_logs": [dict(x) for x in logs],
        "stats": {
            "total": total,
            "verified": verified,
            "submitted": submitted,
            "duplicates": flagged,
            "avg_score": avg_score,
        },
    })


@app.route("/api/records/upload", methods=["POST"])
@login_required
def api_upload_record():
    if "document" not in request.files:
        return jsonify({"ok": False, "error": "No file selected."}), 400

    f = request.files["document"]
    if not f or not f.filename:
        return jsonify({"ok": False, "error": "Empty filename."}), 400

    ext = Path(f.filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({"ok": False, "error": f"Unsupported file format: {ext}"}), 400

    safe_orig = secure_filename(f.filename)
    stored_name = f"{uuid.uuid4().hex}_{safe_orig}"
    saved_path = UPLOAD_DIR / stored_name
    f.save(saved_path)

    sha_hash = compute_sha256(saved_path)

    conn = get_db()
    dup_row = conn.execute(
        "SELECT * FROM land_records WHERE sha256_hash = ? ORDER BY id ASC LIMIT 1",
        (sha_hash,),
    ).fetchone()

    if dup_row:
        try:
            saved_path.unlink(missing_ok=True)
        except Exception:
            pass
        existing_dict = dict(dup_row)
        conn.close()
        log_audit(
            session.get("user_email", ""),
            "DUPLICATE_PREVENTED",
            f"Skipped duplicate upload ({safe_orig}); opened existing Record #{existing_dict['id']}",
        )
        return jsonify({
            "ok": True,
            "duplicate_skipped": True,
            "message": f"Duplicate file detected! Opened existing Record #{existing_dict['id']} instead of creating a duplicate.",
            "record": existing_dict,
        })

    try:
        raw_text, ocr_conf = run_ocr_on_file(saved_path)
    except Exception as exc:
        raw_text = f"[OCR Warning: {exc}]"
        ocr_conf = 0.0

    fields = parse_land_fields(raw_text)

    same_parcel_row = _find_existing_parcel(conn, fields)
    if same_parcel_row:
        try:
            saved_path.unlink(missing_ok=True)
        except Exception:
            pass
        existing_dict = dict(same_parcel_row)
        conn.close()
        log_audit(
            session.get("user_email", ""),
            "PARCEL_DEDUP",
            f"Parcel already exists in Record #{existing_dict['id']}; prevented duplicate row.",
        )
        return jsonify({
            "ok": True,
            "duplicate_skipped": True,
            "message": f"This Khasra/Survey parcel already exists in Record #{existing_dict['id']}! Opened existing record to prevent duplicate entries.",
            "record": existing_dict,
        })

    conflict_with_id = _detect_conflict(conn, fields)

    health_score, status, uncertain = calculate_health_score(
        fields=fields,
        ocr_conf=ocr_conf,
        is_duplicate=False,
        is_conflict=conflict_with_id is not None,
        status="Needs Review",
    )

    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO land_records (
            user_id, original_filename, stored_filename, file_type, sha256_hash,
            ocr_confidence, raw_ocr_text, owner_name, father_name, survey_number,
            khasra_number, account_number, village_name, tehsil, district,
            land_area, land_type, ownership_details, mutation_details,
            registration_details, uncertain_fields, health_score,
            duplicate_of_id, conflict_with_id, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session.get("user_id"),
            safe_orig,
            stored_name,
            ext.lstrip(".").upper(),
            sha_hash,
            ocr_conf,
            raw_text,
            fields["owner_name"],
            fields["father_name"],
            fields["survey_number"],
            fields["khasra_number"],
            fields["account_number"],
            fields["village_name"],
            fields["tehsil"],
            fields["district"],
            fields["land_area"],
            fields["land_type"],
            fields["ownership_details"],
            fields["mutation_details"],
            fields["registration_details"],
            ", ".join(uncertain),
            health_score,
            None,
            conflict_with_id,
            status,
        ),
    )
    new_id = cur.lastrowid
    conn.commit()
    record = dict(conn.execute("SELECT * FROM land_records WHERE id = ?", (new_id,)).fetchone())
    conn.close()

    log_audit(
        session.get("user_email", ""),
        "UPLOAD_OCR",
        f"Scanned record #{new_id} ({safe_orig}) | Score: {health_score}/100 | Status: {status}",
    )
    return jsonify({"ok": True, "record": record})


@app.route("/api/records/<int:record_id>", methods=["PUT"])
@login_required
def api_update_record(record_id: int):
    data = request.get_json(silent=True) or {}
    conn = get_db()
    existing = conn.execute("SELECT * FROM land_records WHERE id = ?", (record_id,)).fetchone()
    if not existing:
        conn.close()
        return jsonify({"ok": False, "error": "Record not found."}), 404

    if existing["status"] == "Final Submitted" and not data.get("allow_reopen"):
        conn.close()
        return jsonify({
            "ok": False,
            "error": "Record is Final Submitted & locked. Use Reopen to edit.",
        }), 409

    updated_fields = {k: (data.get(k) or "").strip() for k in CORE_FIELDS}
    requested_status = (data.get("status") or "Verified").strip()
    if requested_status == "Final Submitted":
        requested_status = "Verified"

    conflict_with_id = _detect_conflict(conn, updated_fields, exclude_id=record_id)
    health_score, _, uncertain = calculate_health_score(
        fields=updated_fields,
        ocr_conf=existing["ocr_confidence"],
        is_duplicate=existing["duplicate_of_id"] is not None,
        is_conflict=conflict_with_id is not None,
        status=requested_status,
    )

    conn.execute(
        """
        UPDATE land_records SET
            owner_name = ?, father_name = ?, survey_number = ?, khasra_number = ?,
            account_number = ?, village_name = ?, tehsil = ?, district = ?,
            land_area = ?, land_type = ?, ownership_details = ?, mutation_details = ?,
            registration_details = ?, uncertain_fields = ?, conflict_with_id = ?,
            health_score = ?, status = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (
            updated_fields["owner_name"],
            updated_fields["father_name"],
            updated_fields["survey_number"],
            updated_fields["khasra_number"],
            updated_fields["account_number"],
            updated_fields["village_name"],
            updated_fields["tehsil"],
            updated_fields["district"],
            updated_fields["land_area"],
            updated_fields["land_type"],
            updated_fields["ownership_details"],
            updated_fields["mutation_details"],
            updated_fields["registration_details"],
            ", ".join(uncertain),
            conflict_with_id,
            health_score,
            requested_status,
            record_id,
        ),
    )
    conn.commit()
    record = dict(conn.execute("SELECT * FROM land_records WHERE id = ?", (record_id,)).fetchone())
    conn.close()

    action_name = "REOPEN_RECORD" if data.get("allow_reopen") else "VERIFY_RECORD"
    log_audit(
        session.get("user_email", ""),
        action_name,
        f"Updated record #{record_id} -> {requested_status} (Score: {health_score}/100)",
    )
    return jsonify({"ok": True, "record": record})


@app.route("/api/records/<int:record_id>/final-submit", methods=["POST"])
@login_required
def api_final_submit(record_id: int):
    data = request.get_json(silent=True) or {}
    conn = get_db()
    existing = conn.execute("SELECT * FROM land_records WHERE id = ?", (record_id,)).fetchone()
    if not existing:
        conn.close()
        return jsonify({"ok": False, "error": "Record not found."}), 404

    updated_fields = {
        k: ((data.get(k) if k in data else existing[k]) or "").strip() for k in CORE_FIELDS
    }

    if not updated_fields["owner_name"] or not (
        updated_fields["khasra_number"] or updated_fields["survey_number"]
    ):
        conn.close()
        return jsonify({
            "ok": False,
            "error": "Owner Name and Khasra/Survey No. are required before Final Submit.",
        }), 400

    conflict_with_id = _detect_conflict(conn, updated_fields, exclude_id=record_id)
    health_score, _, uncertain = calculate_health_score(
        fields=updated_fields,
        ocr_conf=existing["ocr_confidence"],
        is_duplicate=existing["duplicate_of_id"] is not None,
        is_conflict=conflict_with_id is not None,
        status="Final Submitted",
    )

    submitter = session.get("user_email", "officer")
    conn.execute(
        """
        UPDATE land_records SET
            owner_name = ?, father_name = ?, survey_number = ?, khasra_number = ?,
            account_number = ?, village_name = ?, tehsil = ?, district = ?,
            land_area = ?, land_type = ?, ownership_details = ?, mutation_details = ?,
            registration_details = ?, uncertain_fields = ?, conflict_with_id = ?,
            health_score = ?, status = 'Final Submitted',
            submitted_by = ?, submitted_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (
            updated_fields["owner_name"],
            updated_fields["father_name"],
            updated_fields["survey_number"],
            updated_fields["khasra_number"],
            updated_fields["account_number"],
            updated_fields["village_name"],
            updated_fields["tehsil"],
            updated_fields["district"],
            updated_fields["land_area"],
            updated_fields["land_type"],
            updated_fields["ownership_details"],
            updated_fields["mutation_details"],
            updated_fields["registration_details"],
            ", ".join(uncertain),
            conflict_with_id,
            health_score,
            submitter,
            record_id,
        ),
    )
    conn.commit()
    record = dict(conn.execute("SELECT * FROM land_records WHERE id = ?", (record_id,)).fetchone())
    conn.close()

    log_audit(
        submitter,
        "FINAL_SUBMIT",
        f"Final Submitted & locked record #{record_id} (Score: {health_score}/100)",
    )
    return jsonify({
        "ok": True,
        "message": f"Record #{record_id} Final Submitted successfully! (Score: {health_score}/100)",
        "record": record,
    })


@app.route("/api/records/<int:record_id>", methods=["DELETE"])
@login_required
def api_delete_record(record_id: int):
    conn = get_db()
    existing = conn.execute("SELECT * FROM land_records WHERE id = ?", (record_id,)).fetchone()
    if not existing:
        conn.close()
        return jsonify({"ok": False, "error": "Record not found."}), 404

    stored_name = existing["stored_filename"]
    conn.execute(
        "UPDATE land_records SET duplicate_of_id = NULL WHERE duplicate_of_id = ?", (record_id,)
    )
    conn.execute(
        "UPDATE land_records SET conflict_with_id = NULL WHERE conflict_with_id = ?", (record_id,)
    )
    conn.execute("DELETE FROM land_records WHERE id = ?", (record_id,))
    conn.commit()
    conn.close()

    if stored_name:
        file_path = UPLOAD_DIR / stored_name
        if file_path.exists():
            try:
                file_path.unlink()
            except Exception:
                pass

    log_audit(
        session.get("user_email", ""),
        "DELETE_RECORD",
        f"Deleted record #{record_id} ({existing['original_filename']})",
    )
    return jsonify({"ok": True, "message": f"Record #{record_id} deleted."})


@app.route("/api/records/export.csv", methods=["GET"])
@login_required
def api_export_csv():
    conn = get_db()
    rows = conn.execute("SELECT * FROM land_records ORDER BY id DESC").fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID",
        "Filename",
        "Owner Name",
        "Father/Husband",
        "Survey No.",
        "Khasra No.",
        "Khata/Account No.",
        "Village",
        "Tehsil",
        "District",
        "Area",
        "Land Type",
        "Ownership",
        "Mutation",
        "Registration",
        "Health Score",
        "Status",
        "Submitted By",
        "SHA-256",
    ])
    for r in rows:
        writer.writerow([
            r["id"],
            r["original_filename"],
            r["owner_name"],
            r["father_name"],
            r["survey_number"],
            r["khasra_number"],
            r["account_number"],
            r["village_name"],
            r["tehsil"],
            r["district"],
            r["land_area"],
            r["land_type"],
            r["ownership_details"],
            r["mutation_details"],
            r["registration_details"],
            r["health_score"],
            r["status"],
            r["submitted_by"],
            r["sha256_hash"],
        ])

    log_audit(session.get("user_email", ""), "EXPORT_CSV", f"Exported {len(rows)} records to CSV")
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=land_records_export.csv"},
    )


@app.route("/uploads/<path:filename>")
@login_required
def serve_upload(filename):
    return send_from_directory(UPLOAD_DIR, filename)


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG", "1") == "1")