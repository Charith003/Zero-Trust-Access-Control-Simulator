from __future__ import annotations

import csv
import io
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, send_file, url_for

from risk_engine import DEFAULT_POLICY, evaluate_access, normalise_record


BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "zero_trust.db"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "zero-trust-academic-demo-key")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024


def db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with db_connection() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                user_id TEXT NOT NULL,
                resource TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                decision TEXT NOT NULL,
                reasons TEXT NOT NULL,
                device_consistency INTEGER NOT NULL,
                location_consistency INTEGER NOT NULL,
                login_consistency INTEGER NOT NULL,
                mfa_status INTEGER NOT NULL,
                anomalous_activity INTEGER NOT NULL,
                failed_transactions INTEGER NOT NULL,
                incident_reports INTEGER NOT NULL,
                password_resets INTEGER NOT NULL,
                session_duration REAL NOT NULL,
                access_frequency REAL NOT NULL,
                sensitive_data INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS policy (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                allow_max INTEGER NOT NULL,
                challenge_max INTEGER NOT NULL
            );
            INSERT OR IGNORE INTO policy(id, allow_max, challenge_max) VALUES (1, 34, 64);
            """
        )


def get_policy():
    with db_connection() as db:
        row = db.execute("SELECT allow_max, challenge_max FROM policy WHERE id=1").fetchone()
    return {"allow_max": row["allow_max"], "challenge_max": row["challenge_max"]}


def save_result(record, result):
    with db_connection() as db:
        db.execute(
            """
            INSERT INTO decisions (
                created_at, user_id, resource, risk_score, risk_level, decision, reasons,
                device_consistency, location_consistency, login_consistency, mfa_status,
                anomalous_activity, failed_transactions, incident_reports, password_resets,
                session_duration, access_frequency, sensitive_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                record["user_id"], record["resource"], result["score"], result["level"],
                result["decision"], " | ".join(result["reasons"]), record["device_consistency"],
                record["location_consistency"], record["login_consistency"], record["mfa_status"],
                record["anomalous_activity"], record["failed_transactions"], record["incident_reports"],
                record["password_resets"], record["session_duration"], record["access_frequency"],
                record["sensitive_data"],
            ),
        )


@app.route("/")
def dashboard():
    with db_connection() as db:
        stats = db.execute(
            """SELECT COUNT(*) total,
            SUM(decision='ALLOW') allowed, SUM(decision='CHALLENGE') challenged,
            SUM(decision='DENY') denied, ROUND(AVG(risk_score), 1) average_risk
            FROM decisions"""
        ).fetchone()
        recent = db.execute("SELECT * FROM decisions ORDER BY id DESC LIMIT 8").fetchall()
    return render_template("dashboard.html", stats=stats, recent=recent)


@app.route("/simulate", methods=["GET", "POST"])
def simulate():
    result = None
    values = {}
    if request.method == "POST":
        values = request.form.to_dict()
        record = normalise_record(values)
        result = evaluate_access(record, get_policy())
        save_result(record, result)
        values = record
    return render_template("simulate.html", result=result, values=values)


@app.route("/scenarios/<name>")
def scenario(name):
    scenarios = {
        "normal": {"user_id": "EMP-101", "resource": "Email Portal", "device_consistency": 1,
                   "location_consistency": 1, "login_consistency": 1, "mfa_status": 1,
                   "anomalous_activity": 0, "failed_transactions": 0, "incident_reports": 0,
                   "password_resets": 0, "session_duration": 35, "access_frequency": 12,
                   "sensitive_data": 0},
        "suspicious": {"user_id": "EMP-204", "resource": "Finance Dashboard", "device_consistency": 0,
                       "location_consistency": 1, "login_consistency": 0, "mfa_status": 1,
                       "anomalous_activity": 0, "failed_transactions": 1, "incident_reports": 0,
                       "password_resets": 0, "session_duration": 130, "access_frequency": 38,
                       "sensitive_data": 1},
        "critical": {"user_id": "EMP-309", "resource": "Customer Database", "device_consistency": 0,
                     "location_consistency": 0, "login_consistency": 0, "mfa_status": 0,
                     "anomalous_activity": 1, "failed_transactions": 5, "incident_reports": 2,
                     "password_resets": 3, "session_duration": 240, "access_frequency": 80,
                     "sensitive_data": 1},
    }
    if name not in scenarios:
        return redirect(url_for("simulate"))
    record = normalise_record(scenarios[name])
    result = evaluate_access(record, get_policy())
    save_result(record, result)
    return render_template("simulate.html", result=result, values=record)


@app.route("/logs")
def logs():
    decision = request.args.get("decision", "")
    with db_connection() as db:
        if decision in {"ALLOW", "CHALLENGE", "DENY"}:
            rows = db.execute("SELECT * FROM decisions WHERE decision=? ORDER BY id DESC", (decision,)).fetchall()
        else:
            rows = db.execute("SELECT * FROM decisions ORDER BY id DESC").fetchall()
    return render_template("logs.html", rows=rows, selected=decision)


@app.route("/logs/export")
def export_logs():
    with db_connection() as db:
        rows = db.execute("SELECT * FROM decisions ORDER BY id DESC").fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(rows[0].keys() if rows else ["No records"])
    writer.writerows([tuple(row) for row in rows])
    data = io.BytesIO(output.getvalue().encode("utf-8"))
    return send_file(data, mimetype="text/csv", as_attachment=True, download_name="zero_trust_decisions.csv")


@app.route("/dataset", methods=["GET", "POST"])
def dataset():
    summary = None
    preview = []
    if request.method == "POST":
        uploaded = request.files.get("dataset")
        if not uploaded or not uploaded.filename.lower().endswith((".csv", ".json")):
            flash("Please choose a CSV or JSON file.", "error")
            return redirect(url_for("dataset"))
        try:
            content = uploaded.stream.read().decode("utf-8-sig")
            if uploaded.filename.lower().endswith(".json"):
                rows = json.loads(content)
                if isinstance(rows, dict):
                    rows = rows.get("data", rows.get("records", []))
            else:
                rows = list(csv.DictReader(io.StringIO(content)))
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                raise ValueError("Expected a list of JSON objects or a CSV table.")
            if not rows:
                raise ValueError("The CSV file has no data rows.")
            decisions = {"ALLOW": 0, "CHALLENGE": 0, "DENY": 0}
            scores = []
            for raw in rows[:2000]:
                record = normalise_record(raw)
                result = evaluate_access(record, get_policy())
                decisions[result["decision"]] += 1
                scores.append(result["score"])
                if len(preview) < 10:
                    preview.append({**record, **result})
            summary = {"rows": min(len(rows), 2000), "average": round(sum(scores) / len(scores), 1), **decisions}
        except (UnicodeDecodeError, csv.Error, json.JSONDecodeError, ValueError) as exc:
            flash(f"Could not process the CSV: {exc}", "error")
    return render_template("dataset.html", summary=summary, preview=preview)


@app.route("/dataset/sample")
def sample_dataset():
    return send_file(BASE_DIR / "data" / "sample_user_activity.csv", as_attachment=True)


@app.route("/dataset/full")
def full_dataset():
    return send_file(BASE_DIR / "data" / "user_activity_data.json", as_attachment=True)


@app.route("/policy", methods=["GET", "POST"])
def policy():
    if request.method == "POST":
        try:
            allow_max = int(request.form["allow_max"])
            challenge_max = int(request.form["challenge_max"])
            if not 0 <= allow_max < challenge_max <= 100:
                raise ValueError
            with db_connection() as db:
                db.execute("UPDATE policy SET allow_max=?, challenge_max=? WHERE id=1", (allow_max, challenge_max))
            flash("Policy thresholds updated.", "success")
        except (ValueError, KeyError):
            flash("Use values from 0 to 100, with Allow lower than Challenge.", "error")
    return render_template("policy.html", policy=get_policy(), weights=DEFAULT_POLICY["weights"])


@app.route("/about")
def about():
    return render_template("about.html")


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="127.0.0.1", port=5000)
