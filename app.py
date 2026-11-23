import os
import io
import csv
import time
import threading
import sqlite3
import secrets
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

import numpy as np
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from scapy.all import PcapReader, AsyncSniffer, IP, IPv6, TCP, UDP, ICMP, DNS, conf, get_if_list
from sklearn.ensemble import IsolationForest
import joblib

from config import Config

app = Flask(__name__)
app.config.from_object(Config)
csrf = CSRFProtect(app)

for folder in (Path(app.config["DATABASE"]).parent, Path(app.config["UPLOAD_FOLDER"]),
               Path(app.config["REPORT_FOLDER"]), Path(app.config["MODEL_FOLDER"])):
    folder.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}
capture_lock = threading.RLock()
sniffer = None
capture_state = {"running": False, "interface": None, "started_at": None, "last_error": None}
model = None
model_lock = threading.RLock()

def load_saved_model():
    global model
    model_path = Path(app.config["MODEL_FOLDER"]) / "isolation_forest.joblib"
    if model_path.exists():
        try:
            model = joblib.load(model_path)
        except Exception:
            model = None

def packet_features(rec):
    proto_map = {"TCP": 1, "UDP": 2, "ICMP": 3, "DNS": 4, "OTHER": 0}
    proto = rec["protocol"].split("/")[0]
    return [[rec["length"], rec["src_port"] or 0, rec["dst_port"] or 0, proto_map.get(proto, 0)]]

load_saved_model()

def db():
    conn = sqlite3.connect(app.config["DATABASE"], timeout=15)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT NOT NULL,
            length INTEGER NOT NULL,
            tcp_flags TEXT,
            dns_query TEXT,
            source TEXT NOT NULL DEFAULT 'live',
            anomaly_score REAL,
            is_anomaly INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            message TEXT NOT NULL,
            evidence TEXT,
            status TEXT NOT NULL DEFAULT 'Open'
        );
        """)
init_db()

def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped

def first_user_exists():
    with db() as con:
        return con.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0

def add_alert(severity, category, message, evidence=""):
    with db() as con:
        con.execute("INSERT INTO alerts(timestamp,severity,category,message,evidence) VALUES(?,?,?,?,?)",
                    (now_iso(), severity, category, message, str(evidence)[:1000]))

def packet_to_record(pkt, source="live"):
    timestamp = now_iso()
    try:
        if hasattr(pkt, "time"):
            timestamp = datetime.fromtimestamp(float(pkt.time), timezone.utc).astimezone().isoformat(timespec="seconds")
    except Exception:
        pass
    src_ip = dst_ip = None
    src_port = dst_port = None
    protocol = "OTHER"
    flags = ""
    dns_query = ""
    if IP in pkt:
        src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
    elif IPv6 in pkt:
        src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
    if TCP in pkt:
        protocol = "TCP"
        src_port, dst_port = int(pkt[TCP].sport), int(pkt[TCP].dport)
        flags = str(pkt[TCP].flags)
    elif UDP in pkt:
        protocol = "UDP"
        src_port, dst_port = int(pkt[UDP].sport), int(pkt[UDP].dport)
    elif ICMP in pkt:
        protocol = "ICMP"
    if DNS in pkt:
        protocol = "DNS" if protocol in ("UDP", "OTHER") else protocol + "/DNS"
        try:
            q = pkt[DNS].qd.qname
            dns_query = q.decode(errors="ignore").rstrip(".") if isinstance(q, bytes) else str(q)
        except Exception:
            pass
    return {
        "timestamp": timestamp, "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": src_port, "dst_port": dst_port, "protocol": protocol,
        "length": int(len(pkt)), "tcp_flags": flags, "dns_query": dns_query,
        "source": source
    }

def detect_rules(rec):
    alerts = []
    if rec["dst_port"] in (23, 445, 3389) and rec["protocol"].startswith(("TCP", "UDP")):
        alerts.append(("Low", "Sensitive service", f"Traffic observed to commonly sensitive service port {rec['dst_port']}.", rec["dst_ip"]))
    if rec["dns_query"] and len(rec["dns_query"]) > 90:
        alerts.append(("Medium", "Unusual DNS query", "A long DNS query name was observed; investigate if unexpected.", rec["dns_query"]))
    if rec["length"] > 1400:
        alerts.append(("Low", "Large packet", f"Large packet observed ({rec['length']} bytes).", f"{rec['src_ip']} → {rec['dst_ip']}"))
    return alerts

def store_record(rec):
    anomaly_score = None
    is_anomaly = 0
    with model_lock:
        active_model = model
    if active_model is not None:
        try:
            features = packet_features(rec)
            is_anomaly = int(active_model.predict(features)[0] == -1)
            anomaly_score = float(active_model.decision_function(features)[0])
        except Exception:
            pass
    with db() as con:
        cur = con.execute("""INSERT INTO packets(timestamp,src_ip,dst_ip,src_port,dst_port,protocol,length,tcp_flags,dns_query,source,anomaly_score,is_anomaly)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (rec["timestamp"], rec["src_ip"], rec["dst_ip"], rec["src_port"], rec["dst_port"],
         rec["protocol"], rec["length"], rec["tcp_flags"], rec["dns_query"], rec["source"],
         anomaly_score, is_anomaly))
        packet_id = cur.lastrowid
    if is_anomaly:
        add_alert("Medium", "ML traffic anomaly", "Isolation Forest marked this packet as an outlier. Review surrounding traffic and context.", f"{rec['src_ip']} → {rec['dst_ip']} | model score {anomaly_score:.4f}")
    for severity, category, message, evidence in detect_rules(rec):
        add_alert(severity, category, message, evidence)
    return packet_id

def on_packet(pkt):
    try:
        store_record(packet_to_record(pkt, "live"))
    except Exception as exc:
        capture_state["last_error"] = str(exc)[:300]

def allowed_file(filename):
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS

def get_stats():
    with db() as con:
        total = con.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
        bytes_total = con.execute("SELECT COALESCE(SUM(length),0) FROM packets").fetchone()[0]
        alert_count = con.execute("SELECT COUNT(*) FROM alerts WHERE status='Open'").fetchone()[0]
        protocols = con.execute("SELECT protocol,COUNT(*) AS count FROM packets GROUP BY protocol ORDER BY count DESC LIMIT 8").fetchall()
        top_ips = con.execute("""SELECT ip, SUM(n) AS count FROM (
            SELECT src_ip AS ip,COUNT(*) AS n FROM packets WHERE src_ip IS NOT NULL GROUP BY src_ip
            UNION ALL SELECT dst_ip AS ip,COUNT(*) AS n FROM packets WHERE dst_ip IS NOT NULL GROUP BY dst_ip
        ) GROUP BY ip ORDER BY count DESC LIMIT 8""").fetchall()
        recent = con.execute("SELECT * FROM packets ORDER BY id DESC LIMIT 12").fetchall()
        alerts = con.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 8").fetchall()
    return total, bytes_total, alert_count, protocols, top_ips, recent, alerts

@app.context_processor
def inject_user():
    return {"current_user": session.get("username")}


def make_demo_records(count=150, seed=17):
    """Create synthetic packet metadata only; no packets are sent on any network."""
    import random
    rng = random.Random(seed)
    records = []
    normal_hosts = ["192.168.1.10", "192.168.1.15", "192.168.1.22", "10.0.0.5"]
    external_hosts = ["93.184.216.34", "1.1.1.1", "8.8.8.8", "142.250.72.14"]
    for i in range(count):
        scenario = i % 6
        src = rng.choice(normal_hosts)
        dst = rng.choice(external_hosts)
        if scenario in (0, 1, 2):
            proto = rng.choice(["TCP", "UDP", "DNS", "ICMP"])
            dst_port = {"TCP": rng.choice([443, 80, 22]), "UDP": 53, "DNS": 53, "ICMP": None}[proto]
            src_port = rng.randint(30000, 62000) if proto in ("TCP", "UDP", "DNS") else None
            length = rng.randint(60, 1250)
            flags = rng.choice(["PA", "A", "S"]) if proto == "TCP" else ""
            dns = rng.choice(["example.com", "www.example.org", "updates.example.net"]) if proto == "DNS" else ""
        elif scenario == 3:
            # Simulated port-scan pattern: same source touches many destination ports.
            proto, dst_port, src_port = "TCP", rng.choice([21, 22, 23, 80, 139, 445, 3389, 8080]), rng.randint(40000, 62000)
            length, flags, dns = 60, "S", ""
            dst = "192.168.1.1"
        elif scenario == 4:
            # Repeated connection attempts to a service port.
            proto, dst_port, src_port = "TCP", 3389, rng.randint(40000, 62000)
            length, flags, dns = 60, "S", ""
            dst = "192.168.1.50"
        else:
            # Unusually large packet / DNS metadata example.
            proto, dst_port, src_port = "DNS", 53, rng.randint(30000, 62000)
            length, flags, dns = rng.randint(1450, 1900), "", "x" * 95 + ".demo.invalid"
        records.append({
            "timestamp": now_iso(), "src_ip": src, "dst_ip": dst,
            "src_port": src_port, "dst_port": dst_port, "protocol": proto,
            "length": length, "tcp_flags": flags, "dns_query": dns,
            "source": "demo"
        })
    return records

def load_demo_dataset():
    records = make_demo_records(180)
    for rec in records:
        store_record(rec)
    return len(records)

def generate_demo_batch():
    records = make_demo_records(60, seed=int(time.time()) % 100000)
    for rec in records:
        store_record(rec)
    return len(records)

@app.route("/")
def index():
    if not first_user_exists():
        return redirect(url_for("register"))
    if "user_id" not in session:
        return redirect(url_for("login"))
    total, byte_count, alert_count, protocols, top_ips, recent, alerts = get_stats()
    return render_template("index.html", total=total, byte_count=byte_count, alert_count=alert_count,
                           protocols=protocols, top_ips=top_ips, recent=recent, alerts=alerts,
                           capture_state=capture_state)

@app.route("/register", methods=["GET", "POST"])
def register():
    if first_user_exists():
        flash("An account already exists. Sign in to continue.", "info")
        return redirect(url_for("login"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if len(username) < 3 or len(username) > 40:
            flash("Username must be 3–40 characters.", "danger")
        elif len(password) < 10:
            flash("Use a password with at least 10 characters.", "danger")
        elif password != confirm:
            flash("Passwords do not match.", "danger")
        else:
            try:
                with db() as con:
                    cur = con.execute("INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)",
                                      (username, generate_password_hash(password), now_iso()))
                    session["user_id"] = cur.lastrowid
                    session["username"] = username
                flash("Administrator account created. Welcome!", "success")
                return redirect(url_for("index"))
            except sqlite3.IntegrityError:
                flash("That username is already taken.", "danger")
    return render_template("auth.html", mode="register")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with db() as con:
            user = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("index"))
        flash("Invalid username or password.", "danger")
    return render_template("auth.html", mode="login")

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


@app.route("/demo", methods=["GET", "POST"])
@login_required
def demo():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "load":
            count = load_demo_dataset()
            flash(f"Loaded {count} synthetic demo packet records. No network traffic was generated.", "success")
        elif action == "generate":
            count = generate_demo_batch()
            flash(f"Generated {count} additional synthetic records for analysis.", "success")
        return redirect(url_for("demo"))
    with db() as con:
        demo_count = con.execute("SELECT COUNT(*) FROM packets WHERE source='demo'").fetchone()[0]
        demo_alerts = con.execute("""SELECT COUNT(*) FROM alerts WHERE category IN
            ('Sensitive service','Unusual DNS query','Large packet','ML traffic anomaly')""").fetchone()[0]
    return render_template("demo.html", demo_count=demo_count, demo_alerts=demo_alerts)

@app.route("/traffic")
@login_required
def traffic():
    page = max(1, request.args.get("page", 1, type=int))
    per_page = 50
    with db() as con:
        total = con.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
        rows = con.execute("SELECT * FROM packets ORDER BY id DESC LIMIT ? OFFSET ?", (per_page, (page-1)*per_page)).fetchall()
    return render_template("traffic.html", rows=rows, page=page, pages=max(1, (total+per_page-1)//per_page))

@app.route("/capture", methods=["GET", "POST"])
@login_required
def capture():
    global sniffer
    if request.method == "POST":
        action = request.form.get("action")
        if action == "start":
            iface = request.form.get("interface") or None
            with capture_lock:
                if capture_state["running"]:
                    flash("Capture is already running.", "info")
                else:
                    try:
                        sniffer = AsyncSniffer(iface=iface, prn=on_packet, store=False)
                        sniffer.start()
                        capture_state.update({"running": True, "interface": iface or "Default interface",
                                              "started_at": now_iso(), "last_error": None})
                        flash("Live capture started. Only monitor networks you own or are authorized to inspect.", "success")
                    except Exception as exc:
                        capture_state["last_error"] = str(exc)
                        flash(f"Could not start capture: {exc}", "danger")
        elif action == "stop":
            with capture_lock:
                try:
                    if sniffer and capture_state["running"]:
                        sniffer.stop()
                    capture_state.update({"running": False, "interface": None})
                    flash("Capture stopped.", "success")
                except Exception as exc:
                    flash(f"Could not stop capture cleanly: {exc}", "warning")
                    capture_state["running"] = False
        return redirect(url_for("capture"))
    try:
        interfaces = get_if_list()
    except Exception:
        interfaces = []
    return render_template("capture.html", interfaces=interfaces, capture_state=capture_state)

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        f = request.files.get("pcap")
        if not f or not f.filename:
            flash("Choose a PCAP or PCAPNG file.", "danger")
        elif not allowed_file(f.filename):
            flash("Only .pcap and .pcapng files are supported.", "danger")
        else:
            name = secure_filename(f.filename)
            unique_name = f"{secrets.token_hex(6)}_{name}"
            path = Path(app.config["UPLOAD_FOLDER"]) / unique_name
            f.save(path)
            count = 0
            try:
                with PcapReader(str(path)) as reader:
                    for pkt in reader:
                        store_record(packet_to_record(pkt, "pcap"))
                        count += 1
                        if count >= 100000:
                            break
                flash(f"Imported {count:,} packets from {name}.", "success")
            except Exception as exc:
                flash(f"Could not parse this capture: {exc}", "danger")
            finally:
                try: path.unlink(missing_ok=True)
                except Exception: pass
        return redirect(url_for("upload"))
    return render_template("upload.html")

@app.route("/alerts")
@login_required
def alerts():
    with db() as con:
        rows = con.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 300").fetchall()
    return render_template("alerts.html", rows=rows)

@app.route("/alerts/<int:alert_id>/resolve", methods=["POST"])
@login_required
def resolve_alert(alert_id):
    with db() as con:
        con.execute("UPDATE alerts SET status='Resolved' WHERE id=?", (alert_id,))
    flash("Alert marked as resolved.", "success")
    return redirect(request.referrer or url_for("alerts"))

def train_model():
    global model
    with db() as con:
        rows = con.execute("SELECT id,length,src_port,dst_port,protocol FROM packets ORDER BY id DESC LIMIT 5000").fetchall()
    if len(rows) < 20:
        return False, "At least 20 packets are needed to train the initial anomaly model."
    proto_map = {"TCP": 1, "UDP": 2, "ICMP": 3, "DNS": 4, "OTHER": 0}
    X = []
    for r in rows:
        p = r["protocol"].split("/")[0]
        X.append([r["length"], r["src_port"] or 0, r["dst_port"] or 0, proto_map.get(p, 0)])
    X = np.asarray(X, dtype=float)
    clf = IsolationForest(n_estimators=150, contamination="auto", random_state=42)
    clf.fit(X)
    with model_lock:
        model = clf
        joblib.dump(clf, Path(app.config["MODEL_FOLDER"]) / "isolation_forest.joblib")
    # Score the training sample so the dashboard can show an initial anomaly count.
    predictions = clf.predict(X)
    scores = clf.decision_function(X)
    with db() as con:
        ids = [r["id"] for r in rows]
        con.executemany("UPDATE packets SET is_anomaly=?, anomaly_score=? WHERE id=?",
                        [(int(pred == -1), float(score), packet_id)
                         for packet_id, pred, score in zip(ids, predictions, scores)])
    return True, f"Model trained and applied to {len(X)} packet records. Outliers are review cues, not proof of malicious activity."

@app.route("/ml", methods=["GET", "POST"])
@login_required
def ml():
    message = None
    if request.method == "POST":
        ok, message = train_model()
        flash(message, "success" if ok else "warning")
    model_exists = (Path(app.config["MODEL_FOLDER"]) / "isolation_forest.joblib").exists()
    with db() as con:
        count = con.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
        anomalies = con.execute("SELECT COUNT(*) FROM packets WHERE is_anomaly=1").fetchone()[0]
    return render_template("ml.html", model_exists=model_exists, count=count, anomalies=anomalies)

@app.route("/export.csv")
@login_required
def export_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp","source_ip","destination_ip","source_port","destination_port","protocol","length","tcp_flags","dns_query","source"])
    with db() as con:
        rows = con.execute("SELECT timestamp,src_ip,dst_ip,src_port,dst_port,protocol,length,tcp_flags,dns_query,source FROM packets ORDER BY id DESC LIMIT 100000").fetchall()
        for row in rows:
            writer.writerow(list(row))
    mem = io.BytesIO(output.getvalue().encode("utf-8-sig"))
    mem.seek(0)
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="network_traffic.csv")

@app.route("/report.pdf")
@login_required
def report_pdf():
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=15*mm, leftMargin=15*mm, topMargin=15*mm, bottomMargin=15*mm)
    styles = getSampleStyleSheet()
    total, byte_count, alert_count, protocols, top_ips, recent, alerts_rows = get_stats()
    story = [Paragraph("Network Traffic Analyzer – Security Summary", styles["Title"]),
             Paragraph(f"Generated: {now_iso()}", styles["Normal"]), Spacer(1, 8),
             Paragraph(f"Packets recorded: {total:,} | Packet bytes: {byte_count:,} | Open alerts: {alert_count:,}", styles["Heading2"]),
             Spacer(1, 10), Paragraph("Protocol distribution", styles["Heading2"])]
    data = [["Protocol", "Packets"]] + [[r["protocol"], str(r["count"])] for r in protocols]
    t = Table(data, hAlign="LEFT")
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#172554")),
                           ("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.4,colors.grey),
                           ("PADDING",(0,0),(-1,-1),6)]))
    story += [t, Spacer(1, 10), Paragraph("Recent alerts", styles["Heading2"])]
    alert_data = [["Time","Severity","Category","Status"]] + [[r["timestamp"],r["severity"],r["category"],r["status"]] for r in alerts_rows]
    at = Table(alert_data, repeatRows=1, colWidths=[55*mm,25*mm,65*mm,25*mm])
    at.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#172554")),
                            ("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.4,colors.grey),
                            ("FONTSIZE",(0,0),(-1,-1),8),("PADDING",(0,0),(-1,-1),5)]))
    story.append(at)
    doc.build(story)
    buf.seek(0)
    return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name="network_security_report.pdf")


@app.route("/api/live")
@login_required
def api_live():
    total, byte_count, alert_count, protocols, top_ips, recent, alerts_rows = get_stats()
    return jsonify({
        "timestamp": now_iso(),
        "packets": total,
        "bytes": byte_count,
        "open_alerts": alert_count,
        "capture_running": capture_state["running"],
        "interface": capture_state["interface"],
        "protocols": [{"name": r["protocol"], "count": r["count"]} for r in protocols],
        "top_ips": [{"ip": r["ip"], "count": r["count"]} for r in top_ips],
        "recent": [{
            "timestamp": r["timestamp"], "src_ip": r["src_ip"], "dst_ip": r["dst_ip"],
            "src_port": r["src_port"], "dst_port": r["dst_port"],
            "protocol": r["protocol"], "length": r["length"], "source": r["source"]
        } for r in recent],
        "alerts": [{
            "timestamp": r["timestamp"], "severity": r["severity"],
            "category": r["category"], "message": r["message"], "status": r["status"]
        } for r in alerts_rows]
    })

@app.route("/api/stats")
@login_required
def api_stats():
    total, byte_count, alert_count, protocols, top_ips, recent, alerts_rows = get_stats()
    return jsonify({"packets": total, "bytes": byte_count, "open_alerts": alert_count,
                    "protocols": [{"name": r["protocol"], "count": r["count"]} for r in protocols],
                    "top_ips": [{"ip": r["ip"], "count": r["count"]} for r in top_ips],
                    "capture_running": capture_state["running"]})

@app.errorhandler(413)
def too_large(_):
    flash("Upload exceeds the 32 MB limit.", "danger")
    return redirect(url_for("upload"))

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
