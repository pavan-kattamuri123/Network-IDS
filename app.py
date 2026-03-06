import sys
import os
# Prevent creation of __pycache__ and .pyc files
sys.dont_write_bytecode = True

from flask import Flask, render_template, request, redirect, jsonify
from flask_socketio import SocketIO, emit
from ml.predict import predict_attack
import json
from datetime import datetime, timezone
from collections import Counter
from functools import lru_cache
from urllib.parse import urlparse, urlunparse

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'safenet-ids-secret')
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins='*')

# Live capture state (one session at a time)
_live_capture = None

# Manually load .env if it exists (robust against PowerShell UTF-16/null bytes)
if os.path.exists(".env"):
    try:
        with open(".env", "rb") as f:
            # Check for UTF-16 BOM
            header = f.read(2)
            f.seek(0)
            content = f.read().decode('utf-16' if header == b'\xff\xfe' else 'utf-8', errors='ignore')
            content = content.replace('\x00', '')
            for line in content.splitlines():
                if "=" in line and not line.strip().startswith("#"):
                    key, value = line.strip().split("=", 1)
                    os.environ[key.strip()] = value.strip().strip('"').strip("'")
    except Exception as e:
        print(f"Warning: Could not parse .env file: {e}")

def _sanitize_mongo_uri(uri: str) -> str:
    """
    Atlas docs show placeholders like mongodb+srv://user:<password>@...
    Users sometimes paste the <> literally, which breaks authentication.
    This function removes:
    - outer "<...>" wrapping the whole URI
    - "<...>" wrapping only the password segment
    """
    if not uri:
        return uri
    uri = uri.strip()
    if uri.startswith("<") and uri.endswith(">") and len(uri) > 2:
        uri = uri[1:-1].strip()

    try:
        p = urlparse(uri)
        netloc = p.netloc
        if "@" in netloc:
            userinfo, host = netloc.rsplit("@", 1)
            if ":" in userinfo:
                user, pwd = userinfo.split(":", 1)
                if pwd.startswith("<") and pwd.endswith(">") and len(pwd) > 2:
                    pwd = pwd[1:-1]
                    netloc = f"{user}:{pwd}@{host}"
                    p = p._replace(netloc=netloc)
                    uri = urlunparse(p)
    except Exception:
        # If parsing fails, keep original string.
        pass

    return uri

# Storage backend for history:
# - mongo: MongoDB collection (mandatory cloud storage)
HISTORY_BACKEND = os.environ.get("HISTORY_BACKEND", "mongo").strip().lower()
MONGO_URI = _sanitize_mongo_uri(os.environ.get("MONGO_URI", "mongodb://localhost:27017"))
MONGO_DB = os.environ.get("MONGO_DB", "network_ids").strip()
MONGO_COLLECTION = os.environ.get("MONGO_COLLECTION", "history").strip()
# Atlas can be slow to select a primary on first connect; 5s is often too low.
MONGO_TIMEOUT_MS = int(os.environ.get("MONGO_TIMEOUT_MS", "20000"))
MONGO_STORE_MODE = os.environ.get("MONGO_STORE_MODE", "summary").strip().lower()  # summary|per_row
HISTORY_LIMIT_DEFAULT = int(os.environ.get("HISTORY_LIMIT", "200"))


def _init_history_storage():
    """Verify MongoDB connection availability on startup."""
    try:
        import pymongo  # type: ignore  # noqa: F401
    except Exception as e:
        raise RuntimeError(
            "MongoDB backend requires pymongo. For MongoDB Atlas (mongodb+srv://), install: pip install \"pymongo[srv]\""
        ) from e

_init_history_storage()

@lru_cache(maxsize=1)
def _mongo_collection():
    try:
        from pymongo import MongoClient  # type: ignore
    except Exception as e:
        raise RuntimeError(
            "MongoDB backend requires pymongo. For MongoDB Atlas (mongodb+srv://), install: pip install \"pymongo[srv]\""
        ) from e

    # Atlas typically uses mongodb+srv:// which needs dnspython (install via pymongo[srv]).
    client = MongoClient(
        MONGO_URI,
        serverSelectionTimeoutMS=MONGO_TIMEOUT_MS,
        connectTimeoutMS=MONGO_TIMEOUT_MS,
        socketTimeoutMS=MONGO_TIMEOUT_MS,
        retryWrites=True,
    )
    db = client[MONGO_DB]
    col = db[MONGO_COLLECTION]
    # Helpful index for fast dashboard + history sorting
    try:
        col.create_index([("timestamp", -1)])
        # Optimized compound index explicitly for dashboard aggregation Speed $O(1)$
        col.create_index([("type", 1), ("timestamp", -1)])
    except Exception:
        pass
    return col

def _append_mongo_attacks(attacks):
    col = _mongo_collection()
    now = datetime.now(timezone.utc)
    docs = [{"attack": str(a), "timestamp": now} for a in attacks]
    if docs:
        col.insert_many(docs, ordered=False)

def _append_mongo_summary(attacks, source_file=None):
    col = _mongo_collection()
    now = datetime.now(timezone.utc)
    counts = Counter(str(a) for a in attacks)
    doc = {
        "type": "summary",
        "timestamp": now,
        "source_file": source_file,
        "total": int(sum(counts.values())),
        "attack_counts": dict(counts),
    }
    col.insert_one(doc)


def _load_dashboard_counts():
    """
    Return data as list[(label, count)] and labels/counts arrays.
    """
    col = _mongo_collection()
    # Support both:
    # - per-row docs: {attack: "..."}
    # - summary docs: {attack_counts: {"BENIGN": 10, ...}}
    pipeline = [
        {
            "$facet": {
                "per_row": [
                    {"$match": {"attack": {"$exists": True}, "attack_counts": {"$exists": False}}},
                    {"$group": {"_id": "$attack", "count": {"$sum": 1}}},
                ],
                "summary": [
                    {"$match": {"attack_counts": {"$exists": True}}},
                    {"$project": {"pairs": {"$objectToArray": "$attack_counts"}}},
                    {"$unwind": "$pairs"},
                    {"$group": {"_id": "$pairs.k", "count": {"$sum": "$pairs.v"}}},
                ],
            }
        },
        {"$project": {"combined": {"$concatArrays": ["$per_row", "$summary"]}}},
        {"$unwind": "$combined"},
        {"$group": {"_id": "$combined._id", "count": {"$sum": "$combined.count"}}},
    ]
    data = []
    for row in col.aggregate(pipeline):
        label = row.get("_id")
        if label is None:
            continue
        data.append((str(label).replace('\ufffd', '-'), int(row.get("count", 0))))

    # Sort by count desc, then label asc for stable display
    data.sort(key=lambda x: (-int(x[1]), str(x[0])))
    labels = [item[0] for item in data]
    counts = [int(item[1]) for item in data]
    return data, labels, counts

def _store_history_results(results, source_file=None):
    if MONGO_STORE_MODE == "per_row":
        _append_mongo_attacks(results)
    else:
        # Default: much faster for large CSVs (1 write per upload)
        _append_mongo_summary(results, source_file=source_file)

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/phishing", methods=["GET", "POST"])
def phishing():
    result = None
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if url:
            try:
                # Lazy import to avoid circular dependency or slowing down startup
                from ml.phishing_detector import predict_url
                prob, verdict, reasons = predict_url(url)
                result = {
                    "url": url,
                    "probability": prob,
                    "verdict": verdict,
                    "reasons": reasons
                }
            except Exception as e:
                print(f"Phishing detection error: {e}")
                result = {
                    "url": url,
                    "probability": 0,
                    "verdict": "Error",
                    "reasons": [f"System error: {str(e)}"]
                }
    return render_template("phishing.html", result=result)

# Example/seed data shown when no real DB data exists yet
_EXAMPLE_DATA = [
    ("BENIGN",       15423),
    ("DoS Hulk",      3210),
    ("PortScan",       980),
    ("DDoS",           741),
    ("DoS GoldenEye",  432),
    ("FTP-Patator",    201),
    ("SSH-Patator",    187),
    ("Bot",             94),
]

def _load_recent_attacks(limit=10):
    """Return last `limit` non-benign attack records from MongoDB."""
    try:
        col = _mongo_collection()
        # per-row docs have an "attack" key; summary docs have "attack_counts"
        cursor = col.find(
            {"$and": [
                {"attack": {"$exists": True}},
                {"attack_counts": {"$exists": False}},
                {"attack": {"$not": {"$regex": "^BENIGN$", "$options": "i"}}}
            ]},
            {"attack": 1, "timestamp": 1, "_id": 0}
        ).sort("timestamp", -1).limit(limit)
        results = []
        for doc in cursor:
            ts = doc.get("timestamp")
            ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "—"
            results.append({"attack": doc.get("attack", "?"), "timestamp": ts_str})
        return results
    except Exception:
        return []

@app.route("/dashboard")
def dashboard():
    data, labels, counts = _load_dashboard_counts()

    # If DB is empty, show example/seed data so chart isn't blank
    using_example = False
    if not data:
        data = _EXAMPLE_DATA
        labels = [d[0] for d in data]
        counts = [d[1] for d in data]
        using_example = True

    # Compute benign vs threat totals
    total = sum(counts)
    benign_count = 0
    threats_count = 0
    for label, count in data:
        if label.upper() == "BENIGN":
            benign_count += count
        else:
            threats_count += count

    recent_attacks = _load_recent_attacks(limit=10)

    return render_template(
        "dashboard.html",
        data=data,
        labels=labels,
        counts=counts,
        using_example=using_example,
        total=total,
        benign_count=benign_count,
        threats_count=threats_count,
        recent_attacks=recent_attacks,
    )


@app.route("/api/clear_history", methods=["POST"])
def clear_history():
    """Wipes all scan history and live capture data from the database."""
    try:
        col = _mongo_collection()
        col.delete_many({})
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ─── Live Capture Routes ────────────────────────────────────────────────────

@app.route("/live")
def live():
    return render_template("live.html")


@app.route("/api/interfaces")
def api_interfaces():
    try:
        from ml.live_capture import get_network_interfaces
        ifaces = get_network_interfaces()
    except Exception as e:
        ifaces = []
    return jsonify({"interfaces": ifaces})


@socketio.on("start_capture")
def handle_start_capture(data):
    global _live_capture
    from ml.live_capture import LiveCaptureThread

    iface = data.get("iface") or None

    if _live_capture and _live_capture.is_running():
        _live_capture.stop()

    def _on_result(result):
        if "error" in result:
            socketio.emit("capture_error", {"message": result["error"]})
            return

        # Persist non-benign live detections to MongoDB
        label = result.get("label", "")
        if label.upper() not in ("BENIGN", "UNKNOWN", ""):
            try:
                _append_mongo_summary([label], source_file="[LIVE]")
            except Exception:
                pass

        socketio.emit("packet_event", result)

    _live_capture = LiveCaptureThread(on_result=_on_result, iface=iface)
    _live_capture.start()
    emit("capture_status", {"status": "started"})


@socketio.on("stop_capture")
def handle_stop_capture():
    global _live_capture
    if _live_capture:
        _live_capture.stop()
        _live_capture = None
    emit("capture_status", {"status": "stopped"})


if __name__ == "__main__":
    socketio.run(app, debug=True)
