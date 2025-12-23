import sys
import os
# Prevent creation of __pycache__ and .pyc files
sys.dont_write_bytecode = True

from flask import Flask, render_template, request, redirect
from ml.predict import predict_attack
import json
from datetime import datetime, timezone
from collections import Counter
from functools import lru_cache
from urllib.parse import urlparse, urlunparse

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

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

def _load_history_rows(limit=None):
    """
    Return rows as list of tuples: (id, attack, timestamp) sorted newest-first,
    matching what templates/history.html expects.
    """
    limit = HISTORY_LIMIT_DEFAULT if limit is None else int(limit)
    if limit <= 0:
        limit = HISTORY_LIMIT_DEFAULT

    col = _mongo_collection()
    rows = []
    # In summary mode, history is "one row per upload" (fast + readable).
    query = {"type": "summary"} if MONGO_STORE_MODE == "summary" else {}
    cursor = (
        col.find(query, {"attack": 1, "attack_counts": 1, "total": 1, "source_file": 1, "timestamp": 1})
        .sort("timestamp", -1)
        .limit(limit)
    )
    for doc in cursor:
        if doc.get("attack_counts"):
            # Summary row (one per upload) - Format as readable string
            counts = doc.get("attack_counts", {})
            total = doc.get("total", 0)
            filename = doc.get("source_file", "Unknown")
            
            # Find the most frequent attack (excluding Benign if others exist)
            alerts = {k: v for k, v in counts.items() if k.upper() != "BENIGN"}
            if alerts:
                top_attack = max(alerts, key=alerts.get)
                summary = f"⚠️ Scan Results: {total} rows. ALERT: Most frequent: {top_attack}"
            else:
                summary = f"✅ Scan Results: {total} rows. Status: BENIGN"
                
            attack_str = summary
        else:
            attack_str = doc.get("attack")
        rows.append((str(doc.get("_id")), attack_str, doc.get("timestamp")))
    return rows

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

@app.route("/upload", methods=["GET","POST"])
def upload():
    if request.method == "POST":
        if 'file' not in request.files:
            return redirect(request.url)
            
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)

        if file:
            path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(path)

            try:
                results = predict_attack(path)

                try:
                    _store_history_results(results, source_file=file.filename)
                except Exception as storage_error:
                    print(f"History storage error: {storage_error}")
                    hint = (
                        "Check Atlas Network Access (IP allowlist) and ensure your network allows outbound 27017. "
                        "You can also increase MONGO_TIMEOUT_MS (e.g. 30000)."
                    )
                    return render_template("upload.html", error=f"History Storage Error: {storage_error}\n{hint}")

                return redirect("/dashboard")
            except Exception as e:
                print(f"Error during prediction: {e}")
                return render_template("upload.html", error=f"Prediction Error: {e}")
                
    return render_template("upload.html")

@app.route("/dashboard")
def dashboard():
    data, labels, counts = _load_dashboard_counts()
    return render_template("dashboard.html", data=data, labels=labels, counts=counts)

@app.route("/history")
def history():
    # Allow ?limit=50 (optional). Defaults to HISTORY_LIMIT env var (200).
    limit = request.args.get("limit", None)
    rows = _load_history_rows(limit=limit) if limit is not None else _load_history_rows()
    return render_template("history.html", rows=rows)

if __name__ == "__main__":
    app.run(debug=True)
