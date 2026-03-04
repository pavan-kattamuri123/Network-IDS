import os
import sys
from pymongo import MongoClient
import datetime

# Manually load .env if it exists (robust against PowerShell UTF-16/null bytes)
if os.path.exists(".env"):
    try:
        with open(".env", "rb") as f:
            header = f.read(2)
            f.seek(0)
            content = f.read().decode('utf-16' if header == b'\xff\xfe' else 'utf-8', errors='ignore')
            content = content.replace('\x00', '')
            for line in content.splitlines():
                if "=" in line and not line.strip().startswith("#"):
                    key, value = line.strip().split("=", 1)
                    os.environ[key.strip()] = value.strip().strip('"').strip("'")
        print("Loaded .env file successfully.")
    except Exception as e:
        print(f"Warning: Could not parse .env file: {e}")

MODEL_FROM_MONGO = os.environ.get("MODEL_FROM_MONGO", "1").strip() == "1"
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.environ.get("MONGO_DB", "network_ids").strip()
MONGO_MODELS_COLLECTION = os.environ.get("MONGO_MODELS_COLLECTION", "models").strip()

print(f"DEBUG INFO:")
print(f"MODEL_FROM_MONGO: {MODEL_FROM_MONGO}")
print(f"MONGO_URI: {MONGO_URI}") # Be careful not to expose password if real, but for localhost it's fine.
print(f"MONGO_DB: {MONGO_DB}")
print(f"MONGO_MODELS_COLLECTION: {MONGO_MODELS_COLLECTION}")

try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    # Trigger connection
    client.admin.command('ping')
    print("MongoDB connection successful.")
    
    db = client[MONGO_DB]
    col = db[MONGO_MODELS_COLLECTION]
    
    count = col.count_documents({})
    print(f"Documents in '{MONGO_MODELS_COLLECTION}' collection: {count}")
    
    if count > 0:
        doc = col.find_one(sort=[("timestamp", -1)])
        print("Latest document found.")
        print(f"Keys in document: {list(doc.keys())}")
        if "classes" in doc:
            print(f"Classes found: {doc['classes']}")
        else:
            print("ERROR: 'classes' key MISSING in document.")
            
        if "model_bytes" in doc:
            print(f"Model bytes found (size: {len(doc['model_bytes'])} bytes).")
        else:
            print("ERROR: 'model_bytes' key MISSING in document.")
    else:
        print("ERROR: Collection is empty. Model has not been trained/uploaded.")

except Exception as e:
    print(f"MongoDB Error: {e}")
