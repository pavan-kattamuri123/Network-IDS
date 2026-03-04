import sys
import os
import json
from functools import lru_cache

# Prevent creation of __pycache__ and .pyc files
sys.dont_write_bytecode = True

# Manually load .env if it exists
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
    except Exception as e:
        print(f"Warning: Could not parse .env file: {e}")

# Model Configuration
MODEL_FROM_MONGO = os.environ.get("MODEL_FROM_MONGO", "1").strip() == "1"
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.environ.get("MONGO_DB", "network_ids").strip()
MONGO_MODELS_COLLECTION = os.environ.get("MONGO_MODELS_COLLECTION", "models").strip()

def _get_model_data_from_mongo():
    """Fetch the latest model and classes from MongoDB."""
    print(f"Checking Mongo: URI={MONGO_URI}, DB={MONGO_DB}, COL={MONGO_MODELS_COLLECTION}")
    if not MODEL_FROM_MONGO:
        print("MODEL_FROM_MONGO is False")
        return None, None

    try:
        from pymongo import MongoClient
        print("Imported pymongo successfully")
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        db = client[MONGO_DB]
        col = db[MONGO_MODELS_COLLECTION]
        
        # Get the latest model document
        print("Querying for latest document...")
        doc = col.find_one(sort=[("timestamp", -1)])
        if not doc:
            print("No document found in collection.")
            return None, None
            
        print("Document found.")
        classes = doc.get("classes")
        print(f"Classes type: {type(classes)}")
        print(f"Classes truthiness: {bool(classes)}")
        if isinstance(classes, list):
            print(f"Classes length: {len(classes)}")
        
        return doc.get("model_bytes"), classes
    except Exception as e:
        print(f"Warning: Could not load model from MongoDB: {e}")
        import traceback
        traceback.print_exc()
        return None, None

def _get_onnx_classes():
    # Try Mongo first
    _, classes = _get_model_data_from_mongo()
    if classes:
        print("Classes found in Mongo.")
        return classes
        
    print("Classes NOT found in Mongo (or evaluated to False).")
    return None

if __name__ == "__main__":
    try:
        result = _get_onnx_classes()
        if result:
            print("SUCCESS: _get_onnx_classes returned data.")
        else:
            print("FAILURE: _get_onnx_classes returned None.")
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")
