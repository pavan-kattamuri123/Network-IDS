import sys
import os
# Prevent creation of __pycache__ and .pyc files
sys.dont_write_bytecode = True

import pandas as pd
import json
from functools import lru_cache

try:
    import numpy as np
    import onnxruntime as ort
except Exception:
    np = None
    ort = None

# Manually load .env if it exists (robust against PowerShell UTF-16/null bytes)
def load_env(path):
    if not os.path.exists(path):
        return False
    try:
        with open(path, "rb") as f:
            header = f.read(2)
            f.seek(0)
            content = f.read().decode('utf-16' if header == b'\xff\xfe' else 'utf-8', errors='ignore')
            content = content.replace('\x00', '')
            for line in content.splitlines():
                if "=" in line and not line.strip().startswith("#"):
                    key, value = line.strip().split("=", 1)
                    if key.strip() not in os.environ: # Don't overwrite existing
                        os.environ[key.strip()] = value.strip().strip('"').strip("'")
        return True
    except Exception as e:
        print(f"Warning: Could not parse {path}: {e}")
        return False

# Try loading .env from CWD or parent directory
if not load_env(".env"):
    load_env(os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"))


# Model Configuration
MODEL_FROM_MONGO = os.environ.get("MODEL_FROM_MONGO", "1").strip() == "1"
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.environ.get("MONGO_DB", "network_ids").strip()
MONGO_MODELS_COLLECTION = os.environ.get("MONGO_MODELS_COLLECTION", "models").strip()

ONNX_MODEL_PATH = "models/rf_model.onnx"
ONNX_LABELS_PATH = "models/label_classes.json"

@lru_cache(maxsize=1)
def _get_model_data_from_mongo():
    """Fetch the latest model and classes from MongoDB."""
    if not MODEL_FROM_MONGO:
        return None, None

    try:
        from pymongo import MongoClient
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        db = client[MONGO_DB]
        col = db[MONGO_MODELS_COLLECTION]
        
        # Get the latest model document
        doc = col.find_one(sort=[("timestamp", -1)])
        if not doc:
            print(f"Warning: Connected to MongoDB ({MONGO_URI}) but found NO documents in '{MONGO_DB}.{MONGO_MODELS_COLLECTION}'.")
            return None, None
            
        return doc.get("model_bytes"), doc.get("classes")
    except Exception as e:
        print(f"Error loading model from MongoDB: {e}")
        # If we expect to load from Mongo, this is critical.
        # But we return None to allow fallback if intended.
        return None, None

@lru_cache(maxsize=1)
def _get_onnx_classes():
    # Try Mongo first
    global MODEL_FROM_MONGO
    if MODEL_FROM_MONGO:
        _, classes = _get_model_data_from_mongo()
        if classes:
            return classes
        # If Mongo failed (returned None) but was requested, we might want to know why.
        # But for now, let's proceed to fallback.
        
    # Fallback to local
    if os.path.exists(ONNX_LABELS_PATH):
        with open(ONNX_LABELS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
            
    # If we reached here, both sources failed.
    msg = "Model labels not found."
    if MODEL_FROM_MONGO:
        msg += " MongoDB load failed (check console for connection errors) or collection is empty."
    if not os.path.exists(ONNX_LABELS_PATH):
        msg += f" Local file '{ONNX_LABELS_PATH}' also not found."
    raise FileNotFoundError(msg)

@lru_cache(maxsize=1)
def _get_onnx_session():
    if not ort:
        raise RuntimeError("onnxruntime is not available. Install with: pip install onnxruntime")

    # Try Mongo first
    model_bytes, _ = _get_model_data_from_mongo()
    if model_bytes:
        return ort.InferenceSession(model_bytes, providers=["CPUExecutionProvider"])
        
    # Fallback to local
    if os.path.exists(ONNX_MODEL_PATH):
        return ort.InferenceSession(ONNX_MODEL_PATH, providers=["CPUExecutionProvider"])
        
    raise FileNotFoundError("Model file not found in MongoDB or local storage.")

def predict_attack(csv_path):
    # Read specifically as float32 to halve memory and boost processing speed
    # We load everything quickly and only parse columns that might be strings where necessary
    df = pd.read_csv(csv_path)
    
    # Strip column names inplace
    df.columns = df.columns.str.strip()
    
    # Drop label column instantly if it exists
    if 'Label' in df.columns:
        df.drop('Label', axis=1, inplace=True)
        
    # Convert all columns to float32 much faster using vectorization
    df = df.apply(pd.to_numeric, errors='coerce').astype(np.float32)

    # Vectorized replacements for extremely fast NaN/Inf handling
    df.replace([np.inf, -np.inf], 0, inplace=True)
    df.fillna(0, inplace=True)

    classes = _get_onnx_classes()
    sess = _get_onnx_session()
    
    input_name = sess.get_inputs()[0].name
    expected_features = sess.get_inputs()[0].shape[1]
    
    if expected_features is not None and df.shape[1] != expected_features:
        raise ValueError(
            f"Input CSV has {df.shape[1]} features, but model expects {expected_features}."
        )

    # Convert directly to continuous contiguous array for maximum ONNX execution speed
    x = np.ascontiguousarray(df.to_numpy(dtype=np.float32))
    outputs = sess.run(None, {input_name: x})
    preds = outputs[0]

    return [classes[int(i)] for i in preds]
