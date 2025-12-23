import sys
import os
# Prevent creation of __pycache__ and .pyc files
sys.dont_write_bytecode = True

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import os
import json
import datetime
from pymongo import MongoClient

# Optional (replacement for .pkl): save model to ONNX + labels to JSON
try:
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType
except Exception:
    convert_sklearn = None
    FloatTensorType = None

def train():
    print("Loading dataset...")
    df = pd.read_csv("dataset/network_data.csv")

    # Clean column names (remove spaces)
    df.columns = df.columns.str.strip()
    
    # Handle basic preprocessing
    # Encode label
    le = LabelEncoder()
    df['Label'] = le.fit_transform(df['Label'])
    
    # Save label encoder for later use in prediction (to map back if needed, or just predict classes)
    # For this simple example we just train and save model. 
    # Ideally we should save the encoder too, but the user didn't ask for it explicitly. 
    # We will assume predict uses the same model.
    # We need to handle categorical features if any. 
    # CICIDS 2017 is mostly numerical except Label. 
    # Just in case, we apply basic cleaning.
    
    # Drop infinite values or NaNs
    df.replace([float('inf'), -float('inf')], 0, inplace=True)
    df.fillna(0, inplace=True)
    
    # Force numeric conversion for features
    for col in df.columns:
        if col != 'Label':
             df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    X = df.drop('Label', axis=1)
    y = df['Label']

    print(f"Training with {len(X)} records...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Prepare data for MongoDB
    classes = le.classes_.tolist()
    model_bytes = None

    if convert_sklearn and FloatTensorType:
        initial_type = [("float_input", FloatTensorType([None, X_train.shape[1]]))]
        onnx_model = convert_sklearn(model, initial_types=initial_type)
        model_bytes = onnx_model.SerializeToString()
        print("ONNX model generated successfully.")
    else:
        print("skl2onnx not installed; skipped ONNX generation.")
        return

    # Upload to MongoDB Atlas
    # Manually load .env for MongoDB URI
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

    uri = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
    db_name = os.environ.get("MONGO_DB", "network_ids").strip()
    col_name = os.environ.get("MONGO_MODELS_COLLECTION", "models").strip()

    print(f"Uploading model to MongoDB: {db_name}...")
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=10000)
        db = client[db_name]
        col = db[col_name]
        
        doc = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc),
            "model_bytes": model_bytes,
            "classes": classes,
            "filename": "rf_model.onnx"
        }
        
        col.delete_many({}) # Clear old models
        col.insert_one(doc)
        print("Model successfully uploaded to MongoDB Atlas!")
    except Exception as e:
        print(f"Error uploading model: {e}")

    # Print classes safely on Windows consoles (ASCII-only)
    print("Classes:", json.dumps(classes, ensure_ascii=True))

if __name__ == "__main__":
    train()
