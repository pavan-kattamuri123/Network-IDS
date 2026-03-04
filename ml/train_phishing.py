import pandas as pd
import numpy as np
import joblib
import os
import sys
import tldextract
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier

# Feature Extraction Function (Must match phishing_detector.py EXACTLY)
def extract_features_from_url(url):
    try:
        parsed = urlparse(url)
        ext = tldextract.extract(url)
        domain = parsed.netloc
        path = parsed.path
        
        return [
            len(url),                   # quantity_url_char
            url.count('.'),             # qty_dot_url
            url.count('-'),             # qty_hyphen_url
            url.count('@'),             # qty_at_url
            url.count('?'),             # qty_questionmark_url
            url.count('='),             # qty_equal_url
            url.count('%'),             # qty_percent_url
            url.count('/'),             # qty_slash_url
            1 if parsed.scheme == "https" else 0, # tls_ssl_certificate
            len(domain),                # domain_length
            domain.count('.'),          # qty_dot_domain
            domain.count('-'),          # qty_hyphen_domain
            1 if any(c.isdigit() for c in domain) else 0, # domain_in_ip (simplified)
            len(path),                  # path_length
            path.count('/'),            # qty_slash_path
            path.count('.'),            # qty_dot_path
            path.count('-'),            # qty_hyphen_path
            1 if "server" in url.lower() or "client" in url.lower() else 0 # simple keyword
        ]
    except:
        return [0] * 18

feature_names = [
    "url_len", "dot_url", "hyphen_url", "at_url", "qmark_url", "equal_url", "percent_url", "slash_url",
    "is_https", "domain_len", "dot_domain", "hyphen_domain", "has_digits_domain",
    "path_len", "slash_path", "dot_path", "hyphen_path", "has_sus_keywords"
]

def train_phishing_models():
    print("Loading datasets...")
    # Paths adjusted for 'docs/' directory
    dataset_path = os.path.join("docs", "dataset_full.csv")
    urls_path = os.path.join("docs", "phishing_site_urls.csv") 

    # We will use phishing_site_urls.csv because it's just URLs and Labels, 
    # allowing us to compute OUR OWN features that match the detector.
    # The 'dataset_full.csv' has pre-computed features which might differ from our extraction logic.
    
    if os.path.exists(urls_path):
        print(f"Using {urls_path} for training (Raw URLs)...")
        df = pd.read_csv(urls_path)
    else:
        print(f"Error: {urls_path} not found.")
        return

    # Sample for speed (optional, but good for quick feedback)
    df = df.sample(n=20000, random_state=42) 
    print(f"Dataset loaded: {len(df)} records (Sampled for speed)")
    
    # Compute features
    print("Extracting features (this may take a moment)...")
    X = np.array([extract_features_from_url(url) for url in df["URL"]])
    y = (df["Label"] == "bad").astype(int) # 'bad' is phishing in this dataset usually

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    # Scale
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    print("Training Random Forest...")
    rf = RandomForestClassifier(n_estimators=50, max_depth=15, random_state=42)
    rf.fit(X_train, y_train)

    print("Training XGBoost...")
    xgb = XGBClassifier(
        n_estimators=50,
        max_depth=6,
        learning_rate=0.1,
        eval_metric="logloss",
        use_label_encoder=False,
        random_state=42
    )
    xgb.fit(X_train, y_train)

    print("Training LightGBM...")
    lgbm = LGBMClassifier(
        n_estimators=50,
        max_depth=6,
        learning_rate=0.1,
        random_state=42,
        verbose=-1
    )
    lgbm.fit(X_train, y_train)

    # Save everything
    models_dir = os.path.join("ml", "models")
    os.makedirs(models_dir, exist_ok=True)
    
    print("Saving models...")
    joblib.dump(rf, os.path.join(models_dir, "phishing_rf.pkl"))
    joblib.dump(xgb, os.path.join(models_dir, "phishing_xgb.pkl"))
    joblib.dump(lgbm, os.path.join(models_dir, "phishing_lgbm.pkl"))
    joblib.dump(scaler, os.path.join(models_dir, "phishing_scaler.pkl"))
    joblib.dump(feature_names, os.path.join(models_dir, "phishing_features.pkl"))

    print("Training complete and models saved to ml/models/")

if __name__ == "__main__":
    train_phishing_models()
