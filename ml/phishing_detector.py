import re
import math
import difflib
import os
import joblib
import pandas as pd
import numpy as np
import tldextract
import wordfreq
from collections import Counter
from urllib.parse import urlparse

# --- Configuration & Model Loading ---
MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")
MODELS_LOADED = False
rf, xgb, lgbm, scaler, feature_names = None, None, None, None, None

def load_models():
    global rf, xgb, lgbm, scaler, feature_names, MODELS_LOADED
    try:
        rf = joblib.load(os.path.join(MODELS_DIR, "phishing_rf.pkl"))
        xgb = joblib.load(os.path.join(MODELS_DIR, "phishing_xgb.pkl"))
        lgbm = joblib.load(os.path.join(MODELS_DIR, "phishing_lgbm.pkl"))
        scaler = joblib.load(os.path.join(MODELS_DIR, "phishing_scaler.pkl"))
        feature_names = joblib.load(os.path.join(MODELS_DIR, "phishing_features.pkl"))
        MODELS_LOADED = True
        print("Phishing ML models loaded successfully.")
    except FileNotFoundError:
        print("Warning: Phishing ML models not found. Running in Heuristic-Only mode.")
    except Exception as e:
        print(f"Error loading phishing models: {e}")

# Initial load attempt
load_models()

# --- Heuristic Functions ---

def shannon_entropy(s):
    if not s: return 0
    probs = [n / len(s) for n in Counter(s).values()]
    return -sum(p * math.log2(p) for p in probs)

def vowel_ratio(domain):
    vowels = sum(1 for c in domain if c in "aeiou")
    return vowels / max(len(domain), 1)

def max_consecutive_consonants(domain):
    count = max_count = 0
    for c in domain:
        if c.isalpha() and c not in "aeiou":
            count += 1
            max_count = max(max_count, count)
        else:
            count = 0
    return max_count

def get_domain_token(url):
    try:
        domain = urlparse(url).netloc.lower().replace("www.", "")
        return domain.split(".")[0]
    except:
        return ""

def is_typosquatting_domain(url):
    token = get_domain_token(url)
    if len(token) < 5:
        return False

    for word in wordfreq.top_n_list("en", 5000):
        similarity = difflib.SequenceMatcher(None, token, word).ratio()
        if 0.88 < similarity < 0.99:
            return True
    return False

def universal_rule_check(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")
        path = parsed.path.lower()
        
        # Reason list for feedback
        reasons = []

        if re.search(r"\d+\.\d+\.\d+\.\d+", domain):
            reasons.append("IP Address in domain")

        if is_typosquatting_domain(url):
            reasons.append("Potential Typosquatting detected")

        if shannon_entropy(domain) > 4.2:
            reasons.append("High entropy domain name (random characters)")

        if vowel_ratio(domain) < 0.25:
             reasons.append("Low vowel ratio (unpronounceable)")

        if max_consecutive_consonants(domain) >= 6: 
             reasons.append("Long sequence of consonants")

        if len(domain) > 30:
             reasons.append("Domain name suspiciously long")

        return (True, reasons) if reasons else (False, [])
        
    except Exception as e:
        print(f"Error in rule check: {e}")
        return False, ["Error analyzing URL"]

def extract_features_from_url(url):
    # MUST MATCH train_phishing.py logic EXACTLY
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
            1 if any(c.isdigit() for c in domain) else 0, # domain_in_ip
            len(path),                  # path_length
            path.count('/'),            # qty_slash_path
            path.count('.'),            # qty_dot_path
            path.count('-'),            # qty_hyphen_path
            1 if "server" in url.lower() or "client" in url.lower() else 0 # has_sus_keywords
        ]
    except:
        return [0] * 18

def predict_url(url):
    """
    Predicts if a URL is phishing or legitimate.
    Returns: (probability, verdict, reasons)
    """
    # 1. Normalize
    if not url.startswith("http"):
        url = "http://" + url
        
    # 2. Rule-based Checks
    is_sus, reasons = universal_rule_check(url)
    if is_sus:
        return 0.95, "Phishing", reasons

    # 3. ML Model Prediction
    if MODELS_LOADED and feature_names:
        try:
            features_list = extract_features_from_url(url)
            # Ensure 2D array for transform
            features_df = pd.DataFrame([features_list], columns=feature_names)
            features_scaled = scaler.transform(features_df)

            p_rf = rf.predict_proba(features_scaled)[0][1]
            p_xgb = xgb.predict_proba(features_scaled)[0][1]
            p_lgbm = lgbm.predict_proba(features_scaled)[0][1]
            
            avg_prob = (p_rf + p_xgb + p_lgbm) / 3
            
            verdict = "Phishing" if avg_prob > 0.6 else "Legitimate"
            reason = [f"ML Model Confidence: {avg_prob:.2%}"] if verdict == "Phishing" else ["Safe"]
            
            return float(avg_prob), verdict, reason
            
        except Exception as e:
            print(f"ML Prediction failed: {e}")
            return 0.0, "Error", [str(e)]
    
    # 4. Fallback if no ML and no rules triggered
    return 0.1, "Legitimate", ["Passed heuristic checks (ML models not loaded)"]
