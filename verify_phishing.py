from ml.phishing_detector import predict_url
import sys

# Test cases
urls = [
    "http://google.com",  # Legitimate
    "http://paypal.com-login-verify-account.security-update.gq/login.php", # Phishing
    "http://192.168.1.1/login", # IP address (Phishing rule)
    "https://microsoft.com", # Legitimate
]

print("Verifying Phishing Detector...")
for url in urls:
    prob, verdict, reasons = predict_url(url)
    print(f"\nURL: {url}")
    print(f"Verdict: {verdict} ({prob:.2%})")
    print(f"Reasons: {reasons}")

if prob == 0.0 and verdict == "Error":
    print("\nFAILURE: Prediction raised an error.")
    sys.exit(1)

print("\nSUCCESS: Verification complete.")
