import pandas as pd
import numpy as np
import re
import math
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import matplotlib.pyplot as plt
import seaborn as sns

# ==========================================
# 1. FEATURE ENGINEERING (The Detective Work)
# ==========================================
def calculate_entropy(text):
    if not text:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x))) / len(text)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def extract_features(url):
    features = {}
    features['url_length'] = len(url)
    try:
        hostname = urlparse(url).netloc
    except:
        hostname = url
    features['hostname_length'] = len(hostname) if hostname else 0
    features['count_dot'] = url.count('.')
    features['count_hyphen'] = url.count('-')
    features['count_at'] = url.count('@')
    features['count_question'] = url.count('?')
    features['count_percent'] = url.count('%')
    ip_pattern = r'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
    features['has_ip'] = 1 if re.search(ip_pattern, url) else 0
    features['entropy'] = calculate_entropy(url)
    return features

# ==========================================
# 2. SYNTHETIC DATA & TRAINING
# ==========================================
def generate_synthetic_data():
    print("[INFO] Generating synthetic training data...")
    # Safe sites
    safe_urls = ['http://google.com', 'https://youtube.com', 'https://wikipedia.org', 'https://amazon.com', 'https://bbc.co.uk'] * 20
    # Malicious sites (high entropy, weird chars)
    malicious_urls = ['http://secure-login.com', 'http://x83-bank.xyz', 'http://192.168.1.55/login', 'http://free-iphone.net', 'http://verify-account-now.com'] * 20
    
    data = []
    for url in safe_urls:
        f = extract_features(url)
        f['label'] = 0 # Safe
        data.append(f)
    for url in malicious_urls:
        f = extract_features(url)
        f['label'] = 1 # Malicious
        data.append(f)
    return pd.DataFrame(data)

if __name__ == "__main__":
    # Load and Train
    df = generate_synthetic_data()
    X = df.drop('label', axis=1)
    y = df['label']
    
    # Split Data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train Model
    print("[INFO] Training Random Forest Model...")
    model = RandomForestClassifier(n_estimators=100)
    model.fit(X_train, y_train)
    
    # Show Accuracy
    acc = accuracy_score(y_test, model.predict(X_test))
    print(f"[INFO] Model Accuracy: {acc*100:.2f}%")

    # Scanner Loop
    print("\n" + "="*40)
    print("   MALICIOUS URL SCANNER READY")
    print("="*40)
    
    while True:
        url = input("\nEnter a URL to scan (or 'exit'): ").strip()
        if url == 'exit': break
        if not url: continue
        
        # Predict
        features = pd.DataFrame([extract_features(url)])
        prediction = model.predict(features)[0]
        
        # Result
        if prediction == 1:
            print(f">>> Result: MALICIOUS 🚨 (Entropy: {features['entropy'][0]:.2f})")
        else:
            print(f">>> Result: SAFE ✅ (Entropy: {features['entropy'][0]:.2f})")