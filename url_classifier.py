import pandas as pd
import numpy as np
import re
import math
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

# ==========================================
# 1. ADVANCED FEATURE ENGINEERING
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
    url_lower = url.lower()
    
    # --- 1. Lexical Features (Structural Analysis) ---
    features['url_length'] = len(url)
    features['count_dot'] = url.count('.')
    features['count_hyphen'] = url.count('-')
    features['count_special'] = url.count('@') + url.count('%') + url.count('?')
    
    # --- 2. Chaos (Shannon Entropy) ---
    features['entropy'] = calculate_entropy(url)
    
    # --- 3. IP Address Detection ---
    ip_pattern = r'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
    features['has_ip'] = 1 if re.search(ip_pattern, url) else 0

    # --- 4. BRAND IMPERSONATION (The Heavy 50 List) ---
    # List of high-value targets frequently spoofed (Global + Indian Context)
    target_brands = [
        # --- GLOBAL TECH & SOCIAL ---
        'google', 'amazon', 'apple', 'facebook', 'netflix', 'paypal', 'microsoft',
        'instagram', 'whatsapp', 'linkedin', 'twitter', 'tiktok', 'adobe',
        'dropbox', 'zoom', 'slack', 'shopify', 'spotify', 'reddit', 'pinterest',
        'snapchat', 'telegram', 'yahoo', 'bing', 'ebay',

        # --- BANKING & FINANCE (Global) ---
        'chase', 'wellsfargo', 'citi', 'hsbc', 'barclays', 'coinbase', 'binance',
        'kraken', 'mastercard', 'visa',

        # --- INDIAN CRITICAL INFRASTRUCTURE ---
        'sbi', 'hdfc', 'icici', 'axis', 'paytm', 'phonepe', 'razorpay',
        'flipkart', 'zomato', 'swiggy', 'irctc', 'indiapost',

        # --- LOGISTICS & UTILITIES ---
        'dhl', 'fedex', 'ups', 'usps', 'bluedart', 'delhivery', 'maersk'
    ]
    
    features['brand_impersonation'] = 0
    
    try:
        # Extract just the domain part (e.g., 'google.com' from 'http://google.com/login')
        domain = urlparse(url).netloc
        if not domain: domain = url
    except:
        domain = url

    for brand in target_brands:
        # Logic: If the brand name appears in the URL...
        if brand in url_lower:
            # ...BUT the domain is NOT one of the official ones
            official_domains = [
                f"{brand}.com", f"www.{brand}.com", 
                f"{brand}.co.in", f"www.{brand}.co.in", 
                f"{brand}.org", f"{brand}.net", f"{brand}.io"
            ]
            
            # If the domain is NOT in the official list, it's an imposter
            if domain not in official_domains:
                features['brand_impersonation'] = 1  # FLAGGED!

    # --- 5. Suspicious Keywords ---
    suspicious_words = ['login', 'verify', 'update', 'secure', 'gift', 'bonus', 'free', 'signin', 'bank', 'alert', 'account']
    features['suspicious_keywords'] = sum(1 for word in suspicious_words if word in url_lower)
    
    return features

# ==========================================
# 2. DATASET GENERATION
# ==========================================
def generate_synthetic_data():
    print("[INFO] Generating synthetic training data (v3.1 - Expanded Brand List)...")
    
    # 1. SAFE URLs
    safe_urls = [
        'http://google.com', 'https://www.google.com', 'https://amazon.com', 'https://apple.com',
        'https://netflix.com', 'https://wikipedia.org', 'https://github.com', 'https://bbc.co.uk',
        'https://sbi.co.in', 'https://irctc.co.in', 'https://flipkart.com', 'https://hdfcbank.com'
    ] * 50
    
    # 2. MALICIOUS: Brand Imposters (Testing the new list)
    malicious_imposters = [
        'http://googlexyx.com', 'http://googie.com', 'http://amazon-secure.net',
        'http://apple-id-verify.com', 'http://netflix-payment-update.xyz',
        'http://sbi-kyc-update.com', 'http://paytm-cashback-offer.xyz', 
        'http://irctc-booking-refund.net', 'http://flipkart-big-billion-free.com',
        'http://googl-e.com', 'http://xyx-randomgift.com'
    ] * 30
    
    # 3. MALICIOUS: High Entropy & IP
    malicious_tech = [
        'http://192.168.1.1/login', 'http://x83-z92.org', 'http://a1b2c3d4.net',
        'http://secure-login-88.xyz'
    ] * 30
    
    data = []
    
    for url in safe_urls:
        f = extract_features(url)
        f['label'] = 0
        data.append(f)
        
    for url in malicious_imposters + malicious_tech:
        f = extract_features(url)
        f['label'] = 1
        data.append(f)
        
    return pd.DataFrame(data)

if __name__ == "__main__":
    # Train
    df = generate_synthetic_data()
    X = df.drop('label', axis=1)
    y = df['label']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("[INFO] Training Brand-Aware Model...")
    model = RandomForestClassifier(n_estimators=100)
    model.fit(X_train, y_train)
    
    print(f"[INFO] Model Accuracy: {accuracy_score(y_test, model.predict(X_test))*100:.2f}%")
    
    # Scanner
    print("\n" + "="*50)
    print("   MALICIOUS URL SCANNER v3.1 (Brand-Aware)")
    print("="*50)
    
    while True:
        url = input("\nEnter URL (or 'exit'): ").strip()
        if url == 'exit': break
        if not url: continue
        
        # Predict
        feats = extract_features(url)
        features_df = pd.DataFrame([feats])
        prediction = model.predict(features_df)[0]
        
        # Diagnostics
        print(f"   [Debug] Brand Impersonation: {feats['brand_impersonation']} | Suspicious Words: {feats['suspicious_keywords']} | Entropy: {feats['entropy']:.2f}")
        
        if prediction == 1:
            print(f">>> Result: MALICIOUS 🚨")
        else:
            print(f">>> Result: SAFE ✅")