# Malicious URL Classifier 

![Python](https://img.shields.io/badge/Python-3.x-blue.svg) ![License](https://img.shields.io/badge/License-MIT-green.svg) ![Status](https://img.shields.io/badge/Status-Prototype-orange.svg)

**A Supervised Machine Learning engine to detect Zero-Day Phishing attacks, DGA domains, and Brand Impersonation attempts in real-time.**

---

## 📌 Project Overview
Traditional firewalls rely on **static blocklists** (blacklisting). If a hacker creates a new URL today, it takes hours for blocklists to update, leaving users vulnerable. 

This project moves from **Reactive Matching** to **Proactive Prediction**. It analyzes the *structure* and *mathematical properties* of a URL to flag malicious intent instantly—even if the URL has never been seen before.

## 🚀 Key Features (v3.1)
- **🧠 Shannon Entropy Analysis:** Calculates the "Chaos Score" of a domain to detect bot-generated DGA links (e.g., `x83-z92-q11.net`).
- **🛡️ Brand Impersonation Defense:** Protects **50+ High-Value Targets** (Google, SBI, Amazon, IRCTC, etc.) by flagging spoofed domains (e.g., `sbi-kyc-update.com`).
- **🔍 IP-Based Threat Detection:** Identifies raw IP usage in URLs, a common indicator of malware hosting.
- **⚡ Real-Time Scanning:** Classifies URLs in <50ms using a lightweight Random Forest model.

## 🛠️ Technology Stack
- **Language:** Python 3.x
- **ML Engine:** Scikit-Learn (Random Forest Classifier)
- **Data Processing:** Pandas, NumPy, RegEx
- **Feature Engineering:** Shannon Entropy, Lexical Analysis

## ⚙️ How to Run Locally

1. **Clone the Repository**
   ```bash
   git clone [https://github.com/deepuramesh/Malicious-URL-Classifier.git](https://github.com/deepuramesh/Malicious-URL-Classifier.git)
   cd Malicious-URL-Classifier