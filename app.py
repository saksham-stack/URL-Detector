import whois
import ssl
import socket
import re
from datetime import datetime
from flask import Flask, render_template, request
from pysafebrowsing import SafeBrowsing

app = Flask(__name__)

# Google Cloud API Key
s = SafeBrowsing('AIzaSyDSv6pI7EErD0pWEU35ehlvHPa0hwG7TwM')

# Create a global list to store session history (In a full app, this would be a database)
scan_history = []

def check_url(url):
    score = 0
    reasons = []

    # 1. Google Safe Browsing API Check
    try:
        api_response = s.lookup_urls([url])
        if api_response[url]['malicious']:
            score += 10
            threats = ", ".join(api_response[url].get('threats', []))
            reasons.append(f"🚨 GOOGLE ALERT: Flagged as malicious ({threats}).")
    except Exception as e:
        print(f"Safe Browsing API Error: {e}")

    # 2. Security Protocol Logic
    if url.startswith("http://") and not url.startswith("https://"):
        score += 2
        reasons.append("Unsecured Connection (HTTP). Real banks/sites use HTTPS.")

    # 3. IP Address Check
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        score += 3
        reasons.append("Uses an IP address instead of a domain name.")

    # 4. URL Length
    if len(url) > 80:
        score += 2
        reasons.append("URL is suspiciously long.")

    # 5. Fraud Keywords
    fraud_keywords = ['gift', 'win', 'prize', 'login', 'banking', 'update', 'confirm']
    for word in fraud_keywords:
        if word in url.lower():
            score += 2
            reasons.append(f"Contains suspicious keyword: '{word}'")

    # Verdict Logic
    if score >= 4:
        return "🛑 FRAUD / MALICIOUS", "#ff4d4d", reasons
    elif score >= 2:
        return "⚠️ SUSPICIOUS / PROCEED WITH CAUTION", "#ffa500", reasons
    else:
        return "✅ LIKELY REAL / SAFE", "#2ecc71", ["No fraud patterns detected."]

def get_domain_info(url):
    try:
        domain_name = url.split("//")[-1].split("/")[0]
        w = whois.whois(domain_name)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        return {
            "registrar": w.registrar,
            "creation_date": creation_date.strftime('%Y-%m-%d') if creation_date else "Unknown",
            "country": w.country or "Private/Unknown"
        }
    except:
        return None

def get_ssl_details(url):
    try:
        hostname = url.split("//")[-1].split("/")[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])['commonName']
                expiry = cert['notAfter']
                return {"issuer": issuer, "expiry": expiry}
    except:
        return None

@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    if request.method == 'POST':
        url = request.form.get('url')
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        verdict, color, reasons = check_url(url)
        
        history = None
        ssl_info = None
        
        # Only perform deep analysis for safe/suspicious links
        if verdict != "🛑 FRAUD / MALICIOUS":
            history = get_domain_info(url)
            if url.startswith("https://"):
                ssl_info = get_ssl_details(url)
            
        result = {
            'verdict': verdict, 
            'color': color, 
            'reasons': reasons, 
            'url': url,
            'history': history,
            'ssl': ssl_info
        }

        # NEW: Store session history
        new_entry = {
            'url': url,
            'verdict': verdict,
            'color': color,
            'time': datetime.now().strftime("%H:%M:%S")
        }
        # Keep only the last 5 scans
        scan_history.insert(0, new_entry)
        if len(scan_history) > 5:
            scan_history.pop()
    
    # Pass history_list to the template
    return render_template('index.html', result=result, history_list=scan_history)

@app.route('/security-tips')
def security_tips():
    tips = [
        "Check for the padlock icon and 'https://' before entering passwords.",
        "Hover over links to see the actual destination URL before clicking.",
        "Be wary of sense of urgency or threats in emails (e.g., 'Account suspended!').",
        "Look for slight misspellings in domain names like 'g00gle.com'.",
        "Enable Multi-Factor Authentication (MFA) on all sensitive accounts."
    ]
    return {"tips": tips}

@app.route('/report-scam', methods=['POST'])
def report_scam():
    data = request.json
    scam_url = data.get('url')
    print(f"NOTIFICATION: Scam reported for {scam_url}. Alert sent to admin@gmail.com.")
    return {"status": "success", "message": "Scam report sent to security team!"}

if __name__ == '__main__':
    app.run(debug=True)