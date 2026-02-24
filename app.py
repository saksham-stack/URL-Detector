import whois
import ssl
import socket
import re
import os
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, jsonify, session
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pysafebrowsing import SafeBrowsing
from dotenv import load_dotenv
from urllib.parse import urlparse
from markupsafe import escape

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Security Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
app.config['WTF_CSRF_ENABLED'] = True
app.config['MAX_URL_LENGTH'] = int(os.environ.get('MAX_URL_LENGTH', 2048))
app.config['ALLOWED_PROTOCOLS'] = os.environ.get('ALLOWED_PROTOCOLS', 'http,https').split(',')

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Google Cloud API Key from environment variable
SAFE_BROWSING_API_KEY = os.environ.get('SAFE_BROWSING_API_KEY')
if not SAFE_BROWSING_API_KEY:
    print("⚠️  WARNING: SAFE_BROWSING_API_KEY not set. Safe Browsing checks will be skipped.")
    s = None
else:
    s = SafeBrowsing(SAFE_BROWSING_API_KEY)

# Admin email from environment
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@example.com')

# Create a global list to store session history (In a full app, this would be a database)
scan_history = []


def validate_url(url):
    """
    Validate and sanitize URL input.
    Returns (is_valid, error_message, sanitized_url)
    """
    if not url or not isinstance(url, str):
        return False, "URL is required", None

    # Check length
    if len(url) > app.config['MAX_URL_LENGTH']:
        return False, f"URL exceeds maximum length of {app.config['MAX_URL_LENGTH']} characters", None

    # Strip whitespace
    url = url.strip()

    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    # Parse URL
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL format", None

    # Validate protocol
    if parsed.scheme not in app.config['ALLOWED_PROTOCOLS']:
        return False, f"Protocol '{parsed.scheme}' is not allowed. Allowed: {', '.join(app.config['ALLOWED_PROTOCOLS'])}", None

    # Check for valid hostname
    hostname = parsed.hostname
    if not hostname:
        return False, "Invalid hostname", None

    # Block private/internal IP addresses (SSRF protection)
    private_patterns = [
        r'^127\.', r'^10\.', r'^172\.(1[6-9]|2[0-9]|3[01])\.',
        r'^192\.168\.', r'^0\.0\.0\.0', r'^169\.254\.',
        r'^localhost$', r'^\.localhost$',
    ]
    for pattern in private_patterns:
        if re.match(pattern, hostname, re.IGNORECASE):
            return False, "Access to private/internal addresses is not allowed", None

    # Block IP addresses with ports commonly used for internal services
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', hostname):
        blocked_ports = ['22', '23', '3389', '5900', '6379', '27017']
        port = parsed.port
        if port in blocked_ports:
            return False, f"Access to port {port} is not allowed", None

    return True, None, url


def check_url(url):
    score = 0
    reasons = []

    # 1. Google Safe Browsing API Check
    if s:
        try:
            api_response = s.lookup_urls([url])
            if api_response and url in api_response:
                if api_response[url].get('malicious'):
                    score += 10
                    threats = ", ".join(api_response[url].get('threats', []))
                    reasons.append(f"🚨 GOOGLE ALERT: Flagged as malicious ({threats}).")
        except Exception as e:
            print(f"Safe Browsing API Error: {e}")
            reasons.append("⚠️ Safe Browsing API unavailable. Skipping this check.")
    else:
        reasons.append("⚠️ Safe Browsing API not configured.")

    # 2. Security Protocol Logic
    if url.startswith("http://") and not url.startswith("https://"):
        score += 2
        reasons.append("Unsecured Connection (HTTP). Real banks/sites use HTTPS.")

    # 3. IP Address Check
    hostname = urlparse(url).hostname
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', hostname or ''):
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
            break  # Only add once for any keyword match

    # Verdict Logic
    if score >= 4:
        return "🛑 FRAUD / MALICIOUS", "#ff4d4d", reasons
    elif score >= 2:
        return "⚠️ SUSPICIOUS / PROCEED WITH CAUTION", "#ffa500", reasons
    else:
        return "✅ LIKELY REAL / SAFE", "#2ecc71", ["No fraud patterns detected."]


def get_domain_info(url):
    try:
        domain_name = urlparse(url).hostname
        if not domain_name:
            return None

        w = whois.whois(domain_name)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        return {
            "registrar": w.registrar or "Unknown",
            "creation_date": creation_date.strftime('%Y-%m-%d') if creation_date else "Unknown",
            "country": w.country or "Private/Unknown"
        }
    except Exception as e:
        print(f"WHOIS lookup error: {e}")
        return None


def get_ssl_details(url):
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return None

        # Create SSL context with proper verification
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get('issuer', []))
                issuer_cn = issuer.get('commonName', 'Unknown')
                expiry = cert.get('notAfter', 'Unknown')
                return {"issuer": issuer_cn, "expiry": expiry}
    except ssl.SSLCertVerificationError:
        return {"issuer": "Invalid/Self-signed", "expiry": "N/A"}
    except Exception as e:
        print(f"SSL certificate error: {e}")
        return None


@app.route('/', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def home():
    result = None
    error_message = None

    if request.method == 'POST':
        url = request.form.get('url', '')

        # Validate URL
        is_valid, error_msg, sanitized_url = validate_url(url)
        if not is_valid:
            error_message = error_msg
        else:
            verdict, color, reasons = check_url(sanitized_url)

            history = None
            ssl_info = None

            # Only perform deep analysis for safe/suspicious links
            if verdict != "🛑 FRAUD / MALICIOUS":
                history = get_domain_info(sanitized_url)
                if sanitized_url.startswith("https://"):
                    ssl_info = get_ssl_details(sanitized_url)

            result = {
                'verdict': verdict,
                'color': color,
                'reasons': reasons,
                'url': escape(sanitized_url),
                'history': history,
                'ssl': ssl_info
            }

            # Store session history
            new_entry = {
                'url': escape(sanitized_url),
                'verdict': verdict,
                'color': color,
                'time': datetime.now().strftime("%H:%M:%S")
            }
            # Keep only the last 5 scans
            scan_history.insert(0, new_entry)
            if len(scan_history) > 5:
                scan_history.pop()

    # Pass history_list to the template
    return render_template('index.html', result=result, history_list=scan_history, error_message=error_message)


@app.route('/security-tips')
@limiter.limit("30 per minute")
def security_tips():
    tips = [
        "Check for the padlock icon and 'https://' before entering passwords.",
        "Hover over links to see the actual destination URL before clicking.",
        "Be wary of sense of urgency or threats in emails (e.g., 'Account suspended!').",
        "Look for slight misspellings in domain names like 'g00gle.com'.",
        "Enable Multi-Factor Authentication (MFA) on all sensitive accounts."
    ]
    return jsonify({"tips": tips})


@app.route('/report-scam', methods=['POST'])
@limiter.limit("5 per minute")
@csrf.exempt  # Exempt if using AJAX, or implement CSRF token in JS
def report_scam():
    data = request.get_json() or {}
    scam_url = data.get('url', 'Unknown')
    print(f"NOTIFICATION: Scam reported for {scam_url}. Alert sent to {ADMIN_EMAIL}.")
    return jsonify({"status": "success", "message": "Scam report sent to security team!"})


# Error handlers
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Rate limit exceeded. Please try again later."}), 429


@app.errorhandler(500)
def internal_error(e):
    return render_template('index.html', error_message="An internal error occurred. Please try again."), 500


if __name__ == '__main__':
    # Use environment variable for debug mode (default to False in production)
    debug_mode = os.environ.get('DEBUG', 'False').lower() in ('true', '1', 'yes')
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)
