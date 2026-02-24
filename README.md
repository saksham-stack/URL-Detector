# URL-Detector 🛡️

A high-performance web application designed to detect malicious URLs, phishing attempts, and suspicious websites. Built with Flask and powered by Google Safe Browsing API.

## 🚀 Features

- **Malicious Link Detection**: Uses Google Safe Browsing API to flag potential phishing or malware-hosting URLs
- **Protocol Validation**: Checks for HTTPS encryption and flags unsecured HTTP connections
- **Domain Analysis**: Extracts WHOIS information including registrar, creation date, and country
- **SSL/TLS Certificate Verification**: Validates SSL certificates and displays issuer/expiry details
- **Fraud Keyword Detection**: Identifies suspicious keywords commonly used in phishing attacks
- **URL Pattern Analysis**: Detects IP-based URLs, excessive length, and other suspicious patterns
- **Rate Limiting**: Protects against API abuse with configurable rate limits
- **CSRF Protection**: Secure forms with CSRF token validation
- **SSRF Protection**: Blocks access to private/internal IP addresses
- **Activity History**: Tracks recent scans (last 5 URLs)
- **Downloadable Reports**: Generate text reports of URL analysis
- **Security Tips**: Built-in educational content for safe browsing

## 📋 Requirements

- Python 3.8+
- Flask 3.0+
- Google Safe Browsing API Key (optional but recommended)

## 🔧 Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd URL-Detector
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment variables**
   
   Copy `.env.example` to `.env` and configure:
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` file:
   ```env
   # Flask Configuration
   FLASK_ENV=development
   SECRET_KEY=your-secret-key-here-change-in-production
   DEBUG=False

   # Google Safe Browsing API
   SAFE_BROWSING_API_KEY=your-api-key-here

   # Admin Configuration
   ADMIN_EMAIL=admin@example.com

   # Rate Limiting
   RATE_LIMIT_PER_MINUTE=10

   # Security Settings
   ALLOWED_PROTOCOLS=http,https
   MAX_URL_LENGTH=2048
   ```

4. **Get Google Safe Browsing API Key** (Optional)
   - Visit [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select existing
   - Enable Safe Browsing API
   - Create credentials (API Key)
   - Add the key to your `.env` file

## 🚀 Usage

1. **Run the application**
   ```bash
   python app.py
   ```

2. **Open your browser**
   Navigate to `http://localhost:5000`

3. **Analyze a URL**
   - Paste any suspicious URL into the input box
   - Click "ANALYZE URL"
   - View the security verdict and detailed analysis

## 🔒 Security Features

| Feature | Description |
|---------|-------------|
| **Input Validation** | All URLs are validated and sanitized before processing |
| **SSRF Protection** | Blocks access to private/internal IP addresses |
| **CSRF Protection** | All forms include CSRF token validation |
| **Rate Limiting** | Prevents API abuse (10 requests/minute default) |
| **XSS Prevention** | Output is escaped using MarkupSafe |
| **Secure SSL Context** | Proper certificate verification enabled |

## 📁 Project Structure

```
URL-Detector/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── .env.example          # Environment variables template
├── .gitignore            # Git ignore rules
├── README.md             # This file
├── templates/
│   └── index.html        # Main HTML template
├── static/
│   ├── style.css         # Stylesheet
│   └── assets/           # Images and other static files
└── LICENSE               # License file
```

## ⚠️ Important Security Notes

1. **Never commit `.env` file** - Contains sensitive API keys and secrets
2. **Change SECRET_KEY** - Generate a strong random key for production
3. **Disable DEBUG mode** - Set `DEBUG=False` in production
4. **Use HTTPS** - Always deploy behind HTTPS in production
5. **Rate Limiting** - Adjust limits based on your API quota

## 🛠️ Configuration Options

| Variable | Default | Description |
|----------|---------|-------------|
| `FLASK_ENV` | development | Flask environment mode |
| `SECRET_KEY` | dev-key... | Session encryption key |
| `DEBUG` | False | Enable/disable debug mode |
| `SAFE_BROWSING_API_KEY` | None | Google API key |
| `ADMIN_EMAIL` | admin@example.com | Report destination email |
| `MAX_URL_LENGTH` | 2048 | Maximum URL length (chars) |
| `ALLOWED_PROTOCOLS` | http,https | Allowed URL protocols |

## 📝 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET, POST | Main URL analysis page |
| `/security-tips` | GET | Returns security tips (JSON) |
| `/report-scam` | POST | Submit malicious URL report |

## 🧪 Testing

Run the application and test with these sample URLs:

- **Safe**: `https://google.com`
- **Suspicious**: `http://login-secure-bank.com`
- **Test patterns**: Try URLs with keywords like "win", "prize", "gift"

## 📄 License

See [LICENSE](LICENSE) file for details.

## 👥 Authors

- **Yash Gupta** - Full-Stack Developer & Cybersecurity Enthusiast
- **Saksham Gupta** - Backend Architecture & Security

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📞 Support

For issues or questions, please open an issue on GitHub or contact the authors directly.

---

**# PHISHERMEN | System Active: 2026**
