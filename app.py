from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import sqlite3
import os
from datetime import datetime
import csv
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = 'supersecretkey'

DB_PATH = 'logs.db'
ADMIN_USERNAME = 'tanvir'
ADMIN_PASSWORD = 'tanv1r'

EMAIL_FROM = os.getenv("EMAIL_FROM")
EMAIL_TO = os.getenv("EMAIL_TO")
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

SUSPICIOUS_PATTERNS = [
    '../', 'SELECT', 'UNION', ' OR ', '<script>', 'etc/passwd',
    'nmap', 'masscan', 'curl', 'wget', 'python-requests', 'nikto',
    'sqlmap', 'scan', 'ping', '127.0.0.1', ';', '|', '&'
]

# -------------------- Database Setup --------------------
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                path TEXT,
                headers TEXT,
                timestamp TEXT,
                suspicious INTEGER DEFAULT 0
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                email TEXT,
                message TEXT,
                timestamp TEXT,
                ip TEXT,
                suspicious INTEGER DEFAULT 0
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip TEXT PRIMARY KEY,
                reason TEXT,
                timestamp TEXT
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')
        # Default setting
        conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('auto_block', 'off')")
init_db()

# -------------------- Helpers --------------------
def is_auto_block_enabled():
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key = 'auto_block'")
        result = cur.fetchone()
        return result and result[0] == 'on'

def toggle_auto_block():
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key = 'auto_block'")
        current = cur.fetchone()[0]
        new_val = 'off' if current == 'on' else 'on'
        cur.execute("UPDATE settings SET value = ? WHERE key = 'auto_block'", (new_val,))
        conn.commit()
        return new_val

def send_alert_email(ip, path, headers):
    if not all([EMAIL_FROM, EMAIL_TO, SMTP_SERVER, EMAIL_PASSWORD]):
        return
    subject = "🚨 CyberSecure Alert: Suspicious Request Detected"
    body = f"Suspicious activity:\nIP: {ip}\nPath: {path}\nHeaders: {headers}\nTime: {datetime.now()}"
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_FROM
    msg['To'] = EMAIL_TO
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_FROM, EMAIL_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        print("❌ Email send failed:", e)

def send_contact_email(name, email, subject_text, message):
    if not all([EMAIL_FROM, EMAIL_TO, SMTP_SERVER, EMAIL_PASSWORD]):
        return
    body = f"Contact:\nName: {name}\nEmail: {email}\nSubject: {subject_text}\nMessage:\n{message}"
    msg = MIMEText(body)
    msg['Subject'] = f"Contact: {subject_text}"
    msg['From'] = EMAIL_FROM
    msg['To'] = EMAIL_TO
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_FROM, EMAIL_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        print("❌ Contact email failed:", e)

# -------------------- Middleware Logging --------------------
@app.before_request
def log_request():
    ip = request.remote_addr
    path = request.path
    headers = str(dict(request.headers))
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    user_input = f"{request.url} {request.get_data(as_text=True)} {dict(request.form)} {headers}".lower()
    suspicious = any(p in user_input for p in SUSPICIOUS_PATTERNS)

    try:
        with sqlite3.connect(DB_PATH, timeout=5) as conn:
            cur = conn.cursor()

            cur.execute("SELECT 1 FROM blocked_ips WHERE ip = ?", (ip,))
            if cur.fetchone():
                return "🚫 Access Denied. Your IP has been blocked.", 403

            cur.execute('''
                INSERT INTO logs (ip, path, headers, timestamp, suspicious)
                VALUES (?, ?, ?, ?, ?)
            ''', (ip, path, headers, timestamp, int(suspicious)))

            if suspicious:
                send_alert_email(ip, path, headers)
                if is_auto_block_enabled():
                    cur.execute('''
                        INSERT OR IGNORE INTO blocked_ips (ip, reason, timestamp)
                        VALUES (?, ?, ?)
                    ''', (ip, 'Auto-blocked due to suspicious activity', timestamp))

            conn.commit()
    except Exception as e:
        return "❌ Database error.", 500

# -------------------- Routes --------------------
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']
        ip = request.remote_addr
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        user_input = f"{name} {email} {subject} {message}".lower()
        suspicious = any(p in user_input for p in SUSPICIOUS_PATTERNS)

        with sqlite3.connect(DB_PATH) as conn:
            conn.execute('''
                INSERT INTO contacts (name, email, message, timestamp, ip, suspicious)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (name, email, message, timestamp, ip, int(suspicious)))
            conn.commit()

        send_contact_email(name, email, subject, message)
        flash("Thank you for contacting us!")
        return redirect(url_for('contact'))
    return render_template('contact.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form['username'] == ADMIN_USERNAME and request.form['password'] == ADMIN_PASSWORD:
            session['admin'] = True
            return redirect(url_for('admin_dashboard'))
        flash("Invalid credentials.")
    return render_template('login.html')

@app.route('/admin')
def admin_dashboard():
    if not session.get('admin'):
        return redirect(url_for('login'))
    with sqlite3.connect(DB_PATH) as conn:
        logs = conn.execute("SELECT * FROM logs ORDER BY id DESC").fetchall()
        contacts = conn.execute("SELECT * FROM contacts ORDER BY id DESC").fetchall()
        auto_block = conn.execute("SELECT value FROM settings WHERE key = 'auto_block'").fetchone()[0]
    return render_template("admin.html", logs=logs, contacts=contacts, auto_block=auto_block)

@app.route('/toggle_autoblock', methods=['POST'])
def toggle_autoblock():
    if not session.get('admin'):
        return redirect(url_for('login'))
    new_status = toggle_auto_block()
    flash(f"🔄 Auto-block is now set to: {new_status.upper()}")
    return redirect(url_for('admin_dashboard'))

@app.route('/block_ip', methods=['POST'])
def block_ip():
    if not session.get('admin'):
        return redirect(url_for('login'))
    ip = request.form['ip']
    reason = request.form.get('reason', 'Manually blocked')
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("INSERT OR IGNORE INTO blocked_ips (ip, reason, timestamp) VALUES (?, ?, ?)", (ip, reason, timestamp))
        conn.commit()
    flash(f"IP {ip} has been blocked.")
    return redirect(url_for('admin_dashboard'))

@app.route('/blocked')
def blocked_ips():
    if not session.get('admin'):
        return redirect(url_for('login'))
    with sqlite3.connect(DB_PATH) as conn:
        ips = conn.execute("SELECT * FROM blocked_ips ORDER BY timestamp DESC").fetchall()
    return render_template("blocked.html", ips=ips)

@app.route('/unblock/<ip>', methods=['POST'])
def unblock_ip(ip):
    if not session.get('admin'):
        return redirect(url_for('login'))
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
        conn.commit()
    flash(f"✅ IP {ip} has been unblocked.")
    return redirect(url_for('blocked_ips'))

@app.route('/export')
def export_logs():
    if not session.get('admin'):
        return redirect(url_for('login'))
    filename = 'logs.csv'
    with sqlite3.connect(DB_PATH) as conn:
        logs = conn.execute("SELECT * FROM logs").fetchall()
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['ID', 'IP', 'Path', 'Headers', 'Timestamp', 'Suspicious'])
        writer.writerows(logs)
    return send_file(filename, as_attachment=True)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# -------------------- Run --------------------
if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
