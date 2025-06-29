# CyberSecure 🛡️

CyberSecure is a Flask-based web application that functions as an educational honeypot and cybersecurity monitoring system. It detects suspicious activities like SQL injection attempts, port scans, and ping probes, logs them, sends alerts, and allows administrators to manage blocked IPs in real-time via a secure dashboard.

---

## 🚀 Features

- 🔐 **Admin Login** – Secure access to the admin dashboard
- 📋 **Suspicious Activity Detection** – Detects SQLi, ping, Nmap scans
- 📊 **Dashboard** – View activity logs with filtering and export options
- ❌ **Manual and Auto IP Blocking** – Block/Unblock IPs, enable auto-blocking
- 📧 **Email Alerts** – Sends notifications when threats are detected
- 📥 **Contact Form** – Visitors can submit messages securely
- 💾 **Export Logs** – Download suspicious activity logs as CSV
- 🧱 **IP Monitoring** – View and manage the list of blocked IP addresses

---

## 🛠️ Tech Stack

- **Backend:** Python, Flask
- **Frontend:** HTML5, CSS3 (Custom design)
- **Database:** SQLite
- **Libraries:** 
  - `bcrypt` for password hashing
  - `python-dotenv` for environment variable management
  - `smtplib` for sending email
 
  
---

## 📁 Project Structure
      CyberSecure/
      ├── app.py
      ├── templates/
      │ ├── base.html
      │ ├── home.html
      │ ├── about.html
      │ ├── contact.html
      │ ├── login.html
      │ ├── admin.html
      │ └── blocked.html
      ├── static/
      │ └── style.css
      ├── database/
      │ └── cybersecure.db
      ├── .env
      └── README.md
---

## 🔧 Installation

**1.** **Clone the repository**
     git clone https://github.com/tanv1r-0x/CyberSecure.git
     cd CyberSecure

     
**2. Create a virtual environment**
    python -m venv venv
    source venv/bin/activate  
    
    # On Windows: venv\Scripts\activate

    
**3. Install dependencies**
    Flask
    bcrypt
    python-dotenv

**4. **Configure environment variables
      Create a .env file:**
      
      ADMIN_USERNAME=admin
     
      ADMIN_PASSWORD=yourpassword
     
      EMAIL_ADDRESS=youremail@example.com
      
      EMAIL_PASSWORD=yourapppassword


**5. Run the app**

    python app.py

  
**6. Access the application**

    Home: http://localhost:5000/
    
    Admin: http://localhost:5000/login
