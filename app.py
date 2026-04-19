import os
import requests
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth
from io import BytesIO
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "nids-shield-2026")

# ================= DB FIX =================
# Try MYSQL_URL first (Railway default), then DB_URL, then fallback to local sqlite
DATABASE_URL = os.getenv("MYSQL_URL") or os.getenv("DB_URL") or "sqlite:///nids.db"

if DATABASE_URL.startswith("mysql://"):
    DATABASE_URL = DATABASE_URL.replace("mysql://", "mysql+pymysql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ================= MODELS =================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    email = db.Column(db.String(100), unique=True)
    phone = db.Column(db.String(20))
    password = db.Column(db.String(255))
    is_paid = db.Column(db.Boolean, default=False)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    source_ip = db.Column(db.String(45))
    threat_type = db.Column(db.String(100))
    severity = db.Column(db.String(20), default="HIGH")
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Ensure tables are created
with app.app_context():
    db.create_all()

# ================= DARAJA =================
def trigger_stk_push(phone):
    try:
        ck = os.getenv("DARAJA_CONSUMER_KEY")
        cs = os.getenv("DARAJA_CONSUMER_SECRET")
        shortcode = os.getenv("DARAJA_SHORTCODE", "174379")
        passkey = os.getenv("DARAJA_PASSKEY")

        if not ck or not cs:
            print("⚠️ Daraja credentials missing.")
            return None

        auth_url = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
        res = requests.get(auth_url, auth=HTTPBasicAuth(ck, cs))
        token = res.json().get("access_token")

        stk_url = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
        headers = {"Authorization": f"Bearer {token}"}

        payload = {
            "BusinessShortCode": shortcode,
            "Password": passkey,
            "Timestamp": datetime.now().strftime('%Y%m%d%H%M%S'),
            "TransactionType": "CustomerPayBillOnline",
            "Amount": 1,
            "PartyA": phone,
            "PartyB": shortcode,
            "PhoneNumber": phone,
            "CallBackURL": "https://your-app-name.up.railway.app/callback",
            "AccountReference": "NIDS",
            "TransactionDesc": "Access Fee"
        }

        response = requests.post(stk_url, json=payload, headers=headers)
        return response
    except Exception as e:
        print("[DARAJA ERROR]", e)
        return None

# ================= ROUTES =================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        if User.query.filter_by(email=email).first():
            flash("Email already exists.")
            return redirect(url_for('login'))

        trigger_stk_push(request.form.get('phone'))
        hashed_pw = generate_password_hash(request.form['password'])

        user = User(
            username=request.form['username'],
            email=email,
            phone=request.form['phone'],
            password=hashed_pw,
            is_paid=True
        )
        db.session.add(user)
        db.session.commit()
        flash("Signup successful!")
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and check_password_hash(user.password, request.form['password']):
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        flash("Invalid credentials")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    alerts = Alert.query.filter_by(user_id=session['user_id']).all()
    return render_template('dashboard.html', alerts=alerts)

@app.route('/api/alerts', methods=['POST'])
def receive_alert():
    data = request.json
    alert = Alert(
        user_id=data.get("user_id", 1),
        source_ip=data.get("source_ip"),
        threat_type=data.get("threat_type")
    )
    db.session.add(alert)
    db.session.commit()
    return jsonify({"status": "success"}), 200

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    alerts = Alert.query.all()
    return jsonify([{"ip": a.source_ip, "threat": a.threat_type, "time": a.timestamp.isoformat()} for a in alerts])

@app.route('/dashboard/download-report')
def download_pdf():
    alerts = Alert.query.all()
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer)
    elements = []
    data = [['Timestamp', 'IP', 'Threat']]
    for a in alerts:
        data.append([a.timestamp.strftime('%Y-%m-%d %H:%M'), a.source_ip, a.threat_type])
    
    table = Table(data)
    table.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.teal), ('TEXTCOLOR', (0,0), (-1,0), colors.white)]))
    elements.append(Paragraph("NIDS Report", getSampleStyleSheet()['Title']))
    elements.append(table)
    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="report.pdf")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == "__main__":
    # Use PORT env provided by Railway, default to 5000 for local
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
