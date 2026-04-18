import os
import requests
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
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


DATABASE_URL = os.getenv("DB_URL")
if DATABASE_URL and DATABASE_URL.startswith("mysql://"):
    DATABASE_URL = DATABASE_URL.replace("mysql://", "mysql+pymysql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
mail = Mail(app)


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(100), unique=True)
    phone = db.Column(db.String(20)) 
    password = db.Column(db.String(255))
    is_paid = db.Column(db.Boolean, default=False)
    # Notifications
    smtp_email = db.Column(db.String(100))
    smtp_password = db.Column(db.String(100))
    email_enabled = db.Column(db.Boolean, default=False)

class Alert(db.Model):
    __tablename__ = 'alerts'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    source_ip = db.Column(db.String(45))
    threat_type = db.Column(db.String(100))
    severity = db.Column(db.String(20), default="HIGH")
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Create tables
with app.app_context():
    db.create_all()


def trigger_stk_push(phone):
    try:
        ck = os.getenv("DARAJA_CONSUMER_KEY")
        cs = os.getenv("DARAJA_CONSUMER_SECRET")
        shortcode = os.getenv("DARAJA_SHORTCODE", "174379")
        passkey = os.getenv("DARAJA_PASSKEY")
        
        # 1. Get Access Token
        auth_url = "https://safaricom.co.ke"
        res = requests.get(auth_url, auth=HTTPBasicAuth(ck, cs), timeout=5)
        token = res.json().get('access_token')

        # 2. Trigger Push (Lipa na M-Pesa Online)
        # Note: In a real app, 'Password' is a base64 encoded string of Shortcode+Passkey+Timestamp
        stk_url = "https://safaricom.co.ke"
        headers = {"Authorization": f"Bearer {token}"}
        payload = {
            "BusinessShortCode": shortcode,
            "Password": "MTc0Mzc5YmZiMjc5ZjlhYTliZGJjM2M1Y2VhY2VjM2E0OTZlMzI5MTc5ZDZlNjM4OGY4YTJjZTAwNTU4ZGYyMDI0MDgxMDIyMDQzOA==",
            "Timestamp": "20240810220438",
            "TransactionType": "CustomerPayBillOnline",
            "Amount": 1, # Use 1 KES for testing
            "PartyA": phone,
            "PartyB": shortcode,
            "PhoneNumber": phone,
            "CallBackURL": "https://railway.app",
            "AccountReference": "NIDS_SHIELD",
            "TransactionDesc": "System Access Fee"
        }
        requests.post(stk_url, json=payload, headers=headers, timeout=5)
    except Exception as e:
        print(f"M-Pesa error: {e}")



@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        hashed_pw = generate_password_hash(request.form['password'])
        new_user = User(
            username=request.form['username'],
            email=request.form['email'],
            phone=request.form['phone'],
            password=hashed_pw,
            is_paid=True # Forced True for demo purposes
        )
        try:
            db.session.add(new_user)
            db.session.commit()
            trigger_stk_push(new_user.phone)
            flash("Registration Successful! Please login.")
            return redirect(url_for('login'))
        except:
            flash("User already exists!")
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
    if 'user_id' not in session: return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    alerts = Alert.query.filter_by(user_id=user.id).order_by(Alert.timestamp.desc()).all()
    return render_template('dashboard.html', user=user, alerts=alerts)


@app.route('/api/alerts', methods=['POST'])
def receive_alert():
    data = request.json
    new_alert = Alert(
        user_id=data.get('user_id', 1),
        source_ip=data.get('source_ip'),
        threat_type=data.get('threat_type')
    )
    db.session.add(new_alert)
    db.session.commit()
    return jsonify({"status": "success"}), 200

@app.route('/dashboard/sync')
def sync_data():
    if 'user_id' not in session: return jsonify({"new_count": 0})
    # Check if more alerts were added in the last 5 seconds
    new_alerts = Alert.query.filter_by(user_id=session['user_id']).count()
    return jsonify({"new_count": new_alerts})

@app.route('/dashboard/download-report')
def download_pdf():
    if 'user_id' not in session: return "Unauthorized"
    alerts = Alert.query.filter_by(user_id=session['user_id']).all()
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer)
    elements = []
    
    data = [['Timestamp', 'Source IP', 'Detection Reason']]
    for a in alerts:
        data.append([a.timestamp.strftime('%Y-%m-%d %H:%M'), a.source_ip, a.threat_type])
    
    table = Table(data)
    table.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.teal), ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke)]))
    elements.append(Paragraph("NIDS Shield - Threat Analysis Report", getSampleStyleSheet()['Title']))
    elements.append(table)
    doc.build(elements)
    
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="NIDS_Report.pdf")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
