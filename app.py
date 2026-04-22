import os
import requests
import base64
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

# ================= DB FIX =================
# Try MYSQL_URL first (Railway default), then DB_URL, then fallback to local sqlite
DATABASE_URL = os.getenv("MYSQL_URL") or os.getenv("DB_URL") or "sqlite:///nids.db"

if DATABASE_URL.startswith("mysql://"):
    DATABASE_URL = DATABASE_URL.replace("mysql://", "mysql+pymysql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("EMAIL_USER")
app.config['MAIL_PASSWORD'] = os.getenv("EMAIL_PASS")


mail = Mail(app)

db = SQLAlchemy(app)

# ================= MODELS =================
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    email = db.Column(db.String(100), unique=True)
    phone = db.Column(db.String(20))
    password = db.Column(db.String(255))
    is_paid = db.Column(db.Boolean, default=False)
    checkout_id = db.Column(db.String(100), nullable=True)

class Alert(db.Model):
    __tablename__ = 'alert'
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

        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        str_to_encode = shortcode + passkey + timestamp
        online_password = base64.b64encode(str_to_encode.encode()).decode('utf-8')

        # 3. Format Phone Number to 254XXXXXXXXX
        if phone.startswith("0"):
            phone = "254" + phone[1:]
        elif phone.startswith("+254"):
            phone = phone[1:]
        elif phone.startswith("7") or phone.startswith("1"):
            phone = "254" + phone

        stk_url = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
        headers = {"Authorization": f"Bearer {token}"}

        payload = {
            "BusinessShortCode": shortcode,
            "Password": online_password,
            "Timestamp": timestamp,
            "TransactionType": "CustomerPayBillOnline",
            "Amount": 1,
            "PartyA": phone,
            "PartyB": shortcode,
            "PhoneNumber": phone,
            "CallBackURL": "https://web-production-8c5fe.up.railway.app/callback",
            "AccountReference": "NIDS_SHIELD",
            "TransactionDesc": "Payment For NIDS Access"
        }

        response = requests.post(stk_url, json=payload, headers=headers)
        res_data = response.json()

        return res_data.get("CheckoutRequestID")
    except Exception as e:
        print("[STK ERROR]", e)
        return None
       
def notify_user_of_threat(email, threat_type, ip):
    try:
        msg = Message("🔴 NIDS SHIELD: HIGH PRIORITY ALERT",
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[email])
        msg.body = f"Hello,\n\nA confirmed threat has been detected on your network.\n\n" \
                   f"Threat Type: {threat_type}\n" \
                   f"Source IP: {ip}\n\n" \
                   f"Please log in to your dashboard immediately to view the full report."
        mail.send(msg)
        print(f"📧 Alert email sent to {email}")
    except Exception as e:
        print(f"❌ Email notification failed: {e}")


# ================= ROUTES =================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        phone = request.form.get('phone')
        user = User.query.filter_by(email=email).first()

        # CASE 1: User exists and has already paid
        if user and user.is_paid:
            flash("Account already exists. Please login.")
            return redirect(url_for('login'))

        # CASE 2: User exists but HAS NOT paid (Retry Payment)
        if user and not user.is_paid:
            cid = trigger_stk_push(phone)
            user.checkout_id = cid
            db.session.commit()
            session['pending_user_id'] = user.id
            return render_template('waiting_payment.html')

        # CASE 3: Brand new user
        cid = trigger_stk_push(phone)
        hashed_pw = generate_password_hash(request.form['password'])
        new_user = User(
            username=request.form['username'],
            email=email,
            phone=phone,
            password=hashed_pw,
            is_paid=False,
            checkout_id=cid
        )
        db.session.add(new_user)
        db.session.commit()
        
        session['pending_user_id'] = new_user.id
        return render_template('waiting_payment.html')

    return render_template('signup.html')


@app.route('/api/check-payment')
def check_payment():
    user_id = session.get('pending_user_id')
    if not user_id:
        return jsonify({"paid": False})
    
    # Refresh user from database to see if the callback updated 'is_paid'
    user = User.query.get(user_id)
    
    if user and user.is_paid:
        # User has successfully paid
        session.pop('pending_user_id', None) # Clear the pending session
        return jsonify({"paid": True})
    
    return jsonify({"paid": False})


@app.route('/callback', methods=['POST'])
def mpesa_callback():
    data = request.get_json()
    stk_callback_response = data['Body']['stkCallback']
    result_code = stk_callback_response['ResultCode']
    checkout_id = stk_callback_response['CheckoutRequestID'] # Get the ID from Safaricom

    if result_code == 0:
        # Match the user exactly by the ID we saved earlier
        user = User.query.filter_by(checkout_id=checkout_id).first()
        if user:
            user.is_paid = True
            db.session.commit()
            print(f"Verified payment for: {user.username}")
            
    return jsonify({"ResultCode": 0, "ResultDesc": "Success"})




@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        
        if user and check_password_hash(user.password, request.form['password']):
            if not user.is_paid:
                # Trigger payment again if they try to log in without paying
                cid = trigger_stk_push(user.phone)
                user.checkout_id = cid
                db.session.commit()
                session['pending_user_id'] = user.id
                flash("Please complete your M-Pesa payment.")
                return render_template('waiting_payment.html')
            
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
            
        flash("Invalid credentials")
    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # 1. Fetch the user object using the ID stored in the session
    user = User.query.get(session['user_id'])
    
    # 2. Fetch the alerts
    alerts = Alert.query.filter_by(user_id=session['user_id']).all()
    
    # 3. Pass BOTH user and alerts to the template
    return render_template('dashboard.html', user=user, alerts=alerts)


@app.route('/api/alerts', methods=['POST'])
def receive_alert():
    data = request.json
    username = data.get("username")
    user = User.query.filter_by(username=username).first()
    user_id = user.id if user else 1

    # Get threat type and determine severity
    threat_type = data.get("threat_type", "[SAFE]")
    
    # Logic: If it's safe, set severity to LOW. If it's a threat, set to HIGH.
    severity = "HIGH" if threat_type != "[SAFE]" else "LOW"

    alert = Alert(
        user_id=user_id,
        source_ip=data.get("source_ip"),
        threat_type=threat_type,
        severity=severity  # This helps the PDF filter later
    )

    db.session.add(alert)
    db.session.commit()
    
    if user and severity == "HIGH":
        notify_user_of_threat(user.email, threat_type, data.get("source_ip"))

    return jsonify({"status": "success"}), 200



@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    # Only get alerts for the logged-in user
    if 'user_id' not in session:
        return jsonify([]), 401
        
    alerts = Alert.query.filter_by(user_id=session['user_id']).all()
    return jsonify([
        {
            "ip": a.source_ip,
            "threat": a.threat_type,
            "time": a.timestamp.isoformat(),
            "severity": a.severity
        } for a in alerts
    ])


@app.route('/dashboard/download-report')
def download_pdf():
    alerts = Alert.query.filter_by(severity="HIGH").all()
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
