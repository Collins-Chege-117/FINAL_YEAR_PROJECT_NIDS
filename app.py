import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.secret_key = "nids-shield-2026"

# DATABASE CONFIG
DATABASE_URL = os.getenv("DB_URL")
if DATABASE_URL and DATABASE_URL.startswith("mysql://"):
    DATABASE_URL = DATABASE_URL.replace("mysql://", "mysql+pymysql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(255))
    is_paid = db.Column(db.Boolean, default=True)

class Alert(db.Model):
    __tablename__ = 'alerts'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, default=1)
    source_ip = db.Column(db.String(45))
    threat_type = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()

@app.route('/')
def index(): return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            new_user = User(
                username=request.form['username'],
                email=request.form['email'],
                password=generate_password_hash(request.form['password']),
                is_paid=True
            )
            db.session.add(new_user)
            db.session.commit()
            flash("Registration Successful! Account Activated.")
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
        flash("Invalid Credentials")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: 
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    
    # FOR THE DEMO: Get EVERY alert in the database, no matter what.
    alerts = Alert.query.order_by(Alert.id.desc()).all()
    return render_template('dashboard.html', user=user, alerts=alerts)

@app.route('/api/alerts', methods=['POST'])
def receive_alert():
    try:
        data = request.json
        # Create alert with a hardcoded user_id so it definitely matches
        new_alert = Alert(
            user_id=1, 
            source_ip=data.get('source_ip', '0.0.0.0'),
            threat_type=data.get('threat_type', 'Unknown Threat')
        )
        db.session.add(new_alert)
        db.session.commit()
        return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500



@app.route('/dashboard/sync')
def sync():
    # Return the total count of ALL alerts so the page knows to refresh
    count = Alert.query.count()
    return jsonify({"new_count": count})


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run()
