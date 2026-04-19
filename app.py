import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.secret_key = "nids-shield-presentation"

# DATABASE CONFIG
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DB_URL").replace("mysql://", "mysql+pymysql://")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# MODELS
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    email = db.Column(db.String(100))
    password = db.Column(db.String(255))

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
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
        pw = generate_password_hash(request.form['password'])
        new_user = User(username=request.form['username'], email=request.form['email'], password=pw)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and check_password_hash(user.password, request.form['password']):
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    # FORCE SHOW: Show ALL alerts in the database to anyone logged in
    user = User.query.get(session.get('user_id', 1))
    alerts = Alert.query.order_by(Alert.id.desc()).all()
    return render_template('dashboard.html', user=user, alerts=alerts)

@app.route('/api/alerts', methods=['POST'])
def receive_alert():
    # FORCE SAVE: Save exactly what is received
    data = request.get_json()
    new_alert = Alert(
        source_ip=data.get('source_ip', 'Unknown'),
        threat_type=data.get('threat_type', 'Detection')
    )
    db.session.add(new_alert)
    db.session.commit()
    return jsonify({"status": "success"}), 200

if __name__ == '__main__':
    app.run()
