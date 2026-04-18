import smtplib
from email.mime.text import MIMEText
from datetime import datetime

def send_alert_email(user_email, app_password, threat_type, source_ip):
    if not user_email or not app_password:
        return

    subject = f"🚨 NIDS Alert: {threat_type} Detected!"
    body = f"""
    Hello,
    
    A HIGH severity threat was detected on your network.
    
    Threat Type: {threat_type}
    Source IP: {source_ip}
    Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    
    Investigate this immediately in your NIDS Dashboard.
    """
    
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = user_email
    msg['To'] = user_email # Sending to themselves

    try:
        with smtplib.SMTP_SSL("://gmail.com", 465) as server:
            server.login(user_email, app_password)
            server.sendmail(user_email, user_email, msg.as_string())
        print(f"📧 Alert email sent to {user_email}")
    except Exception as e:
        print(f"❌ Email failed: {e}")
