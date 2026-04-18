import requests
import base64
from datetime import datetime
import os
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv

load_dotenv()

def get_access_token():
    url = "https://safaricom.co.ke"
    consumer_key = os.getenv("DARAJA_CONSUMER_KEY")
    consumer_secret = os.getenv("DARAJA_CONSUMER_SECRET")
    
    try:
        res = requests.get(url, auth=HTTPBasicAuth(consumer_key, consumer_secret), timeout=10)
        
        if res.status_code != 200:
            print(f"❌ Daraja Auth Failed. Status: {res.status_code}, Body: {res.text}")
            return None
            
        return res.json().get('access_token')
    except Exception as e:
        print(f"❌ Network/JSON Error: {e}")
        return None

def trigger_stk_push(phone_number, amount=1, account_ref="NIDS_Shield"):
    token = get_access_token()
    if not token:
        return {"error": "Failed to get token"}

    # Format phone: 2547XXXXXXXX
    if phone_number.startswith("0"):
        phone_number = "254" + phone_number[1:]
    
    shortcode = os.getenv("DARAJA_SHORTCODE")
    passkey = os.getenv("DARAJA_PASSKEY")
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    
    password_str = shortcode + passkey + timestamp
    password = base64.b64encode(password_str.encode()).decode()

    url = "https://safaricom.co.ke"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    payload = {
        "BusinessShortCode": shortcode,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": amount,
        "PartyA": phone_number,
        "PartyB": shortcode,
        "PhoneNumber": phone_number,
        "CallBackURL": "https://your-public-url.com",
        "AccountReference": account_ref,
        "TransactionDesc": "NIDS Subscription"
    }

    try:
        res = requests.post(url, json=payload, headers=headers, timeout=10)
        print(f"Daraja Response: {res.json()}")
        return res.json()
    except Exception as e:
        print(f"STK Error: {e}")
        return {"error": str(e)}
