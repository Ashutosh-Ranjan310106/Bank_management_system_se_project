import threading
from datetime import datetime, timedelta
from functools import wraps
from model import db, User
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import random
import os
import smtplib
import hashlib
from dotenv import load_dotenv

# Load variables from .env
load_dotenv()
smtp_user = os.getenv('smtp_user')
smtp_server = os.getenv('smtp_server')
smtp_port = os.getenv('smtp_port')
smtp_password = os.getenv('smtp_password')
def run_in_thread(func):
    """
    A decorator to run the decorated function in a separate thread.
    """
    @wraps(func) #used to keep original fuction metadata like name doc etc
    def wrapper(*args, **kwargs):
        thread = threading.Thread(target=func, args=args, kwargs=kwargs)
        thread.start()
        return thread  
    return wrapper

def recreate_database():
    # Drop all tables
    db.drop_all()
    
    # Create all tables
    db.create_all()
    
    # Create admin user
    admin_password = generate_password_hash('admin123')  # You should change this password
    admin = User(username='admin', password=admin_password, first_name='Admin',
                 last_name='User', phone='1234567890', city='Admin City',
                 email='admin@example.com', account_type='admin', age=30, is_admin=True,is_verified = True, account_number = genrate_account_number('admin', 'admin'), aadhaar_url = 'qwert', pan_url='qwert')
    db.session.add(admin)
    db.session.commit()
    print("Database recreated and admin user added.")
#================================================================================================================================================================


def genrate_account_number(username, account_type):
    print(datetime.now())
    date = datetime.now().strftime('%Y%m%d_%H%M%S')
    data = f"{username.lower()}-{account_type.lower()}-{date}"
    
    # Create a hash
    hash_value = hashlib.md5(data.encode()).hexdigest()
    
    # Extract first 12 digits of the hash as the account number
    account_number = hash_value[:12].upper()  # Convert to uppercase for consistency
    
    return account_number

#================================================================================================================================================================


def genrate_document_url(file_type):
    print(datetime.now())
    date = datetime.now().strftime('%Y%m%d_%H%M%S')
    data = f"{file_type.lower()}{date}"
    
    # Create a hash
    hash_value = hashlib.md5(data.encode()).hexdigest()
    
    # Extract first 12 digits of the hash as the account number
    url = hash_value[:10].lower()+'.png'  # Convert to uppercase for consistency
    
    return url


#================================================================================================================================================================


def generate_token(account_number, app):
    return jwt.encode({'account_number': account_number, 'exp': datetime.utcnow() + timedelta(minutes=30)},
                      app.config['JWT_SECRET_KEY'], algorithm='HS256')





#================================================================================================================================================================


def generate_transaction_hash(transaction):
    """Generate a hash for the transaction to ensure integrity."""
    data = f"{transaction.account_number}{transaction.transaction_type}{transaction.amount}{transaction.balance_after}{transaction.date}"
    return generate_password_hash(data)


#================================================================================================================================================================


def verify_transaction_integrity(transaction):
    """Verify the integrity of a transaction by checking its hash."""
    data = f"{transaction.account_number}{transaction.transaction_type}{transaction.amount}{transaction.balance_after}{transaction.date}"
    return check_password_hash(transaction.hash, data)



def generate_otp():
    otp = ''.join(random.choices('0123456789', k=6))  # 6-digit OTP
    return otp

import json


def format_message(message_attributes, message_type):

    """Load the JSON file containing notification templates."""
    with open("notification.json", 'r') as file:
        all_message_template = json.load(file)
    """Format a message by replacing @ placeholders with values."""
    message_template = all_message_template["notifications"].get(message_type, '')
    if not message_template:
        print("Invalid message type")
        return 
    message = message_template["message"]
    subject = message_template["subject"]
    for value in message_attributes:
        message= message.replace('@', str(value), 1)
    
    return message, subject
@run_in_thread
def send_email_message(recipient_email, text, subject):    
    print(text,subject, str(text), str(subject))
    body = text
    message = MIMEMultipart()
    message["From"] = smtp_user
    message["To"] = recipient_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # Secure the connection with TLS
        server.login(smtp_user, smtp_password)
        #server.sendmail(smtp_user, recipient_email, message.as_string())
        res = 1

    except Exception as e:
        print(e)
        res = -1
        
    finally:
        server.quit()

    return res


