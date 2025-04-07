from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
db = SQLAlchemy()
# Models
#================================================================================================================================================================
class User(db.Model):
    #id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(500), nullable=False)
    account_number = db.Column(db.String(12), primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    city = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    account_type = db.Column(db.String(10), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    loan_amount = db.Column(db.Float, default=0.0)
    age = db.Column(db.Integer, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime)
    aadhaar_url = db.Column(db.String(15), nullable=False)
    pan_url = db.Column(db.String(15), nullable=False)



#================================================================================================================================================================

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_number = db.Column(db.String(12), db.ForeignKey('user.account_number'), nullable=False)
    related_account_number = db.Column(db.String(12), db.ForeignKey('user.account_number'))
    transaction_type = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200))
    balance_after = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=datetime.now)
    hash = db.Column(db.String(500), nullable=False, unique=True)



#================================================================================================================================================================

class Loan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_number = db.Column(db.String(12), db.ForeignKey('user.account_number'), nullable=False)
    loan_type = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    due_amount = db.Column(db.Float, nullable=False, default = amount)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    years =db.Column(db.Integer, nullable=False)
    monthly_payment = db.Column(db.Float, nullable=False)
    is_approved = db.Column(db.Integer, nullable=False, default = 0)
    transaction_id = db.Column(db.Integer, db.ForeignKey('transaction.id'))
#================================================================================================================================================================
