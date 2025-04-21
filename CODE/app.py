#================================================================================================================================================================

import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, make_response
from xhtml2pdf import pisa
from io import BytesIO
from datetime import datetime, timedelta
from sqlalchemy.exc import IntegrityError
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jwt
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
import bleach
from flask_limiter.errors import RateLimitExceeded
import re
import glob
from operator import itemgetter
from model import *
from functions import *
from forms import *



#================================================================================================================================================================

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'your_secret_key'  # Use environment variable for production
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI') or 'mysql+pymysql://root:password@localhost:3306/flask_bank'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY') or 'your_jwt_secret_key'  # Use environment variable for production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] =  os.getenv("JWT_ACCESS_TOKEN_EXPIRES", "15m")  # Token expires after 30 minutes
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max file size
app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.jpeg', '.png']
app.config['UPLOAD_FOLDER'] = 'static/uploads'
env = os.getenv("FLASK_ENV", "development")
app.config["FLASK_ENV"] = env
app.config["DEBUG"] = env == "development"
print(env, app.config["DEBUG"])
db.init_app(app)
#migrate = Migrate(app, db)
csrf = CSRFProtect(app)
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)


#================================================================================================================================================================



# Set up logging
if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/flask_bank.log', maxBytes=10240, backupCount=10, delay=True)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
app.logger.addHandler(file_handler)
#app.logger.setLevel(logging.INFO)
app.logger.setLevel(logging.DEBUG)
#app.logger.info('app started')

#================================================================================================================================================================


#================================================================================================================================================================


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get('token')
        if not token:
            flash('You need to log in to access this page.', 'error')
            return redirect(url_for('login'))
        try:
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['account_number'])
            if not current_user.is_verified:
                print("an un verifed user")
                flash('your account is under process we will notify when it is verified.', 'error')

                return redirect(url_for('login'))
        except:
            flash('Invalid session. Please log in again.', 'error')
            return redirect(url_for('login'))
        return f(current_user, *args, **kwargs)
    return decorated


#================================================================================================================================================================


@app.errorhandler(RateLimitExceeded)
def handle_rate_limit_exceeded(e):
    return render_template('rate_limit_exceeded.html'), 429





def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = session.get('token')
        if not token:
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('login'))
        try:
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(data['account_number'])
            if user:
                print(f"Admin access granted for user: {user.username}")
            if not user or not user.is_admin:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('dashboard'))
        except Exception as e:
            print(f"Admin access denied: >>>>>>>>>>>>>>{e}\n\n\n")
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


#================================================================================================================================================================

@app.before_request
def log_request_info():
    if request.path.startswith("/static/"):
        return
    user_agent = request.headers.get("User-Agent", "Unknown")
    app.logger.debug(
    "Request Info: IP=%s, UserAgent=%s, Method=%s, Path=%s",
    request.remote_addr,
    user_agent,
    request.method,
    request.path
    )

#================================================================================================================================================================


@app.route('/')
def home():
    return render_template('home.html')




#================================================================================================================================================================

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limiting for brute force prevention
def login():
    try:
        form = LoginForm()
        otpForm = OTPForm()
        if form.validate_on_submit():
            account_no = form.account_no.data
            password = form.password.data
            user = User.query.get(account_no)
            print(user, account_no,'\n\n\n\n')
            if user and user.account_locked_until and user.account_locked_until > datetime.now():
                flash('Account is locked. Please try again later.', 'error')
                return render_template('login.html', form=form)
            if user and not user.is_verified:
                flash('your account is under process we will notifi when it is verified.', 'error')
                return render_template('login.html', form=form)
            if user and check_password_hash(user.password, password):
                user.failed_login_attempts = 0
                db.session.commit()
                session['account_no'] = user.account_number
                return redirect(url_for('send_otp'))
            else:
                if user:
                    user.failed_login_attempts += 1
                    if user.failed_login_attempts >= 3:
                        user.account_locked_until = datetime.now() + timedelta(minutes=15)
                        messsage = render_template(
                            "email/account_locked.html",
                            full_name = user.first_name+' '+user.last_name ,
                            account_number=mask_account_number(user.account_number),
                            lock_time=datetime.now().strftime('%d-%b-%Y %I:%M %p') ,
                            unlock_time=(datetime.now() + timedelta(minutes=15)).strftime('%d-%b-%Y %I:%M %p'),
                            support_link="https://ruppevaletBank.com/support",
                            year= datetime.now().year
                        )
                        send_email(user.email, messsage, "Your Digivault Account Has Been Locked Due to Multiple Failed Login Attempts")
                    db.session.commit()
                flash('Invalid username or password.', 'error')
                app.logger.warning(f'Failed login attempt for username: {account_no}')
        elif otpForm.validate_on_submit():
            recived_otp =  otpForm.otp.data
            encoded_otp = session.get('OTP')
            account_no = session.get('account_no')
            user = User.query.get(account_no)
            try:
                decoded_otp = jwt.decode(encoded_otp, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])['otp']
            except jwt.ExpiredSignatureError:
                flash("OTP has expired. Please login again.", "error")
                session.pop('OTP', None)
                return redirect(url_for('login'))
            if decoded_otp == recived_otp:
                token = generate_token(user.account_number, app)
                session['token'] = token

                session.pop('OTP', None)
                session.pop('account_no', None)

                flash('Logged in successfully.', 'success')
                app.logger.info(f'User {account_no} logged in successfully')
                messsage= render_template(
                        "email/login.html",
                        full_name = user.first_name+' '+user.last_name ,
                        account_number=mask_account_number(user.account_number),
                        login_time=datetime.now().strftime('%d-%b-%Y %I:%M %p'),
                        ip_address=request.remote_addr,
                        user_agent = request.headers.get("User-Agent", "Unknown"),
                        year= datetime.now().year
                    )
                send_email(user.email, messsage, "Security Alert: Login Activity on Your Digivault Account")
                if user.is_admin:
                    return redirect(url_for('admin_dashboard'))
                return redirect(url_for('dashboard'))
            else:
                flash('incorrect otp')
                return render_template('otp.html', otpform=otpForm)

                
        return render_template('login.html', form=form)
    except RateLimitExceeded:
        app.logger.warning(f'Rate limit exceeded for login from IP: {request.remote_addr}')
        return render_template('rate_limit_exceeded.html'), 429
@app.route('/send_otp',methods=['GET'])
def send_otp():
    otpForm = OTPForm()
    account_no = session.get('account_no')
    if account_no:
        otp = generate_otp(6)
        session['OTP'] = jwt.encode({'otp':otp}, app.config['JWT_SECRET_KEY'], algorithm='HS256')
        user = db.session.get(User, account_no)
        print('\n\n\n', session['OTP'], '>>>',otp, '\n\n\n')
        message = render_template('email/otp.html',otp = otp, full_name = user.first_name+' '+user.last_name )
        send_email(user.email, message, 'Digivault Verification Code – Keep This Safe')
    else:
        flash('invalid session')
        return redirect(url_for('login'))
    return render_template('otp.html', otpform=otpForm)
    
#================================================================================================================================================================

@app.route('/logout')
def logout():
    session.pop('token', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('home'))


#================================================================================================================================================================

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per hour")  # Rate limiting for registration
def register():
    try:
        form = RegistrationForm()
        if form.validate_on_submit():
            existing_user = User.query.filter_by(email=form.email.data).first()
            if existing_user:
                flash('Email address already in use. Please use a different email.', 'error')
                return redirect(url_for('register'))

            try:
                hashed_password = generate_password_hash(form.password.data)
                aadhaar = form.aadhaar.data
                pan_card = form.pan_card.data
                aadhaar_url = genrate_document_url('aadhaar')
                pan_url = genrate_document_url('pan_card')
                print('aadhaar=',os.path.join(app.config['UPLOAD_FOLDER'], aadhaar_url))
                print('pan_card=',os.path.join(app.config['UPLOAD_FOLDER'], pan_url))
                aadhaar.save(os.path.join(app.config['UPLOAD_FOLDER'], aadhaar_url))
                pan_card.save(os.path.join(app.config['UPLOAD_FOLDER'], pan_url))
                new_user = User(
                    username=form.username.data,
                    password=hashed_password,
                    account_number = genrate_account_number(form.username.data, form.account_type.data),
                    first_name=form.first_name.data,
                    last_name=form.last_name.data,
                    phone=form.phone.data,
                    city=form.city.data,
                    email=form.email.data,
                    account_type=form.account_type.data,
                    age=form.age.data,
                    aadhaar_url = aadhaar_url,
                    pan_url = pan_url
                )
                print('\n\n\n\n\n',new_user)
                db.session.add(new_user)
                db.session.commit()
                messsage = render_template(
                    "email/account_request_received.html",
                    full_name = new_user.first_name+' '+new_user.last_name ,
                    account_number=new_user.account_number,
                    registration_date=datetime.now().strftime('%d-%b-%Y %I:%M %p'),
                    support_link="https://Digivault.com/support",
                    year= datetime.now().year
                )
                send_email(new_user.email, messsage, "Your Digivault Account Request Has Been Received – Pending Verification")
                flash('your account is succucesfully created wait while we verify your account, we will inform after verification', 'success')
                app.logger.info(f'New user registered: {form.username.data} account number: {new_user.account_number}')
                return redirect(url_for('login'))
            except IntegrityError:
                db.session.rollback()
                flash('An error occurred. Please try again.', 'error')
                return redirect(url_for('register'))

        return render_template('register.html', form=form)
    except RateLimitExceeded:
        app.logger.warning(f'Rate limit exceeded for registration from IP: {request.remote_addr}')
        return render_template('rate_limit_exceeded.html'), 429

#================================================================================================================================================================

@app.route('/dashboard')
@token_required
def dashboard(current_user):
    return render_template('dashboard.html', user=current_user)

#================================================================================================================================================================
@app.route('/transfer/comfirm/<account_no>', methods=['GET', 'POST'])
@token_required
def transfer_confirm(current_user, account_no):
    form = TransferForm()
    reciver_user = db.session.get(User, account_no)
    

@app.route('/transfer', methods=['GET', 'POST'])
@token_required
def transfer(current_user):
    form = TransferForm()
    if form.validate_on_submit():
        try:
            amount = form.amount.data
            description = form.description.data
            reciver_account = form.related_account_number.data
            reciver_user = db.session.get(User, reciver_account)
            if reciver_user:
                amount = float(bleach.clean(str(amount), strip=True))

                current_user.balance -= amount
                transaction_sender = Transaction(account_number=current_user.account_number, transaction_type='Withdraw',
                                        amount=amount, balance_after=current_user.balance, description=description)
                transaction_sender.hash = generate_transaction_hash(transaction_sender)
                reciver_user.balance += amount
                transaction_reciver = Transaction(account_number=reciver_user.account_number, transaction_type='Deposit',
                                        amount=amount, balance_after=reciver_user.balance, description=description)
                transaction_reciver.hash = generate_transaction_hash(transaction_reciver)
                db.session.add(transaction_sender)
                db.session.add(transaction_reciver)
                db.session.commit()
                work=True
            
        except Exception as e:
            work=False
            db.session.rollback()
            app.logger.error(f'Error during transfer: {str(e)}')
        if work:
            flash(f'{amount:.2f} Transfer successfully.', 'success')
            app.logger.info(f'User {current_user.account_number} transfer {amount:.2f} to user {reciver_user.account_number}')
            sender_message = render_template(
                "email/fund_transfer_sent.html",
                sender_name=current_user.first_name+' '+current_user.last_name ,
                sender_account=current_user.account_number,
                receiver_name=reciver_user.first_name+' '+reciver_user.last_name ,
                receiver_account=reciver_user.account_number,
                amount=amount,
                transaction_date=datetime.now().strftime('%d-%b-%Y %I:%M %p'),
                dashboard_link=url_for('dashboard'),
                year=datetime.now().year
            )

            # Receiver confirmation
            receiver_message = render_template(
                "email/fund_transfer_received.html",
                sender_name=current_user.first_name+' '+current_user.last_name ,
                sender_account=current_user.account_number,
                receiver_name=reciver_user.first_name+' '+reciver_user.last_name ,
                receiver_account=reciver_user.account_number,
                amount=amount,
                transaction_date=datetime.now().strftime('%d-%b-%Y %I:%M %p'),
                dashboard_link=url_for('dashboard'),
                year=datetime.now().year
            )
            send_email(current_user.email, sender_message, f"Fund Transfer to { reciver_user.first_name+' '+reciver_user.last_name } (₹{ amount }) Completed")
            send_email(reciver_user.email, receiver_message, f"You Received ₹{amount} from { current_user.first_name+' '+current_user.last_name}")
            return render_template('transfer_confirmation.html', form=form, receiver_name=reciver_user.first_name+' '+reciver_user.last_name, amount=amount, account_number=reciver_user.account_number, description=description)
        else:
            flash('An error occurred during the transfer. Please try again.', 'error')
    return render_template('transfer.html', form=form)
#================================================================================================================================================================

@app.route('/deposit', methods=['GET', 'POST'])
@token_required
def deposit(current_user):
    form = DepositForm()
    if form.validate_on_submit():
        try:
            amount = form.amount.data
            description = form.description.data
            amount = float(bleach.clean(str(amount), strip=True))
            current_user.balance += amount
            transaction = Transaction(account_number=current_user.account_number, transaction_type='Deposit',
                                      amount=amount, balance_after=current_user.balance, description=description)
            transaction.hash = generate_transaction_hash(transaction)
            db.session.add(transaction)
            db.session.commit()
            work=True
            
        except Exception as e:
            work=False
            db.session.rollback()
            app.logger.error(f'Error during deposit: {str(e)}')
        if work:
            flash(f'Deposited {amount:.2f} successfully.', 'success')
            app.logger.info(f'User {current_user.username} deposited {amount:.2f}')
            subject = f"₹{amount:.2f} Deposited to Your Digivault Account"
            messsage = render_template("email/deposit_email.html", full_name=current_user.first_name + ' ' + current_user.last_name, account_number=current_user.account_number, amount=amount, transaction_date=datetime.now().strftime('%d-%b-%Y %I:%M %p'), new_balance=current_user.balance, description="Monthly savings deposit", dashboard_link="https://Digivault.com/dashboard", year=datetime.now().year)
            send_email(current_user.email, messsage, subject)
            return redirect(url_for('dashboard'))
        else:
            flash('An error occurred during the deposit. Please try again.', 'error')
    return render_template('deposit.html', form=form)


#================================================================================================================================================================

@app.route('/withdraw', methods=['GET', 'POST'])
@token_required
def withdraw(current_user):
    form = WithdrawForm()
    if form.validate_on_submit():
        try:
            amount = form.amount.data
            description = form.description.data
            amount = float(bleach.clean(str(amount), strip=True))
            if current_user.balance >= amount:
                current_user.balance -= amount
                transaction = Transaction(account_number=current_user.account_number, transaction_type='withdraw',
                            amount=amount, balance_after=current_user.balance, description=description)
                transaction.hash = generate_transaction_hash(transaction)
                db.session.add(transaction)
                db.session.commit()
                flash(f'Withdrawn {amount:.2f} successfully.', 'success')
                app.logger.info(f'User {current_user.username} withdrew {amount:.2f}')
                subject = f"₹{amount:.2f} Withdrawn from Your Digivault Account"
                message = render_template(
                    "email/withdraw_email.html",
                    full_name=current_user.first_name + ' ' + current_user.last_name,
                    account_number=current_user.account_number,
                    amount=amount,
                    transaction_date=datetime.now().strftime('%d-%b-%Y %I:%M %p'),
                    new_balance=current_user.balance,
                    support_link="https://Digivault.com/support",
                    year=datetime.now().year
                )
                send_email(current_user.email, message, subject)
            else:
                flash('Insufficient funds.', 'error')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error during withdrawal: {str(e)}')
            flash('An error occurred during the withdrawal. Please try again.', 'error')
    return render_template('withdraw.html', form=form)

#================================================================================================================================================================

@app.route('/transactions')
@token_required
def transactions(current_user):
    user_transactions = Transaction.query.filter_by(account_number=current_user.account_number).order_by(Transaction.date.desc()).all()
    for transaction in user_transactions:
        if not verify_transaction_integrity(transaction):
            flash('Warning: Some transactions may have been tampered with.', 'error')
            app.logger.warning(f'Transaction integrity check failed for transaction ID: {transaction.id}')
            break
    return render_template('transactions.html', transactions=user_transactions)
@app.route('/transactions/pdf/<int:email>')
@token_required
def download_transactions_pdf(current_user, email):
    user_transactions = Transaction.query.filter_by(account_number=current_user.account_number).order_by(Transaction.date.desc()).all()
    for transaction in user_transactions:
        if not verify_transaction_integrity(transaction):
            flash('Warning: Some transactions may have been tampered with.', 'error')
            app.logger.warning(f'Transaction integrity check failed for transaction ID: {transaction.id}')
            break
    html = render_template('transactions_pdf.html', transactions=user_transactions, user=current_user, current_date=datetime.now())

    result = BytesIO()
    pisa_status = pisa.CreatePDF(src=html, dest=result)
    result.seek(0)

    if pisa_status.err:
        return "PDF generation failed", 500

    if email:
        message = render_template(
            "email/transaction_statement_email.html",
            full_name=current_user.first_name + ' ' + current_user.last_name,
            account_number=mask_account_number(current_user.account_number),
            generated_on=datetime.now().strftime('%d-%b-%Y %I:%M %p'),
            support_link="https://Digivault.com/support",
            year=datetime.now().year
        )
        send_email(current_user.email, message, "Your Digivault Transaction Statement (PDF Attached)", attachments=[("transaction_history.pdf", result.read())])
        flash("email send","success")
        return render_template('transactions.html', transactions=user_transactions)
    else:
        # Send as response
        response = make_response(result.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename=transaction_history.pdf'
        return response

    

#================================================================================================================================================================

@app.route('/loan', methods=['GET', 'POST'])
@token_required
def loan(current_user):
    loan_transaction = Loan.query.filter_by(account_number=current_user.account_number).all()
    return render_template('user_loan.html', loans=loan_transaction)
#================================================================================================================================================================

@app.route('/loan/apply', methods=['GET', 'POST'])
@token_required
def apply_loan(current_user):
    form = LoanForm()
    print(form.amount.data, form.years.data)
    if form.validate_on_submit():
        try:
            amount = form.amount.data
            amount = float(bleach.clean(str(amount), strip=True))
            years = form.years.data
            loan_type = form.loan_type.data
            print(123, '\n\n\n\n')
            interest_rates = {
                'education': 0.01,
                'car': 0.06,
                'home': 0.02,
                'personal': 0.08
            }
            interest_rate = interest_rates.get(loan_type)
            if interest_rate is None:
                flash('Invalid loan type.', 'error')
                return redirect(url_for('apply_loan'))

            monthly_rate = interest_rate / 12
            months = years * 12
            monthly_payment = (amount * monthly_rate * (1 + monthly_rate) ** months) / ((1 + monthly_rate) ** months - 1)
            #current_user.balance += amount
            #current_user.loan_amount += amount
            loan = Loan(account_number= current_user.account_number,
                        loan_type= loan_type,
                        amount = amount,
                        years = years,
                        monthly_payment = monthly_payment
                         )
            db.session.add(loan)
            db.session.commit()
            print(1233267567657)
            flash(f'request for Loan of {amount:.2f} is succesfully recived.  Monthly payment: {monthly_payment:.2f} wait until we verify it', 'success')
            app.logger.info(f'User {current_user.username} took a loan of {amount:.2f}')
            subject = f'Loan Request of ₹{amount:.2f} Received – Pending Verification'
            message = render_template(
                "email/loan_request_received_email.html",
                full_name=current_user.first_name + ' ' + current_user.last_name,
                account_number=current_user.account_number,
                amount=amount,
                monthly_payment=monthly_payment,
                date_applied=datetime.now().strftime('%d-%b-%Y %I:%M %p'),
                support_link="https://Digivault.com/support",
                duration=years,
                year=datetime.now().year
            )
            send_email(current_user.email, message, subject)
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error during loan application: {str(e)}')
            flash('An error occurred during the loan application. Please try again.', 'error')
    print(234,'\n\n\n')
    return render_template('apply_loan.html', form=form)


#================================================================================================================================================================

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    users = {"Verified":[], "NonVerified":[]}
    users["Verified"] = User.query.filter_by(is_verified = True).all()
    users["NonVerified"] = User.query.filter_by(is_verified = False).all()
    print("\n\n\n",users)
    return render_template('admin_dashboard.html', users=users)


#================================================================================================================================================================

@app.route('/admin/user/create', methods=['GET', 'POST'])
@admin_required
def admin_create_user():
    form = AdminCreateUserForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email address already in use. Please use a different email.', 'error')
            return redirect(url_for('admin_create_user'))

        try:
            hashed_password = generate_password_hash(form.password.data)
            new_user = User(
                username=form.username.data,
                password=hashed_password,
                first_name=form.first_name.data,
                last_name=form.last_name.data,
                phone=form.phone.data,
                city=form.city.data,
                email=form.email.data,
                account_type=form.account_type.data,
                age=form.age.data,
                is_admin=form.is_admin.data,
                is_verified=True
            )
            new_user.account_number = genrate_account_number(form.username.data, form.account_type.data)
            db.session.add(new_user)
            db.session.commit()
            flash('User created successfully.', 'success')
            app.logger.info(f'Admin created new user: {form.username.data}')
            message = render_template(
                "email/account_verified.html",
                full_name=new_user.first_name + ' ' + new_user.last_name,
                account_number=new_user.account_number,
                login_link=url_for('login'),
                support_link="https://Digivault.com/support",
                year=datetime.now().year
            )
            send_email_message(new_user.email, message, "Your Digivault Account Is Now Verified and Ready to Use")
            return redirect(url_for('admin_dashboard'))
        except IntegrityError:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'error')
            return redirect(url_for('admin_create_user'))

    return render_template('admin_create_user.html', form=form)

#===============================================================================================================================================================
@app.route('/admin/user/delete/<string:account_no>', methods =['POST'])
@admin_required
def delete_user(account_no):
        user = db.session.query(User).filter_by(account_number=account_no).first()
        if user:
            db.session.delete(user)
            db.session.commit()
            flash("User deleted successfully!", "success")
            message = render_template(
                "email/account_deleted_email.html",
                full_name=user.first_name + ' ' + user.last_name,
                account_number=user.account_number,
                support_link="https://Digivault.com/support",
                year=datetime.now().year
            )

            send_email(
                recipient_email=user.email,
                text=message,
                subject="Your Digivault Account Has Been Deleted"
            )
        else:
            flash("User not found!", "danger")
        return redirect(url_for('admin_dashboard'))

#================================================================================================================================================================
@app.route('/admin/user/transaction<string:account_no>', methods =['POST'])
@admin_required
def view_user_transaction(account_no):
        transactions = Transaction.query.filter_by(account_number=account_no).all()
        if transactions:
            return render_template('admin_view_transactions.html', transactions=transactions, account_no = account_no)
        else:
            flash("no transaction found!", "danger")
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/user/transaction/pdf/<string:account_no>/<int:email>')
@admin_required
def admin_download_transactions_pdf(account_no, email):
    view_user = User.query.get(account_no)
    if view_user:
        user_transactions = Transaction.query.filter_by(account_number=account_no).order_by(Transaction.date.desc()).all()
        for transaction in user_transactions:
            if not verify_transaction_integrity(transaction):
                flash('Warning: Some transactions may have been tampered with.', 'error')
                app.logger.warning(f'Transaction integrity check failed for transaction ID: {transaction.id}')
                break
        html = render_template('transactions_pdf.html', transactions=user_transactions, user=view_user, current_date=datetime.now())

        result = BytesIO()
        pisa_status = pisa.CreatePDF(src=html, dest=result)

        if pisa_status.err:
            return "PDF generation failed", 500
        
        # Send as response
        response = make_response(result.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename=transaction_history.pdf'

        return response
    flash("no user found")
    return "PDF generation failed no user found", 404

#================================================================================================================================================================

@app.route('/admin/user/verify/<string:account_no>', methods =['GET', 'POST'])
@admin_required
def verify_edit_user(account_no):
        print(123)
        if request.method == 'GET':
            print(123442)
            user = db.session.query(User).filter(User.account_number == account_no).first()
            if user:
                print(2345)
                aadhaar_url = app.config['UPLOAD_FOLDER'][7::]+'/' + user.aadhaar_url
                pan_url = app.config['UPLOAD_FOLDER'][7::]+'/'+ user.pan_url
                print('aadhaar url','\n\n\n\n',aadhaar_url)
                return render_template('user_page.html', user=user, aadhar_image_url = aadhaar_url , pan_image_url = pan_url)
            else:
                flash("User not found", "success")
                return redirect(url_for('admin_dashboard'))
        else:
            user = db.session.query(User).filter(User.account_number == account_no).first()
            if user:
                user.is_verified = True
                aadhaar_url = app.config['UPLOAD_FOLDER']+'/' + user.aadhaar_url
                pan_url = app.config['UPLOAD_FOLDER']+'/'+ user.pan_url
                flash("user is verified", "success")
                db.session.commit()
                message = render_template(
                    "email/account_verified.html",
                    full_name=user.first_name + ' ' + user.last_name,
                    account_number=user.account_number,
                    login_link=url_for('login'),
                    support_link="https://Digivault.com/support",
                    year=datetime.now().year
                )
                send_email(user.email, message, "Your Digivault Account Is Now Verified and Ready to Use")
                return render_template('user_page.html', user=user, aadhar_image_url = aadhaar_url.strip() , pan_image_url = pan_url.strip())
            else:
                flash("User not found", "success")
                return redirect(url_for('admin_dashboard'))
#================================================================================================================================================================
@app.route('/admin/approve/loan/', methods=['GET', 'POST'])
@admin_required
def approve_loan():
    if request.method == 'POST':
        id = request.args.get('id', None)
        approved = request.args.get('approved', 0)
        if id and approved:
            loan_transaction = Loan.query.get(id)
            print(id,approved,'\n\n\n')
            if loan_transaction and loan_transaction.is_approved != -1:
                if approved:
                    user = User.query.filter(User.account_number == loan_transaction.account_number).first()
                    user.balance += loan_transaction.amount
                    user.loan_amount += loan_transaction.amount
                    loan_transaction.is_approved = 1
                    transaction = Transaction(account_number=user.account_number, amount=loan_transaction.amount, description='loan approved', balance_after=user.balance, transaction_type='Loan')
                    transaction.hash = generate_transaction_hash(transaction)
                    loan_transaction.transaction_id = transaction.id
                    db.session.add(transaction)
                    db.session.commit()
                    flash("loan approved","success")
                    message = render_template(
                        "email/loan_approved_email.html",
                        full_name=user.first_name + ' ' + user.last_name,
                        account_number=user.account_number,
                        amount=loan_transaction.amount,
                        loan_type=loan_transaction.loan_type,
                        duration=loan_transaction.years,  # in years
                        monthly_payment=loan_transaction.monthly_payment,
                        approval_date=datetime.now().strftime('%d-%b-%Y %I:%M %p'),
                        login_link=url_for('login'),
                        support_link="https://Digivault.com/support",
                        year=datetime.now().year
                    )

                    send_email(
                        recipient_email=user.email,
                        text=message,
                        subject="🎉 Your Digivault Loan Request Has Been Approved!"
                    )

                else:
                    loan_transaction.is_approved = -1
                    flash("loan rejected","success")
                    db.session.commit()
            else:
                flash("loan not found","error")
        return redirect(url_for('approve_loan'))
    loan_transaction = Loan.query.filter().all()
    return render_template('admin_loan.html', loans=loan_transaction)

#================================================================================================================================================================

@app.route('/profile')
@token_required
def profile(current_user):
    aadhaar_url = app.config['UPLOAD_FOLDER']+'/'+current_user.aadhaar_url
    pan_url = app.config['UPLOAD_FOLDER']+'/'+current_user.pan_url


    return render_template('profile.html', user=current_user, aadhar_image_url = aadhaar_url.strip() , pan_image_url = pan_url.strip() )


#================================================================================================================================================================

@app.route('/change_password', methods=['GET', 'POST'])
@token_required
def change_password(current_user):
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if not check_password_hash(current_user.password, old_password):
            flash('Current password is incorrect.', 'error')
        elif new_password != confirm_password:
            flash('New passwords do not match.', 'error')
        elif len(new_password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
        else:
            current_user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('Password changed successfully.', 'success')
            app.logger.info(f'User {current_user.username} changed their password')
            message = render_template(
                "email/password_changed.html",
                full_name=current_user.first_name + ' ' + current_user.last_name,
                account_number=current_user.account_number,
                changed_on=datetime.now().strftime('%d-%b-%Y %I:%M %p'),
                reset_link="https://Digivault.com/reset-password",
                year=datetime.now().year
            )
            send_email(current_user.email, message, "Your Digivault Account Password Was Successfully Changed")
            return redirect(url_for('profile'))

    return render_template('change_password.html')

#================================================================================================================================================================

@app.route('/audit_log')
@admin_required
def audit_log():
    logs = []
    with open('logs/Digivaultbank.log', 'r') as log_file:
        logs = log_file.readlines()
    return render_template('audit_log.html', logs=logs)

#================================================================================================================================================================

@app.route('/api/balance')
@token_required
def get_balance(current_user):
    return jsonify({'balance': current_user.balance})





#================================================================================================================================================================


@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

#================================================================================================================================================================

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500


#================================================================================================================================================================
@app.route('/api/admin/logs')
@admin_required
def get_logs(search_query=None):
    print("working")
    try:
        logs = []
        log_files = glob.glob('logs/flask_bank.log*')
        
        app.logger.debug(f"Found log files: {log_files}")

        for log_file_path in sorted(log_files, key=os.path.getmtime, reverse=True):
            with open(log_file_path, 'r') as log_file:
                for line in log_file:
                    if True or search_query in line:
                        match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) (\w+): (.+) \[in .+\]', line)
                        if match:
                            timestamp, level, message = match.groups()
                            
                            # Extract IP, UserAgent, Method, and Path from the message
                            ip_match = re.search(r'IP=([\d\.]+)', message)
                            method_match = re.search(r'Method=(\w+)', message)
                            path_match = re.search(r'Path=(/[^\s]+)', message)
                            
                            log_entry = {
                                'timestamp': timestamp,
                                'level': level,
                                'message': message,
                                'ip': ip_match.group(1) if ip_match else 'N/A',
                                'method': method_match.group(1) if method_match else None,
                                'path': path_match.group(1) if path_match else None
                            }
                            logs.append(log_entry)

        # Sort logs by timestamp (newest first)
        sorted_logs = sorted(logs, key=lambda x: datetime.strptime(x['timestamp'], '%Y-%m-%d %H:%M:%S,%f'), reverse=True)

        app.logger.debug(f"Returning {len(sorted_logs)} log entries")
        return jsonify(sorted_logs)
    except Exception as e:
        app.logger.error(f"Error in get_logs: {str(e)}")
        return jsonify({"error": "An error occurred while fetching logs"}), 500


#================================================================================================================================================================

# @app.before_request
# def before_request():
#     if not request.is_secure:
#         url = request.url.replace('http://', 'https://', 1)
#         code = 301
#         return redirect(url, code=code)


#================================================================================================================================================================

with app.app_context():
        try:
            user = User.query.filter_by(is_admin=True).first()
        except Exception as e:
            if 'no such table: user' in str(e):
                print("Updating database schema...")
                recreate_database()
            else:
                raise e
if __name__ == '__main__':
   
                

    app.run(host='0.0.0.0', port=5000)  # Run without SSL

    # app.run(debug=False, host='0.0.0.0', port=5000)  # Run without SSL
    # app.run(debug=False, ssl_context='adhoc')  # Use 'adhoc' for development, proper SSL cert for production
    # app.run(debug=False, port=5000)  # Change the port if necessary
