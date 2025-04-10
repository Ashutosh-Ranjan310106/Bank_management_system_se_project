from wtforms import StringField, PasswordField, SelectField, IntegerField, FloatField, BooleanField
from wtforms.validators import DataRequired, Email, Length, NumberRange, Regexp
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=15)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=15)])
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=15)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=15)])
    phone = StringField('Phone', validators=[DataRequired(), Regexp('^[0-9]{10,15}$', message='Phone number must be between 10 and 15 digits')])
    city = StringField('City', validators=[DataRequired(), Length(max=15)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    account_type = SelectField('Account Type', choices=[('savings', 'Savings'), ('current', 'Current')])
    age = IntegerField('Age', validators=[DataRequired(), NumberRange(min=18, max=120)])
    # New fields for document uploads
    aadhaar = FileField('Aadhaar Card', validators=[
        FileRequired(message='Aadhaar card is required.'),
        FileAllowed(['jpg', 'png', 'jpeg', 'pdf'], 'Images or PDFs only!')
    ])
    pan_card = FileField('PAN Card', validators=[
        FileRequired(message='PAN card is required.'),
        FileAllowed(['jpg', 'png', 'jpeg', 'pdf'], 'Images or PDFs only!')
    ])

#================================================================================================================================================================

class AdminCreateUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=15)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=15)])
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=15)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=15)])
    phone = StringField('Phone', validators=[DataRequired(), Regexp('^[0-9]{10,15}$', message='Phone number must be between 10 and 15 digits')])
    city = StringField('City', validators=[DataRequired(), Length(max=15)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    account_type = SelectField('Account Type', choices=[('savings', 'Savings'), ('current', 'Current'), ('islamic', 'Islamic')])
    age = IntegerField('Age', validators=[DataRequired(), NumberRange(min=18, max=120)])
    is_admin = BooleanField('Is Admin')


#================================================================================================================================================================

class DepositForm(FlaskForm):
    amount = FloatField('Amount', validators=[DataRequired(), NumberRange(min=0.01, max=1000000)])
    description = StringField('description')



#================================================================================================================================================================

class WithdrawForm(FlaskForm):
    amount = FloatField('Amount', validators=[DataRequired(), NumberRange(min=0.01, max=1000000)])
    description = StringField('description')

#================================================================================================================================================================

class LoanForm(FlaskForm):
    amount = FloatField('Amount', validators=[DataRequired(), NumberRange(min=100, max=1000000)])
    years = IntegerField('Years', validators=[DataRequired(), NumberRange(min=1, max=30)])
    loan_type = SelectField('Loan Type', choices=[('education', 'Education'), ('car', 'Car'), ('home', 'Home'), ('personal', 'Personal')])



#================================================================================================================================================================
class LoginForm(FlaskForm):
    account_no = StringField('Account Number', validators=[DataRequired(), Length(min=12, max=12)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=15)])

class OTPForm(FlaskForm):
    otp = StringField('OTP', validators=[DataRequired(), Length(min=6, max=6)])

#================================================================================================================================================================
class TransferForm(FlaskForm):
    amount = FloatField('Amount', validators=[DataRequired(), NumberRange(min=0.01, max=1000000)])
    related_account_number = StringField('Transfer account number', validators=[DataRequired()])
    description = StringField('Description')