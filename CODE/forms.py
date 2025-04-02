from wtforms import StringField, PasswordField, SelectField, IntegerField, FloatField, BooleanField
from wtforms.validators import DataRequired, Email, Length, NumberRange, Regexp
from flask_wtf import FlaskForm

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=15)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=15)])
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=15)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=15)])
    phone = StringField('Phone', validators=[DataRequired(), Regexp('^[0-9]{10,15}$', message='Phone number must be between 10 and 15 digits')])
    city = StringField('City', validators=[DataRequired(), Length(max=15)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    account_type = SelectField('Account Type', choices=[('savings', 'Savings'), ('current', 'Current'), ('islamic', 'Islamic')])
    age = IntegerField('Age', validators=[DataRequired(), NumberRange(min=18, max=120)])

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



#================================================================================================================================================================

class WithdrawForm(FlaskForm):
    amount = FloatField('Amount', validators=[DataRequired(), NumberRange(min=0.01, max=1000000)])


#================================================================================================================================================================

class LoanForm(FlaskForm):
    amount = FloatField('Amount', validators=[DataRequired(), NumberRange(min=100, max=1000000)])
    years = IntegerField('Years', validators=[DataRequired(), NumberRange(min=1, max=30)])
    loan_type = SelectField('Loan Type', choices=[('education', 'Education'), ('car', 'Car'), ('home', 'Home'), ('personal', 'Personal')])



#================================================================================================================================================================
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=15)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=15)])