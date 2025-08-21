
## Live Demo

Experience Digivault Banking System live at: **[https://bank-management-system-se-project.onrender.com/](https://bank-management-system-se-project.onrender.com/)**

### Demo Features
- Full banking functionality available
- Test user registration and verification process
- Explore admin dashboard features
- Experience secure transaction processing

**Note**: This is a demonstration environment. Please do not enter real personal or financial information.

---
# 🏦 Digivault Banking System

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Visit%20Site-blue?style=for-the-badge&logo=render)](https://bank-management-system-se-project.onrender.com/)

## 📑 Table of Contents
- [Live Demo](#live-demo)
- [Overview](#overview)
- [Features](#features)
- [Security Measures](#security-measures)
- [Tech Stack](#tech-stack)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Using Virtual Environment](#using-virtual-environment)
  - [Database Setup](#database-setup)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Email Templates](#email-templates)
- [Admin Features](#admin-features)
- [File Structure](#file-structure)
- [Contributing](#contributing)
- [License](#license)

---

## 🌟 Overview

Digivault Banking System is a comprehensive, secure, and feature-rich banking application built with Flask. It provides a complete digital banking experience with robust security measures, document verification, email notifications, and comprehensive admin controls.

The system supports multiple account types, loan management, transaction processing, and includes a sophisticated admin dashboard for user verification and system monitoring.

---

## 🚀 Features

### User Features
- 👤 **User Registration & Verification**
  - Document upload (Aadhaar & PAN card)
  - Admin verification process
  - Email notifications throughout verification
- 🔐 **Secure Authentication**
  - Two-factor authentication with OTP
  - JWT-based session management
  - Account lockout protection
- 💰 **Account Management**
  - Multiple account types (Savings, Current, Business)
  - Real-time balance tracking
  - Profile management with document viewing
- 💸 **Transaction Services**
  - Secure money transfers between accounts
  - Deposit and withdrawal operations
  - Transaction history with PDF export
  - Email notifications for all transactions
- 💳 **Loan Management**
  - Multiple loan types (Personal, Education, Car, Home)
  - Automatic EMI calculations
  - Loan application tracking
  - Admin approval workflow
- 📊 **Reports & Statements**
  - Detailed transaction history
  - PDF statement generation
  - Email statement delivery
  - Transaction integrity verification

### Admin Features
- 👑 **Admin Dashboard**
  - User verification management
  - Account approval/rejection
  - System monitoring
- 👥 **User Management**
  - Create, verify, and delete users
  - View user transaction history
  - Document verification interface
- 💼 **Loan Administration**
  - Review loan applications
  - Approve/reject loans with notifications
  - Monitor loan portfolio
- 📋 **System Monitoring**
  - Comprehensive audit logs
  - Real-time log viewing API
  - Security event tracking

---

## 🔒 Security Measures

- 🔐 **Password Security**: Werkzeug password hashing with salt
- 🚫 **Rate Limiting**: Configurable limits to prevent brute force attacks
- 🔑 **JWT Authentication**: Secure token-based session management
- 🛡️ **CSRF Protection**: Flask-WTF CSRF tokens on all forms
- 🧹 **Input Sanitization**: Bleach library for XSS prevention
- 🔍 **Comprehensive Logging**: Rotating file logs with detailed audit trails
- 🔒 **Account Security**: Automatic lockout after failed attempts
- 📧 **Email Notifications**: Security alerts for all account activities
- 🔐 **OTP Verification**: Two-factor authentication for login
- 📜 **Transaction Integrity**: Hash-based transaction verification
- 🎫 **Session Management**: Secure session handling with expiration
- 📁 **File Upload Security**: Restricted file types and size limits

---

## 💻 Tech Stack

- **Backend**: Flask (Python)
- **Database**: SQLite/MySQL with SQLAlchemy ORM
- **Authentication**: JWT tokens with OTP verification
- **Email Service**: SMTP with HTML templates
- **PDF Generation**: xhtml2pdf
- **Security**: Flask-WTF, Flask-Limiter, Bleach
- **Frontend**: HTML, CSS, JavaScript (responsive design)
- **File Handling**: Document upload and verification system

---

## 🛠️ Installation

Choose one of the following installation methods:

### Prerequisites
- **For Docker**: Docker and Docker Compose
- **For Virtual Environment**: Python 3.8+, SQLite (default) or MySQL Server (optional), SMTP Server

### Using Docker (Recommended)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/digivault-banking-system.git
   cd digivault-banking-system
   ```

2. **Create environment file:**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Build and run with Docker Compose:**
   ```bash
   docker-compose up --build
   ```

4. **Access the application:**
   - Main application: `http://localhost:5000`
   - Email interface (SMTP4dev): `http://localhost:3000`

**Docker Services:**
- **flaskapp**: Main Digivault banking application
- **smtp**: SMTP4dev server for email testing and development

**Docker Volumes:**
- `bankdata_volume`: Persistent storage for application data
- `smtp4dev_volume`: Email storage for SMTP4dev

**To stop the services:**
```bash
docker-compose down
```

**To rebuild after code changes:**
```bash
docker-compose up --build
```

### Using Virtual Environment

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/digivault-banking-system.git
   cd digivault-banking-system
   ```

2. **Create and activate virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Create required directories:**
   ```bash
   mkdir -p static/uploads logs
   ```

### Database Setup

**For SQLite (Default - No additional setup required):**
The application will automatically create `database.sqlite3` in your project directory.

**For MySQL (Optional):**
1. **Create MySQL database:**
   ```sql
   CREATE DATABASE flask_bank;
   ```

2. **Update DATABASE_URI in .env file:**
   ```bash
   DATABASE_URI=mysql+pymysql://username:password@localhost:3306/flask_bank
   ```

---

## ⚙️ Configuration

### Environment Variables

Create a `.env` file with the following structure:

```env
# ======================
# Flask Environment
# ======================
FLASK_ENV=development
FLASK_APP=app.py
#SECRET_KEY=your_flask_secret_key_here

# ======================
# Database Configuration
# ======================
DATABASE_URI=sqlite:///database.sqlite3

# ======================
# JWT Configuration
# ======================
#JWT_SECRET_KEY=your_jwt_secret_key_here
JWT_ACCESS_TOKEN_EXPIRES=15m  
JWT_REFRESH_TOKEN_EXPIRES=30d

# ======================
# Production SMTP Config (Live Emails)
# ======================
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_production_email@aruppevaletbank.com
SMTP_PASSWORD=your_production_email_password

# ======================
# Development SMTP Config (Local Testing)
# ======================
SMTP_DEV_SERVER=smtp
SMTP_DEV_PORT=25
SMTP_DEV_USER=email.test@aruppevaletbank.com
```

**Note**: Uncomment and set the `SECRET_KEY` and `JWT_SECRET_KEY` for production use. The application will use default values for development.

### Email Service Setup

**For Development (Local SMTP Testing):**
```bash
docker volume create smtp4dev_volume
docker run --rm -it -p 3000:80 -p 1025:25 -v smtp4dev_volume:/smtp4dev rnwood/smtp4dev
```

**For Production:**
- Configure Gmail SMTP or your preferred email service
- Update the production SMTP settings in your `.env` file
- Enable "App Passwords" for Gmail if using 2FA

---

## 🖥️ Usage

### 🌐 Live Demo
Visit the live application at: **[https://bank-management-system-se-project.onrender.com/](https://bank-management-system-se-project.onrender.com/)**

### Using Docker
1. **Start the services:**
   ```bash
   docker-compose up
   ```

2. **Access the application:**
   - Main application: `http://localhost:5000`
   - Email interface: `http://localhost:3000`

### Using Virtual Environment
1. **Start the application:**
   ```bash
   python app.py
   ```

2. **Access the application:**
   - Main application: `http://localhost:5000`
   - Email interface: `http://localhost:3000` (if using smtp4dev)

### Initial Setup (Both Methods)
- Register a new account with required documents
- Admin verification required for account activation
- Default admin account created automatically

### User Workflow
- Register → Document Upload → Admin Verification → OTP Login → Banking Services

---

## 🔗 API Endpoints

### Public Endpoints
- `GET /` - Home page
- `POST /login` - User authentication
- `POST /register` - User registration
- `GET /send_otp` - OTP generation and sending

### Protected User Endpoints
- `GET /dashboard` - User dashboard
- `GET /api/balance` - Get current balance
- `POST /transfer` - Money transfer
- `POST /deposit` - Deposit money
- `POST /withdraw` - Withdraw money
- `GET /transactions` - Transaction history
- `GET /transactions/pdf/<email>` - Download/email PDF statement
- `POST /loan/apply` - Apply for loan
- `GET /profile` - User profile
- `POST /change_password` - Change password

### Admin Endpoints
- `GET /admin/dashboard` - Admin dashboard
- `POST /admin/user/create` - Create new user
- `POST /admin/user/verify/<account_no>` - Verify user account
- `POST /admin/user/delete/<account_no>` - Delete user
- `GET /admin/approve/loan/` - Loan management
- `GET /api/admin/logs` - System logs API

---

## 📧 Email Templates

The system includes comprehensive email templates for:
- Account registration confirmation
- Account verification notifications
- Login security alerts
- Transaction confirmations
- Loan application updates
- Password change notifications
- Account lockout alerts

---

## 👑 Admin Features

### User Management
- **Verification Interface**: View and verify user documents (Aadhaar, PAN)
- **Account Creation**: Direct user account creation with verification
- **User Monitoring**: Transaction history and account activity tracking

### Loan Administration
- **Application Review**: Comprehensive loan application interface
- **Approval Workflow**: Automated loan processing with email notifications
- **Portfolio Management**: Track all loans and their status

### System Administration
- **Audit Logs**: Real-time system log monitoring
- **Security Monitoring**: Failed login attempts and security events
- **Database Management**: User and transaction oversight

---

## 📁 File Structure

```
digivault-banking-system/
├── app.py                 # Main Flask application
├── model.py              # Database models
├── functions.py          # Utility functions
├── forms.py              # WTForms definitions
├── requirements.txt      # Python dependencies
├── recreate_db.py        # create database if not exist
├── static/
│   └── uploads/          # User document uploads
├── templates/
│   ├── email/           # Email templates
│   ├── admin/           # Admin interface templates
│   └── *.html           # User interface templates
└── logs/
    └── flask_bank.log   # Application logs
```
