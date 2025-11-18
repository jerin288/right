# Right Fit Thrissur - E-Commerce Web Application

A full-featured e-commerce web application built with Flask for clothing and accessories retail business. This application provides complete shopping functionality for customers and comprehensive management tools for administrators.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Technology Stack](#technology-stack)
- [Installation](#installation)
- [Configuration](#configuration)
- [Database Models](#database-models)
- [Key Routes](#key-routes)
- [Security Features](#security-features)
- [Payment Integration](#payment-integration)
- [Email Notifications](#email-notifications)
- [Default Credentials](#default-credentials)
- [Usage](#usage)
- [Customization](#customization)
- [Contributing](#contributing)

## 🎯 Overview

Right Fit Thrissur is a modern e-commerce platform designed for clothing and accessories retail. The application features a responsive design, secure payment processing via Cashfree, automated email notifications, and a powerful admin dashboard for business management.

## ✨ Features

### Customer Features
- **User Authentication**: Secure registration and login with strong password requirements
- **Product Browsing**: Browse products by category with search and filtering options
- **Shopping Cart**: Add, update, and remove items with real-time stock validation
- **Checkout Process**: Support for both Cash on Delivery (COD) and Online Payment
- **Order Tracking**: View order history and status updates
- **Email Notifications**: Automatic order confirmation emails
- **Invoice Generation**: Download PDF invoices for orders
- **Order Cancellation**: Cancel pending/processing orders with automatic stock restoration

### Admin Features
- **Dashboard**: Comprehensive analytics and business metrics
- **Product Management**: Add, edit, delete, and activate/deactivate products
- **Order Management**: Update order status, process refunds, cancel orders
- **Category Management**: Organize products into categories
- **Inventory Control**: Real-time stock tracking and low stock alerts
- **Revenue Analytics**: Track total revenue, paid vs pending amounts
- **User Management**: Monitor customer accounts
- **Refund Processing**: Automated refund handling via Cashfree API

## 🛠️ Technology Stack

### Backend
- **Framework**: Flask 2.3.3
- **Database**: SQLite (SQLAlchemy ORM 2.0.44)
- **Authentication**: Flask-Login 0.6.2
- **Security**: Werkzeug 2.3.7 (password hashing)
- **PDF Generation**: ReportLab 4.0.7

### Payment Gateway
- **Cashfree Payment Gateway SDK**: v4.5.0+
- **Environment**: SANDBOX/PRODUCTION support

### Frontend
- **CSS Framework**: Bootstrap 5.1.3
- **Icons**: Font Awesome 6.0.0
- **Templates**: Jinja2

### Notifications
- **Email**: SMTP (Gmail support)
- **SMS**: Fast2SMS API (optional)

## 📥 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Git (for cloning repository)

### Step 1: Clone Repository
```bash
git clone <repository-url>
cd right_fit
```

### Step 2: Create Virtual Environment
```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# Linux/Mac
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
```bash
# Copy the example file
cp .env.example .env

# Edit .env and configure your settings
```

### Step 5: Run Application
```bash
python app.py
```

The application will be available at `http://127.0.0.1:5000`

## ⚙️ Configuration

### Required Environment Variables

Create a `.env` file based on `.env.example`:

```env
# Flask Configuration
SECRET_KEY=your-secret-key-here
SESSION_COOKIE_SECURE=False  # Set True in production with HTTPS

# Database
DATABASE_URL=sqlite:///ecommerce.db

# Cashfree Payment Gateway
CASHFREE_APP_ID=your-cashfree-app-id
CASHFREE_SECRET_KEY=your-cashfree-secret-key
CASHFREE_ENVIRONMENT=SANDBOX  # or PRODUCTION
CASHFREE_API_VERSION=2023-08-01

# Email Notifications
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=your-email@gmail.com
USE_EMAIL_NOTIFICATION=True

# SMS Notifications (Optional)
ADMIN_PHONE_NUMBER=your-phone-number
SMS_GATEWAY_API_KEY=your-fast2sms-api-key
USE_SMS_NOTIFICATION=False
```

### Generate SECRET_KEY
```python
python -c "import secrets; print(secrets.token_hex(32))"
```

### Gmail App Password Setup
1. Enable 2-Factor Authentication on your Gmail account
2. Go to https://myaccount.google.com/apppasswords
3. Generate an App Password for "Mail"
4. Use the generated password in `MAIL_PASSWORD`

## 🗄️ Database Models

### User
Manages customer and admin accounts
- `id`: Primary key
- `username`: Unique username
- `email`: Unique email address
- `password_hash`: Encrypted password
- `is_admin`: Admin privilege flag
- `created_at`: Registration timestamp

### Product
Stores product information
- `id`: Primary key
- `name`: Product name
- `description`: Product details
- `price`: Product price
- `stock`: Available quantity
- `category_id`: Foreign key to Category
- `image_url`: Product image path
- `sizes`: Available sizes (comma-separated)
- `colors`: Available colors (comma-separated)
- `is_active`: Product visibility flag

### Category
Organizes products into categories
- `id`: Primary key
- `name`: Category name (unique)
- `description`: Category description

### Cart
Manages shopping cart items
- `id`: Primary key
- `user_id`: Foreign key to User
- `product_id`: Foreign key to Product
- `quantity`: Item quantity
- `size`: Selected size
- `color`: Selected color
- `added_at`: Timestamp

### Order
Tracks customer orders
- `id`: Primary key
- `user_id`: Foreign key to User
- `total_amount`: Order total (including shipping)
- `status`: Order status (Pending, Processing, Shipped, Delivered, Cancelled)
- `shipping_address`: Delivery address
- `phone`: Contact number
- `payment_method`: COD or ONLINE
- `payment_status`: PENDING, PAID, FAILED, CANCELLED, REFUNDED, REFUND_PENDING
- `payment_id`: Cashfree transaction ID
- `cashfree_order_id`: Cashfree order reference
- `created_at`: Order timestamp

### OrderItem
Stores individual items in an order
- `id`: Primary key
- `order_id`: Foreign key to Order
- `product_id`: Foreign key to Product
- `quantity`: Item quantity
- `price`: Price at time of purchase
- `size`: Selected size
- `color`: Selected color

## 🛣️ Key Routes

### Public Routes
- `GET /`: Homepage with featured products
- `GET /products`: Product listing with filters
- `GET /product/<id>`: Product detail page
- `GET /about`: About us page
- `GET /register`: User registration
- `GET /login`: User login

### Customer Routes (Login Required)
- `GET /cart`: View shopping cart
- `POST /add_to_cart/<product_id>`: Add item to cart
- `POST /update_cart/<cart_id>`: Update cart quantity
- `GET /remove_from_cart/<cart_id>`: Remove cart item
- `GET|POST /checkout`: Checkout process
- `GET /my_orders`: Order history
- `POST /order/cancel/<order_id>`: Cancel order
- `GET /order/invoice/<order_id>`: Download invoice PDF

### Payment Routes
- `GET /payment/initiate/<order_id>`: Initialize Cashfree payment
- `GET|POST /payment/callback`: Payment verification callback
- `POST /payment/webhook`: Cashfree webhook handler
- `GET /payment/success/<order_id>`: Payment success page
- `GET /payment/failed/<order_id>`: Payment failure page

### Admin Routes (Admin Only)
- `GET /admin`: Admin dashboard
- `GET /admin/products`: Product management
- `GET|POST /admin/product/add`: Add new product
- `GET|POST /admin/product/edit/<id>`: Edit product
- `POST /admin/product/delete/<id>`: Delete product
- `GET /admin/product/toggle/<id>`: Toggle product status
- `GET /admin/orders`: Order management
- `POST /admin/order/update/<id>`: Update order status
- `POST /admin/order/delete/<id>`: Delete order (restores stock)
- `POST /admin/order/cancel-paid/<id>`: Cancel paid order with refund
- `GET /admin/categories`: Category management
- `POST /admin/category/add`: Add category
- `POST /admin/category/edit/<id>`: Edit category
- `POST /admin/category/delete/<id>`: Delete category

## 🔒 Security Features

### Authentication & Authorization
- **Password Strength**: Minimum 8 characters with uppercase, lowercase, and numbers
- **Password Hashing**: Werkzeug's secure password hashing (PBKDF2)
- **Session Security**: HttpOnly cookies, SameSite=Lax protection
- **Session Timeout**: 24-hour session lifetime
- **Role-based Access**: Admin/Customer separation

### Input Validation
- **Email Validation**: RFC 5321 compliant (max 254 characters)
- **Phone Validation**: Indian mobile numbers (10 digits, 6-9 prefix)
- **Price Validation**: Positive numbers only
- **Stock Validation**: Non-negative integers
- **File Upload Validation**: Allowed extensions, size limits (16MB max)

### Data Protection
- **Sensitive Data Redaction**: Passwords and payment info excluded from logs
- **SQL Injection Protection**: SQLAlchemy ORM with parameterized queries
- **XSS Protection**: Jinja2 auto-escaping
- **CSRF Protection**: Ready for Flask-WTF integration

### Stock Management
- **Race Condition Prevention**: Atomic database transactions
- **Stock Validation**: Double-check before order confirmation
- **Automatic Rollback**: Failed transactions restore inventory

## 💳 Payment Integration

### Cashfree Configuration

1. **Sign up** at https://merchant.cashfree.com
2. **Get credentials** from Cashfree dashboard
3. **Configure** in `.env`:
   ```env
   CASHFREE_APP_ID=your-app-id
   CASHFREE_SECRET_KEY=your-secret-key
   CASHFREE_ENVIRONMENT=SANDBOX  # Use PRODUCTION for live
   ```

### Payment Flow

1. Customer selects "Pay Online" at checkout
2. Order created with `payment_status=PENDING`
3. Cashfree payment session initialized
4. Customer redirected to Cashfree payment page
5. Payment processed (UPI, Cards, Net Banking, Wallets)
6. Callback received and payment verified
7. Order updated with `payment_status=PAID`
8. Email confirmation sent to customer

### Refund Process

1. Admin cancels paid order
2. Automatic refund initiated via Cashfree API
3. On success: `payment_status=REFUNDED`
4. On failure: `payment_status=REFUND_PENDING` (manual processing required)
5. Stock automatically restored

## 📧 Email Notifications

### Features
- **HTML Email Templates**: Professional, branded design
- **Order Confirmations**: Sent for both COD and Online orders
- **Payment Success**: Confirmation after successful payment
- **Order Details**: Complete item list, pricing, shipping address
- **Track Order Link**: Direct link to order status page

### Email Content
- Order ID and date
- Payment method and status
- Shipping address and phone
- Itemized order list with quantities and prices
- Order total
- Contact information

## 🔑 Default Credentials

### Admin Account
- **Username**: `admin`
- **Password**: `admin123`
- **Access**: Full admin dashboard

### Customer Account
- **Username**: `customer`
- **Password**: `customer123`
- **Access**: Shopping and order features

**⚠️ Important**: Change these credentials immediately in production!

## 📖 Usage

### For Customers

1. **Register/Login**: Create account or login
2. **Browse Products**: Search and filter by category
3. **Add to Cart**: Select size, color, quantity
4. **Checkout**: Enter shipping details, choose payment method
5. **Track Orders**: View order status in "My Orders"
6. **Cancel Orders**: Cancel pending orders if needed
7. **Download Invoice**: Get PDF invoice for completed orders

### For Administrators

1. **Login**: Use admin credentials
2. **Dashboard**: Monitor business metrics
3. **Manage Products**: Add/edit/delete products
4. **Process Orders**: Update status, handle refunds
5. **Track Inventory**: Monitor stock levels
6. **Manage Categories**: Organize product catalog

## 🎨 Customization

### Branding

**Update logo and colors in** `templates/base.html`:
```css
:root {
    --primary-color: #dc143c;  /* Change to your brand color */
    --secondary-color: #ff0000;
    --accent-color: #b22222;
}
```

**Replace logo image**:
```html
<img src="{{ url_for('static', filename='images/your-logo.jpg') }}" alt="Logo">
```

### Shipping Charges

**Edit in** `app.py`:
```python
FREE_SHIPPING_THRESHOLD = 999.00  # Free shipping above this amount
SHIPPING_CHARGE = 50.00          # Shipping fee
```

### Business Information

**Update contact details in**:
- `templates/base.html` (footer)
- `templates/about.html` (about page)
- Email templates in `app.py` (`generate_order_confirmation_email`)

### Product Categories

Add/edit categories through admin panel or database initialization in `app.py`:
```python
categories_data = [
    {'name': 'Your Category', 'description': 'Description'},
    # Add more categories
]
```

### File Upload Settings

**Modify in** `app.py`:
```python
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
```

### Session Security (Production)

**Enable in** `.env`:
```env
SESSION_COOKIE_SECURE=True  # Requires HTTPS
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Make your changes
4. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
5. Push to the branch (`git push origin feature/AmazingFeature`)
6. Open a Pull Request

### Utility Commands

The `utils.py` file provides helpful management commands:

```bash
# Generate SECRET_KEY
python utils.py generate-key

# View database statistics
python utils.py stats

# Check low stock products
python utils.py low-stock 10

# Cleanup old cart items
python utils.py cleanup-carts 30

# Export orders to CSV
python utils.py export-orders orders.csv

# Create admin user
python utils.py create-admin username email password

# Reset user password
python utils.py reset-password username newpassword
```

---

## 📄 License

This project is developed for Right Fit Thrissur.

## 📞 Support

For support, email rightfit2023@gmail.com or call +91 8157971886

---

**Built with ❤️ for Right Fit Thrissur**
