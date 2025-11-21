"""
E-Commerce Web Application for Clothing and Accessories
Main application file with routes and business logic
"""

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect, CSRFError
from datetime import datetime, timedelta
import os
import requests
import re
from dotenv import load_dotenv
from sqlalchemy import func, or_
from sqlalchemy.orm import Mapped, WriteOnlyMapped, relationship
from io import BytesIO
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from typing import TYPE_CHECKING
import logging
import sys
# Email imports - DISABLED
# import smtplib
# from email.mime.text import MIMEText
# from email.mime.multipart import MIMEMultipart
# from email.mime.base import MIMEBase
# from email import encoders

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from typing import List

# UPI Payment System - No external SDK required

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
# Configure for reverse proxy (Railway)
app.config['PREFERRED_URL_SCHEME'] = 'https'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-change-in-production')
# Database configuration with psycopg2 support
database_url = os.getenv('DATABASE_URL', 'sqlite:///ecommerce.db')
# Fix for Railway/Render's postgres:// URL (psycopg2 needs postgresql://)
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
csrf = CSRFProtect(app)
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads', 'products')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Session security configuration
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'  # Set True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# Shipping configuration
FREE_SHIPPING_THRESHOLD = 999.00
SHIPPING_CHARGE = 100.00

# SMS Gateway Configuration (Free SMS notification)
ADMIN_PHONE_NUMBER = os.getenv('ADMIN_PHONE_NUMBER', '7510556919')  # Admin phone number for SMS (without country code)
SMS_GATEWAY_API_KEY = os.getenv('SMS_GATEWAY_API_KEY')  # Fast2SMS API Key
USE_SMS_NOTIFICATION = os.getenv('USE_SMS_NOTIFICATION', 'False').lower() == 'true'  # Set to True to enable SMS notifications (requires ₹100 credit)

if not SMS_GATEWAY_API_KEY and USE_SMS_NOTIFICATION:
    print("⚠️  WARNING: SMS_GATEWAY_API_KEY not set. SMS notifications will fail.")

# Email Configuration - DISABLED
# Email notification functionality has been removed from the application
# MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
# MAIL_PORT = int(os.getenv('MAIL_PORT', '587'))
# MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
# MAIL_USERNAME = os.getenv('MAIL_USERNAME', '')
# MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', '')
# MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', MAIL_USERNAME)
# USE_EMAIL_NOTIFICATION = os.getenv('USE_EMAIL_NOTIFICATION', 'False').lower() == 'true'

# UPI Payment Configuration
UPI_ID = os.getenv('UPI_ID', '8157971886-1@okbizaxis')  # Your UPI ID
UPI_PAYEE_NAME = os.getenv('UPI_PAYEE_NAME', 'Right Fit Thrissur')  # Payee name
UPI_QR_CODE_PATH = 'images/QR .png'  # Path to QR code in static folder

# Security Warning for Production
if not os.getenv('SECRET_KEY') or os.getenv('SECRET_KEY') == 'your-secret-key-change-in-production':
    print("⚠️  WARNING: Using default SECRET_KEY. Set a secure key in production!")

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_phone(phone):
    """Validate Indian phone number (10 digits starting with 6-9)"""
    if not phone:
        return False
    # Remove spaces, hyphens, and country code prefix
    cleaned = re.sub(r'[\s\-+]', '', phone.strip())
    if cleaned.startswith('91'):
        cleaned = cleaned[2:]
    pattern = r'^[6-9]\d{9}$'
    return re.match(pattern, cleaned) is not None

def validate_email(email):
    """Validate email format"""
    if not email:
        return False
    email = email.strip()
    if len(email) > 254:  # RFC 5321
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password_strength(password):
    """Validate password strength"""
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    
    if not (has_upper and has_lower and has_digit):
        return False, "Password must contain uppercase, lowercase, and numbers."
    
    return True, "Password is strong."

def calculate_order_total(cart_items, coupon=None):
    """Calculate order total including shipping and coupon discount"""
    subtotal = sum(item.product.price * item.quantity for item in cart_items)
    shipping = 0 if subtotal >= FREE_SHIPPING_THRESHOLD else SHIPPING_CHARGE
    
    # Apply coupon discount
    coupon_discount = 0
    if coupon:
        # Check minimum purchase requirement
        if subtotal >= coupon.min_purchase:
            coupon_discount = coupon.calculate_discount(subtotal)
        else:
            coupon_discount = 0  # Don't apply if minimum not met
    
    # Calculate final total
    total = subtotal + shipping - coupon_discount
    total = max(total, 0)  # Ensure total is never negative
    
    return total, subtotal, shipping, coupon_discount

# Email notification function - DISABLED
# def send_email_notification(to_email, subject, html_body, text_body=None):
#     """Send email notification to user - DISABLED"""
#     print("Email notifications have been disabled")
#     return False

# Email template generation function - DISABLED
# def generate_order_confirmation_email(order):
#     """Generate HTML email for order confirmation - DISABLED"""
#     return None, None

def send_sms_notification(order):
    """Send SMS notification to admin about new order using Fast2SMS"""
    try:
        if not USE_SMS_NOTIFICATION or not SMS_GATEWAY_API_KEY:
            print("SMS notification disabled or API key not configured")
            return False
        
        # Prepare SMS message (160 characters limit)
        message = f"New Order #{order.id} - Customer: {order.user.username} - Amount: Rs.{order.total_amount:.0f} - Items: {len(order.items)} - Phone: {order.phone}"
        
        # Fast2SMS Quick API endpoint
        url = "https://www.fast2sms.com/dev/bulkV2"
        
        payload = {
            'route': 'q',  # 'q' for Quick route (RCS/SMS)
            'message': message,
            'language': 'english',
            'flash': 0,
            'numbers': ADMIN_PHONE_NUMBER
        }
        
        headers = {
            'authorization': SMS_GATEWAY_API_KEY,
            'Content-Type': 'application/json'
        }
        
        response = requests.post(url, json=payload, headers=headers)
        
        print(f"SMS API Response: {response.status_code} - {response.text}")
        
        if response.status_code == 200:
            result = response.json()
            if result.get('return'):
                print(f"SMS sent successfully for Order #{order.id}")
                return True
            else:
                print(f"SMS sending failed: {result}")
                return False
        else:
            print(f"SMS API error: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        print(f"Error sending SMS notification: {e}")
        return False

def send_customer_sms(phone, message):
    """Send SMS to customer using Fast2SMS"""
    try:
        if not USE_SMS_NOTIFICATION or not SMS_GATEWAY_API_KEY:
            print("Customer SMS disabled or API key not configured")
            return False
        
        if not validate_phone(phone):
            print(f"Invalid customer phone: {phone}")
            return False
        
        # Extract last 10 digits
        clean_phone = re.sub(r'\D', '', phone)[-10:]
        
        # Fast2SMS Quick API endpoint
        url = "https://www.fast2sms.com/dev/bulkV2"
        
        payload = {
            'route': 'q',
            'message': message,
            'language': 'english',
            'flash': 0,
            'numbers': clean_phone
        }
        
        headers = {
            'authorization': SMS_GATEWAY_API_KEY,
            'Content-Type': 'application/json'
        }
        
        response = requests.post(url, json=payload, headers=headers, timeout=15)
        
        print(f"Customer SMS API Response: {response.status_code} - {response.text}")
        
        if response.status_code == 200:
            result = response.json()
            if result.get('return'):
                print(f"Customer SMS sent successfully to {clean_phone}")
                return True
            else:
                print(f"Customer SMS failed: {result}")
                return False
        else:
            print(f"Customer SMS API error: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        print(f"Error sending customer SMS: {e}")
        return False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # pyright: ignore[reportAttributeAccessIssue]

# Request logging middleware
@app.before_request
def log_request_info():
    print(f"\n{'='*60}")
    print(f"REQUEST: {request.method} {request.path}")
    print(f"From: {request.remote_addr}")
    if request.method == 'POST':
        # Don't log sensitive form data (passwords, payment info)
        safe_form_data = {k: '***REDACTED***' if k in ['password', 'card_number', 'cvv', 'pin'] else v 
                         for k, v in request.form.items()}
        print(f"Form data: {safe_form_data}")
    print(f"{'='*60}\n")
    logger.info(f"{request.method} {request.path}")

@app.after_request
def log_response_info(response):
    print(f"RESPONSE: {response.status}")
    return response

# Context processor to inject config into templates
@app.context_processor
def inject_config():
    return {
        'config': {
            'UPI_ENABLED': True,
            'UPI_PAYEE_NAME': UPI_PAYEE_NAME
        }
    }

# ==================== DATABASE MODELS ====================

class User(UserMixin, db.Model):
    """User model for authentication and customer information"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    if TYPE_CHECKING:
        orders: 'List[Order]'
        cart_items: 'List[Cart]'
    else:
        orders = db.relationship('Order', backref='user', lazy=True)
    
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Category(db.Model):
    """Product categories (e.g., T-Shirts, Jeans, Accessories)"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.Text)
    
    # Relationships
    if TYPE_CHECKING:
        products: 'List[Product]'
    else:
        products = db.relationship('Product', backref='category', lazy=True)
    
    def __init__(self, **kwargs):
        super(Category, self).__init__(**kwargs)


class Product(db.Model):
    """Product model for clothing and accessories"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, default=0)
    image_url = db.Column(db.String(200))
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    sizes = db.Column(db.String(100))  # e.g., "S,M,L,XL"
    colors = db.Column(db.String(100))  # e.g., "Red,Blue,Black"
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    if TYPE_CHECKING:
        category: 'Category'
        cart_items: 'List[Cart]'
        order_items: 'List[OrderItem]'
        features: 'List[ProductFeature]'
    
    def __init__(self, **kwargs):
        super(Product, self).__init__(**kwargs)


class ProductFeature(db.Model):
    """Product features with enable/disable toggle"""
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    feature_text = db.Column(db.String(200), nullable=False)
    is_enabled = db.Column(db.Boolean, default=True)
    display_order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    if TYPE_CHECKING:
        product: 'Product'
    else:
        product = db.relationship('Product', backref=db.backref('features', lazy=True, order_by='ProductFeature.display_order'))
    
    def __init__(self, **kwargs):
        super(ProductFeature, self).__init__(**kwargs)


class Cart(db.Model):
    """Shopping cart items"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    size = db.Column(db.String(10))
    color = db.Column(db.String(20))
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    if TYPE_CHECKING:
        product: 'Product'
        user: 'User'
    else:
        product = db.relationship('Product', backref='cart_items')
        user = db.relationship('User', backref='cart_items')
    
    def __init__(self, **kwargs):
        super(Cart, self).__init__(**kwargs)


class Order(db.Model):
    """Customer orders"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='Pending')  # Pending, Processing, Shipped, Delivered, Cancelled
    shipping_address = db.Column(db.Text, nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    payment_method = db.Column(db.String(20), default='COD')  # COD, UPI
    payment_status = db.Column(db.String(20), default='PENDING')  # PENDING, PAID, FAILED, CANCELLED, REFUND_PENDING, REFUNDED
    payment_id = db.Column(db.String(100))  # UPI transaction ID
    refund_note = db.Column(db.Text)  # Note for refund requests
    coupon_code = db.Column(db.String(50))  # Applied coupon code
    coupon_discount = db.Column(db.Float, default=0)  # Discount amount from coupon
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    if TYPE_CHECKING:
        items: 'List[OrderItem]'
        user: 'User'
    else:
        items = db.relationship('OrderItem', backref='order', lazy=True)
    
    def __init__(self, **kwargs):
        super(Order, self).__init__(**kwargs)


class OrderItem(db.Model):
    """Individual items in an order"""
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    size = db.Column(db.String(10))
    color = db.Column(db.String(20))
    
    # Relationships
    if TYPE_CHECKING:
        product: 'Product'
        order: 'Order'
    else:
        product = db.relationship('Product', backref='order_items')
    
    def __init__(self, **kwargs):
        super(OrderItem, self).__init__(**kwargs)


class Coupon(db.Model):
    """Coupon codes for discounts"""
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    discount_type = db.Column(db.String(20), nullable=False)  # 'percentage' or 'fixed'
    discount_value = db.Column(db.Float, nullable=False)  # percentage (0-100) or fixed amount
    min_purchase = db.Column(db.Float, default=0)  # minimum purchase amount required
    max_discount = db.Column(db.Float)  # maximum discount for percentage type
    start_date = db.Column(db.DateTime, default=datetime.utcnow)
    expiry_date = db.Column(db.DateTime)
    usage_limit = db.Column(db.Integer)  # total times coupon can be used (NULL = unlimited)
    usage_count = db.Column(db.Integer, default=0)  # times coupon has been used
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __init__(self, **kwargs):
        super(Coupon, self).__init__(**kwargs)
    
    def is_valid(self):
        """Check if coupon is currently valid"""
        if not self.is_active:
            return False, "Coupon is inactive"
        
        # Check expiry date
        if self.expiry_date and datetime.utcnow() > self.expiry_date:
            return False, "Coupon has expired"
        
        # Check start date
        if self.start_date and datetime.utcnow() < self.start_date:
            return False, "Coupon is not yet active"
        
        # Check usage limit
        if self.usage_limit and self.usage_count >= self.usage_limit:
            return False, "Coupon usage limit reached"
        
        return True, "Coupon is valid"
    
    def calculate_discount(self, subtotal):
        """Calculate discount amount for given subtotal"""
        if self.discount_type == 'percentage':
            discount = subtotal * (self.discount_value / 100)
            if self.max_discount:
                discount = min(discount, self.max_discount)
        else:  # fixed
            discount = self.discount_value
        
        # Discount cannot exceed subtotal
        return min(discount, subtotal)


class SiteSetting(db.Model):
    """Application-wide settings"""
    id = db.Column(db.Integer, primary_key=True)
    setting_key = db.Column(db.String(50), unique=True, nullable=False)
    setting_value = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(200))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __init__(self, **kwargs):
        super(SiteSetting, self).__init__(**kwargs)
    
    @staticmethod
    def get_setting(key, default='True'):
        """Get setting value by key"""
        setting = SiteSetting.query.filter_by(setting_key=key).first()
        if setting:
            return setting.setting_value
        return default
    
    @staticmethod
    def set_setting(key, value, description=None):
        """Set or update setting value"""
        setting = SiteSetting.query.filter_by(setting_key=key).first()
        if setting:
            setting.setting_value = value
            setting.updated_at = datetime.utcnow()
        else:
            setting = SiteSetting(
                setting_key=key,
                setting_value=value,
                description=description
            )
            db.session.add(setting)
        db.session.commit()
        return setting
    
    @staticmethod
    def is_cod_enabled():
        """Check if Cash on Delivery is enabled"""
        value = SiteSetting.get_setting('cod_enabled', 'True')
        return value.lower() == 'true'


# ==================== LOGIN MANAGER ====================

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ==================== AUTO-INITIALIZE DATABASE ====================
# Initialize database tables on startup (for production deployment)
with app.app_context():
    try:
        # Check if tables exist by trying to query
        db.session.execute(db.text('SELECT 1 FROM product LIMIT 1'))
        print('✅ Database tables already exist')
        
        # Always ensure admin user exists (even if tables already existed)
        try:
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                admin = User(username='admin', email='admin@rightfit.com', is_admin=True)
                admin.set_password('admin123')
                db.session.add(admin)
                db.session.commit()
                print('✅ Admin user created (username: admin, password: admin123)')
            else:
                print('✅ Admin user already exists')
        except Exception as admin_error:
            print(f'⚠️ Admin user check note: {admin_error}')
            
    except Exception as e:
        # Tables don't exist, create them
        print('🔨 Creating database tables...')
        db.create_all()
        print('✅ Database tables created successfully')
        
        # Create default admin user
        try:
            admin = User(username='admin', email='admin@rightfit.com', is_admin=True)
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print('✅ Admin user created (username: admin, password: admin123)')
        except Exception as admin_error:
            print(f'⚠️ Admin user creation note: {admin_error}')


# ==================== ROUTES - HOME & PRODUCTS ====================

@app.route('/')
def index():
    """Homepage with featured products"""
    products = Product.query.filter_by(is_active=True).limit(8).all()
    categories = Category.query.all()
    return render_template('index.html', products=products, categories=categories)


@app.route('/products')
def products():
    """All products page with filtering and sorting"""
    category_id = request.args.get('category', type=int)
    search_query = request.args.get('search', '')
    sort_by = request.args.get('sort', 'newest')  # newest, price_low, price_high, name
    min_price = request.args.get('min_price', type=float)
    max_price = request.args.get('max_price', type=float)
    
    query = Product.query.filter_by(is_active=True)
    
    if category_id:
        query = query.filter_by(category_id=category_id)
    
    if search_query:
        search_pattern = f'%{search_query}%'
        query = query.filter(
            or_(
                Product.name.ilike(search_pattern),
                Product.description.ilike(search_pattern)
            )
        )
    
    if min_price is not None:
        query = query.filter(Product.price >= min_price)
    
    if max_price is not None:
        query = query.filter(Product.price <= max_price)
    
    # Sorting
    if sort_by == 'price_low':
        query = query.order_by(Product.price.asc())
    elif sort_by == 'price_high':
        query = query.order_by(Product.price.desc())
    elif sort_by == 'name':
        query = query.order_by(Product.name.asc())
    else:  # newest (default)
        query = query.order_by(Product.created_at.desc())
    
    products = query.all()
    categories = Category.query.all()
    
    return render_template('products.html', products=products, categories=categories)


@app.route('/product/<int:product_id>')
def product_detail(product_id):
    """Individual product page"""
    product = db.session.get(Product, product_id)
    if not product:
        flash('Product not found', 'danger')
        return redirect(url_for('products'))
    
    # Safely get features (handle missing product_feature table)
    try:
        features = product.features
    except Exception as e:
        logger.warning(f"Could not load product features: {e}")
        features = []
    
    return render_template('product_detail.html', product=product, features=features)


@app.route('/about')
def about():
    """About Us page"""
    return render_template('about.html')


@app.route('/terms')
def terms():
    """Terms & Conditions page"""
    return render_template('terms.html')


# ==================== ROUTES - AUTHENTICATION ====================

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        # Validate input fields
        if not username or len(username) < 3:
            flash('Username must be at least 3 characters long.', 'danger')
            return redirect(url_for('register'))
        
        if not email:
            flash('Email is required.', 'danger')
            return redirect(url_for('register'))
        
        # Validate password strength
        is_valid, message = validate_password_strength(password)
        if not is_valid:
            flash(message, 'danger')
            return redirect(url_for('register'))
        
        # Validate email format
        if not validate_email(email):
            flash('Invalid email format. Please enter a valid email address.', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
        
        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Validate input
        if not username or not password:
            flash('Please provide both username and password.', 'danger')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash(f'Welcome back, {user.username}!', 'success')
            
            # Redirect to admin if admin user
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """User logout"""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


# ==================== ROUTES - SHOPPING CART ====================

@app.route('/cart')
@login_required
def view_cart():
    """View shopping cart"""
    # Redirect admin to dashboard
    if current_user.is_admin:
        flash('Admin accounts cannot access cart. Please use a customer account.', 'warning')
        return redirect(url_for('admin_dashboard'))
    
    cart_items = Cart.query.filter_by(user_id=current_user.id).all()
    
    if cart_items:
        total_amount, subtotal, shipping, _ = calculate_order_total(cart_items)
    else:
        total_amount = subtotal = shipping = 0
    
    return render_template('cart.html', 
                         cart_items=cart_items, 
                         subtotal=subtotal,
                         shipping=shipping,
                         total=total_amount,
                         free_shipping_threshold=FREE_SHIPPING_THRESHOLD)


@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    """Add product to cart"""
    # Prevent admin from adding to cart
    if current_user.is_admin:
        flash('Admin accounts cannot add products to cart. Please use a customer account.', 'warning')
        return redirect(url_for('product_detail', product_id=product_id))
    
    product = db.session.get(Product, product_id)
    if not product:
        flash('Product not found', 'danger')
        return redirect(url_for('products'))
    
    # Check if product is active
    if not product.is_active:
        flash('This product is currently unavailable.', 'warning')
        return redirect(url_for('products'))
    
    quantity = int(request.form.get('quantity', 1))
    size = request.form.get('size')
    color = request.form.get('color')
    
    # Validate quantity
    if quantity < 1:
        flash('Invalid quantity.', 'danger')
        return redirect(url_for('product_detail', product_id=product_id))
    
    # Check stock availability
    if quantity > product.stock:
        flash(f'Sorry, only {product.stock} units available in stock.', 'warning')
        return redirect(url_for('product_detail', product_id=product_id))
    
    # Check if product already in cart with same size and color
    existing_cart_item = Cart.query.filter_by(
        user_id=current_user.id,
        product_id=product_id,
        size=size,
        color=color
    ).first()
    
    if existing_cart_item:
        # Check if adding this quantity would exceed stock
        new_quantity = existing_cart_item.quantity + quantity
        if new_quantity > product.stock:
            flash(f'Cannot add {quantity} more units. Only {product.stock - existing_cart_item.quantity} units available (you already have {existing_cart_item.quantity} in cart).', 'warning')
            return redirect(url_for('product_detail', product_id=product_id))
        existing_cart_item.quantity = new_quantity
    else:
        cart_item = Cart(
            user_id=current_user.id,
            product_id=product_id,
            quantity=quantity,
            size=size,
            color=color
        )
        db.session.add(cart_item)
    
    db.session.commit()
    flash(f'{product.name} added to cart!', 'success')
    return redirect(url_for('view_cart'))


@app.route('/update_cart/<int:cart_id>', methods=['POST'])
@login_required
def update_cart(cart_id):
    """Update cart item quantity"""
    # Prevent admin from updating cart
    if current_user.is_admin:
        flash('Admin accounts cannot modify cart. Please use a customer account.', 'warning')
        return redirect(url_for('admin_dashboard'))
    
    cart_item = db.session.get(Cart, cart_id)
    if not cart_item:
        flash('Cart item not found', 'danger')
        return redirect(url_for('view_cart'))
    
    if cart_item.user_id != current_user.id:
        flash('Unauthorized action', 'danger')
        return redirect(url_for('view_cart'))
    
    quantity = int(request.form.get('quantity', 1))
    
    # Validate quantity
    if quantity < 1:
        flash('Invalid quantity. Cart item removed.', 'warning')
        db.session.delete(cart_item)
        db.session.commit()
        return redirect(url_for('view_cart'))
    
    # Check stock availability
    if quantity > cart_item.product.stock:
        flash(f'Sorry, only {cart_item.product.stock} units available in stock for {cart_item.product.name}.', 'warning')
        return redirect(url_for('view_cart'))
    
    if quantity > 0:
        cart_item.quantity = quantity
        db.session.commit()
        flash('Cart updated!', 'success')
    
    return redirect(url_for('view_cart'))


@app.route('/remove_from_cart/<int:cart_id>')
@login_required
def remove_from_cart(cart_id):
    """Remove item from cart"""
    # Prevent admin from removing from cart
    if current_user.is_admin:
        flash('Admin accounts cannot modify cart. Please use a customer account.', 'warning')
        return redirect(url_for('admin_dashboard'))
    
    cart_item = db.session.get(Cart, cart_id)
    if not cart_item:
        flash('Cart item not found', 'danger')
        return redirect(url_for('view_cart'))
    
    if cart_item.user_id != current_user.id:
        flash('Unauthorized action', 'danger')
        return redirect(url_for('view_cart'))
    
    db.session.delete(cart_item)
    db.session.commit()
    flash('Item removed from cart', 'info')
    return redirect(url_for('view_cart'))


# ==================== ROUTES - CHECKOUT & ORDERS ====================

@app.route('/validate-coupon', methods=['POST'])
@login_required
def validate_coupon():
    """Validate coupon code via AJAX"""
    coupon_code = request.form.get('coupon_code', '').strip().upper()
    
    if not coupon_code:
        return {'valid': False, 'message': 'Please enter a coupon code'}, 400
    
    # Prevent admin from using coupons
    if current_user.is_admin:
        return {'valid': False, 'message': 'Admin accounts cannot use coupons'}, 403
    
    # Get cart items to calculate subtotal
    cart_items = Cart.query.filter_by(user_id=current_user.id).all()
    if not cart_items:
        return {'valid': False, 'message': 'Cart is empty'}, 400
    
    # Find coupon
    coupon = Coupon.query.filter_by(code=coupon_code).first()
    if not coupon:
        return {'valid': False, 'message': 'Invalid coupon code'}, 404
    
    # Validate coupon
    is_valid, message = coupon.is_valid()
    if not is_valid:
        return {'valid': False, 'message': message}, 400
    
    # Calculate totals
    total, subtotal, shipping, coupon_discount = calculate_order_total(cart_items, coupon)
    
    # Check minimum purchase
    if subtotal < coupon.min_purchase:
        return {
            'valid': False, 
            'message': f'Minimum purchase of ₹{coupon.min_purchase:.2f} required'
        }, 400
    
    # Return success with discount info
    return {
        'valid': True,
        'message': 'Coupon applied successfully!',
        'coupon_code': coupon.code,
        'discount_type': coupon.discount_type,
        'discount_value': coupon.discount_value,
        'discount_amount': coupon_discount,
        'subtotal': subtotal,
        'shipping': shipping,
        'total': total
    }, 200


@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    """Checkout process - select payment method"""
    # Prevent admin from checking out
    if current_user.is_admin:
        flash('Admin accounts cannot place orders. Please use a customer account.', 'warning')
        return redirect(url_for('admin_dashboard'))
    
    cart_items = Cart.query.filter_by(user_id=current_user.id).all()
    
    if not cart_items:
        flash('Your cart is empty', 'warning')
        return redirect(url_for('products'))
    
    if request.method == 'POST':
        print(f"DEBUG: Checkout POST received")
        print(f"DEBUG: Form data: {dict(request.form)}")
        
        shipping_address = request.form.get('shipping_address')
        phone = request.form.get('phone')
        payment_method = request.form.get('payment_method', 'COD')  # COD or ONLINE
        
        print(f"DEBUG: Payment method from form: {repr(payment_method)}")
        
        # Check if COD is enabled when customer selects COD
        if payment_method == 'COD' and not SiteSetting.is_cod_enabled():
            flash('Cash on Delivery is currently not available. Please choose online payment.', 'danger')
            return redirect(url_for('checkout'))
        
        # Validate phone number
        if not validate_phone(phone):
            flash('Invalid phone number. Please enter a valid 10-digit Indian mobile number starting with 6-9.', 'danger')
            return redirect(url_for('checkout'))
        
        # Validate stock availability before creating order (with locking to prevent race conditions)
        for cart_item in cart_items:
            # Refresh product data to get latest stock
            db.session.refresh(cart_item.product)
            
            if cart_item.quantity > cart_item.product.stock:
                flash(f'Insufficient stock for {cart_item.product.name}. Only {cart_item.product.stock} units available.', 'danger')
                return redirect(url_for('view_cart'))
            if not cart_item.product.is_active:
                flash(f'{cart_item.product.name} is no longer available. Please remove it from your cart.', 'danger')
                return redirect(url_for('view_cart'))
        
        # Calculate total including shipping
        coupon = None
        coupon_code = request.form.get('coupon_code', '').strip().upper()
        
        # Get subtotal first for coupon validation
        _, subtotal, _, _ = calculate_order_total(cart_items)
        
        # Validate and apply coupon if provided
        if coupon_code:
            coupon = Coupon.query.filter_by(code=coupon_code).first()
            if coupon:
                is_valid, message = coupon.is_valid()
                if not is_valid:
                    flash(f'Coupon error: {message}', 'warning')
                    coupon = None
                elif subtotal < coupon.min_purchase:
                    flash(f'Minimum purchase of ₹{coupon.min_purchase:.2f} required for this coupon', 'warning')
                    coupon = None
            else:
                flash('Invalid coupon code', 'warning')
        
        total_amount, subtotal_calc, shipping, coupon_discount = calculate_order_total(cart_items, coupon)
        
        # Create order
        order = Order(
            user_id=current_user.id,
            total_amount=total_amount,
            shipping_address=shipping_address,
            phone=phone,
            payment_method=payment_method,
            payment_status='PENDING',
            coupon_code=coupon.code if coupon else None,
            coupon_discount=coupon_discount
        )
        db.session.add(order)
        db.session.flush()  # Get order ID
        
        # Create order items and update stock atomically
        for cart_item in cart_items:
            # Lock the product row for update to prevent race conditions
            product = db.session.query(Product).with_for_update().get(cart_item.product_id)
            
            # Double-check stock availability before deducting
            if not product or product.stock < cart_item.quantity:
                db.session.rollback()
                flash(f'Stock changed for {cart_item.product.name}. Please review your cart.', 'danger')
                return redirect(url_for('view_cart'))
            
            order_item = OrderItem(
                order_id=order.id,
                product_id=cart_item.product_id,
                quantity=cart_item.quantity,
                price=product.price,
                size=cart_item.size,
                color=cart_item.color
            )
            db.session.add(order_item)
            
            # Update product stock
            product.stock -= cart_item.quantity
        
        # Clear cart
        Cart.query.filter_by(user_id=current_user.id).delete()
        
        # Increment coupon usage count
        if coupon:
            coupon.usage_count += 1
        
        db.session.commit()
        
        print(f"DEBUG: Order #{order.id} created with payment method: {payment_method}")
        
        # Email notifications have been disabled
        # try:
        #     print(f"DEBUG: Attempting to send email to {current_user.email}")
        #     html_body, text_body = generate_order_confirmation_email(order)
        #     send_email_notification(
        #         to_email=current_user.email,
        #         subject=f"Order Confirmation - #{order.id} | Right Fit Thrissur",
        #         html_body=html_body,
        #         text_body=text_body
        #     )
        #     print(f"DEBUG: Email send attempt completed")
        # except Exception as e:
        #     print(f"Error sending order confirmation email: {e}")
        #     # Don't fail the order if email fails
        
        # Handle payment method
        if payment_method == 'ONLINE':
            print(f"DEBUG: Redirecting to UPI payment for order #{order.id}")
            # Redirect to UPI payment
            return redirect(url_for('initiate_payment', order_id=order.id))
        else:
            print(f"DEBUG: COD order #{order.id}, sending notifications")
            # COD - Send notifications (non-blocking, don't fail order if they fail)
            try:
                send_sms_notification(order)  # Send to admin
            except Exception as e:
                print(f"Error sending admin SMS: {e}")
            
            try:
                # Send SMS to customer
                customer_sms = f"Order #{order.id} placed successfully! Total: Rs.{order.total_amount:.0f}. Track at rightfitthrissur.store - Right Fit Thrissur"
                send_customer_sms(order.phone, customer_sms)
            except Exception as e:
                print(f"Error sending customer SMS: {e}")
            
            flash(f'Order placed successfully! Order ID: {order.id}. You will receive SMS updates.', 'success')
            return redirect(url_for('order_confirmation', order_id=order.id))
    
    total_amount, subtotal, shipping, _ = calculate_order_total(cart_items)
    cod_enabled = SiteSetting.is_cod_enabled()
    return render_template('checkout.html', 
                         cart_items=cart_items, 
                         subtotal=subtotal,
                         shipping=shipping,
                         total=total_amount,
                         free_shipping_threshold=FREE_SHIPPING_THRESHOLD,
                         cod_enabled=cod_enabled)


@app.route('/order/<int:order_id>')
@login_required
def order_confirmation(order_id):
    """Order confirmation page"""
    order = db.session.get(Order, order_id)
    if not order:
        flash('Order not found', 'danger')
        return redirect(url_for('index'))
    
    if order.user_id != current_user.id and not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('index'))
    
    return render_template('order_confirmation.html', order=order)


@app.route('/my_orders')
@login_required
def my_orders():
    """User's order history"""
    # Redirect admin to admin orders page
    if current_user.is_admin:
        return redirect(url_for('admin_orders'))
    
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).all()
    return render_template('my_orders.html', orders=orders)


@app.route('/order/cancel/<int:order_id>', methods=['POST'])
@login_required
def cancel_order(order_id):
    """Cancel an order (customer only)"""
    # Prevent admin from cancelling orders this way
    if current_user.is_admin:
        flash('Please use admin panel to manage orders.', 'warning')
        return redirect(url_for('admin_orders'))
    
    order = db.session.get(Order, order_id)
    if not order:
        flash('Order not found', 'danger')
        return redirect(url_for('my_orders'))
    
    # Verify order belongs to current user
    if order.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('my_orders'))
    
    # Check if order can be cancelled (only Pending or Processing orders)
    if order.status in ['Shipped', 'Delivered', 'Cancelled']:
        flash(f'Cannot cancel order. Order is already {order.status}.', 'warning')
        return redirect(url_for('my_orders'))
    
    # Check if order is already paid - require refund process
    if order.payment_status == 'PAID':
        flash('This order has already been paid. Please contact customer support for refund processing. Support: 8157971886')  
        return redirect(url_for('my_orders'))
    
    # Update order status to Cancelled
    order.status = 'Cancelled'
    
    # Update payment status to Cancelled
    order.payment_status = 'CANCELLED'
    
    # Restore product stock
    for item in order.items:
        item.product.stock += item.quantity
    
    db.session.commit()
    
    flash(f'Order #{order.id} has been cancelled successfully!', 'success')
    return redirect(url_for('my_orders'))


@app.route('/order/invoice/<int:order_id>')
@login_required
def download_invoice(order_id):
    """Generate and download invoice PDF"""
    order = db.session.get(Order, order_id)
    if not order:
        flash('Order not found', 'danger')
        return redirect(url_for('my_orders'))
    
    # Verify order belongs to current user or user is admin
    if order.user_id != current_user.id and not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('my_orders'))
    
    # Create PDF in memory
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    
    # Container for elements
    elements = []
    
    # Define styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#2c3e50'),
        spaceAfter=30,
        alignment=TA_CENTER
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#34495e'),
        spaceAfter=12
    )
    
    # Company Header
    elements.append(Paragraph('<b>RIGHT FIT THRISSUR</b>', title_style))
    elements.append(Paragraph('Clothing & Accessories Store', styles['Normal']))
    elements.append(Paragraph('Thrissur, Kerala', styles['Normal']))
    elements.append(Paragraph('Phone: 7510556919', styles['Normal']))
    elements.append(Spacer(1, 20))
    
    # Invoice Title
    elements.append(Paragraph(f'<b>INVOICE #{order.id}</b>', heading_style))
    elements.append(Spacer(1, 12))
    
    # Order Details
    order_data = [
        ['Order Date:', order.created_at.strftime('%B %d, %Y')],
        ['Order Status:', order.status],
        ['Payment Method:', 'Cash on Delivery' if order.payment_method == 'COD' else 'Online Payment'],
        ['Payment Status:', order.payment_status],
    ]
    
    order_table = Table(order_data, colWidths=[2*inch, 4*inch])
    order_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#2c3e50')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    elements.append(order_table)
    elements.append(Spacer(1, 20))
    
    # Customer Details
    elements.append(Paragraph('<b>Customer Details:</b>', heading_style))
    customer_data = [
        ['Name:', order.user.username],
        ['Email:', order.user.email],
        ['Phone:', order.phone],
        ['Shipping Address:', order.shipping_address],
    ]
    
    customer_table = Table(customer_data, colWidths=[2*inch, 4*inch])
    customer_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#2c3e50')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    elements.append(customer_table)
    elements.append(Spacer(1, 20))
    
    # Items Table
    elements.append(Paragraph('<b>Order Items:</b>', heading_style))
    
    item_data = [['Product', 'Size', 'Color', 'Qty', 'Price', 'Subtotal']]
    
    for item in order.items:
        item_data.append([
            item.product.name,
            item.size or 'N/A',
            item.color or 'N/A',
            str(item.quantity),
            f'₹{item.price:.2f}',
            f'₹{(item.price * item.quantity):.2f}'
        ])
    
    # Add total row
    item_data.append(['', '', '', '', 'Total:', f'₹{order.total_amount:.2f}'])
    
    items_table = Table(item_data, colWidths=[2.5*inch, 0.8*inch, 0.8*inch, 0.5*inch, 1*inch, 1*inch])
    items_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -2), colors.beige),
        ('GRID', (0, 0), (-1, -2), 1, colors.black),
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, -1), (-1, -1), 12),
        ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#ecf0f1')),
        ('TEXTCOLOR', (0, -1), (-1, -1), colors.HexColor('#2c3e50')),
        ('ALIGN', (4, -1), (-1, -1), 'RIGHT'),
        ('TOPPADDING', (0, -1), (-1, -1), 10),
        ('BOTTOMPADDING', (0, -1), (-1, -1), 10),
    ]))
    elements.append(items_table)
    elements.append(Spacer(1, 30))
    
    # Footer
    footer_text = Paragraph(
        '<i>Thank you for shopping with Right Fit Thrissur!<br/>For any queries, contact us at 7510556919</i>',
        ParagraphStyle('Footer', parent=styles['Normal'], alignment=TA_CENTER, fontSize=9, textColor=colors.grey)
    )
    elements.append(footer_text)
    
    # Build PDF
    doc.build(elements)
    
    # Move buffer position to beginning
    buffer.seek(0)
    
    # Send PDF file
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f'Invoice_Order_{order.id}.pdf',
        mimetype='application/pdf'
    )


# ==================== ROUTES - PAYMENT ====================

@app.route('/payment/initiate/<int:order_id>')
@login_required
def initiate_payment(order_id):
    """Initiate UPI payment"""
    # Prevent admin from initiating payment
    if current_user.is_admin:
        flash('Admin accounts cannot make payments. Please use a customer account.', 'warning')
        return redirect(url_for('admin_dashboard'))
    
    order = db.session.get(Order, order_id)
    if not order:
        flash('Order not found', 'danger')
        return redirect(url_for('index'))
    
    if order.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('index'))
    
    # Check if order is already paid or cancelled
    if order.payment_status == 'PAID':
        flash('This order is already paid.', 'info')
        return redirect(url_for('order_confirmation', order_id=order.id))
    
    if order.status == 'Cancelled':
        flash('This order has been cancelled.', 'warning')
        return redirect(url_for('my_orders'))
    
    print(f"DEBUG: Initiating UPI payment for Order #{order.id}")
    
    # Render UPI payment page with QR code
    return render_template('payment.html', 
                         order=order,
                         upi_id=UPI_ID,
                         upi_payee_name=UPI_PAYEE_NAME,
                         qr_code_path=UPI_QR_CODE_PATH)

@app.route('/payment/verify/<int:order_id>', methods=['POST'])
@login_required
def verify_payment(order_id):
    """Verify UPI payment (admin marks as paid after verification)"""
    order = db.session.get(Order, order_id)
    if not order:
        return {'status': 'error', 'message': 'Order not found'}, 404
    
    if order.user_id != current_user.id:
        return {'status': 'error', 'message': 'Unauthorized access'}, 403
    
    # Return current payment status
    return {
        'status': 'success',
        'payment_status': order.payment_status,
        'order_status': order.status,
        'message': 'Payment status retrieved successfully'
    }, 200

@app.route('/payment/confirm/<int:order_id>', methods=['POST'])
@login_required
def confirm_payment(order_id):
    """Customer confirms payment completion"""
    order = db.session.get(Order, order_id)
    if not order:
        flash('Order not found', 'danger')
        return redirect(url_for('index'))
    
    if order.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('index'))
    
    # Get transaction details from form
    transaction_id = request.form.get('transaction_id', '').strip()
    
    if not transaction_id:
        flash('Please provide the UPI transaction ID.', 'danger')
        return redirect(url_for('initiate_payment', order_id=order.id))
    
    # Update order with transaction details
    order.payment_id = transaction_id
    order.payment_status = 'PENDING'  # Admin will verify and mark as PAID
    db.session.commit()
    
    # Send notification to admin
    try:
        admin_message = f"Payment submitted for Order #{order.id} - Amount: Rs.{order.total_amount:.0f} - Transaction ID: {transaction_id} - Customer: {order.user.username}"
        send_sms_notification(order)
    except Exception as e:
        print(f"Error sending admin SMS: {e}")
    
    flash(f'Payment details submitted! Transaction ID: {transaction_id}. Your payment will be verified shortly.', 'success')
    return redirect(url_for('payment_pending', order_id=order.id))

@app.route('/payment/pending/<int:order_id>')
@login_required
def payment_pending(order_id):
    """Payment pending verification page"""
    order = db.session.get(Order, order_id)
    if not order:
        flash('Order not found', 'danger')
        return redirect(url_for('index'))
    
    if order.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('index'))
    
    # If already paid, redirect to success page
    if order.payment_status == 'PAID':
        return redirect(url_for('payment_success', order_id=order.id))
    
    return render_template('payment_pending.html', order=order)


@app.route('/payment/success/<int:order_id>')
@login_required
def payment_success(order_id):
    """Payment success page"""
    order = db.session.get(Order, order_id)
    if not order:
        flash('Order not found', 'danger')
        return redirect(url_for('index'))
    
    if order.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('index'))
    
    return render_template('payment_success.html', order=order)


@app.route('/payment/failed/<int:order_id>')
@login_required
def payment_failed(order_id):
    """Payment failed page with option to retry or cancel"""
    order = db.session.get(Order, order_id)
    if not order:
        flash('Order not found', 'danger')
        return redirect(url_for('index'))
    
    if order.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('index'))
    
    return render_template('payment_failed.html', order=order)


# ==================== ROUTES - ADMIN PANEL ====================

@app.route('/admin')
@login_required
def admin_dashboard():
    """Admin dashboard with comprehensive analytics"""
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    # Basic counts
    total_products = Product.query.count()
    active_products = Product.query.filter_by(is_active=True).count()
    total_orders = Order.query.count()
    total_users = User.query.filter_by(is_admin=False).count()
    pending_orders = Order.query.filter_by(status='Pending').count()
    
    # Revenue analytics
    total_revenue = db.session.query(func.sum(Order.total_amount)).filter(
        Order.payment_status.in_(['PAID', 'PENDING'])
    ).scalar() or 0
    
    paid_revenue = db.session.query(func.sum(Order.total_amount)).filter(
        Order.payment_status == 'PAID'
    ).scalar() or 0
    
    pending_revenue = db.session.query(func.sum(Order.total_amount)).filter(
        Order.status == 'Pending',
        Order.payment_method == 'COD'
    ).scalar() or 0
    
    # Low stock alert (products with stock < 10)
    low_stock_products = Product.query.filter(
        Product.stock < 10,
        Product.is_active == True
    ).all()
    
    # Recent orders
    recent_orders = Order.query.order_by(Order.created_at.desc()).limit(5).all()
    
    # Top selling products (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    top_products = db.session.query(
        Product.name,
        func.sum(OrderItem.quantity).label('total_sold'),
        func.sum(OrderItem.price * OrderItem.quantity).label('revenue')
    ).join(OrderItem).join(Order).filter(
        Order.created_at >= thirty_days_ago
    ).group_by(Product.id, Product.name).order_by(
        func.sum(OrderItem.quantity).desc()
    ).limit(5).all()
    
    # Get COD enabled status
    cod_enabled = SiteSetting.is_cod_enabled()
    
    return render_template('admin/dashboard.html',
                         total_products=total_products,
                         active_products=active_products,
                         total_orders=total_orders,
                         total_users=total_users,
                         pending_orders=pending_orders,
                         total_revenue=total_revenue,
                         paid_revenue=paid_revenue,
                         pending_revenue=pending_revenue,
                         low_stock_products=low_stock_products,
                         recent_orders=recent_orders,
                         top_products=top_products,
                         cod_enabled=cod_enabled)


@app.route('/admin/products')
@login_required
def admin_products():
    """Admin product management"""
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    products = Product.query.all()
    return render_template('admin/products.html', products=products)


@app.route('/admin/product/add', methods=['GET', 'POST'])
@login_required
def admin_add_product():
    """Add new product"""
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        sizes = request.form.get('sizes', '').strip()
        colors = request.form.get('colors', '').strip()
        
        # Validate required fields
        if not name:
            flash('Product name is required.', 'danger')
            return redirect(url_for('admin_add_product'))
        
        if not description:
            flash('Product description is required.', 'danger')
            return redirect(url_for('admin_add_product'))
        
        # Parse and validate numeric fields
        try:
            price = float(request.form.get('price', 0))
            stock = int(request.form.get('stock', 0))
            category_id = int(request.form.get('category_id', 0))
        except (ValueError, TypeError):
            flash('Invalid price, stock, or category value.', 'danger')
            return redirect(url_for('admin_add_product'))
        
        # Validate numeric values
        if price <= 0:
            flash('Product price must be greater than zero.', 'danger')
            return redirect(url_for('admin_add_product'))
        
        if stock < 0:
            flash('Stock cannot be negative.', 'danger')
            return redirect(url_for('admin_add_product'))
        
        if category_id <= 0:
            flash('Please select a valid category.', 'danger')
            return redirect(url_for('admin_add_product'))
        
        # Handle image upload with better validation
        image_url = request.form.get('image_url', '')  # Keep URL as fallback
        if image_url and not image_url.startswith(('http://', 'https://', '/static/')):
             flash('Invalid image URL. Must start with http://, https://, or /static/', 'danger')
             return redirect(url_for('admin_add_product'))

        if 'image_file' in request.files:
            file = request.files['image_file']
            print(f"DEBUG: File received: {file.filename}")
            if file and file.filename and allowed_file(file.filename):
                # Validate file size (already handled by MAX_CONTENT_LENGTH)
                filename = secure_filename(file.filename)
                # Add timestamp to avoid filename conflicts
                filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                
                try:
                    print(f"DEBUG: Saving to: {filepath}")
                    file.save(filepath)
                    image_url = url_for('static', filename=f'uploads/products/{filename}')
                    print(f"DEBUG: Image URL: {image_url}")
                except Exception as e:
                    print(f"ERROR: Failed to save file: {e}")
                    flash('Error uploading image. Please try again.', 'danger')
                    return redirect(url_for('admin_add_product'))
            else:
                print(f"DEBUG: File validation failed or empty")
        
        product = Product(
            name=name,
            description=description,
            price=price,
            stock=stock,
            category_id=category_id,
            image_url=image_url,
            sizes=sizes,
            colors=colors
        )
        
        db.session.add(product)
        db.session.commit()
        
        flash('Product added successfully!', 'success')
        return redirect(url_for('admin_products'))
    
    categories = Category.query.all()
    return render_template('admin/add_product.html', categories=categories)


@app.route('/admin/product/edit/<int:product_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_product(product_id):
    """Edit existing product"""
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    product = db.session.get(Product, product_id)
    if not product:
        flash('Product not found', 'danger')
        return redirect(url_for('admin_products'))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        sizes = request.form.get('sizes', '').strip()
        colors = request.form.get('colors', '').strip()
        
        # Validate required fields
        if not name:
            flash('Product name is required.', 'danger')
            return redirect(url_for('admin_edit_product', product_id=product_id))
        
        if not description:
            flash('Product description is required.', 'danger')
            return redirect(url_for('admin_edit_product', product_id=product_id))
        
        # Parse and validate numeric fields
        try:
            price = float(request.form.get('price', 0))
            stock = int(request.form.get('stock', 0))
            category_id = int(request.form.get('category_id', 0))
        except (ValueError, TypeError):
            flash('Invalid price, stock, or category value.', 'danger')
            return redirect(url_for('admin_edit_product', product_id=product_id))
        
        # Validate numeric values
        if price <= 0:
            flash('Product price must be greater than zero.', 'danger')
            return redirect(url_for('admin_edit_product', product_id=product_id))
        
        if stock < 0:
            flash('Stock cannot be negative.', 'danger')
            return redirect(url_for('admin_edit_product', product_id=product_id))
        
        if category_id <= 0:
            flash('Please select a valid category.', 'danger')
            return redirect(url_for('admin_edit_product', product_id=product_id))
        
        # Update product fields
        product.name = name
        product.description = description
        product.price = price
        product.stock = stock
        product.category_id = category_id
        product.sizes = sizes
        product.colors = colors
        product.is_active = 'is_active' in request.form
        
        # Handle image upload
        if 'image_file' in request.files:
            file = request.files['image_file']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                product.image_url = url_for('static', filename=f'uploads/products/{filename}')
        elif request.form.get('image_url'):
            product.image_url = request.form.get('image_url')
        
        db.session.commit()
        
        flash('Product updated successfully!', 'success')
        return redirect(url_for('admin_products'))
    
    categories = Category.query.all()
    return render_template('admin/edit_product.html', product=product, categories=categories)


@app.route('/admin/product/delete/<int:product_id>', methods=['POST'])
@login_required
def admin_delete_product(product_id):
    """Delete product"""
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    product = db.session.get(Product, product_id)
    if not product:
        flash('Product not found', 'danger')
        return redirect(url_for('admin_products'))
    
    # Check if product has any order items
    order_items_count = OrderItem.query.filter_by(product_id=product_id).count()
    
    if order_items_count > 0:
        # Instead of deleting, mark product as inactive
        product.is_active = False
        db.session.commit()
        flash(f'Product cannot be deleted as it has {order_items_count} order(s). It has been marked as inactive instead.', 'warning')
    else:
        # Safe to delete if no orders reference it
        try:
            # First delete associated cart items to prevent foreign key constraint error
            Cart.query.filter_by(product_id=product_id).delete()
            
            # Delete associated product features
            ProductFeature.query.filter_by(product_id=product_id).delete()
            
            # Now delete the product
            db.session.delete(product)
            db.session.commit()
            flash('Product deleted successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error deleting product {product_id}: {e}")
            flash(f'Error deleting product: {str(e)}', 'danger')
    
    return redirect(url_for('admin_products'))


@app.route('/admin/product/toggle/<int:product_id>')
@login_required
def admin_toggle_product(product_id):
    """Toggle product active status"""
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    product = db.session.get(Product, product_id)
    if not product:
        flash('Product not found', 'danger')
        return redirect(url_for('admin_products'))
    product.is_active = not product.is_active
    db.session.commit()
    
    status = 'activated' if product.is_active else 'deactivated'
    flash(f'Product "{product.name}" has been {status}!', 'success')
    return redirect(url_for('admin_products'))


@app.route('/admin/product/<int:product_id>/features', methods=['GET', 'POST'])
@login_required
def admin_product_features(product_id):
    """Manage product features"""
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    product = db.session.get(Product, product_id)
    if not product:
        flash('Product not found', 'danger')
        return redirect(url_for('admin_products'))
    
    if request.method == 'POST':
        feature_text = request.form.get('feature_text', '').strip()
        
        if not feature_text:
            flash('Feature text is required.', 'danger')
            return redirect(url_for('admin_product_features', product_id=product_id))
        
        if len(feature_text) > 200:
            flash('Feature text must be 200 characters or less.', 'danger')
            return redirect(url_for('admin_product_features', product_id=product_id))
        
        # Get the highest display order and add 1
        max_order = db.session.query(func.max(ProductFeature.display_order)).filter_by(product_id=product_id).scalar() or 0
        
        feature = ProductFeature(
            product_id=product_id,
            feature_text=feature_text,
            display_order=max_order + 1
        )
        db.session.add(feature)
        db.session.commit()
        
        flash('Feature added successfully!', 'success')
        return redirect(url_for('admin_product_features', product_id=product_id))
    
    features = ProductFeature.query.filter_by(product_id=product_id).order_by(ProductFeature.display_order).all()
    return render_template('admin/product_features.html', product=product, features=features)


@app.route('/admin/product/feature/edit/<int:feature_id>', methods=['POST'])
@login_required
def admin_edit_feature(feature_id):
    """Edit product feature"""
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    feature = db.session.get(ProductFeature, feature_id)
    if not feature:
        flash('Feature not found', 'danger')
        return redirect(url_for('admin_products'))
    
    feature_text = request.form.get('feature_text', '').strip()
    
    if not feature_text:
        flash('Feature text is required.', 'danger')
        return redirect(url_for('admin_product_features', product_id=feature.product_id))
    
    if len(feature_text) > 200:
        flash('Feature text must be 200 characters or less.', 'danger')
        return redirect(url_for('admin_product_features', product_id=feature.product_id))
    
    feature.feature_text = feature_text
    db.session.commit()
    
    flash('Feature updated successfully!', 'success')
    return redirect(url_for('admin_product_features', product_id=feature.product_id))


@app.route('/admin/product/feature/toggle/<int:feature_id>')
@login_required
def admin_toggle_feature(feature_id):
    """Toggle feature enabled status"""
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    feature = db.session.get(ProductFeature, feature_id)
    if not feature:
        flash('Feature not found', 'danger')
        return redirect(url_for('admin_products'))
    
    feature.is_enabled = not feature.is_enabled
    db.session.commit()
    
    status = 'enabled' if feature.is_enabled else 'disabled'
    flash(f'Feature has been {status}!', 'success')
    return redirect(url_for('admin_product_features', product_id=feature.product_id))


@app.route('/admin/product/feature/delete/<int:feature_id>', methods=['POST'])
@login_required
def admin_delete_feature(feature_id):
    """Delete product feature"""
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    feature = db.session.get(ProductFeature, feature_id)
    if not feature:
        flash('Feature not found', 'danger')
        return redirect(url_for('admin_products'))
    
    product_id = feature.product_id
    db.session.delete(feature)
    db.session.commit()
    
    flash('Feature deleted successfully!', 'success')
    return redirect(url_for('admin_product_features', product_id=product_id))


@app.route('/admin/orders')
@login_required
def admin_orders():
    """Admin order management"""
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    orders = Order.query.order_by(Order.created_at.desc()).all()
    return render_template('admin/orders.html', orders=orders)


@app.route('/admin/order/update/<int:order_id>', methods=['POST'])
@login_required
def admin_update_order(order_id):
    """Update order status"""
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    order = db.session.get(Order, order_id)
    if not order:
        flash('Order not found', 'danger')
        return redirect(url_for('admin_orders'))
    new_status = request.form.get('status')
    
    if not new_status:
        flash('No status selected', 'warning')
        return redirect(url_for('admin_orders'))
    
    old_status = order.status
    order.status = new_status
    
    # For COD orders, update payment status when delivered
    if order.payment_method == 'COD' and new_status == 'Delivered':
        if order.payment_status == 'PENDING':
            order.payment_status = 'PAID'
            flash(f'Order #{order.id} status updated: {old_status} → {new_status}. COD payment marked as received.', 'success')
        else:
            flash(f'Order #{order.id} status updated: {old_status} → {new_status}.', 'success')
    else:
        flash(f'Order #{order.id} status updated: {old_status} → {new_status}.', 'success')
    
    db.session.commit()
    
    return redirect(url_for('admin_orders'))


@app.route('/admin/order/delete/<int:order_id>', methods=['POST'])
@login_required
def admin_delete_order(order_id):
    """Delete an order (admin only)"""
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    order = db.session.get(Order, order_id)
    if not order:
        flash('Order not found', 'danger')
        return redirect(url_for('admin_orders'))
    
    # Restore product stock before deleting order
    for item in order.items:
        item.product.stock += item.quantity
        print(f"Restored {item.quantity} units of {item.product.name} (Order #{order_id} deleted)")
    
    # Delete associated order items first (due to foreign key constraint)
    OrderItem.query.filter_by(order_id=order.id).delete()
    
    # Delete the order
    db.session.delete(order)
    db.session.commit()
    
    flash(f'Order #{order_id} has been deleted successfully! Product stock has been restored.', 'success')
    return redirect(url_for('admin_orders'))


@app.route('/admin/order/cancel-paid/<int:order_id>', methods=['POST'])
@login_required
def admin_cancel_paid_order(order_id):
    """Cancel a paid order and initiate manual refund (admin only)"""
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    order = db.session.get(Order, order_id)
    if not order:
        flash('Order not found', 'danger')
        return redirect(url_for('admin_orders'))
    
    # Check if order is paid
    if order.payment_status != 'PAID':
        flash('This order has not been paid yet.', 'warning')
        return redirect(url_for('admin_orders'))
    
    # Check if already cancelled
    if order.status == 'Cancelled':
        flash('This order is already cancelled.', 'info')
        return redirect(url_for('admin_orders'))
    
    # Mark order as cancelled and refund pending
    order.status = 'Cancelled'
    order.payment_status = 'REFUND_PENDING'
    order.refund_note = f'Order cancelled by admin on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}. Manual refund required for UPI payment of ₹{order.total_amount}. Transaction ID: {order.payment_id}'
    
    # Restore product stock
    for item in order.items:
        item.product.stock += item.quantity
    
    db.session.commit()
    
    flash(f'Order #{order_id} cancelled. Please process manual refund of ₹{order.total_amount} to customer via UPI. Transaction ID: {order.payment_id}', 'warning')
    return redirect(url_for('admin_orders'))


@app.route('/admin/order/mark-refunded/<int:order_id>', methods=['POST'])
@login_required
def admin_mark_refunded(order_id):
    """Mark order as refunded after manual processing (admin only) - For REFUND_PENDING status"""
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    order = db.session.get(Order, order_id)
    if not order:
        flash('Order not found', 'danger')
        return redirect(url_for('admin_orders'))
    
    # Check if refund is pending
    if order.payment_status != 'REFUND_PENDING':
        flash('This order is not pending refund.', 'warning')
        return redirect(url_for('admin_orders'))
    
    # Update payment status to refunded
    order.payment_status = 'REFUNDED'
    if not order.refund_note:
        order.refund_note = f'Refund marked as completed by admin on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'
    else:
        order.refund_note += f' | Marked as completed by admin on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'
    
    db.session.commit()
    
    flash(f'Order #{order_id} marked as refunded!', 'success')
    return redirect(url_for('admin_orders'))


@app.route('/admin/order/verify-payment/<int:order_id>', methods=['POST'])
@login_required
def admin_verify_payment(order_id):
    """Verify and approve UPI payment (admin only)"""
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    order = db.session.get(Order, order_id)
    if not order:
        flash('Order not found', 'danger')
        return redirect(url_for('admin_orders'))
    
    # Check if payment is pending
    if order.payment_status != 'PENDING':
        flash('This order payment is not pending verification.', 'warning')
        return redirect(url_for('admin_orders'))
    
    # Mark payment as verified and paid
    order.payment_status = 'PAID'
    db.session.commit()
    
    # Send SMS notification to customer
    try:
        customer_sms = f"Payment verified for Order #{order.id}! Your order is being processed. Total: Rs.{order.total_amount:.0f} - Right Fit Thrissur"
        send_customer_sms(order.phone, customer_sms)
    except Exception as e:
        print(f"Error sending customer SMS: {e}")
    
    flash(f'Payment verified and marked as PAID for Order #{order_id}!', 'success')
    return redirect(url_for('admin_orders'))


@app.route('/admin/categories')
@login_required
def admin_categories():
    """Admin category management"""
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    categories = Category.query.all()
    return render_template('admin/categories.html', categories=categories)


@app.route('/admin/category/add', methods=['POST'])
@login_required
def admin_add_category():
    """Add new category"""
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    
    # Validate required fields
    if not name:
        flash('Category name is required.', 'danger')
        return redirect(url_for('admin_categories'))
    
    # Check for duplicate category name
    existing_category = Category.query.filter_by(name=name).first()
    if existing_category:
        flash(f'Category "{name}" already exists.', 'danger')
        return redirect(url_for('admin_categories'))
    
    category = Category(name=name, description=description)
    db.session.add(category)
    db.session.commit()
    
    flash('Category added successfully!', 'success')
    return redirect(url_for('admin_categories'))


@app.route('/admin/category/delete/<int:category_id>', methods=['POST'])
@login_required
def admin_delete_category(category_id):
    """Delete a category"""
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    category = db.session.get(Category, category_id)
    if not category:
        flash('Category not found', 'danger')
        return redirect(url_for('admin_categories'))
    
    # Check if category has products
    if category.products:
        flash(f'Cannot delete category "{category.name}" because it has {len(category.products)} products. Please reassign or delete those products first.', 'danger')
        return redirect(url_for('admin_categories'))
    
    db.session.delete(category)
    db.session.commit()
    
    flash('Category deleted successfully!', 'success')
    return redirect(url_for('admin_categories'))


@app.route('/admin/category/edit/<int:category_id>', methods=['POST'])
@login_required
def admin_edit_category(category_id):
    """Edit an existing category"""
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    category = db.session.get(Category, category_id)
    if not category:
        flash('Category not found', 'danger')
        return redirect(url_for('admin_categories'))
    
    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    
    # Validate required fields
    if not name:
        flash('Category name is required.', 'danger')
        return redirect(url_for('admin_categories'))
    
    # Check for duplicate category name (excluding current category)
    existing_category = Category.query.filter(Category.name == name, Category.id != category_id).first()
    if existing_category:
        flash(f'Category "{name}" already exists.', 'danger')
        return redirect(url_for('admin_categories'))
    
    # Update category details
    category.name = name
    category.description = description
    db.session.commit()
    
    flash(f'Category "{category.name}" updated successfully!', 'success')
    return redirect(url_for('admin_categories'))


@app.route('/admin/config-check')
@login_required
def admin_config_check():
    """Admin route to check notification configuration"""
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    import json
    config_status = {
        'Email Notification': {
            'Status': 'DISABLED - Email functionality has been removed'
        },
        'SMS Notification': {
            'Enabled': USE_SMS_NOTIFICATION,
            'Admin Phone': ADMIN_PHONE_NUMBER if ADMIN_PHONE_NUMBER else 'NOT SET',
            'API Key': 'SET' if SMS_GATEWAY_API_KEY else 'NOT SET'
        },
        'UPI Payment': {
            'UPI ID': UPI_ID,
            'Payee Name': UPI_PAYEE_NAME,
            'QR Code Path': UPI_QR_CODE_PATH
        }
    }
    
    return f"<html><body><h1>Configuration Status</h1><pre>{json.dumps(config_status, indent=2)}</pre></body></html>"


# ==================== ROUTES - ADMIN COUPONS ====================

@app.route('/admin/coupons')
@login_required
def admin_coupons():
    """Admin coupon management"""
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    coupons = Coupon.query.order_by(Coupon.created_at.desc()).all()
    return render_template('admin/coupons.html', coupons=coupons, now=datetime.utcnow())


@app.route('/admin/coupon/add', methods=['POST'])
@login_required
def admin_add_coupon():
    """Add new coupon"""
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    code = request.form.get('code', '').strip().upper()
    description = request.form.get('description', '').strip()
    discount_type = request.form.get('discount_type', 'percentage')
    
    # Validate required fields
    if not code:
        flash('Coupon code is required.', 'danger')
        return redirect(url_for('admin_coupons'))
    
    # Check for duplicate coupon code
    existing_coupon = Coupon.query.filter_by(code=code).first()
    if existing_coupon:
        flash(f'Coupon code "{code}" already exists.', 'danger')
        return redirect(url_for('admin_coupons'))
    
    # Parse numeric fields
    try:
        discount_value = float(request.form.get('discount_value', 0))
        min_purchase = float(request.form.get('min_purchase', 0))
        max_discount = request.form.get('max_discount', '').strip()
        max_discount = float(max_discount) if max_discount else None
        usage_limit = request.form.get('usage_limit', '').strip()
        usage_limit = int(usage_limit) if usage_limit else None
    except (ValueError, TypeError):
        flash('Invalid numeric value provided.', 'danger')
        return redirect(url_for('admin_coupons'))
    
    # Validate discount value
    if discount_value <= 0:
        flash('Discount value must be greater than zero.', 'danger')
        return redirect(url_for('admin_coupons'))
    
    if discount_type == 'percentage' and discount_value > 100:
        flash('Percentage discount cannot exceed 100%.', 'danger')
        return redirect(url_for('admin_coupons'))
    
    # Parse dates
    expiry_date_str = request.form.get('expiry_date', '').strip()
    expiry_date = None
    if expiry_date_str:
        try:
            expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d')
        except ValueError:
            flash('Invalid expiry date format.', 'danger')
            return redirect(url_for('admin_coupons'))
    
    # Create coupon
    coupon = Coupon(
        code=code,
        description=description,
        discount_type=discount_type,
        discount_value=discount_value,
        min_purchase=min_purchase,
        max_discount=max_discount,
        expiry_date=expiry_date,
        usage_limit=usage_limit
    )
    
    db.session.add(coupon)
    db.session.commit()
    
    flash(f'Coupon "{code}" added successfully!', 'success')
    return redirect(url_for('admin_coupons'))


@app.route('/admin/coupon/edit/<int:coupon_id>', methods=['POST'])
@login_required
def admin_edit_coupon(coupon_id):
    """Edit existing coupon"""
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    coupon = db.session.get(Coupon, coupon_id)
    if not coupon:
        flash('Coupon not found', 'danger')
        return redirect(url_for('admin_coupons'))
    
    description = request.form.get('description', '').strip()
    
    # Parse numeric fields
    try:
        discount_value = float(request.form.get('discount_value', 0))
        min_purchase = float(request.form.get('min_purchase', 0))
        max_discount = request.form.get('max_discount', '').strip()
        max_discount = float(max_discount) if max_discount else None
        usage_limit = request.form.get('usage_limit', '').strip()
        usage_limit = int(usage_limit) if usage_limit else None
    except (ValueError, TypeError):
        flash('Invalid numeric value provided.', 'danger')
        return redirect(url_for('admin_coupons'))
    
    # Validate discount value
    if discount_value <= 0:
        flash('Discount value must be greater than zero.', 'danger')
        return redirect(url_for('admin_coupons'))
    
    if coupon.discount_type == 'percentage' and discount_value > 100:
        flash('Percentage discount cannot exceed 100%.', 'danger')
        return redirect(url_for('admin_coupons'))
    
    # Parse dates
    expiry_date_str = request.form.get('expiry_date', '').strip()
    expiry_date = None
    if expiry_date_str:
        try:
            expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d')
        except ValueError:
            flash('Invalid expiry date format.', 'danger')
            return redirect(url_for('admin_coupons'))
    
    # Update coupon
    coupon.description = description
    coupon.discount_value = discount_value
    coupon.min_purchase = min_purchase
    coupon.max_discount = max_discount
    coupon.expiry_date = expiry_date
    coupon.usage_limit = usage_limit
    coupon.is_active = 'is_active' in request.form
    
    db.session.commit()
    
    flash(f'Coupon "{coupon.code}" updated successfully!', 'success')
    return redirect(url_for('admin_coupons'))


@app.route('/admin/coupon/delete/<int:coupon_id>', methods=['POST'])
@login_required
def admin_delete_coupon(coupon_id):
    """Delete a coupon"""
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    coupon = db.session.get(Coupon, coupon_id)
    if not coupon:
        flash('Coupon not found', 'danger')
        return redirect(url_for('admin_coupons'))
    
    db.session.delete(coupon)
    db.session.commit()
    
    flash(f'Coupon "{coupon.code}" deleted successfully!', 'success')
    return redirect(url_for('admin_coupons'))


@app.route('/admin/coupon/toggle/<int:coupon_id>')
@login_required
def admin_toggle_coupon(coupon_id):
    """Toggle coupon active status"""
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    coupon = db.session.get(Coupon, coupon_id)
    if not coupon:
        flash('Coupon not found', 'danger')
        return redirect(url_for('admin_coupons'))
    
    coupon.is_active = not coupon.is_active
    db.session.commit()
    
    status = 'activated' if coupon.is_active else 'deactivated'
    flash(f'Coupon "{coupon.code}" has been {status}!', 'success')
    return redirect(url_for('admin_coupons'))


# ==================== ROUTES - ADMIN SETTINGS ====================

@app.route('/admin/settings/toggle-cod', methods=['POST'])
@login_required
def admin_toggle_cod():
    """Toggle Cash on Delivery payment option"""
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    # Get current status
    current_status = SiteSetting.is_cod_enabled()
    
    # Toggle the status
    new_status = 'False' if current_status else 'True'
    SiteSetting.set_setting('cod_enabled', new_status, 'Enable or disable Cash on Delivery payment method')
    
    status_text = 'enabled' if new_status == 'True' else 'disabled'
    flash(f'Cash on Delivery has been {status_text} successfully!', 'success')
    
    return redirect(url_for('admin_dashboard'))


# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    """Handle 500 errors"""
    db.session.rollback()  # Rollback any failed database transactions
    logger.error(f"Internal server error: {e}")
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden(e):
    """Handle 403 errors"""
    return render_template('errors/403.html'), 403

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """Handle CSRF errors"""
    return render_template('errors/403.html', description=e.description), 403

@app.errorhandler(413)
def request_entity_too_large(e):
    """Handle file upload too large"""
    flash('File size too large. Maximum size is 16MB.', 'danger')
    return redirect(request.referrer or url_for('index'))


# ==================== DATABASE INITIALIZATION ====================

def ensure_admin_user():
    """Ensure admin user exists with correct password (safe for production)"""
    with app.app_context():
        db.create_all()
        
        # Check if admin user exists
        admin = User.query.filter_by(username='admin').first()
        
        if admin:
            # Update password to ensure it's correct
            admin.set_password('admin123')
            admin.is_admin = True
            db.session.commit()
            print("✅ Admin user password updated successfully!")
        else:
            # Create new admin user
            admin = User(username='admin', email='admin@ecommerce.com', is_admin=True)
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin user created successfully!")

def init_db():
    """Initialize database with sample data"""
    with app.app_context():
        db.create_all()
        
        # Check if data already exists
        if User.query.first():
            return
        
        # Create admin user
        admin = User(username='admin', email='admin@ecommerce.com', is_admin=True)
        admin.set_password('admin123')
        db.session.add(admin)
        
        # Create regular user
        user = User(username='customer', email='customer@ecommerce.com')
        user.set_password('customer123')
        db.session.add(user)
        
        # Create categories
        categories_data = [
            {'name': 'T-Shirts', 'description': 'Comfortable cotton t-shirts'},
            {'name': 'Jeans', 'description': 'Stylish denim jeans'},
            {'name': 'Shirts', 'description': 'Formal and casual shirts'},
            {'name': 'Accessories', 'description': 'Belts, wallets, and more'},
        ]
        
        for cat_data in categories_data:
            category = Category(**cat_data)
            db.session.add(category)
        
        db.session.commit()
        
        # Create sample products
        products_data = [
            {
                'name': 'Classic White T-Shirt',
                'description': 'Premium cotton white t-shirt. Perfect for casual wear.',
                'price': 499.00,
                'stock': 50,
                'category_id': 1,
                'image_url': 'https://via.placeholder.com/400x400?text=White+T-Shirt',
                'sizes': 'S,M,L,XL,XXL',
                'colors': 'White'
            },
            {
                'name': 'Black Polo Shirt',
                'description': 'Elegant black polo shirt with collar. Great for semi-formal occasions.',
                'price': 799.00,
                'stock': 30,
                'category_id': 1,
                'image_url': 'https://via.placeholder.com/400x400?text=Black+Polo',
                'sizes': 'S,M,L,XL',
                'colors': 'Black,Navy,Gray'
            },
            {
                'name': 'Blue Denim Jeans',
                'description': 'Classic fit blue denim jeans. Comfortable and durable.',
                'price': 1499.00,
                'stock': 40,
                'category_id': 2,
                'image_url': 'https://via.placeholder.com/400x400?text=Blue+Jeans',
                'sizes': '28,30,32,34,36',
                'colors': 'Blue,Black'
            },
            {
                'name': 'Formal White Shirt',
                'description': 'Crisp white formal shirt. Perfect for office and events.',
                'price': 1299.00,
                'stock': 25,
                'category_id': 3,
                'image_url': 'https://via.placeholder.com/400x400?text=Formal+Shirt',
                'sizes': 'S,M,L,XL',
                'colors': 'White,Blue,Pink'
            },
            {
                'name': 'Leather Belt',
                'description': 'Genuine leather belt with metal buckle.',
                'price': 599.00,
                'stock': 60,
                'category_id': 4,
                'image_url': 'https://via.placeholder.com/400x400?text=Leather+Belt',
                'sizes': '32,34,36,38',
                'colors': 'Black,Brown'
            },
            {
                'name': 'Striped T-Shirt',
                'description': 'Trendy striped cotton t-shirt for casual outings.',
                'price': 599.00,
                'stock': 45,
                'category_id': 1,
                'image_url': 'https://via.placeholder.com/400x400?text=Striped+Tee',
                'sizes': 'S,M,L,XL',
                'colors': 'Red,Blue,Green'
            },
        ]
        
        for prod_data in products_data:
            product = Product(**prod_data)
            db.session.add(product)
        
        db.session.commit()
        print("Database initialized with sample data!")


# ==================== RUN APPLICATION ====================

if __name__ == '__main__':
    init_db()
    print("="*60)
    print("🚀 RIGHT FIT E-COMMERCE - DEBUG MODE ENABLED")
    print("="*60)
    print(f"UPI Payment System: Enabled")
    print(f"UPI ID: {UPI_ID}")
    print(f"QR Code: {UPI_QR_CODE_PATH}")
    print(f"Debug logging: ENABLED")
    print("="*60)
    port = int(os.environ.get("PORT", 3000))
    app.run(debug=False, host="0.0.0.0", port=port)
    