
#Poster_Marketplace application develop by YASH SOLOAMN
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, make_response, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime, timedelta
import os
import shutil
import io
import csv
import secrets
import string
import zipfile

try:
    from PIL import Image
except ImportError:
    Image = None

# ============================================================================
# APP AND DATABASE CONFIGURATION
# ============================================================================

app = Flask(__name__)

# SECURITY: Move to environment variables in production
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Dual database configuration
base_dir = os.path.dirname(os.path.abspath(__file__))
accounts_db_path = os.path.join(base_dir, 'accounts.db')
orders_db_path = os.path.join(base_dir, 'orders.db')

app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{accounts_db_path}'
app.config['SQLALCHEMY_BINDS'] = {
    'orders': f'sqlite:///{orders_db_path}'
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 280,
    'pool_pre_ping': True,
}

# File upload configuration
UPLOAD_FOLDER = os.path.join(base_dir, 'uploads')
SEED_FOLDER = os.path.join(base_dir, 'seed_images')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB max file size

db = SQLAlchemy(app)

# ============================================================================
# LOGIN MANAGER CONFIGURATION
# ============================================================================

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ============================================================================
# DATABASE MODELS
# ============================================================================

user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True)
)

class TimestampMixin:
    """Mixin for automatic timestamp tracking"""
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

class Role(db.Model):
    """User roles for role-based access control"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False, index=True)
    description = db.Column(db.String(255))
    
    def __repr__(self):
        return f'<Role {self.name}>'

class User(UserMixin, db.Model, TimestampMixin):
    """Enhanced User model with email verification and role support"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    
    # Profile information
    full_name = db.Column(db.String(120))
    profile_bio = db.Column(db.Text)
    profile_image = db.Column(db.String(200))
    phone = db.Column(db.String(20))
    
    # Account status
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_email_verified = db.Column(db.Boolean, default=False, nullable=False)
    email_verified_at = db.Column(db.DateTime)
    
    # Security & verification tokens
    verification_token = db.Column(db.String(255), unique=True)
    verification_token_expires = db.Column(db.DateTime)
    password_reset_token = db.Column(db.String(255), unique=True)
    password_reset_token_expires = db.Column(db.DateTime)
    
    # Relationships
    roles = db.relationship('Role', secondary=user_roles, backref=db.backref('users', lazy='dynamic'))
    
    # Note: posters, cart_items, and orders relationships removed due to cross-database architecture
    # They are stored in separate 'orders' database and accessed by user_id only
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    
    def check_password(self, password):
        """Verify password hash"""
        return check_password_hash(self.password_hash, password)
    
    def has_role(self, role_name):
        """Check if user has a specific role"""
        return any(role.name == role_name for role in self.roles)
    
    def get_roles(self):
        """Get all role names"""
        return [role.name for role in self.roles]
    
    def generate_verification_token(self, expires_in=86400):
        """Generate email verification token (24 hours default)"""
        token = secrets.token_urlsafe(32)
        self.verification_token = token
        self.verification_token_expires = datetime.utcnow() + timedelta(seconds=expires_in)
        return token
    
    def verify_email_token(self, token):
        """Verify email token is valid and not expired"""
        if self.verification_token != token:
            return False
        if datetime.utcnow() > self.verification_token_expires:
            return False
        return True
    
    def generate_reset_token(self, expires_in=3600):
        """Generate password reset token (1 hour default)"""
        token = secrets.token_urlsafe(32)
        self.password_reset_token = token
        self.password_reset_token_expires = datetime.utcnow() + timedelta(seconds=expires_in)
        return token
    
    def verify_reset_token(self, token):
        """Verify password reset token is valid and not expired"""
        if self.password_reset_token != token:
            return False
        if datetime.utcnow() > self.password_reset_token_expires:
            return False
        return True
    
    def __repr__(self):
        return f'<User {self.username}>'
    # 1. ADD THIS NEW CLASS
class OrderItem(db.Model):
    __bind_key__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    poster_id = db.Column(db.Integer, db.ForeignKey('poster.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)

class Poster(db.Model, TimestampMixin):
    """Poster product model"""
    __bind_key__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False, index=True)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_filename = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(50), nullable=False, index=True)
    
    # User reference (no foreign key - stored in different database)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    
    # Metadata
    views = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    cart_items = db.relationship('CartItem', backref='poster', lazy=True, cascade='all, delete-orphan')
    order_items = db.relationship('OrderItem', backref='poster', lazy=True)
    
    def __repr__(self):
        return f'<Poster {self.title}>'

class CartItem(db.Model, TimestampMixin):
    """Shopping cart item"""
    __bind_key__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    quantity = db.Column(db.Integer, default=1, nullable=False)
    
    # Foreign keys (user_id stored as integer - user data in accounts database)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    poster_id = db.Column(db.Integer, db.ForeignKey('poster.id'), nullable=False, index=True)
    
    def __repr__(self):
        return f'<CartItem user={self.user_id} poster={self.poster_id}>'

# --- 1. FIND THE 'Order' CLASS AND REPLACE IT WITH THIS ---
class Order(db.Model, TimestampMixin):
    """Order model with shipping details and payment info"""
    __bind_key__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    order_number = db.Column(db.String(50), unique=True, nullable=False, index=True)
    total_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), default='Pending', nullable=False, index=True)
    
    # Shipping details
    full_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    address = db.Column(db.Text, nullable=False)
    city = db.Column(db.String(50), nullable=False)
    state = db.Column(db.String(50), nullable=False)
    pincode = db.Column(db.String(10), nullable=False)
    
    # NEW: Payment Method
    payment_method = db.Column(db.String(50), default='COD', nullable=False)
    
    # User reference
    user_id = db.Column(db.Integer, nullable=False, index=True)
    
    # Relationships
    items = db.relationship('OrderItem', backref='order', lazy=True, cascade='all, delete-orphan')
    user = db.relationship('User', foreign_keys=[user_id], viewonly=True, primaryjoin='Order.user_id==User.id')
    
    def __repr__(self):
        return f'<Order {self.order_number}>'


@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    """Checkout page"""
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    
    if not cart_items:
        flash('Your cart is empty!', 'warning')
        return redirect(url_for('view_cart'))
    
    if request.method == 'POST':
        # If form is submitted from checkout page, proceed to place order
        return redirect(url_for('place_order'))
    
    total = sum(item.poster.price * item.quantity for item in cart_items)
    return render_template('checkout.html', cart_items=cart_items, total=total, user=current_user)

@app.route('/place_order', methods=['GET', 'POST'])
@login_required
def place_order():
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    
    if not cart_items:
        flash('Your cart is empty!')
        return redirect(url_for('view_cart'))

    # 1. Calculate Total
    total_amount = sum(item.poster.price * item.quantity for item in cart_items)

    # 2. Generate unique order number
    import uuid
    order_number = f"ORD-{uuid.uuid4().hex[:8].upper()}"
    
    # 3. Create the Order with shipping details from form
    new_order = Order(
        user_id=current_user.id,
        order_number=order_number,
        total_amount=total_amount,
        status='Pending',
        full_name=request.form.get('full_name', getattr(current_user, 'full_name', None) or ''),
        phone=request.form.get('phone', getattr(current_user, 'phone', None) or ''),
        email=request.form.get('email', current_user.email or ''),
        address=request.form.get('address', ''),
        city=request.form.get('city', ''),
        state=request.form.get('state', ''),
        pincode=request.form.get('pincode', ''),
        payment_method=request.form.get('payment_method', 'COD')
    )
    db.session.add(new_order)
    db.session.flush()  # This generates the new_order.id before committing

    # 4. SAVE THE ITEMS
    for item in cart_items:
        order_item = OrderItem(
            order_id=new_order.id,
            poster_id=item.poster.id,
            quantity=item.quantity
        )
        db.session.add(order_item)

    # 5. Clear the User's Cart
    for item in cart_items:
        db.session.delete(item)

    db.session.commit()
    
    return redirect(url_for('order_confirmation', order_id=new_order.id))   

# ============================================================================
# DECORATORS FOR ROLE-BASED ACCESS CONTROL
# ============================================================================

def role_required(*roles):
    """Decorator to require specific roles"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in first.', 'error')
                return redirect(url_for('login'))
            
            if not any(current_user.has_role(role) for role in roles):
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('index'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def init_roles():
    """Initialize default roles"""
    default_roles = [
        ('Seller', 'Can sell posters'),
        ('Buyer', 'Can buy posters'),
        ('Admin', 'Full admin access'),
        ('Moderator', 'Can moderate content')
    ]
    
    for name, description in default_roles:
        if not Role.query.filter_by(name=name).first():
            role = Role(name=name, description=description)
            db.session.add(role)
    
    db.session.commit()

@app.context_processor
def inject_cart_count():
    """Inject cart count into all templates"""
    if current_user.is_authenticated:
        cart_count = db.session.query(db.func.sum(CartItem.quantity)).filter_by(user_id=current_user.id).scalar() or 0
        return dict(cart_count=int(cart_count))
    return dict(cart_count=0)

# ============================================================================
# ROUTES - AUTHENTICATION
# ============================================================================

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration with validation"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        if not username or len(username) < 3:
            flash('Username must be at least 3 characters.', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register'))
        
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return redirect(url_for('register'))
        
        # Create user
        user = User(username=username, email=email)
        user.set_password(password)
        
        # Assign default Buyer role
        buyer_role = Role.query.filter_by(name='Buyer').first()
        if buyer_role:
            user.roles.append(buyer_role)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        user = User.query.filter_by(email=email).first()
        
        if not user or not user.check_password(password):
            flash('Invalid email or password.', 'error')
            return redirect(url_for('login'))
        
        if not user.is_active:
            flash('Your account is disabled.', 'error')
            return redirect(url_for('login'))
        
        login_user(user)
        next_page = request.args.get('next')
        return redirect(next_page) if next_page and next_page.startswith('/') else redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """User logout"""
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

# ============================================================================
# ROUTES - USER PROFILE & DASHBOARD
# ============================================================================

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard - analytics and user-specific info"""
    # Get user's posters
    user_posters = Poster.query.filter_by(user_id=current_user.id).all()
    
    # Get user's recent orders
    recent_orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).limit(5).all()
    
    # Calculate statistics
    total_sales = sum(order.total_amount for order in recent_orders)
    total_posters = len(user_posters)
    
    stats = {
        'total_posters': total_posters,
        'total_sales': total_sales,
        'recent_orders': recent_orders,
        'user_posters': user_posters,
    }
    
    return render_template('dashboard.html', stats=stats)

@app.route('/profile')
@login_required
def profile():
    """User profile page - personal information"""
    return render_template('profile.html', user=current_user)

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """Edit user profile information"""
    if request.method == 'POST':
        current_user.full_name = request.form.get('full_name', '')
        current_user.profile_bio = request.form.get('profile_bio', '')
        current_user.phone = request.form.get('phone', '')
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('edit_profile.html', user=current_user)

# ============================================================================
# ROUTES - ADMIN PANEL
# ============================================================================

@app.route('/admin/dashboard')
@login_required
@role_required('Admin')
def admin_dashboard():
    """Admin dashboard"""
    total_users = User.query.count()
    total_orders = Order.query.count()
    total_revenue = db.session.query(db.func.sum(Order.total_amount)).scalar() or 0
    total_posters = Poster.query.count()
    
    recent_orders = Order.query.order_by(Order.created_at.desc()).limit(10).all()
    
    return render_template('admin_dashboard.html', 
                         total_users=total_users,
                         total_orders=total_orders,
                         total_revenue=total_revenue,
                         total_posters=total_posters,
                         recent_orders=recent_orders)

@app.route('/admin/users')
@login_required
@role_required('Admin')
def admin_users():
    """Admin users management"""
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/orders')
@login_required
@role_required('Admin')
def admin_orders():
    """Admin orders management"""
    orders = Order.query.order_by(Order.created_at.desc()).all()
    return render_template('admin_orders.html', orders=orders)

@app.route('/export/users')
@login_required
@role_required('Admin')
def export_users():
    """Export users to CSV from accounts.db"""
    users = User.query.all()
    
    si = io.StringIO()
    cw = csv.writer(si)
    
    cw.writerow(['ID', 'Username', 'Email', 'Full Name', 'Phone', 'Roles', 'Active', 'Created At'])
    
    for user in users:
        roles = ', '.join(user.get_roles())
        cw.writerow([
            user.id, 
            user.username, 
            user.email, 
            user.full_name or '', 
            user.phone or '',
            roles, 
            'Yes' if user.is_active else 'No',
            user.created_at.strftime('%Y-%m-%d %H:%M:%S') if user.created_at else ''
        ])
    
    output = make_response(si.getvalue())
    output.headers['Content-Disposition'] = 'attachment; filename=accounts_users.csv'
    output.headers['Content-type'] = 'text/csv'
    
    return output

@app.route('/export/posters')
@login_required
@role_required('Admin')
def export_posters():
    """Export posters catalog to CSV from orders.db"""
    posters = Poster.query.all()
    
    si = io.StringIO()
    cw = csv.writer(si)
    
    cw.writerow(['ID', 'Title', 'Description', 'Price', 'Category', 'Seller ID', 'Views', 'Active', 'Image', 'Created At'])
    
    for poster in posters:
        cw.writerow([
            poster.id,
            poster.title,
            poster.description,
            poster.price,
            poster.category,
            poster.user_id,
            poster.views,
            'Yes' if poster.is_active else 'No',
            poster.image_filename,
            poster.created_at.strftime('%Y-%m-%d %H:%M:%S') if poster.created_at else ''
        ])
    
    output = make_response(si.getvalue())
    output.headers['Content-Disposition'] = 'attachment; filename=orders_posters.csv'
    output.headers['Content-type'] = 'text/csv'
    
    return output

@app.route('/export/orders')
@login_required
@role_required('Admin')
def export_orders():
    """Export orders to CSV from orders.db"""
    orders = Order.query.all()
    
    si = io.StringIO()
    cw = csv.writer(si)
    
    cw.writerow(['Order ID', 'Order Number', 'Customer ID', 'Total Amount', 'Status', 'Full Name', 'Email', 'Phone', 'Address', 'City', 'State', 'Pincode', 'Created At'])
    
    for order in orders:
        cw.writerow([
            order.id,
            order.order_number,
            order.user_id,
            order.total_amount,
            order.status,
            order.full_name,
            order.email,
            order.phone,
            order.address,
            order.city,
            order.state,
            order.pincode,
            order.created_at.strftime('%Y-%m-%d %H:%M:%S') if order.created_at else ''
        ])
    
    output = make_response(si.getvalue())
    output.headers['Content-Disposition'] = 'attachment; filename=orders_list.csv'
    output.headers['Content-type'] = 'text/csv'
    
    return output

@app.route('/export/order-items')
@login_required
@role_required('Admin')
def export_order_items():
    """Export order items to CSV from orders.db"""
    order_items = OrderItem.query.all()
    
    si = io.StringIO()
    cw = csv.writer(si)
    
    cw.writerow(['Item ID', 'Order ID', 'Poster ID', 'Poster Title', 'Quantity', 'Price', 'Subtotal'])
    
    for item in order_items:
        # Get poster title (accessing from orders.db)
        poster = Poster.query.get(item.poster_id)
        poster_title = poster.title if poster else 'Unknown'
        
        cw.writerow([
            item.id,
            item.order_id,
            item.poster_id,
            poster_title,
            item.quantity,
            item.price,
            item.quantity * item.price
        ])
    
    output = make_response(si.getvalue())
    output.headers['Content-Disposition'] = 'attachment; filename=orders_items.csv'
    output.headers['Content-type'] = 'text/csv'
    
    return output

@app.route('/export/cart')
@login_required
@role_required('Admin')
def export_cart():
    """Export shopping cart items to CSV from orders.db"""
    cart_items = CartItem.query.all()
    
    si = io.StringIO()
    cw = csv.writer(si)
    
    cw.writerow(['Cart Item ID', 'Customer ID', 'Poster ID', 'Poster Title', 'Quantity', 'Unit Price', 'Total'])
    
    for item in cart_items:
        # Get poster details
        poster = Poster.query.get(item.poster_id)
        poster_title = poster.title if poster else 'Unknown'
        poster_price = poster.price if poster else 0
        
        cw.writerow([
            item.id,
            item.user_id,
            item.poster_id,
            poster_title,
            item.quantity,
            poster_price,
            item.quantity * poster_price
        ])
    
    output = make_response(si.getvalue())
    output.headers['Content-Disposition'] = 'attachment; filename=orders_cart.csv'
    output.headers['Content-type'] = 'text/csv'
    
    return output

@app.route('/export/all')
@login_required
@role_required('Admin')
def export_all():
    """Export all data (accounts and orders) as ZIP with multiple CSV files"""
    import zipfile
    from io import BytesIO
    
    zip_buffer = BytesIO()
    
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        # Export Users
        users = User.query.all()
        users_csv = io.StringIO()
        cw = csv.writer(users_csv)
        cw.writerow(['ID', 'Username', 'Email', 'Full Name', 'Phone', 'Roles', 'Active', 'Created At'])
        for user in users:
            roles = ', '.join(user.get_roles())
            cw.writerow([
                user.id, user.username, user.email, user.full_name or '', 
                user.phone or '', roles, 'Yes' if user.is_active else 'No',
                user.created_at.strftime('%Y-%m-%d %H:%M:%S') if user.created_at else ''
            ])
        zip_file.writestr('accounts_users.csv', users_csv.getvalue())
        
        # Export Posters
        posters = Poster.query.all()
        posters_csv = io.StringIO()
        cw = csv.writer(posters_csv)
        cw.writerow(['ID', 'Title', 'Description', 'Price', 'Category', 'Seller ID', 'Views', 'Active', 'Image', 'Created At'])
        for poster in posters:
            cw.writerow([
                poster.id, poster.title, poster.description, poster.price, 
                poster.category, poster.user_id, poster.views,
                'Yes' if poster.is_active else 'No', poster.image_filename,
                poster.created_at.strftime('%Y-%m-%d %H:%M:%S') if poster.created_at else ''
            ])
        zip_file.writestr('orders_posters.csv', posters_csv.getvalue())
        
        # Export Orders
        orders = Order.query.all()
        orders_csv = io.StringIO()
        cw = csv.writer(orders_csv)
        cw.writerow(['Order ID', 'Order Number', 'Customer ID', 'Total Amount', 'Status', 'Full Name', 'Email', 'Phone', 'Address', 'City', 'State', 'Pincode', 'Created At'])
        for order in orders:
            cw.writerow([
                order.id, order.order_number, order.user_id, order.total_amount, 
                order.status, order.full_name, order.email, order.phone,
                order.address, order.city, order.state, order.pincode,
                order.created_at.strftime('%Y-%m-%d %H:%M:%S') if order.created_at else ''
            ])
        zip_file.writestr('orders_list.csv', orders_csv.getvalue())
        
        # Export Order Items
        order_items = OrderItem.query.all()
        items_csv = io.StringIO()
        cw = csv.writer(items_csv)
        cw.writerow(['Item ID', 'Order ID', 'Poster ID', 'Poster Title', 'Quantity', 'Price', 'Subtotal'])
        for item in order_items:
            poster = Poster.query.get(item.poster_id)
            poster_title = poster.title if poster else 'Unknown'
            cw.writerow([
                item.id, item.order_id, item.poster_id, poster_title,
                item.quantity, item.price, item.quantity * item.price
            ])
        zip_file.writestr('orders_items.csv', items_csv.getvalue())
        
        # Export Cart Items
        cart_items = CartItem.query.all()
        cart_csv = io.StringIO()
        cw = csv.writer(cart_csv)
        cw.writerow(['Cart Item ID', 'Customer ID', 'Poster ID', 'Poster Title', 'Quantity', 'Unit Price', 'Total'])
        for item in cart_items:
            poster = Poster.query.get(item.poster_id)
            poster_title = poster.title if poster else 'Unknown'
            poster_price = poster.price if poster else 0
            cw.writerow([
                item.id, item.user_id, item.poster_id, poster_title,
                item.quantity, poster_price, item.quantity * poster_price
            ])
        zip_file.writestr('orders_cart.csv', cart_csv.getvalue())
    
    zip_buffer.seek(0)
    
    output = make_response(zip_buffer.getvalue())
    output.headers['Content-Disposition'] = 'attachment; filename=marketplace_export_all.zip'
    output.headers['Content-type'] = 'application/zip'
    
    return output


# ============================================================================
# ROUTES - POSTER MANAGEMENT
# ============================================================================

@app.route('/add-poster', methods=['GET', 'POST'])
@login_required
def add_poster():
    """Add new poster"""
    if request.method == 'POST':
        if 'image' not in request.files:
            flash('No file selected.', 'error')
            return redirect(request.url)
        
        file = request.files['image']
        
        if not allowed_file(file.filename):
            flash(f'Invalid file type. Allowed: {", ".join(ALLOWED_EXTENSIONS)}', 'error')
            return redirect(request.url)
        
        try:
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            price = float(request.form.get('price', 0))
            category = request.form.get('category', '').strip()
            
            if not title or not description or price <= 0 or not category:
                flash('All fields are required and price must be positive.', 'error')
                return redirect(request.url)
            
            # Save file
            filename = secure_filename(file.filename)
            name, ext = os.path.splitext(filename)
            counter = 1
            
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            
            while os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], filename)):
                filename = f"{name}_{counter}{ext}"
                counter += 1
            
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Validate image
            if Image:
                try:
                    with Image.open(file_path) as img:
                        img.verify()
                except:
                    os.remove(file_path)
                    flash('Invalid image file.', 'error')
                    return redirect(request.url)
            
            # Create poster
            poster = Poster(
                title=title,
                description=description,
                price=price,
                category=category,
                image_filename=filename,
                owner=current_user
            )
            
            db.session.add(poster)
            db.session.commit()
            
            flash('Poster added successfully!', 'success')
            return redirect(url_for('dashboard'))
        
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'error')
            return redirect(request.url)
    
    return render_template('add_poster.html')

@app.route('/edit-poster/<int:poster_id>', methods=['GET', 'POST'])
@login_required
def edit_poster(poster_id):
    """Edit poster"""
    poster = Poster.query.get_or_404(poster_id)
    
    if poster.user_id != current_user.id:
        flash('Unauthorized.', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        poster.title = request.form.get('title', '').strip()
        poster.description = request.form.get('description', '').strip()
        poster.price = float(request.form.get('price', poster.price))
        poster.category = request.form.get('category', '').strip()
        
        db.session.commit()
        flash('Poster updated!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('edit_poster.html', poster=poster)

@app.route('/delete-poster/<int:poster_id>', methods=['POST'])
@login_required
def delete_poster(poster_id):
    """Delete poster"""
    poster = Poster.query.get_or_404(poster_id)
    
    if poster.user_id != current_user.id:
        flash('Unauthorized.', 'error')
        return redirect(url_for('index'))
    
    try:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], poster.image_filename)
        if os.path.exists(image_path):
            os.remove(image_path)
        
        db.session.delete(poster)
        db.session.commit()
        
        flash('Poster deleted!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))

# ============================================================================
# ROUTES - SHOPPING
# ============================================================================

@app.route('/')
def index():
    """Homepage"""
    featured_posters = Poster.query.filter_by(is_active=True).limit(8).all()
    return render_template('index.html', featured_posters=featured_posters)

@app.route('/anime')
def anime_page():
    """Anime category page"""
    posters = Poster.query.filter_by(category='Anime', is_active=True).all()
    return render_template('anime.html', posters=posters)

@app.route('/gaming')
def gaming_page():
    """Gaming category page"""
    posters = Poster.query.filter_by(category='Gaming', is_active=True).all()
    return render_template('gaming.html', posters=posters)

@app.route('/posters/<category>')
def category_posters(category):
    """Browse by category"""
    posters = Poster.query.filter_by(category=category, is_active=True).all()
    return render_template('category.html', posters=posters, category=category)

@app.route('/search')
def search():
    """Search posters"""
    query = request.args.get('q', '').strip()
    
    if not query:
        return redirect(url_for('index'))
    
    results = Poster.query.filter(
        (Poster.title.ilike(f'%{query}%')) |
        (Poster.description.ilike(f'%{query}%')) |
        (Poster.category.ilike(f'%{query}%'))
    ).filter_by(is_active=True).all()
    
    return render_template('search.html', results=results, query=query)

@app.route('/add-to-cart/<int:poster_id>', methods=['POST'])
@login_required
def add_to_cart(poster_id):
    """Add poster to cart"""
    poster = Poster.query.get_or_404(poster_id)
    quantity = int(request.form.get('quantity', 1))
    
    if quantity < 1:
        flash('Invalid quantity.', 'error')
        return redirect(request.referrer)
    
    cart_item = CartItem.query.filter_by(user_id=current_user.id, poster_id=poster_id).first()
    
    if cart_item:
        cart_item.quantity += quantity
    else:
        cart_item = CartItem(user_id=current_user.id, poster_id=poster_id, quantity=quantity)
        db.session.add(cart_item)
    
    db.session.commit()
    flash(f'{poster.title} added to cart!', 'success')
    return redirect(request.referrer or url_for('index'))

@app.route('/cart')
@login_required
def view_cart():
    """View shopping cart"""
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    total = sum(item.poster.price * item.quantity for item in cart_items)
    return render_template('cart.html', cart_items=cart_items, total=total)

@app.route('/update-cart/<int:item_id>', methods=['POST'])
@login_required
def update_cart(item_id):
    """Update cart item quantity"""
    cart_item = CartItem.query.get_or_404(item_id)
    
    if cart_item.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    quantity = int(request.form.get('quantity', 1))
    
    if quantity > 0:
        cart_item.quantity = quantity
        db.session.commit()
    
    return redirect(url_for('view_cart'))

@app.route('/remove-from-cart/<int:item_id>')
@login_required
def remove_from_cart(item_id):
    """Remove item from cart"""
    cart_item = CartItem.query.get_or_404(item_id)
    
    if cart_item.user_id != current_user.id:
        flash('Unauthorized.', 'error')
        return redirect(url_for('view_cart'))
    
    db.session.delete(cart_item)
    db.session.commit()
    flash('Item removed from cart.', 'success')
    return redirect(url_for('view_cart'))


@app.route('/order-confirmation/<int:order_id>')
@login_required
def order_confirmation(order_id):
    """Order confirmation page"""
    order = Order.query.get_or_404(order_id)
    
    if order.user_id != current_user.id:
        flash('Unauthorized.', 'error')
        return redirect(url_for('index'))
    
    return render_template('order_confirmation.html', order=order)

@app.route('/my-orders')
@login_required
def my_orders():
    """View user's orders"""
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).all()
    return render_template('my_orders.html', orders=orders)

# ============================================================================
# UTILITY ROUTES
# ============================================================================

@app.route('/uploads/<filename>')
def serve_upload(filename):
    """Serve uploaded files"""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.errorhandler(404)
def not_found(error):
    """404 error handler"""
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(error):
    """500 error handler"""
    return render_template('500.html'), 500

# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

def seed_posters():
    """Seed database with sample posters from seed_images folder"""
    try:
        # Check if posters already exist
        if Poster.query.first():
            print("[OK] Posters already seeded, skipping.")
            return
        
        # Get or create admin user
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            print("[ERROR] Admin user not found. Cannot seed posters.")
            return
        
        poster_data = [
            # Anime Posters
            ("Gojo Satoru - Sorcerer King", "Premium anime poster featuring Gojo from Jujutsu Kaisen", 299, "Anime", "gojo1.png"),
            ("Gojo Blue Eyes", "Stunning artwork of Gojo's powerful blue eyes", 279, "Anime", "gojo2.png"),
            ("Gohan Ultra Instinct", "Dragon Ball's ultimate warrior form", 299, "Anime", "gohan1.png"),
            ("Itachi Uchiha - The Prodigy", "Iconic Naruto character poster", 289, "Anime", "itachi1.png"),
            ("Madara Susanoo", "Madara's legendary power unleashed", 319, "Anime", "madara1.png"),
            ("Madara Full Body", "The legendary Uchiha clan leader", 299, "Anime", "madara2.png"),
            ("Madara Dark Power", "Madara's overwhelming dark energy", 309, "Anime", "madara3.png"),
            ("Madara Eternal Mangekyou", "Madara's most powerful form", 329, "Anime", "madara4.png"),
            ("Mikasa Ackerman", "Attack on Titan's fierce warrior", 279, "Anime", "mikasa1.png"),
            ("Obito Uchiha", "The masked shinobi's story", 289, "Anime", "obito1.png"),
            ("Obito Tobi", "Obito's true identity revealed", 299, "Anime", "obito2.png"),
            ("Sakura Haruno", "Naruto's powerful kunoichi", 269, "Anime", "sakun2.png"),
            ("Sukuna Full Power", "Jujutsu Kaisen's king of curses", 349, "Anime", "sakuna1.png"),
            ("Sasuke Rinnegan", "Sasuke's ultimate power", 319, "Anime", "sasuke1.png"),
            ("Sasuke Evolution", "The avenger's journey", 299, "Anime", "sasuke2.png"),
            ("Super Saiyan Power", "Dragon Ball's legendary transformation", 289, "Anime", "supper_saiyyan1.png"),
            ("Super Saiyan Gold", "Golden warrior form", 299, "Anime", "supper_saiyyan2.png"),
            ("Yagami Light", "Death Note's protagonist", 279, "Anime", "yagami2.png"),
            ("Yuji Itadori - Jujutsu Kaisen", "The vessel of Sukuna", 289, "Anime", "yuji1.png"),
            ("Yuji Power", "Yuji's hidden potential", 299, "Anime", "yuji2.png"),
            ("Zenitsu Thunder Breathing", "Demon Slayer's electric hero", 289, "Anime", "zenitsu1.png"),
            ("Zenitsu Sleep Power", "Zenitsu's unique ability", 279, "Anime", "zenitsu2.png"),
            ("Zoro Three Swords", "One Piece's legendary swordsman", 309, "Anime", "zoro1.png"),
            ("Zoro Asura", "Zoro's mythical form", 329, "Anime", "zoro2.png"),
            ("Hinata Hyuga", "Naruto's gentle princess", 279, "Anime", "hinata1.png"),
            
            # Gaming Posters
            ("Assassin's Creed Brotherhood", "Parkour assassin action", 289, "Gaming", "assains_creed1.png"),
            ("Assassin's Creed Odyssey", "Ancient Greek adventure", 299, "Gaming", "assains_creed2.png"),
            ("Assassin's Creed Valhalla", "Viking era masterpiece", 309, "Gaming", "assains_creed3.png"),
            ("Call of Duty Modern Warfare", "Military shooter legend", 319, "Gaming", "cod1.png"),
            ("Call of Duty Black Ops", "Intense combat operations", 299, "Gaming", "cod2.png"),
            ("Far Cry Adventure", "Survival in the wild", 279, "Gaming", "far_cry2.png"),
            ("FIFA 24 Champions", "Football gaming excellence", 269, "Gaming", "fifa1.png"),
            ("FIFA Pro Player", "Soccer superstar", 279, "Gaming", "fifa2.png"),
            ("Franklin GTA 5", "Grand Theft Auto protagonist", 299, "Gaming", "franklin1.png"),
            ("Franklin Street Life", "GTA 5 street action", 289, "Gaming", "franklin2.png"),
            ("GTA V Sunset", "Los Santos city vibes", 299, "Gaming", "gtav_1.png"),
            ("GTA V Criminal Life", "The ultimate crime simulator", 309, "Gaming", "gtav_2.png"),
            ("Indiana Jones Adventure", "Ancient temples explorer", 309, "Gaming", "indianna_jones1.png"),
            ("Valorant Jett Agent", "Tactical shooter precision", 279, "Gaming", "jett1.png"),
            ("Valorant Duelist", "Valorant's fastest agent", 289, "Gaming", "jett2.png"),
            ("Michael GTA V", "Retired criminal life", 299, "Gaming", "micheal1.png"),
            ("Michael Action", "GTA 5 heist master", 299, "Gaming", "micheal2.png"),
            ("Minecraft World", "Block building legend", 249, "Gaming", "minecraft1.png"),
            ("Red Dead Redemption", "Wild west outlaw saga", 319, "Gaming", "rdr1.png"),
            ("RDR 2 Cowboy", "The ultimate western game", 329, "Gaming", "rdr2.png"),
            ("Valorant Reyna Agent", "Mexican duelist power", 289, "Gaming", "reyna1.png"),
            ("Reyna Dismiss", "Valorant's immortal agent", 299, "Gaming", "reyna2.png"),
            ("Reyna Glory", "Ultimate agent showcase", 299, "Gaming", "reyna3.png"),
            ("Spider-Man PS5", "Marvel's web-slinger", 299, "Gaming", "spiderman2.png"),
            ("Trevor GTA 5", "Chaos agent of San Andreas", 289, "Gaming", "trevor1.png"),
        ]
        
        # Create posters
        for title, description, price, category, image_file in poster_data:
            # Check if poster already exists
            if Poster.query.filter_by(title=title).first():
                continue
            
            # Check if image exists in seed folder
            image_path = os.path.join(SEED_FOLDER, category, image_file)
            if not os.path.exists(image_path):
                print(f"[WARN] Image not found: {image_path}")
                continue
            
            # Copy image to uploads folder
            dest_path = os.path.join(app.config['UPLOAD_FOLDER'], image_file)
            if not os.path.exists(dest_path):
                shutil.copy(image_path, dest_path)
            
            # Create poster
            poster = Poster(
                title=title,
                description=description,
                price=price,
                category=category,
                image_filename=image_file,
                user_id=admin.id,
                is_active=True
            )
            db.session.add(poster)
        
        db.session.commit()
        poster_count = Poster.query.count()
        print(f"[OK] Seeded {poster_count} posters successfully!")
    except Exception as e:
        db.session.rollback()
        print(f"[WARNING] Error seeding posters (continuing anyway): {str(e)}")
        import traceback
        traceback.print_exc()

def init_database():
    """Initialize both databases with tables and seed data"""
    with app.app_context():
        print("\n" + "="*60)
        print("DATABASE INITIALIZATION - DUAL DATABASE SETUP")
        print("="*60)
        
        # Create upload folder
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # Create both databases
        print("\n[STEP 1] Creating database tables...")
        db.create_all()
        print("[OK] Both 'accounts.db' and 'orders.db' created successfully!")
        print("     - accounts.db: User authentication & account data")
        print("     - orders.db: Products, orders, and order items")
        
        # Initialize roles (in accounts database)
        print("\n[STEP 2] Initializing user roles...")
        init_roles()
        print("[OK] Roles initialized in accounts.db")
        
        # Create admin user if doesn't exist
        print("\n[STEP 3] Creating admin account...")
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@marketplace.com')
            admin.set_password('admin123')  # CHANGE THIS IN PRODUCTION
            
            admin_role = Role.query.filter_by(name='Admin').first()
            seller_role = Role.query.filter_by(name='Seller').first()
            
            if admin_role:
                admin.roles.append(admin_role)
            if seller_role:
                admin.roles.append(seller_role)
            
            db.session.add(admin)
            db.session.commit()
            print("[OK] Admin user created (username: admin, password: admin123)")
            print("[WARNING] CHANGE ADMIN PASSWORD IN PRODUCTION!")
        else:
            print("[INFO] Admin user already exists")
        
        # Seed posters (in orders database)
        print("\n[STEP 4] Seeding product catalog...")
        seed_posters()
        
        print("\n" + "="*60)
        print("DATABASE INITIALIZATION COMPLETE")
        print("="*60)
        print("Database Files:")
        print(f"  - accounts.db: {os.path.join(os.path.dirname(__file__), 'accounts.db')}")
        print(f"  - orders.db:   {os.path.join(os.path.dirname(__file__), 'orders.db')}")
        print("="*60 + "\n")
        

# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == '__main__':
    try:
        init_database()
        app.run(debug=True, host='127.0.0.1', port=8080)
    except Exception as e:
        print(f"\n[FATAL ERROR] Database initialization failed:")
        print(f"{str(e)}")
        import traceback
        traceback.print_exc()
        # Don't exit, let the error be visible
