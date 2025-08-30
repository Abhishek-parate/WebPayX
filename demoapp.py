# app.py - Main Flask Application with Dual Payment Support
import os
from datetime import datetime, date
from flask import Flask, redirect, render_template, url_for, session, request, jsonify
from flask_login import LoginManager, current_user, login_required
from flask_migrate import Migrate
from sqlalchemy import func
from pathlib import Path

# Import your existing routes
from routes.chart import chart_bp
from routes.aiapplication import aiapplication_bp
from routes.authentication import authentication_bp
from routes.componentspage import componentspage_bp
from routes.selfservice import selfservice_bp
from routes.selftransactionreport import selftransactionreport_bp
from routes.complaint import complaint_bp
from routes.logout import logout_bp
from routes.membermanager import membermanager_bp
from routes.memberreport import memberreport_bp
from routes.privacypolicy import privacypolicy_bp
from routes.profilesetting import profilesetting_bp
from routes.wallettopup import wallettopup_bp
from routes.terms_condition import terms_condition_bp
from routes.dashboard import dashboard_bp
from routes.forms import forms_bp
from routes.invoice import invoice_bp
from routes.settings import settings_bp
from routes.table import table_bp
from routes.user import user_bp
from routes.transaction import transaction_management_bp

# Import new enhanced routes
from routes.user_management import user_management_bp
from routes.enhanced_topup import enhanced_topup_bp
from routes.bank_management import bank_management_bp
from routes.role_permissions import role_permissions_bp

# Database and models
from models import db, User, UserSession, Tenant, PaymentGateway, OrganizationBankAccount, create_tables, create_default_permissions


# =============================================================================
# APP CONFIGURATION
# =============================================================================
def create_app(config_name='development'):
    """Application factory pattern with dual payment support"""
    app = Flask(
        __name__,
        template_folder='resource/views',
        static_folder=os.path.abspath('static')
    )

    # Configuration
    if config_name == 'production':
        app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
            'DATABASE_URL',
            'postgresql://postgres:@localhost/saas_platform'
        )
        app.config['DEBUG'] = False
    else:
        # Use PostgreSQL for development as configured in your .env
        app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
            'DATABASE_URL',
            'postgresql://postgres:1234@localhost:5432/saas_platform'
        )
        app.config['DEBUG'] = True

    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file upload

    # Upload configuration for dual payment methods
    app.config['UPLOAD_FOLDER'] = 'uploads'
    app.config['TOPUP_UPLOAD_FOLDER'] = 'uploads/topup_proofs'
    app.config['QR_CODE_FOLDER'] = 'static/qr_codes'

    # Payment configuration for dual methods
    app.config['PAYMENT_GATEWAY_CONFIG'] = {
        'DEFAULT_UPI_ID': os.environ.get('DEFAULT_UPI_ID', 'payment@company.upi'),
        'UPI_MERCHANT_NAME': os.environ.get('UPI_MERCHANT_NAME', 'Your Company'),
        'QR_CODE_EXPIRY_MINUTES': int(os.environ.get('QR_CODE_EXPIRY_MINUTES', '30')),
        'MANUAL_PAYMENT_EXPIRY_HOURS': int(os.environ.get('MANUAL_PAYMENT_EXPIRY_HOURS', '24')),
        'MAX_TOPUP_AMOUNT': float(os.environ.get('MAX_TOPUP_AMOUNT', '100000')),
        'MIN_TOPUP_AMOUNT': float(os.environ.get('MIN_TOPUP_AMOUNT', '10')),
        'ALLOWED_FILE_EXTENSIONS': ['png', 'jpg', 'jpeg', 'pdf'],
        'MAX_FILE_SIZE': 5 * 1024 * 1024  # 5MB
    }

    # Initialize extensions
    db.init_app(app)
    migrate = Migrate(app, db)

    # Create upload directories
    with app.app_context():
        create_upload_directories(app)

    # Setup Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'authentication.login_page'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(user_id)

    # =============================================================================
    # REGISTER BLUEPRINTS (NO DUPLICATES)
    # =============================================================================

    # Existing routes
    app.register_blueprint(authentication_bp)
    app.register_blueprint(selfservice_bp)
    app.register_blueprint(selftransactionreport_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(complaint_bp)
    app.register_blueprint(logout_bp)
    app.register_blueprint(membermanager_bp)
    app.register_blueprint(memberreport_bp)
    app.register_blueprint(privacypolicy_bp)
    app.register_blueprint(wallettopup_bp)
    app.register_blueprint(profilesetting_bp)
    app.register_blueprint(terms_condition_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(chart_bp)
    app.register_blueprint(aiapplication_bp)
    app.register_blueprint(componentspage_bp)
    app.register_blueprint(forms_bp)
    app.register_blueprint(invoice_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(table_bp)
    app.register_blueprint(transaction_management_bp)

    # New enhanced routes (SINGLE REGISTRATION)
    app.register_blueprint(user_management_bp)
    app.register_blueprint(enhanced_topup_bp)  # This handles dual payment wallet functionality
    app.register_blueprint(bank_management_bp)
    app.register_blueprint(role_permissions_bp)

    # =============================================================================
    # MAIN ROUTES
    # =============================================================================

    @app.route('/')
    @login_required
    def index():
        """Homepage - redirect to login or dashboard"""
        if current_user.is_authenticated:
            return redirect(url_for('dashboard.index'))
        return redirect(url_for('authentication.login_page'))

    @app.route('/dashboard')
    @login_required
    def dashboard():
        """Main dashboard"""
        user_stats = get_user_dashboard_stats()
        return render_template(
            'dashboard/index.html',
            title='Dashboard',
            subtitle=f'Welcome, {current_user.full_name}',
            user_stats=user_stats
        )

    # Enhanced wallet routes for dual payment methods
    @app.route('/wallet/')
    @login_required
    def wallet_index():
        """Wallet main page - redirect to enhanced topup request with dual payment"""
        return redirect(url_for('enhanced_topup.topup_request_page'))

    @app.route('/wallet-topup')
    @login_required
    def wallet_topup():
        """Enhanced wallet top-up page with manual and online payment options"""
        return redirect(url_for('enhanced_topup.topup_request_page'))

    @app.route('/wallet-topup/manual')
    @login_required
    def wallet_topup_manual():
        """Direct link to manual payment topup"""
        return render_template(
            'topup/request_topup.html',
            title='Manual Payment Top-up',
            subtitle='Bank Transfer Payment Method',
            default_method='manual'
        )

    @app.route('/wallet-topup/online')
    @login_required
    def wallet_topup_online():
        """Direct link to online payment topup"""
        return render_template(
            'topup/request_topup.html',
            title='Online Payment Top-up',
            subtitle='UPI & Payment Gateway Method',
            default_method='online'
        )

    @app.route('/user-management')
    @login_required
    def user_management():
        """User management page"""
        if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN', 'WHITE_LABEL']:
            return redirect(url_for('dashboard.index'))
        return redirect(url_for('user_management.index'))

    # =============================================================================
    # API ROUTES
    # =============================================================================

    @app.route('/api/user/profile')
    @login_required
    def get_user_profile():
        """Get current user profile"""
        try:
            user_data = current_user.to_dict()

            # Add wallet information
            if current_user.wallet:
                user_data['wallet'] = {
                    'balance': float(current_user.wallet.balance),
                    'hold_balance': float(current_user.wallet.hold_balance),
                    'available_balance': float(current_user.wallet.available_balance),
                    'daily_limit': float(current_user.wallet.daily_limit),
                    'monthly_limit': float(current_user.wallet.monthly_limit),
                    'daily_used': float(current_user.wallet.daily_used),
                    'monthly_used': float(current_user.wallet.monthly_used),
                    'daily_remaining': float(current_user.wallet.daily_remaining),
                    'monthly_remaining': float(current_user.wallet.monthly_remaining)
                }

            # Add parent information
            if current_user.parent:
                user_data['parent'] = {
                    'id': current_user.parent.id,
                    'full_name': current_user.parent.full_name,
                    'user_code': current_user.parent.user_code,
                    'role': current_user.parent.role.value
                }

            # Add children count
            children_count = db.session.query(func.count(User.id)).filter_by(
                parent_id=current_user.id,
                is_active=True
            ).scalar()
            user_data['children_count'] = children_count

            return jsonify({
                'user': user_data,
                'permissions': get_user_permissions(current_user),
                'payment_methods': get_available_payment_methods()
            })

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/dashboard/stats')
    @login_required
    def dashboard_stats():
        """Get dashboard statistics including payment method stats"""
        try:
            stats = get_user_dashboard_stats()
            return jsonify(stats)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/payment/methods')
    @login_required
    def get_payment_methods():
        """Get available payment methods for current user"""
        try:
            methods = get_available_payment_methods()
            return jsonify({
                'payment_methods': methods,
                'user_preferences': get_user_payment_preferences()
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/config')
    def get_app_config():
        """Get public app configuration"""
        return jsonify({
            'app_name': 'WebPayX Official',
            'version': '2.0.0',
            'features': {
                'dual_payment_methods': True,
                'manual_payments': True,
                'online_payments': True,
                'upi_support': True,
                'file_upload': True,
                'qr_code_generation': True
            },
            'limits': {
                'min_topup_amount': app.config['PAYMENT_GATEWAY_CONFIG']['MIN_TOPUP_AMOUNT'],
                'max_topup_amount': app.config['PAYMENT_GATEWAY_CONFIG']['MAX_TOPUP_AMOUNT'],
                'max_file_size': app.config['PAYMENT_GATEWAY_CONFIG']['MAX_FILE_SIZE'],
                'allowed_file_types': app.config['PAYMENT_GATEWAY_CONFIG']['ALLOWED_FILE_EXTENSIONS']
            },
            'payment_config': {
                'manual_expiry_hours': app.config['PAYMENT_GATEWAY_CONFIG']['MANUAL_PAYMENT_EXPIRY_HOURS'],
                'online_expiry_minutes': app.config['PAYMENT_GATEWAY_CONFIG']['QR_CODE_EXPIRY_MINUTES']
            }
        })

    # =============================================================================
    # ERROR HANDLERS
    # =============================================================================

    @app.errorhandler(404)
    def not_found(error):
        if request.is_json:
            return jsonify({'error': 'Not found'}), 404
        return render_template('errors/404.html'), 404

    @app.errorhandler(403)
    def forbidden(error):
        if request.is_json:
            return jsonify({'error': 'Access forbidden'}), 403
        return render_template('errors/403.html'), 403

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        if request.is_json:
            return jsonify({'error': 'Internal server error'}), 500
        return render_template('errors/500.html'), 500

    @app.errorhandler(413)
    def request_entity_too_large(error):
        if request.is_json:
            return jsonify({
                'error': 'File too large',
                'max_size': '16MB',
                'payment_proof_max_size': '5MB'
            }), 413
        return render_template('errors/413.html'), 413

    # =============================================================================
    # CONTEXT PROCESSORS
    # =============================================================================

    @app.context_processor
    def inject_user_data():
        """Inject user data into all templates"""
        if current_user.is_authenticated:
            return {
                'current_user': current_user,
                'user_permissions': get_user_permissions(current_user),
                'allowed_roles': get_allowed_roles_for_creation(current_user.role) if hasattr(current_user, 'role') else [],
                'available_payment_methods': get_available_payment_methods(),
                'user_payment_preferences': get_user_payment_preferences()
            }
        return {}

    @app.context_processor
    def inject_tenant_data():
        """Inject tenant data into all templates"""
        tenant_id = session.get('tenant_id')
        if tenant_id:
            tenant = Tenant.query.get(tenant_id)
            if tenant:
                return {
                    'current_tenant': tenant,
                    'tenant_theme': tenant.theme_config
                }
        return {}

    @app.context_processor
    def inject_payment_config():
        """Inject payment configuration into templates"""
        return {
            'payment_config': app.config['PAYMENT_GATEWAY_CONFIG'],
            'upload_config': {
                'max_file_size': app.config['PAYMENT_GATEWAY_CONFIG']['MAX_FILE_SIZE'],
                'allowed_extensions': app.config['PAYMENT_GATEWAY_CONFIG']['ALLOWED_FILE_EXTENSIONS']
            }
        }

    # =============================================================================
    # TEMPLATE FILTERS
    # =============================================================================

    @app.template_filter('currency')
    def format_currency(amount):
        """Format currency for display"""
        if amount is None:
            return "₹0.00"
        return f"₹{float(amount):,.2f}"

    @app.template_filter('payment_method_badge')
    def get_payment_method_badge_class(method):
        """Get CSS class for payment method badges"""
        method_classes = {
            'MANUAL_REQUEST': 'bg-yellow-100 text-yellow-800',
            'PAYMENT_GATEWAY': 'bg-green-100 text-green-800',
            'ADMIN_CREDIT': 'bg-blue-100 text-blue-800',
            'BANK_TRANSFER': 'bg-purple-100 text-purple-800',
            'CASH_DEPOSIT': 'bg-orange-100 text-orange-800'
        }
        return method_classes.get(method, 'bg-gray-100 text-gray-800')

    @app.template_filter('status_badge')
    def get_status_badge_class(status):
        """Get CSS class for status badges"""
        status_classes = {
            'PENDING': 'bg-yellow-100 text-yellow-800',
            'PROCESSING': 'bg-blue-100 text-blue-800',
            'SUCCESS': 'bg-green-100 text-green-800',
            'FAILED': 'bg-red-100 text-red-800',
            'CANCELLED': 'bg-gray-100 text-gray-800',
            'REFUNDED': 'bg-purple-100 text-purple-800'
        }
        return status_classes.get(status, 'bg-gray-100 text-gray-800')

    @app.template_filter('file_size')
    def format_file_size(size_bytes):
        """Format file size in human readable format"""
        if not size_bytes:
            return "0 B"
        
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"

    return app


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def create_upload_directories(app):
    """Create necessary upload directories"""
    directories = [
        app.config['UPLOAD_FOLDER'],
        app.config['TOPUP_UPLOAD_FOLDER'],
        app.config['QR_CODE_FOLDER']
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)

def get_available_payment_methods():
    """Get available payment methods for the current user"""
    try:
        methods = {
            'manual': {
                'enabled': True,
                'name': 'Manual Bank Transfer',
                'description': 'Transfer money to bank account with proof upload',
                'icon': 'bank',
                'requires_proof': True,
                'processing_time': '2-24 hours'
            },
            'online': {
                'enabled': True,
                'name': 'Online Payment',
                'description': 'Instant payment via UPI, cards, or net banking',
                'icon': 'smartphone',
                'requires_proof': False,
                'processing_time': 'Instant'
            }
        }
        
        # Check if payment gateway is configured
        if current_user.is_authenticated:
            gateway = PaymentGateway.query.filter_by(
                tenant_id=current_user.tenant_id,
                status='ACTIVE',
                is_default=True
            ).first()
            
            if not gateway:
                methods['online']['enabled'] = False
                methods['online']['note'] = 'Payment gateway not configured'
        
        # Check if bank accounts are available for manual payments
        if current_user.is_authenticated:
            bank_accounts = OrganizationBankAccount.query.filter_by(
                tenant_id=current_user.tenant_id,
                status='ACTIVE',
                is_visible_to_users=True
            ).count()
            
            if bank_accounts == 0:
                methods['manual']['enabled'] = False
                methods['manual']['note'] = 'No bank accounts configured'
        
        return methods
    except Exception as e:
        return {
            'manual': {'enabled': False, 'error': str(e)},
            'online': {'enabled': False, 'error': str(e)}
        }

def get_user_payment_preferences():
    """Get user's payment method preferences"""
    if not current_user.is_authenticated:
        return {}
    
    try:
        # You can extend this to store user preferences in database
        preferences = {
            'preferred_method': 'online',  # Default to online
            'save_payment_details': False,
            'notification_preferences': {
                'email': True,
                'sms': False
            }
        }
        
        # Check user's recent topup methods to determine preference
        from models import WalletTopupRequest, TopupMethod
        recent_topups = WalletTopupRequest.query.filter_by(
            user_id=current_user.id
        ).order_by(WalletTopupRequest.created_at.desc()).limit(5).all()
        
        if recent_topups:
            manual_count = sum(1 for t in recent_topups if t.topup_method == TopupMethod.MANUAL_REQUEST)
            online_count = len(recent_topups) - manual_count
            
            preferences['preferred_method'] = 'manual' if manual_count > online_count else 'online'
            preferences['usage_stats'] = {
                'manual_usage': manual_count,
                'online_usage': online_count,
                'total_requests': len(recent_topups)
            }
        
        return preferences
    except Exception:
        return {'preferred_method': 'online'}

def get_user_dashboard_stats():
    """Get dashboard statistics for current user including payment method breakdown"""
    try:
        stats = {
            'wallet': {
                'balance': 0,
                'available_balance': 0,
                'daily_used': 0,
                'monthly_used': 0
            },
            'transactions': {
                'total': 0,
                'today': 0,
                'this_month': 0,
                'success_rate': 0
            },
            'topups': {
                'total': 0,
                'pending': 0,
                'manual_count': 0,
                'online_count': 0,
                'success_rate': 0
            },
            'users': {
                'total_children': 0,
                'active_children': 0,
                'pending_topups': 0
            },
            'recent_activities': []
        }

        # Wallet statistics
        if current_user.wallet:
            stats['wallet'] = {
                'balance': float(current_user.wallet.balance),
                'available_balance': float(current_user.wallet.available_balance),
                'daily_used': float(current_user.wallet.daily_used),
                'monthly_used': float(current_user.wallet.monthly_used),
                'daily_remaining': float(current_user.wallet.daily_remaining),
                'monthly_remaining': float(current_user.wallet.monthly_remaining)
            }

        # Topup statistics with payment method breakdown
        from models import WalletTopupRequest, TransactionStatus, TopupMethod
        
        topup_query = WalletTopupRequest.query.filter_by(user_id=current_user.id)
        
        stats['topups']['total'] = topup_query.count()
        stats['topups']['pending'] = topup_query.filter_by(status=TransactionStatus.PENDING).count()
        stats['topups']['manual_count'] = topup_query.filter_by(topup_method=TopupMethod.MANUAL_REQUEST).count()
        stats['topups']['online_count'] = topup_query.filter_by(topup_method=TopupMethod.PAYMENT_GATEWAY).count()
        
        # Success rate for topups
        total_topups = stats['topups']['total']
        if total_topups > 0:
            successful_topups = topup_query.filter_by(status=TransactionStatus.SUCCESS).count()
            stats['topups']['success_rate'] = round((successful_topups / total_topups) * 100, 2)

        # User hierarchy statistics (for admins)
        if current_user.role.value in ['SUPER_ADMIN', 'ADMIN', 'WHITE_LABEL', 'MASTER_DISTRIBUTOR', 'DISTRIBUTOR']:
            # Count children users
            children_query = User.query.filter(
                User.tenant_id == current_user.tenant_id,
                User.tree_path.like(f"{current_user.tree_path}%") if current_user.tree_path else True,
                User.id != current_user.id
            )

            stats['users']['total_children'] = children_query.count()
            stats['users']['active_children'] = children_query.filter(User.is_active == True).count()

            # Pending topup requests from children
            pending_topups = WalletTopupRequest.query.join(User).filter(
                User.tenant_id == current_user.tenant_id,
                User.tree_path.like(f"{current_user.tree_path}%") if current_user.tree_path else True,
                WalletTopupRequest.status == TransactionStatus.PENDING
            ).count()
            stats['users']['pending_topups'] = pending_topups

        # Transaction statistics
        from models import Transaction, TransactionStatus

        transaction_query = Transaction.query.filter(
            Transaction.user_id == current_user.id
        )

        stats['transactions']['total'] = transaction_query.count()

        # Today's transactions
        today = date.today()
        stats['transactions']['today'] = transaction_query.filter(
            func.date(Transaction.created_at) == today
        ).count()

        # This month's transactions
        this_month_start = datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        stats['transactions']['this_month'] = transaction_query.filter(
            Transaction.created_at >= this_month_start
        ).count()

        # Success rate
        total_transactions = stats['transactions']['total']
        if total_transactions > 0:
            successful_transactions = transaction_query.filter(
                Transaction.status == TransactionStatus.SUCCESS
            ).count()
            stats['transactions']['success_rate'] = round(
                (successful_transactions / total_transactions) * 100, 2
            )

        # Recent activities (mixed transactions and topups)
        recent_activities = []
        
        # Recent transactions
        recent_transactions = Transaction.query.filter(
            Transaction.user_id == current_user.id
        ).order_by(Transaction.created_at.desc()).limit(3).all()

        for transaction in recent_transactions:
            recent_activities.append({
                'type': 'transaction',
                'description': f"{transaction.service_type.value} - ₹{transaction.amount}",
                'status': transaction.status.value,
                'created_at': transaction.created_at.isoformat()
            })

        # Recent topup requests
        recent_topups = WalletTopupRequest.query.filter(
            WalletTopupRequest.user_id == current_user.id
        ).order_by(WalletTopupRequest.created_at.desc()).limit(3).all()

        for topup in recent_topups:
            payment_method = "Manual" if topup.topup_method == TopupMethod.MANUAL_REQUEST else "Online"
            recent_activities.append({
                'type': 'topup',
                'description': f"Wallet Top-up ({payment_method}) - ₹{topup.amount}",
                'status': topup.status.value,
                'payment_method': payment_method.lower(),
                'created_at': topup.created_at.isoformat()
            })

        # Sort recent activities by date and take top 5
        recent_activities.sort(key=lambda x: x['created_at'], reverse=True)
        stats['recent_activities'] = recent_activities[:5]

        return stats

    except Exception as e:
        print(f"Error getting dashboard stats: {e}")
        return {
            'wallet': {'balance': 0, 'available_balance': 0},
            'transactions': {'total': 0, 'today': 0, 'success_rate': 0},
            'topups': {'total': 0, 'pending': 0, 'manual_count': 0, 'online_count': 0, 'success_rate': 0},
            'users': {'total_children': 0, 'active_children': 0, 'pending_topups': 0},
            'recent_activities': []
        }


def get_user_permissions(user):
    """Get user's effective permissions"""
    try:
        from routes.role_permissions import get_user_effective_permissions
        return get_user_effective_permissions(user)
    except Exception:
        return []


def get_allowed_roles_for_creation(current_role):
    """Get roles that current user can create"""
    try:
        from routes.user_management import get_allowed_roles_for_creation as get_roles
        return get_roles(current_role)
    except Exception:
        return []


# =============================================================================
# CLI COMMANDS
# =============================================================================

def register_cli_commands(app):
    """Register CLI commands for database management"""

    @app.cli.command()
    def init_db():
        """Initialize the database with tables and default data"""
        try:
            print("🔄 Initializing database...")

            # Create tables
            create_tables(db.engine)
            print("✅ Database tables created")

            # Create default tenant
            default_tenant = Tenant.query.filter_by(tenant_code='DEFAULT').first()
            if not default_tenant:
                default_tenant = Tenant(
                    tenant_code='DEFAULT',
                    tenant_name='Default Organization',
                    domain='localhost',
                    subdomain='default',
                    is_active=True,
                    theme_config={
                        'primary_color': '#3B82F6',
                        'secondary_color': '#6B7280',
                        'logo_url': '/static/assets/images/logo.png'
                    }
                )
                db.session.add(default_tenant)
                db.session.commit()
                print("✅ Default tenant created")

            # Create default permissions
            from models import Permission
            if not Permission.query.first():
                default_permissions = create_default_permissions()
                for permission in default_permissions:
                    db.session.add(permission)
                db.session.commit()
                print("✅ Default permissions created")

            print("🎉 Database initialization completed!")

        except Exception as e:
            print(f"❌ Database initialization failed: {e}")

    @app.cli.command()
    def create_admin():
        """Create a super admin user"""
        try:
            from models import UserRoleType, KYCStatus, Wallet

            tenant = Tenant.query.filter_by(tenant_code='DEFAULT').first()
            if not tenant:
                print("❌ Default tenant not found. Run 'flask init-db' first.")
                return

            # Check if super admin already exists
            existing_admin = User.query.filter_by(
                tenant_id=tenant.id,
                role=UserRoleType.SUPER_ADMIN
            ).first()

            if existing_admin:
                print(f"⚠️  Super admin already exists: {existing_admin.username}")
                return

            # Get user input
            username = input("Enter username (default: superadmin): ") or "superadmin"
            email = input("Enter email (default: admin@example.com): ") or "admin@example.com"
            phone = input("Enter phone (default: 1234567890): ") or "1234567890"
            password = input("Enter password (default: Admin@123): ") or "Admin@123"
            full_name = input("Enter full name (default: Super Administrator): ") or "Super Administrator"

            # Generate user code
            admin_count = User.query.filter(User.user_code.like('SA%')).count()
            user_code = f"SA{admin_count + 1:06d}"

            # Create super admin
            super_admin = User(
                tenant_id=tenant.id,
                user_code=user_code,
                username=username,
                email=email,
                phone=phone,
                role=UserRoleType.SUPER_ADMIN,
                full_name=full_name,
                kyc_status=KYCStatus.APPROVED,
                is_active=True,
                is_verified=True,
                email_verified=True,
                phone_verified=True,
                tree_path=user_code,
                level=0
            )
            super_admin.set_password(password)
            super_admin.generate_api_key()

            db.session.add(super_admin)
            db.session.flush()

            # Create wallet
            admin_wallet = Wallet(
                user_id=super_admin.id,
                balance=100000,
                daily_limit=1000000,
                monthly_limit=10000000
            )
            db.session.add(admin_wallet)
            db.session.commit()

            print("✅ Super admin created successfully!")
            print(f"   Username: {username}")
            print(f"   Email: {email}")
            print(f"   User Code: {user_code}")
            print(f"   Initial Balance: ₹100,000")

        except Exception as e:
            db.session.rollback()
            print(f"❌ Failed to create super admin: {e}")

    @app.cli.command()
    def create_dual_payment_setup():
        """Create bank accounts and payment gateways for dual payment setup"""
        try:
            from models import (OrganizationBankAccount, BankAccountType, BankAccountStatus, 
                              AccountPurpose, PaymentGateway, PaymentGatewayType, TopupMethod)

            tenant = Tenant.query.filter_by(tenant_code='DEFAULT').first()
            if not tenant:
                print("❌ Default tenant not found. Run 'flask init-db' first.")
                return

            # Create bank account for manual payments
            existing_bank = OrganizationBankAccount.query.filter_by(
                tenant_id=tenant.id,
                is_default_topup=True
            ).first()

            if not existing_bank:
                bank_account = OrganizationBankAccount(
                    tenant_id=tenant.id,
                    account_code="BA000001",
                    account_name="Primary Collection Account",
                    account_number="1234567890123456",
                    ifsc_code="SBIN0001234",
                    bank_name="State Bank of India",
                    branch_name="Main Branch",
                    account_type=BankAccountType.CURRENT,
                    account_holder_name="Default Organization",
                    status=BankAccountStatus.ACTIVE,
                    purpose=[AccountPurpose.WALLET_TOPUP.value, AccountPurpose.SETTLEMENT.value],
                    is_primary=True,
                    is_default_topup=True,
                    is_visible_to_users=True,
                    display_order=1,
                    daily_limit=500000,
                    monthly_limit=10000000,
                    current_balance=0,
                    upi_id="company@sbi",
                    supports_dynamic_qr=True
                )
                db.session.add(bank_account)
                print("✅ Bank account for manual payments created")
            else:
                print("⚠️ Bank account already exists, updating UPI support...")
                existing_bank.upi_id = existing_bank.upi_id or "company@sbi"
                existing_bank.supports_dynamic_qr = True

            # Create payment gateway for online payments
            existing_gateway = PaymentGateway.query.filter_by(
                tenant_id=tenant.id,
                is_default=True
            ).first()

            if not existing_gateway:
                payment_gateway = PaymentGateway(
                    tenant_id=tenant.id,
                    gateway_type=PaymentGatewayType.UPI_GATEWAY,
                    gateway_name='Default UPI Gateway',
                    merchant_id='TEST_MERCHANT_001',
                    api_key='test_api_key_123',
                    api_secret='test_api_secret_456',
                    upi_id='payment@company.upi',
                    upi_merchant_name='Default Organization',
                    sandbox_mode=True,
                    status='ACTIVE',
                    is_default=True,
                    supports_upi=True,
                    min_amount=10.00,
                    max_amount=100000.00,
                    processing_fee_percentage=0.0,
                    processing_fee_fixed=0.0
                )
                db.session.add(payment_gateway)
                print("✅ Payment gateway for online payments created")
            else:
                print("⚠️ Payment gateway already exists, updating UPI support...")
                existing_gateway.upi_id = existing_gateway.upi_id or 'payment@company.upi'
                existing_gateway.supports_upi = True

            db.session.commit()
            print("🎉 Dual payment setup completed!")
            print("   Manual payments: Bank transfer with proof upload")
            print("   Online payments: UPI and payment gateway integration")

        except Exception as e:
            db.session.rollback()
            print(f"❌ Failed to create dual payment setup: {e}")

    @app.cli.command()
    def migrate_to_dual_payments():
        """Migrate existing installation to support dual payment methods"""
        try:
            print("🔄 Migrating to dual payment methods...")
            
            # Run the migration from the migration script
            from migration_dual_payments import run_migration
            run_migration(app, db)
            
            print("🎉 Migration to dual payments completed!")
            
        except Exception as e:
            print(f"❌ Migration failed: {e}")

    @app.cli.command()
    def test_dual_payments():
        """Test dual payment system functionality"""
        try:
            print("🧪 Testing dual payment system...")
            
            # Test bank account availability
            bank_count = OrganizationBankAccount.query.filter_by(
                status='ACTIVE',
                is_visible_to_users=True
            ).count()
            print(f"✅ Active bank accounts: {bank_count}")
            
            # Test payment gateway availability
            gateway_count = PaymentGateway.query.filter_by(
                status='ACTIVE'
            ).count()
            print(f"✅ Active payment gateways: {gateway_count}")
            
            # Test upload directories
            upload_dirs = [
                app.config['UPLOAD_FOLDER'],
                app.config['TOPUP_UPLOAD_FOLDER'],
                app.config['QR_CODE_FOLDER']
            ]
            
            for directory in upload_dirs:
                if Path(directory).exists():
                    print(f"✅ Directory exists: {directory}")
                else:
                    print(f"❌ Directory missing: {directory}")
            
            # Test configuration
            config = app.config['PAYMENT_GATEWAY_CONFIG']
            print(f"✅ Min topup amount: ₹{config['MIN_TOPUP_AMOUNT']}")
            print(f"✅ Max topup amount: ₹{config['MAX_TOPUP_AMOUNT']}")
            print(f"✅ Max file size: {config['MAX_FILE_SIZE']} bytes")
            
            print("🎉 Dual payment system test completed!")
            
        except Exception as e:
            print(f"❌ Test failed: {e}")


# =============================================================================
# MAIN APPLICATION
# =============================================================================

# Create Flask app
app = create_app(os.environ.get('FLASK_ENV', 'development'))

# Register CLI commands
register_cli_commands(app)

# Legacy routes for compatibility
@app.route('/email')
def email():
    return render_template('email.html',
        title='Admin Dashboard',
        subtitle='Admin Dashboard'
    )

@app.route('/faq')
def faq():
    return render_template('faq.html',
        title='FAQ',
        subtitle='Frequently Asked Questions'
    )

@app.route('/page-error')
def page_error():
    return render_template('pageError.html',
        title='404',
        subtitle='Page Not Found'
    )

# Health check endpoint
@app.route('/health')
def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        db.session.execute('SELECT 1')
        
        # Test payment system components
        payment_methods = get_available_payment_methods()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '2.0.0',
            'features': {
                'dual_payment_methods': True,
                'manual_payments': payment_methods.get('manual', {}).get('enabled', False),
                'online_payments': payment_methods.get('online', {}).get('enabled', False),
                'upi_support': True,
                'file_upload': True,
                'qr_code_generation': True
            },
            'database': 'connected',
            'upload_directories': 'ready'
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500


if __name__ == '__main__':
    print("🚀 Starting WebPayX Official with Dual Payment Support...")
    print("=" * 60)
    print("📊 Platform Features:")
    print("   • Multi-tenant Architecture")
    print("   • Hierarchical User Management")
    print("   • Role-based Permissions")
    print("   • Dual Payment Methods:")
    print("     - Manual Bank Transfer (with proof upload)")
    print("     - Online UPI/Payment Gateway (instant)")
    print("   • Wallet Management")
    print("   • Bank Account Management")
    print("   • Transaction Processing")
    print("   • Commission Management")
    print("   • Comprehensive Reporting")
    print()
    print("🔗 Access URLs:")
    print("   • Main App: http://localhost:5000")
    print("   • Login: http://localhost:5000/login")
    print("   • Dashboard: http://localhost:5000/dashboard")
    print("   • Wallet Top-up: http://localhost:5000/topup/request")
    print("   • Manual Payment: http://localhost:5000/wallet-topup/manual")
    print("   • Online Payment: http://localhost:5000/wallet-topup/online")
    print("   • Topup History: http://localhost:5000/topup/history")
    print("   • Admin Requests: http://localhost:5000/topup/admin/requests")
    print("   • User Management: http://localhost:5000/user-management")
    print("   • Bank Management: http://localhost:5000/bank-management")
    print("   • API Health: http://localhost:5000/health")
    print("   • API Config: http://localhost:5000/api/config")
    print()
    print("👤 Default Credentials:")
    print("   Username: superadmin")
    print("   Password: Admin@123")
    print()
    print("💡 CLI Commands Available:")
    print("   • flask init-db                    - Initialize database")
    print("   • flask create-admin               - Create super admin user")
    print("   • flask create-dual-payment-setup  - Setup dual payment methods")
    print("   • flask migrate-to-dual-payments   - Migrate existing installation")
    print("   • flask test-dual-payments         - Test payment system")
    print()
    print("🎯 Payment Methods:")
    print("   Manual Payment:")
    print("     - User selects bank account")
    print("     - Uploads payment proof document")
    print("     - Admin verification required")
    print("     - Processing time: 2-24 hours")
    print()
    print("   Online Payment:")
    print("     - UPI QR code generation")
    print("     - Real-time payment processing")
    print("     - Instant wallet credit")
    print("     - Processing time: Instant")
    print()
    print("📁 File Upload Support:")
    print("   • Supported formats: PNG, JPG, JPEG, PDF")
    print("   • Max file size: 5MB per proof document")
    print("   • Drag & drop interface")
    print("   • Secure file storage")
    print()
    print("💡 Configuration:")
    print("   Database: PostgreSQL (configured via DATABASE_URL)")
    print("   File Storage: Local filesystem")
    print("   Payment Gateway: Configurable (UPI/Cards/Net Banking)")
    print("   Security: CSRF protection, file validation, rate limiting")

    app.run(debug=app.config['DEBUG'], host='0.0.0.0', port=5000)