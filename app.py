# app.py - Main Flask Application
import os
from datetime import datetime, date
from flask import Flask, redirect, render_template, url_for, session, request, jsonify
from flask_login import LoginManager, current_user, login_required
from flask_migrate import Migrate
from sqlalchemy import func

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
from routes.tenant_management import tenant_management_bp


# Import new enhanced routes
from routes.user_management import user_management_bp
from routes.enhanced_topup import enhanced_topup_bp
from routes.bank_management import bank_management_bp
from routes.role_permissions import role_permissions_bp

# Database and models
from models import db, User, UserSession, Tenant, create_tables, create_default_permissions


# =============================================================================
# APP CONFIGURATION
# =============================================================================
def create_app(config_name='development'):
    """Application factory pattern"""
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

    # Initialize extensions
    db.init_app(app)
    migrate = Migrate(app, db)

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
    app.register_blueprint(tenant_management_bp)


    # New enhanced routes (SINGLE REGISTRATION)
    app.register_blueprint(user_management_bp)
    app.register_blueprint(enhanced_topup_bp)  # This handles wallet functionality
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

    # Wallet route aliases for clean URLs
    @app.route('/wallet/')
    @login_required
    def wallet_index():
        """Wallet main page - redirect to enhanced topup request"""
        return redirect(url_for('enhanced_topup.topup_request_page'))

    @app.route('/wallet-topup')
    @login_required
    def wallet_topup():
        """Enhanced wallet top-up page"""
        return redirect(url_for('enhanced_topup.topup_request_page'))

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
                    'monthly_used': float(current_user.wallet.monthly_used)
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
                'permissions': get_user_permissions(current_user)
            })

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/dashboard/stats')
    @login_required
    def dashboard_stats():
        """Get dashboard statistics"""
        try:
            stats = get_user_dashboard_stats()
            return jsonify(stats)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

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
                'allowed_roles': get_allowed_roles_for_creation(current_user.role) if hasattr(current_user, 'role') else []
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

    return app


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_user_dashboard_stats():
    """Get dashboard statistics for current user"""
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

            # Pending topup requests
            from models import WalletTopupRequest, TransactionStatus
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

        # Recent activities (last 5)
        recent_transactions = Transaction.query.filter(
            Transaction.user_id == current_user.id
        ).order_by(Transaction.created_at.desc()).limit(5).all()

        for transaction in recent_transactions:
            stats['recent_activities'].append({
                'type': 'transaction',
                'description': f"{transaction.service_type.value} - ₹{transaction.amount}",
                'status': transaction.status.value,
                'created_at': transaction.created_at.isoformat()
            })

        # Add recent topup requests
        from models import WalletTopupRequest
        recent_topups = WalletTopupRequest.query.filter(
            WalletTopupRequest.user_id == current_user.id
        ).order_by(WalletTopupRequest.created_at.desc()).limit(3).all()

        for topup in recent_topups:
            stats['recent_activities'].append({
                'type': 'topup',
                'description': f"Wallet Top-up - ₹{topup.amount}",
                'status': topup.status.value,
                'created_at': topup.created_at.isoformat()
            })

        # Sort recent activities by date
        stats['recent_activities'].sort(key=lambda x: x['created_at'], reverse=True)
        stats['recent_activities'] = stats['recent_activities'][:5]

        return stats

    except Exception as e:
        print(f"Error getting dashboard stats: {e}")
        return {
            'wallet': {'balance': 0, 'available_balance': 0},
            'transactions': {'total': 0, 'today': 0, 'success_rate': 0},
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
    def create_bank_account():
        """Create a default bank account"""
        try:
            from models import OrganizationBankAccount, BankAccountType, BankAccountStatus, AccountPurpose

            tenant = Tenant.query.filter_by(tenant_code='DEFAULT').first()
            if not tenant:
                print("❌ Default tenant not found. Run 'flask init-db' first.")
                return

            # Check if bank account already exists
            existing_account = OrganizationBankAccount.query.filter_by(
                tenant_id=tenant.id
            ).first()

            if existing_account:
                print(f"⚠️  Bank account already exists: {existing_account.account_name}")
                return

            # Create default bank account
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
                current_balance=0
            )

            db.session.add(bank_account)
            db.session.commit()

            print("✅ Default bank account created successfully!")
            print(f"   Account Name: {bank_account.account_name}")
            print(f"   Account Number: {bank_account.account_number}")
            print(f"   IFSC Code: {bank_account.ifsc_code}")

        except Exception as e:
            db.session.rollback()
            print(f"❌ Failed to create bank account: {e}")


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


if __name__ == '__main__':
    print("🚀 Starting FinTech Platform...")
    print("📊 Features Available:")
    print("   • Multi-tenant Architecture")
    print("   • Hierarchical User Management")
    print("   • Role-based Permissions")
    print("   • Wallet Management with Top-up Requests")
    print("   • Bank Account Management")
    print("   • Transaction Processing")
    print("   • Commission Management")
    print("   • Comprehensive Reporting")
    print()
    print("🔗 Access URLs:")
    print("   • Main App: http://localhost:5000")
    print("   • Login: http://localhost:5000/login")
    print("   • Dashboard: http://localhost:5000/dashboard")
    print("   • Wallet: http://localhost:5000/wallet/")
    print("   • Wallet Top-up: http://localhost:5000/wallet-topup")
    print("   • User Management: http://localhost:5000/user-management")
    print("   • Bank Management: http://localhost:5000/bank-management")
    print("   • Role Permissions: http://localhost:5000/role-permissions")
    print()
    print("👤 Default Credentials:")
    print("   Username: superadmin")
    print("   Password: Admin@123")
    print()
    print("💡 CLI Commands Available:")
    print("   • flask init-db          - Initialize database")
    print("   • flask create-admin     - Create super admin user")
    print("   • flask create-bank-account - Create default bank account")
    print()
    print("💡 Note: Database connection via DATABASE_URL environment variable")
    print("   or default PostgreSQL connection string.")

    app.run(debug=True, host='0.0.0.0', port=5000)
