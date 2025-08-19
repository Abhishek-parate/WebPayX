# app.py - Main Flask Application
import os
from flask import Flask, redirect, render_template, url_for, session, request, jsonify
from flask_login import LoginManager, current_user, login_required
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date
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

# Database and models
from models import db, User, UserSession, Tenant

# =============================================================================
# APP CONFIGURATION
# =============================================================================

def create_app(config_name='development'):
    """Application factory pattern"""
    
    # Check template folder
    template_folder = 'resource/views'
    if not os.path.exists(template_folder):
        template_folder = 'templates'
    
    app = Flask(__name__,
                template_folder=template_folder,
                static_folder=os.path.abspath('static'))
    
    # Configuration
    if config_name == 'production':
        app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 
            'postgresql://postgres:@localhost/saas_platform')
        app.config['DEBUG'] = False
    else:
        app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 
            'postgresql://postgres:1234@localhost:5432/saas_platform')
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
    # REGISTER BLUEPRINTS
    # =============================================================================
    
    # Core authentication and user management
    app.register_blueprint(authentication_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(logout_bp)
    
    # User management and hierarchy
    app.register_blueprint(user_bp)
    app.register_blueprint(membermanager_bp) 
    app.register_blueprint(memberreport_bp)
    app.register_blueprint(profilesetting_bp)
    
    # Wallet and financial services
    app.register_blueprint(wallettopup_bp)
    
    # Services and transactions  
    app.register_blueprint(selfservice_bp) 
    app.register_blueprint(selftransactionreport_bp)
    
    # Support and legal
    app.register_blueprint(complaint_bp)
    app.register_blueprint(privacypolicy_bp)
    app.register_blueprint(terms_condition_bp)
    
    # Admin and utility pages
    app.register_blueprint(chart_bp)
    app.register_blueprint(aiapplication_bp)
    app.register_blueprint(componentspage_bp)
    app.register_blueprint(forms_bp)
    app.register_blueprint(invoice_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(table_bp)

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
                'monthly_used': 0,
                'daily_remaining': 0,
                'monthly_remaining': 0
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
        
        # Safely get wallet statistics
        if hasattr(current_user, 'wallet') and current_user.wallet:
            wallet = current_user.wallet
            stats['wallet'] = {
                'balance': float(getattr(wallet, 'balance', 0)),
                'available_balance': float(getattr(wallet, 'balance', 0) - getattr(wallet, 'hold_balance', 0)),
                'daily_used': float(getattr(wallet, 'daily_used', 0)),
                'monthly_used': float(getattr(wallet, 'monthly_used', 0)),
                'daily_remaining': float(getattr(wallet, 'daily_limit', 0) - getattr(wallet, 'daily_used', 0)),
                'monthly_remaining': float(getattr(wallet, 'monthly_limit', 0) - getattr(wallet, 'monthly_used', 0))
            }
        
        return stats
        
    except Exception as e:
        print(f"Error getting dashboard stats: {e}")
        return stats

def get_user_permissions(user):
    """Get user's effective permissions based on role"""
    try:
        if not hasattr(user, 'role'):
            return []
        
        role_permissions = {
            'SUPER_ADMIN': [
                'create_users', 'manage_users', 'delete_users', 'view_all_users',
                'approve_topups', 'manage_bank_accounts', 'view_all_transactions'
            ],
            'ADMIN': [
                'create_users', 'manage_users', 'view_users', 
                'approve_topups', 'view_transactions'
            ],
            'WHITE_LABEL': [
                'create_distributors', 'manage_distributors',
                'approve_topups', 'view_transactions'
            ],
            'MASTER_DISTRIBUTOR': [
                'create_distributors', 'create_retailers', 
                'request_topups', 'view_transactions'
            ],
            'DISTRIBUTOR': [
                'create_retailers', 'request_topups', 'view_transactions'
            ],
            'RETAILER': [
                'request_topups', 'view_own_transactions'
            ]
        }
        
        role_value = getattr(user.role, 'value', 'RETAILER') if hasattr(user, 'role') else 'RETAILER'
        return role_permissions.get(role_value, [])
        
    except Exception:
        return []

def get_allowed_roles_for_creation(current_role):
    """Get roles that current user can create"""
    try:
        role_hierarchy = {
            'SUPER_ADMIN': ['ADMIN', 'WHITE_LABEL', 'MASTER_DISTRIBUTOR', 'DISTRIBUTOR', 'RETAILER'],
            'ADMIN': ['WHITE_LABEL', 'MASTER_DISTRIBUTOR', 'DISTRIBUTOR', 'RETAILER'],
            'WHITE_LABEL': ['MASTER_DISTRIBUTOR', 'DISTRIBUTOR', 'RETAILER'],
            'MASTER_DISTRIBUTOR': ['DISTRIBUTOR', 'RETAILER'],
            'DISTRIBUTOR': ['RETAILER'],
            'RETAILER': []
        }
        
        role_value = getattr(current_role, 'value', 'RETAILER') if hasattr(current_role, 'value') else 'RETAILER'
        return role_hierarchy.get(role_value, [])
        
    except Exception:
        return []

# =============================================================================
# CREATE WALLET_TOPUP BLUEPRINT
# =============================================================================

from flask import Blueprint

# Create the wallet_topup blueprint to handle the missing routes
wallet_topup_bp = Blueprint('wallet_topup', __name__, url_prefix='/wallet')

@wallet_topup_bp.route('/topup-request', methods=['GET', 'POST'])
@login_required
def topup_request():
    """Handle wallet topup requests"""
    if request.method == 'GET':
        return render_template('wallet/topup_request.html', 
                             title='Wallet Top-up Request')
    
    # Handle POST request for form submission
    try:
        # Get form data
        amount = request.form.get('amount')
        method = request.form.get('topup_method', 'MANUAL_TRANSFER')
        remarks = request.form.get('remarks', '')
        
        # Basic validation
        if not amount:
            return jsonify({'success': False, 'message': 'Amount is required'}), 400
        
        try:
            amount = float(amount)
            if amount <= 0:
                return jsonify({'success': False, 'message': 'Amount must be greater than zero'}), 400
        except ValueError:
            return jsonify({'success': False, 'message': 'Invalid amount'}), 400
        
        # For now, just return success (you can implement database logic later)
        return jsonify({
            'success': True, 
            'message': f'Top-up request for ₹{amount:,.2f} submitted successfully!',
            'request_id': f'TR{datetime.now().strftime("%Y%m%d%H%M%S")}'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

@wallet_topup_bp.route('/my-requests')
@login_required
def my_requests():
    """View user's topup requests"""
    # For now, return empty list (implement database logic later)
    mock_requests = {
        'items': [],
        'total': 0,
        'pages': 1,
        'page': 1,
        'per_page': 10,
        'has_prev': False,
        'has_next': False
    }
    
    return render_template('wallet/my_requests.html',
                         title='My Top-up Requests',
                         topup_requests=type('obj', (object,), mock_requests)())

@wallet_topup_bp.route('/pending-approvals')
@login_required
def pending_approvals():
    """View pending approvals (admin only)"""
    # Check if user can approve topups
    user_permissions = get_user_permissions(current_user)
    if 'approve_topups' not in user_permissions:
        return redirect(url_for('dashboard.index'))
    
    # For now, return empty list (implement database logic later)
    mock_requests = {
        'items': [],
        'total': 0,
        'pages': 1,
        'page': 1,
        'per_page': 10,
        'has_prev': False,
        'has_next': False
    }
    
    return render_template('wallet/pending_approvals.html',
                         title='Pending Approvals',
                         pending_requests=type('obj', (object,), mock_requests)())

@wallet_topup_bp.route('/all-requests')
@login_required
def all_requests():
    """View all requests (admin only)"""
    # Check if user can view all requests
    user_permissions = get_user_permissions(current_user)
    if 'approve_topups' not in user_permissions:
        return redirect(url_for('dashboard.index'))
    
    # For now, return empty list (implement database logic later)
    mock_requests = {
        'items': [],
        'total': 0,
        'pages': 1,
        'page': 1,
        'per_page': 20,
        'has_prev': False,
        'has_next': False
    }
    
    return render_template('wallet/all_requests.html',
                         title='All Top-up Requests',
                         all_requests=type('obj', (object,), mock_requests)())

@wallet_topup_bp.route('/api/pending-count')
@login_required
def api_pending_count():
    """Get count of pending requests"""
    try:
        # For now, return 0 (implement database logic later)
        return jsonify({'success': True, 'count': 0})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# =============================================================================
# MAIN APPLICATION
# =============================================================================

# Create Flask app
app = create_app(os.environ.get('FLASK_ENV', 'development'))

# Register the wallet_topup blueprint
app.register_blueprint(wallet_topup_bp)

# =============================================================================
# MAIN ROUTES
# =============================================================================

@app.route('/')
def index():
    """Homepage - redirect to login or dashboard"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    return redirect(url_for('authentication.login_page'))

@app.route('/main-dashboard')
@login_required
def main_dashboard():
    """Main dashboard with enhanced statistics"""
    user_stats = get_user_dashboard_stats()
    
    return render_template('dashboard/index.html',
        title='Dashboard',
        subtitle=f'Welcome, {getattr(current_user, "full_name", current_user.username)}',
        user_stats=user_stats
    )

# =============================================================================
# API ROUTES
# =============================================================================

@app.route('/api/user/profile')
@login_required
def get_user_profile():
    """Get current user profile"""
    try:
        user_data = {
            'id': current_user.id,
            'username': current_user.username,
            'full_name': getattr(current_user, 'full_name', ''),
            'email': getattr(current_user, 'email', ''),
            'phone': getattr(current_user, 'phone', ''),
            'role': getattr(getattr(current_user, 'role', None), 'value', 'UNKNOWN'),
            'is_active': getattr(current_user, 'is_active', True)
        }
        
        return jsonify({
            'success': True,
            'user': user_data,
            'permissions': get_user_permissions(current_user)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/dashboard/stats')
@login_required
def dashboard_stats():
    """Get dashboard statistics"""
    try:
        stats = get_user_dashboard_stats()
        return jsonify({'success': True, 'stats': stats})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

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
            'user_role': getattr(getattr(current_user, 'role', None), 'value', 'UNKNOWN')
        }
    return {}

@app.context_processor
def inject_global_data():
    """Inject global template data"""
    return {
        'app_name': 'SaaS Wallet Platform',
        'current_year': datetime.now().year,
        'app_version': '1.0.0'
    }

# =============================================================================
# ERROR HANDLERS (Simplified)
# =============================================================================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    if request.is_json:
        return jsonify({'error': 'Not found'}), 404
    
    # Return a simple HTML response if template doesn't exist
    return '''
    <html>
    <head><title>404 - Page Not Found</title></head>
    <body style="font-family: Arial, sans-serif; text-align: center; margin-top: 100px;">
        <h1>404 - Page Not Found</h1>
        <p>The page you are looking for doesn't exist.</p>
        <a href="/" style="color: blue;">Go Home</a> | 
        <a href="javascript:history.back()" style="color: blue;">Go Back</a>
    </body>
    </html>
    ''', 404

# Legacy routes for compatibility
@app.route('/email')
def email():
    return render_template('email.html',
        title='Admin Dashboard',
        subtitle='Admin Dashboard'
    )

@app.route('/page-error')
def pageError():
    return render_template('pageError.html',
        title='404',
        subtitle='404'
    )

if __name__ == '__main__':
    print("🚀 Starting SaaS Wallet Platform...")
    print("📊 Features Available:")
    print("   • Multi-tenant Architecture")
    print("   • Hierarchical User Management")
    print("   • Role-based Permissions")
    print("   • Wallet Management")
    print("   • Transaction Processing")
    print()
    print("🔗 Access URLs:")
    print("   • Main App: http://localhost:5000")
    print("   • Login: http://localhost:5000/login")
    print("   • Dashboard: http://localhost:5000/dashboard")
    print("   • Wallet Topup: http://localhost:5000/wallet/topup-request")
    print("   • My Requests: http://localhost:5000/wallet/my-requests")
    print()
    print("👤 Default Credentials (if created):")
    print("   Username: superadmin")
    print("   Password: Admin@123")
    print()
    
    app.run(debug=True, host='0.0.0.0', port=5000)
