# routes/tenant_management.py
from flask import Blueprint, request, render_template, flash, redirect, url_for, jsonify, make_response
from flask_login import login_required, current_user
from models import db, Tenant, User, UserRoleType
from datetime import datetime, timedelta
from decimal import Decimal
import secrets
import string
import uuid
import json
import csv
import io
from functools import wraps
from sqlalchemy import and_, or_, desc, func

tenant_management_bp = Blueprint('tenant_management', __name__, url_prefix='/tenant-management')

# =============================================================================
# DECORATORS AND UTILITIES
# =============================================================================

def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role.name != 'SUPER_ADMIN':
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role.name not in ['SUPER_ADMIN', 'ADMIN']:
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def validate_uuid(uuid_string):
    """Validate UUID format"""
    try:
        uuid.UUID(uuid_string)
        return True
    except (ValueError, TypeError):
        return False

def generate_tenant_code():
    """Generate unique tenant code"""
    characters = string.ascii_uppercase + string.digits
    while True:
        code = ''.join(secrets.choice(characters) for _ in range(8))
        if not Tenant.query.filter_by(tenant_code=code).first():
            return code

def generate_subdomain():
    """Generate unique subdomain"""
    characters = string.ascii_lowercase + string.digits
    while True:
        subdomain = ''.join(secrets.choice(characters) for _ in range(8))
        if not Tenant.query.filter_by(subdomain=subdomain).first():
            return subdomain

def generate_user_code(tenant_code, user_count):
    """Generate unique user code"""
    return f"U{tenant_code}{user_count + 1:04d}"

# =============================================================================
# TENANT MANAGEMENT PAGES
# =============================================================================

@tenant_management_bp.route('/')
@login_required
@admin_required
def index():
    """Enhanced tenant management dashboard"""
    try:
        # Get tenant statistics based on user role
        if current_user.role.name == 'SUPER_ADMIN':
            tenants = Tenant.query.all()
        else:
            # Admins can only see their own tenant
            tenants = [current_user.tenant] if current_user.tenant else []
        
        # Calculate comprehensive statistics
        total_tenants = len(tenants)
        active_tenants = sum(1 for t in tenants if t.is_active)
        inactive_tenants = total_tenants - active_tenants
        
        # Subscription statistics
        expired_tenants = sum(1 for t in tenants 
                            if t.subscription_expires_at and t.subscription_expires_at < datetime.utcnow())
        expiring_soon = sum(1 for t in tenants 
                          if t.subscription_expires_at and 
                          t.subscription_expires_at < datetime.utcnow() + timedelta(days=30))
        
        # Subscription plan distribution
        plan_distribution = {}
        for tenant in tenants:
            plan = tenant.subscription_plan or 'BASIC'
            plan_distribution[plan] = plan_distribution.get(plan, 0) + 1
        
        # User statistics across all tenants
        total_users = 0
        active_users = 0
        if current_user.role.name == 'SUPER_ADMIN':
            total_users = User.query.count()
            active_users = User.query.filter_by(is_active=True).count()
        elif current_user.tenant:
            total_users = User.query.filter_by(tenant_id=current_user.tenant_id).count()
            active_users = User.query.filter_by(
                tenant_id=current_user.tenant_id, 
                is_active=True
            ).count()
        
        # Recent tenants (last 10)
        recent_tenants = sorted(tenants, key=lambda x: x.created_at or datetime.min, reverse=True)[:10]
        
        # Revenue calculation (simplified)
        monthly_revenue = 0
        for tenant in tenants:
            if tenant.subscription_plan == 'BASIC':
                monthly_revenue += 99
            elif tenant.subscription_plan == 'PREMIUM':
                monthly_revenue += 199
            elif tenant.subscription_plan == 'ENTERPRISE':
                monthly_revenue += 499
        
        stats = {
            'total_tenants': total_tenants,
            'active_tenants': active_tenants,
            'inactive_tenants': inactive_tenants,
            'expired_tenants': expired_tenants,
            'expiring_soon': expiring_soon,
            'plan_distribution': plan_distribution,
            'total_users': total_users,
            'active_users': active_users,
            'estimated_monthly_revenue': monthly_revenue,
            'recent_tenants': recent_tenants
        }
        
        return render_template('tenant_management/index.html',
            title='Tenant Management',
            subtitle='Manage White Label Organizations',
            stats=stats,
            tenants=tenants
        )
        
    except Exception as e:
        flash(f'Error loading tenant dashboard: {str(e)}', 'error')
        # Return safe dashboard with empty data
        empty_stats = {
            'total_tenants': 0, 'active_tenants': 0, 'inactive_tenants': 0,
            'expired_tenants': 0, 'expiring_soon': 0, 'plan_distribution': {},
            'total_users': 0, 'active_users': 0, 'estimated_monthly_revenue': 0,
            'recent_tenants': []
        }
        return render_template('tenant_management/index.html',
            title='Tenant Management',
            subtitle='Manage White Label Organizations',
            stats=empty_stats,
            tenants=[]
        )

@tenant_management_bp.route('/tenants')
@login_required
@admin_required
def list_tenants():
    """Enhanced list of all tenants with filtering and pagination"""
    try:
        # Get filter parameters
        page = max(request.args.get('page', 1, type=int), 1)
        per_page = min(max(request.args.get('per_page', 20, type=int), 10), 100)
        status_filter = request.args.get('status', '').strip()
        plan_filter = request.args.get('plan', '').strip()
        search = request.args.get('search', '').strip()
        sort_by = request.args.get('sort_by', 'created_at').strip()
        sort_order = request.args.get('sort_order', 'desc').strip()
        
        # Base query
        if current_user.role.name == 'SUPER_ADMIN':
            query = Tenant.query
        else:
            query = Tenant.query.filter_by(id=current_user.tenant_id)
        
        # Apply filters
        if status_filter:
            if status_filter == 'active':
                query = query.filter_by(is_active=True)
            elif status_filter == 'inactive':
                query = query.filter_by(is_active=False)
            elif status_filter == 'expired':
                query = query.filter(Tenant.subscription_expires_at < datetime.utcnow())
            elif status_filter == 'expiring_soon':
                query = query.filter(
                    Tenant.subscription_expires_at < datetime.utcnow() + timedelta(days=30),
                    Tenant.subscription_expires_at > datetime.utcnow()
                )
        
        if plan_filter and plan_filter != 'all':
            query = query.filter_by(subscription_plan=plan_filter)
        
        if search:
            search_pattern = f'%{search}%'
            query = query.filter(
                or_(
                    Tenant.tenant_name.ilike(search_pattern),
                    Tenant.tenant_code.ilike(search_pattern),
                    Tenant.domain.ilike(search_pattern)
                )
            )
        
        # Apply sorting
        if sort_by in ['tenant_name', 'created_at', 'subscription_expires_at']:
            sort_column = getattr(Tenant, sort_by)
            if sort_order == 'desc':
                sort_column = sort_column.desc()
            query = query.order_by(sort_column)
        else:
            query = query.order_by(desc(Tenant.created_at))
        
        # Execute query with pagination
        tenants = query.paginate(
            page=page, per_page=per_page, error_out=False, max_per_page=100
        )
        
        # Add user statistics for each tenant
        for tenant in tenants.items:
            user_count = User.query.filter_by(tenant_id=tenant.id).count()
            active_user_count = User.query.filter_by(
                tenant_id=tenant.id, 
                is_active=True
            ).count()
            
            tenant.user_count = user_count
            tenant.active_user_count = active_user_count
            
            # Check subscription status
            if tenant.subscription_expires_at:
                days_until_expiry = (tenant.subscription_expires_at - datetime.utcnow()).days
                tenant.days_until_expiry = max(days_until_expiry, 0)
                tenant.is_expired = days_until_expiry < 0
                tenant.is_expiring_soon = 0 <= days_until_expiry <= 30
            else:
                tenant.days_until_expiry = None
                tenant.is_expired = False
                tenant.is_expiring_soon = False
        
        return render_template('tenant_management/list.html',
            title='All Tenants',
            subtitle='Manage White Label Organizations',
            tenants=tenants,
            current_status=status_filter,
            current_plan=plan_filter,
            current_search=search,
            current_sort_by=sort_by,
            current_sort_order=sort_order
        )
        
    except Exception as e:
        flash(f'Error loading tenants: {str(e)}', 'error')
        return redirect(url_for('tenant_management.index'))

@tenant_management_bp.route('/create-tenant', methods=['GET', 'POST'])
@login_required
@super_admin_required
def create_tenant():
    """Enhanced tenant creation with comprehensive validation"""
    if request.method == 'POST':
        try:
            # Extract and validate form data
            tenant_name = request.form.get('tenant_name', '').strip()
            domain = request.form.get('domain', '').strip()
            subscription_plan = request.form.get('subscription_plan', 'BASIC').strip()
            subscription_months = max(int(request.form.get('subscription_months', 12)), 1)
            
            # Validate required fields
            validation_errors = []
            if not tenant_name:
                validation_errors.append('Tenant name is required')
            elif len(tenant_name) < 3:
                validation_errors.append('Tenant name must be at least 3 characters')
            elif len(tenant_name) > 100:
                validation_errors.append('Tenant name must be less than 100 characters')
            
            if validation_errors:
                for error in validation_errors:
                    flash(error, 'error')
                return render_template('tenant_management/create.html',
                    title='Create Tenant',
                    subtitle='Create New White Label Organization'
                )
            
            # Check for duplicates
            if Tenant.query.filter_by(tenant_name=tenant_name).first():
                flash('Tenant name already exists', 'error')
                return render_template('tenant_management/create.html',
                    title='Create Tenant',
                    subtitle='Create New White Label Organization'
                )
            
            if domain and Tenant.query.filter_by(domain=domain).first():
                flash('Domain already exists', 'error')
                return render_template('tenant_management/create.html',
                    title='Create Tenant',
                    subtitle='Create New White Label Organization'
                )
            
            # Generate unique identifiers
            tenant_code = generate_tenant_code()
            subdomain = generate_subdomain()
            
            # Calculate subscription expiry
            subscription_expires_at = datetime.utcnow() + timedelta(days=30 * subscription_months)
            
            # Create comprehensive tenant configuration
            tenant = Tenant(
                tenant_code=tenant_code,
                tenant_name=tenant_name,
                domain=domain if domain else None,
                subdomain=subdomain,
                subscription_plan=subscription_plan,
                subscription_expires_at=subscription_expires_at,
                is_active=True,
                created_by=current_user.id,
                theme_config={
                    'primary_color': request.form.get('primary_color', '#3B82F6'),
                    'secondary_color': request.form.get('secondary_color', '#10B981'),
                    'logo_url': request.form.get('logo_url', ''),
                    'brand_name': request.form.get('brand_name', tenant_name),
                    'favicon_url': request.form.get('favicon_url', ''),
                    'custom_css': request.form.get('custom_css', ''),
                    'footer_text': request.form.get('footer_text', f'© 2025 {tenant_name}')
                },
                api_settings={
                    'max_requests_per_minute': int(request.form.get('max_requests_per_minute', 1000)),
                    'max_users': int(request.form.get('max_users', 10000)),
                    'max_transactions_per_day': int(request.form.get('max_transactions_per_day', 50000)),
                    'features_enabled': request.form.getlist('features_enabled') or 
                                      ['wallet', 'recharge', 'bill_payment', 'money_transfer'],
                    'api_version': '1.0',
                    'webhook_url': request.form.get('webhook_url', ''),
                    'callback_url': request.form.get('callback_url', '')
                },
                rate_limits={
                    'transactions_per_minute': int(request.form.get('transactions_per_minute', 100)),
                    'api_calls_per_hour': int(request.form.get('api_calls_per_hour', 10000)),
                    'wallet_topup_per_day': int(request.form.get('wallet_topup_per_day', 10)),
                    'max_transaction_amount': Decimal(request.form.get('max_transaction_amount', '100000'))
                }
            )
            
            db.session.add(tenant)
            db.session.flush()  # Get the tenant ID
            
            # Create admin user for the tenant if details provided
            admin_full_name = request.form.get('admin_full_name', '').strip()
            admin_username = request.form.get('admin_username', '').strip()
            admin_email = request.form.get('admin_email', '').strip()
            admin_phone = request.form.get('admin_phone', '').strip()
            admin_password = request.form.get('admin_password', '').strip()
            
            admin_user = None
            if all([admin_full_name, admin_username, admin_email, admin_phone, admin_password]):
                # Validate admin user data
                if User.query.filter_by(username=admin_username).first():
                    flash('Username already exists', 'error')
                    db.session.rollback()
                    return render_template('tenant_management/create.html',
                        title='Create Tenant',
                        subtitle='Create New White Label Organization'
                    )
                
                if User.query.filter_by(email=admin_email).first():
                    flash('Email already exists', 'error')
                    db.session.rollback()
                    return render_template('tenant_management/create.html',
                        title='Create Tenant',
                        subtitle='Create New White Label Organization'
                    )
                
                if User.query.filter_by(phone=admin_phone).first():
                    flash('Phone number already exists', 'error')
                    db.session.rollback()
                    return render_template('tenant_management/create.html',
                        title='Create Tenant',
                        subtitle='Create New White Label Organization'
                    )
                
                # Generate user code
                user_count = User.query.filter_by(tenant_id=tenant.id).count()
                user_code = generate_user_code(tenant_code, user_count)
                
                admin_user = User(
                    tenant_id=tenant.id,
                    user_code=user_code,
                    username=admin_username,
                    email=admin_email,
                    phone=admin_phone,
                    full_name=admin_full_name,
                    role=UserRoleType.ADMIN,
                    is_active=True,
                    is_verified=True,
                    email_verified=True,
                    phone_verified=True,
                    created_by=current_user.id,
                    level=1,
                    tree_path=f"/{user_code}/",
                    settings={
                        'created_by_super_admin': True,
                        'initial_setup_completed': False,
                        'theme_preference': 'default'
                    }
                )
                admin_user.set_password(admin_password)
                admin_user.generate_api_key()
                
                db.session.add(admin_user)
            
            db.session.commit()
            
            success_message = f'Tenant "{tenant_name}" created successfully with code: {tenant_code}'
            if admin_user:
                success_message += f' and admin user "{admin_username}" created'
            
            flash(success_message, 'success')
            return redirect(url_for('tenant_management.view_tenant', tenant_id=tenant.id))
            
        except ValueError as e:
            db.session.rollback()
            flash(f'Invalid input data: {str(e)}', 'error')
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating tenant: {str(e)}', 'error')
    
    # GET request - show form with default values
    subscription_plans = ['BASIC', 'PREMIUM', 'ENTERPRISE']
    available_features = [
        'wallet', 'recharge', 'bill_payment', 'money_transfer', 
        'aeps', 'dmt', 'payout', 'cms', 'bbps'
    ]
    
    return render_template('tenant_management/create.html',
        title='Create Tenant',
        subtitle='Create New White Label Organization',
        subscription_plans=subscription_plans,
        available_features=available_features
    )

@tenant_management_bp.route('/tenant/<tenant_id>')
@login_required
@admin_required
def view_tenant(tenant_id):
    """Enhanced tenant details view"""
    if not validate_uuid(tenant_id):
        flash('Invalid tenant ID', 'error')
        return redirect(url_for('tenant_management.index'))
    
    try:
        tenant = Tenant.query.get(tenant_id)
        if not tenant:
            flash('Tenant not found', 'error')
            return redirect(url_for('tenant_management.index'))
        
        # Check access rights
        if (current_user.role.name == 'ADMIN' and 
            str(current_user.tenant_id) != str(tenant_id)):
            flash('Access denied', 'error')
            return redirect(url_for('tenant_management.index'))
        
        # Get comprehensive tenant statistics
        users = User.query.filter_by(tenant_id=tenant.id).order_by(
            User.created_at.desc()
        ).all()
        
        # User statistics by role
        user_stats_by_role = {}
        for role in UserRoleType:
            count = sum(1 for u in users if u.role == role)
            if count > 0:
                user_stats_by_role[role.value] = count
        
        # Activity statistics
        total_users = len(users)
        active_users = sum(1 for u in users if u.is_active)
        verified_users = sum(1 for u in users if u.is_verified)
        recent_users = users[:5]  # Last 5 users
        
        # Subscription information
        subscription_info = {
            'plan': tenant.subscription_plan or 'BASIC',
            'expires_at': tenant.subscription_expires_at,
            'is_expired': (tenant.subscription_expires_at < datetime.utcnow() 
                          if tenant.subscription_expires_at else False),
            'days_remaining': None
        }
        
        if tenant.subscription_expires_at:
            days_remaining = (tenant.subscription_expires_at - datetime.utcnow()).days
            subscription_info['days_remaining'] = max(days_remaining, 0)
            subscription_info['is_expiring_soon'] = 0 <= days_remaining <= 30
        
        # Feature usage statistics (placeholder)
        feature_usage = {
            'total_transactions': 0,  # Would come from transaction table
            'total_wallet_balance': 0,  # Would come from wallet table
            'api_calls_today': 0,  # Would come from api logs
            'active_services': len(tenant.api_settings.get('features_enabled', []))
        }
        
        stats = {
            'total_users': total_users,
            'active_users': active_users,
            'verified_users': verified_users,
            'user_stats_by_role': user_stats_by_role,
            'subscription_info': subscription_info,
            'feature_usage': feature_usage
        }
        
        return render_template('tenant_management/view.html',
            title=f'Tenant - {tenant.tenant_name}',
            subtitle=f'Code: {tenant.tenant_code}',
            tenant=tenant,
            users=recent_users,
            stats=stats
        )
        
    except Exception as e:
        flash(f'Error loading tenant details: {str(e)}', 'error')
        return redirect(url_for('tenant_management.index'))

@tenant_management_bp.route('/tenant/<tenant_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_tenant(tenant_id):
    """Enhanced tenant editing with comprehensive configuration"""
    if not validate_uuid(tenant_id):
        flash('Invalid tenant ID', 'error')
        return redirect(url_for('tenant_management.index'))
    
    try:
        tenant = Tenant.query.get(tenant_id)
        if not tenant:
            flash('Tenant not found', 'error')
            return redirect(url_for('tenant_management.index'))
        
        # Check access rights
        if (current_user.role.name == 'ADMIN' and 
            str(current_user.tenant_id) != str(tenant_id)):
            flash('Access denied', 'error')
            return redirect(url_for('tenant_management.index'))
        
        if request.method == 'POST':
            try:
                # Update basic information
                tenant.tenant_name = request.form.get('tenant_name', tenant.tenant_name).strip()
                new_domain = request.form.get('domain', '').strip()
                
                # Check domain uniqueness if changed
                if new_domain != tenant.domain:
                    if new_domain and Tenant.query.filter(
                        Tenant.domain == new_domain,
                        Tenant.id != tenant.id
                    ).first():
                        flash('Domain already exists', 'error')
                        return render_template('tenant_management/edit.html',
                            title=f'Edit Tenant - {tenant.tenant_name}',
                            subtitle=f'Code: {tenant.tenant_code}',
                            tenant=tenant
                        )
                    tenant.domain = new_domain or None
                
                # Update subscription (only super admin)
                if current_user.role.name == 'SUPER_ADMIN':
                    tenant.subscription_plan = request.form.get(
                        'subscription_plan', tenant.subscription_plan
                    )
                    
                    # Extend subscription if requested
                    extend_months = request.form.get('extend_months')
                    if extend_months and int(extend_months) > 0:
                        extension_days = 30 * int(extend_months)
                        if tenant.subscription_expires_at:
                            # Extend from current expiry or now, whichever is later
                            base_date = max(tenant.subscription_expires_at, datetime.utcnow())
                            tenant.subscription_expires_at = base_date + timedelta(days=extension_days)
                        else:
                            tenant.subscription_expires_at = datetime.utcnow() + timedelta(days=extension_days)
                
                # Update theme configuration
                if not tenant.theme_config:
                    tenant.theme_config = {}
                
                tenant.theme_config.update({
                    'primary_color': request.form.get('primary_color', '#3B82F6'),
                    'secondary_color': request.form.get('secondary_color', '#10B981'),
                    'brand_name': request.form.get('brand_name', tenant.tenant_name),
                    'logo_url': request.form.get('logo_url', ''),
                    'favicon_url': request.form.get('favicon_url', ''),
                    'custom_css': request.form.get('custom_css', ''),
                    'footer_text': request.form.get('footer_text', f'© 2025 {tenant.tenant_name}')
                })
                
                # Update API settings
                if not tenant.api_settings:
                    tenant.api_settings = {}
                
                tenant.api_settings.update({
                    'max_requests_per_minute': int(request.form.get('max_requests_per_minute', 1000)),
                    'max_users': int(request.form.get('max_users', 10000)),
                    'max_transactions_per_day': int(request.form.get('max_transactions_per_day', 50000)),
                    'features_enabled': request.form.getlist('features_enabled'),
                    'webhook_url': request.form.get('webhook_url', ''),
                    'callback_url': request.form.get('callback_url', '')
                })
                
                # Update rate limits
                if not tenant.rate_limits:
                    tenant.rate_limits = {}
                
                tenant.rate_limits.update({
                    'transactions_per_minute': int(request.form.get('transactions_per_minute', 100)),
                    'api_calls_per_hour': int(request.form.get('api_calls_per_hour', 10000)),
                    'wallet_topup_per_day': int(request.form.get('wallet_topup_per_day', 10)),
                    'max_transaction_amount': Decimal(request.form.get('max_transaction_amount', '100000'))
                })
                
                tenant.updated_at = datetime.utcnow()
                db.session.commit()
                
                flash('Tenant updated successfully', 'success')
                return redirect(url_for('tenant_management.view_tenant', tenant_id=tenant.id))
                
            except ValueError as e:
                db.session.rollback()
                flash(f'Invalid input data: {str(e)}', 'error')
            except Exception as e:
                db.session.rollback()
                flash(f'Error updating tenant: {str(e)}', 'error')
        
        # GET request - show edit form
        subscription_plans = ['BASIC', 'PREMIUM', 'ENTERPRISE']
        available_features = [
            'wallet', 'recharge', 'bill_payment', 'money_transfer', 
            'aeps', 'dmt', 'payout', 'cms', 'bbps'
        ]
        
        return render_template('tenant_management/edit.html',
            title=f'Edit Tenant - {tenant.tenant_name}',
            subtitle=f'Code: {tenant.tenant_code}',
            tenant=tenant,
            subscription_plans=subscription_plans,
            available_features=available_features
        )
        
    except Exception as e:
        flash(f'Error loading tenant for editing: {str(e)}', 'error')
        return redirect(url_for('tenant_management.index'))

@tenant_management_bp.route('/tenant/<tenant_id>/toggle-status', methods=['POST'])
@login_required
@super_admin_required
def toggle_tenant_status(tenant_id):
    """Toggle tenant active status with enhanced validation"""
    if not validate_uuid(tenant_id):
        return jsonify({'error': 'Invalid tenant ID'}), 400
    
    try:
        tenant = Tenant.query.get(tenant_id)
        if not tenant:
            return jsonify({'error': 'Tenant not found'}), 404
        
        old_status = tenant.is_active
        tenant.is_active = not tenant.is_active
        tenant.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        status_text = 'activated' if tenant.is_active else 'deactivated'
        
        if request.is_json:
            return jsonify({
                'success': True,
                'message': f'Tenant "{tenant.tenant_name}" has been {status_text}',
                'new_status': tenant.is_active,
                'tenant_name': tenant.tenant_name
            })
        else:
            flash(f'Tenant "{tenant.tenant_name}" has been {status_text}', 'success')
            return redirect(url_for('tenant_management.view_tenant', tenant_id=tenant.id))
        
    except Exception as e:
        db.session.rollback()
        error_msg = f'Error updating tenant status: {str(e)}'
        
        if request.is_json:
            return jsonify({'error': error_msg}), 500
        else:
            flash(error_msg, 'error')
            return redirect(url_for('tenant_management.view_tenant', tenant_id=tenant_id))

@tenant_management_bp.route('/tenant/<tenant_id>/users')
@login_required
@admin_required
def tenant_users(tenant_id):
    """Enhanced view of all tenant users with filtering"""
    if not validate_uuid(tenant_id):
        flash('Invalid tenant ID', 'error')
        return redirect(url_for('tenant_management.index'))
    
    try:
        tenant = Tenant.query.get(tenant_id)
        if not tenant:
            flash('Tenant not found', 'error')
            return redirect(url_for('tenant_management.index'))
        
        # Check access rights
        if (current_user.role.name == 'ADMIN' and 
            str(current_user.tenant_id) != str(tenant_id)):
            flash('Access denied', 'error')
            return redirect(url_for('tenant_management.index'))
        
        # Get filter parameters
        page = max(request.args.get('page', 1, type=int), 1)
        per_page = min(max(request.args.get('per_page', 20, type=int), 10), 100)
        role_filter = request.args.get('role', '').strip()
        status_filter = request.args.get('status', '').strip()
        search = request.args.get('search', '').strip()
        
        # Base query
        query = User.query.filter_by(tenant_id=tenant.id)
        
        # Apply filters
        if role_filter and role_filter != 'all':
            try:
                role_enum = UserRoleType[role_filter.upper()]
                query = query.filter_by(role=role_enum)
            except (KeyError, ValueError):
                flash(f'Invalid role filter: {role_filter}', 'warning')
        
        if status_filter:
            if status_filter == 'active':
                query = query.filter_by(is_active=True)
            elif status_filter == 'inactive':
                query = query.filter_by(is_active=False)
            elif status_filter == 'verified':
                query = query.filter_by(is_verified=True)
            elif status_filter == 'unverified':
                query = query.filter_by(is_verified=False)
        
        if search:
            search_pattern = f'%{search}%'
            query = query.filter(
                or_(
                    User.full_name.ilike(search_pattern),
                    User.username.ilike(search_pattern),
                    User.email.ilike(search_pattern),
                    User.phone.ilike(search_pattern)
                )
            )
        
        # Execute query with pagination
        users = query.order_by(desc(User.created_at)).paginate(
            page=page, per_page=per_page, error_out=False, max_per_page=100
        )
        
        # Calculate user statistics
        total_users = User.query.filter_by(tenant_id=tenant.id).count()
        active_users = User.query.filter_by(
            tenant_id=tenant.id, 
            is_active=True
        ).count()
        verified_users = User.query.filter_by(
            tenant_id=tenant.id, 
            is_verified=True
        ).count()
        
        user_stats = {
            'total_users': total_users,
            'active_users': active_users,
            'inactive_users': total_users - active_users,
            'verified_users': verified_users,
            'unverified_users': total_users - verified_users
        }
        
        return render_template('tenant_management/users.html',
            title=f'Users - {tenant.tenant_name}',
            subtitle=f'Total Users: {total_users}',
            tenant=tenant,
            users=users,
            user_stats=user_stats,
            user_roles=UserRoleType,
            current_role=role_filter,
            current_status=status_filter,
            current_search=search
        )
        
    except Exception as e:
        flash(f'Error loading tenant users: {str(e)}', 'error')
        return redirect(url_for('tenant_management.view_tenant', tenant_id=tenant_id))

# =============================================================================
# API ENDPOINTS
# =============================================================================

@tenant_management_bp.route('/api/tenants', methods=['GET'])
@login_required
@admin_required
def api_get_tenants():
    """API endpoint to get tenants list"""
    try:
        if current_user.role.name == 'SUPER_ADMIN':
            tenants = Tenant.query.all()
        else:
            tenants = [current_user.tenant] if current_user.tenant else []
        
        tenants_data = []
        for tenant in tenants:
            tenant_data = {
                'id': str(tenant.id),
                'tenant_code': tenant.tenant_code,
                'tenant_name': tenant.tenant_name,
                'domain': tenant.domain,
                'subdomain': tenant.subdomain,
                'subscription_plan': tenant.subscription_plan,
                'is_active': tenant.is_active,
                'created_at': tenant.created_at.isoformat() if tenant.created_at else None,
                'subscription_expires_at': tenant.subscription_expires_at.isoformat() if tenant.subscription_expires_at else None
            }
            tenants_data.append(tenant_data)
        
        return jsonify({
            'success': True,
            'tenants': tenants_data,
            'total': len(tenants_data)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@tenant_management_bp.route('/api/tenant/<tenant_id>/stats', methods=['GET'])
@login_required
@admin_required
def api_tenant_stats(tenant_id):
    """API endpoint to get tenant statistics"""
    if not validate_uuid(tenant_id):
        return jsonify({'error': 'Invalid tenant ID'}), 400
    
    try:
        tenant = Tenant.query.get(tenant_id)
        if not tenant:
            return jsonify({'error': 'Tenant not found'}), 404
        
        # Check access rights
        if (current_user.role.name == 'ADMIN' and 
            str(current_user.tenant_id) != str(tenant_id)):
            return jsonify({'error': 'Access denied'}), 403
        
        # Get tenant statistics
        total_users = User.query.filter_by(tenant_id=tenant.id).count()
        active_users = User.query.filter_by(
            tenant_id=tenant.id, 
            is_active=True
        ).count()
        
        stats = {
            'total_users': total_users,
            'active_users': active_users,
            'inactive_users': total_users - active_users,
            'subscription_plan': tenant.subscription_plan,
            'is_active': tenant.is_active,
            'subscription_expires_at': tenant.subscription_expires_at.isoformat() if tenant.subscription_expires_at else None
        }
        
        return jsonify({
            'success': True,
            'tenant_id': str(tenant.id),
            'tenant_name': tenant.tenant_name,
            'stats': stats
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# EXPORT FUNCTIONALITY
# =============================================================================

@tenant_management_bp.route('/export/tenants')
@login_required
@admin_required
def export_tenants():
    """Export tenants data to CSV"""
    try:
        if current_user.role.name == 'SUPER_ADMIN':
            tenants = Tenant.query.order_by(Tenant.tenant_name).all()
        else:
            tenants = [current_user.tenant] if current_user.tenant else []
        
        # Create CSV
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Tenant Code', 'Tenant Name', 'Domain', 'Subdomain', 
            'Subscription Plan', 'Status', 'Created At', 'Expires At',
            'Total Users', 'Active Users', 'Primary Color', 'Features Enabled'
        ])
        
        # Write data
        for tenant in tenants:
            user_count = User.query.filter_by(tenant_id=tenant.id).count()
            active_user_count = User.query.filter_by(
                tenant_id=tenant.id, 
                is_active=True
            ).count()
            
            features = ', '.join(tenant.api_settings.get('features_enabled', [])) if tenant.api_settings else ''
            primary_color = tenant.theme_config.get('primary_color', '') if tenant.theme_config else ''
            
            writer.writerow([
                tenant.tenant_code,
                tenant.tenant_name,
                tenant.domain or '',
                tenant.subdomain or '',
                tenant.subscription_plan or 'BASIC',
                'Active' if tenant.is_active else 'Inactive',  
                tenant.created_at.strftime('%Y-%m-%d %H:%M:%S') if tenant.created_at else '',
                tenant.subscription_expires_at.strftime('%Y-%m-%d') if tenant.subscription_expires_at else '',
                user_count,
                active_user_count,
                primary_color,
                features
            ])
        
        # Prepare response
        output.seek(0)
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv; charset=utf-8'
        response.headers['Content-Disposition'] = f'attachment; filename="tenants_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv"'
        
        return response
        
    except Exception as e:
        flash(f'Error exporting tenants: {str(e)}', 'error')
        return redirect(url_for('tenant_management.list_tenants'))

# =============================================================================
# BULK OPERATIONS
# =============================================================================

@tenant_management_bp.route('/bulk-actions', methods=['POST'])
@login_required
@super_admin_required
def bulk_actions():
    """Handle bulk actions on tenants"""
    try:
        tenant_ids = request.form.getlist('tenant_ids')
        action = request.form.get('action', '').strip()
        
        if not tenant_ids or not action:
            flash('Please select tenants and action', 'error')
            return redirect(url_for('tenant_management.list_tenants'))
        
        # Validate tenant IDs
        valid_ids = [tid for tid in tenant_ids if validate_uuid(tid)]
        if len(valid_ids) != len(tenant_ids):
            flash('Some tenant IDs are invalid', 'warning')
        
        tenants = Tenant.query.filter(Tenant.id.in_(valid_ids)).all()
        
        if not tenants:
            flash('No valid tenants found', 'error')
            return redirect(url_for('tenant_management.list_tenants'))
        
        updated_count = 0
        error_count = 0
        
        for tenant in tenants:
            try:
                if action == 'activate':
                    tenant.is_active = True
                    updated_count += 1
                elif action == 'deactivate':
                    tenant.is_active = False
                    updated_count += 1
                elif action == 'extend_subscription':
                    extend_days = int(request.form.get('extend_days', 30))
                    if tenant.subscription_expires_at:
                        base_date = max(tenant.subscription_expires_at, datetime.utcnow())
                        tenant.subscription_expires_at = base_date + timedelta(days=extend_days)
                    else:
                        tenant.subscription_expires_at = datetime.utcnow() + timedelta(days=extend_days)
                    updated_count += 1
                
                tenant.updated_at = datetime.utcnow()
                
            except Exception as e:
                error_count += 1
                continue
        
        db.session.commit()
        
        if updated_count > 0:
            flash(f'Successfully updated {updated_count} tenants', 'success')
        if error_count > 0:
            flash(f'{error_count} tenants failed to update', 'error')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error performing bulk action: {str(e)}', 'error')
    
    return redirect(url_for('tenant_management.list_tenants'))
