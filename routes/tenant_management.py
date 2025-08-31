# routes/tenant_management.py
from flask import Blueprint, request, render_template, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user
from models import db, Tenant, User, UserRoleType
from datetime import datetime, timedelta
import secrets
import string

tenant_management_bp = Blueprint('tenant_management', __name__, url_prefix='/tenant-management')

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
        subdomain = ''.join(secrets.choice(characters) for _ in range(6))
        if not Tenant.query.filter_by(subdomain=subdomain).first():
            return subdomain

@tenant_management_bp.route('/')
@login_required
def index():
    """Tenant management dashboard"""
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
        flash('Access denied. Only Super Admins and Admins can manage tenants.', 'error')
        return redirect(url_for('dashboard.index'))
    
    # Get tenant statistics
    if current_user.role.value == 'SUPER_ADMIN':
        tenants = Tenant.query.all()
    else:
        # Admins can only see their own tenant
        tenants = [current_user.tenant] if current_user.tenant else []
    
    active_tenants = sum(1 for t in tenants if t.is_active)
    inactive_tenants = len(tenants) - active_tenants
    
    # Get recent tenants (last 10)
    recent_tenants = sorted(tenants, key=lambda x: x.created_at, reverse=True)[:10]
    
    return render_template('tenant_management/index.html',
        title='Tenant Management',
        subtitle='Manage White Label Tenants',
        tenants=tenants,
        recent_tenants=recent_tenants,
        active_count=active_tenants,
        inactive_count=inactive_tenants,
        total_count=len(tenants)
    )

@tenant_management_bp.route('/tenants')
@login_required
def list_tenants():
    """List all tenants"""
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard.index'))
    
    if current_user.role.value == 'SUPER_ADMIN':
        tenants = Tenant.query.order_by(Tenant.created_at.desc()).all()
    else:
        tenants = [current_user.tenant] if current_user.tenant else []
    
    return render_template('tenant_management/list.html',
        title='All Tenants',
        subtitle='Manage White Label Organizations',
        tenants=tenants
    )

@tenant_management_bp.route('/create-tenant', methods=['GET', 'POST'])
@login_required
def create_tenant():
    """Create new tenant"""
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
        flash('Access denied', 'error')
        return redirect(url_for('tenant_management.index'))
    
    if request.method == 'POST':
        try:
            # Get form data
            tenant_name = request.form.get('tenant_name').strip()
            domain = request.form.get('domain', '').strip()
            subscription_plan = request.form.get('subscription_plan', 'BASIC')
            subscription_months = int(request.form.get('subscription_months', 12))
            
            # Validation
            if not tenant_name:
                flash('Tenant name is required', 'error')
                return redirect(url_for('tenant_management.create_tenant'))
            
            if Tenant.query.filter_by(tenant_name=tenant_name).first():
                flash('Tenant name already exists', 'error')
                return redirect(url_for('tenant_management.create_tenant'))
            
            if domain and Tenant.query.filter_by(domain=domain).first():
                flash('Domain already exists', 'error')
                return redirect(url_for('tenant_management.create_tenant'))
            
            # Generate unique codes
            tenant_code = generate_tenant_code()
            subdomain = generate_subdomain()
            
            # Calculate subscription expiry
            subscription_expires_at = datetime.utcnow() + timedelta(days=30 * subscription_months)
            
            # Create tenant
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
                    'primary_color': '#3B82F6',
                    'secondary_color': '#10B981',
                    'logo_url': '',
                    'brand_name': tenant_name
                },
                api_settings={
                    'max_requests_per_minute': 1000,
                    'max_users': 10000,
                    'features_enabled': ['wallet', 'recharge', 'bill_payment']
                },
                rate_limits={
                    'transactions_per_minute': 100,
                    'api_calls_per_hour': 10000
                }
            )
            
            db.session.add(tenant)
            db.session.flush()  # Get the tenant ID
            
            # Create admin user for the tenant
            admin_full_name = request.form.get('admin_full_name', '').strip()
            admin_username = request.form.get('admin_username', '').strip()
            admin_email = request.form.get('admin_email', '').strip()
            admin_phone = request.form.get('admin_phone', '').strip()
            admin_password = request.form.get('admin_password', '').strip()
            
            if admin_full_name and admin_username and admin_email and admin_phone and admin_password:
                # Check if username/email/phone already exists
                if User.query.filter_by(username=admin_username).first():
                    flash('Username already exists', 'error')
                    return redirect(url_for('tenant_management.create_tenant'))
                
                if User.query.filter_by(email=admin_email).first():
                    flash('Email already exists', 'error')
                    return redirect(url_for('tenant_management.create_tenant'))
                
                if User.query.filter_by(phone=admin_phone).first():
                    flash('Phone number already exists', 'error')
                    return redirect(url_for('tenant_management.create_tenant'))
                
                # Generate user code
                user_count = User.query.filter_by(tenant_id=tenant.id).count()
                user_code = f"U{tenant_code}{user_count + 1:04d}"
                
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
                    settings={'created_by_super_admin': True}
                )
                admin_user.set_password(admin_password)
                admin_user.generate_api_key()
                
                db.session.add(admin_user)
            
            db.session.commit()
            
            flash(f'Tenant "{tenant_name}" created successfully with code: {tenant_code}', 'success')
            return redirect(url_for('tenant_management.view_tenant', tenant_id=tenant.id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating tenant: {str(e)}', 'error')
            return redirect(url_for('tenant_management.create_tenant'))
    
    return render_template('tenant_management/create.html',
        title='Create Tenant',
        subtitle='Create New White Label Organization'
    )

@tenant_management_bp.route('/tenant/<tenant_id>')
@login_required
def view_tenant(tenant_id):
    """View tenant details"""
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
        flash('Access denied', 'error')
        return redirect(url_for('tenant_management.index'))
    
    tenant = Tenant.query.get_or_404(tenant_id)
    
    # Check access rights
    if current_user.role.value == 'ADMIN' and str(current_user.tenant_id) != str(tenant_id):
        flash('Access denied', 'error')
        return redirect(url_for('tenant_management.index'))
    
    # Get tenant users
    users = User.query.filter_by(tenant_id=tenant.id).order_by(User.created_at.desc()).all()
    
    # Get tenant statistics
    total_users = len(users)
    active_users = sum(1 for u in users if u.is_active)
    admin_users = sum(1 for u in users if u.role == UserRoleType.ADMIN)
    
    return render_template('tenant_management/view.html',
        title=f'Tenant - {tenant.tenant_name}',
        subtitle=f'Code: {tenant.tenant_code}',
        tenant=tenant,
        users=users[:10],  # Show only first 10 users
        total_users=total_users,
        active_users=active_users,
        admin_users=admin_users
    )

@tenant_management_bp.route('/tenant/<tenant_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_tenant(tenant_id):
    """Edit tenant"""
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
        flash('Access denied', 'error')
        return redirect(url_for('tenant_management.index'))
    
    tenant = Tenant.query.get_or_404(tenant_id)
    
    # Check access rights
    if current_user.role.value == 'ADMIN' and str(current_user.tenant_id) != str(tenant_id):
        flash('Access denied', 'error')
        return redirect(url_for('tenant_management.index'))
    
    if request.method == 'POST':
        try:
            # Update basic info
            tenant.tenant_name = request.form.get('tenant_name', tenant.tenant_name)
            tenant.domain = request.form.get('domain') or None
            tenant.subscription_plan = request.form.get('subscription_plan', tenant.subscription_plan)
            
            # Update theme config
            if not tenant.theme_config:
                tenant.theme_config = {}
            
            tenant.theme_config.update({
                'primary_color': request.form.get('primary_color', '#3B82F6'),
                'secondary_color': request.form.get('secondary_color', '#10B981'),
                'brand_name': request.form.get('brand_name', tenant.tenant_name),
                'logo_url': request.form.get('logo_url', '')
            })
            
            # Update API settings
            if not tenant.api_settings:
                tenant.api_settings = {}
            
            tenant.api_settings.update({
                'max_requests_per_minute': int(request.form.get('max_requests_per_minute', 1000)),
                'max_users': int(request.form.get('max_users', 10000))
            })
            
            # Update rate limits
            if not tenant.rate_limits:
                tenant.rate_limits = {}
            
            tenant.rate_limits.update({
                'transactions_per_minute': int(request.form.get('transactions_per_minute', 100)),
                'api_calls_per_hour': int(request.form.get('api_calls_per_hour', 10000))
            })
            
            # Extend subscription if requested
            extend_months = request.form.get('extend_months')
            if extend_months and int(extend_months) > 0:
                if tenant.subscription_expires_at:
                    tenant.subscription_expires_at += timedelta(days=30 * int(extend_months))
                else:
                    tenant.subscription_expires_at = datetime.utcnow() + timedelta(days=30 * int(extend_months))
            
            tenant.updated_at = datetime.utcnow()
            
            db.session.commit()
            flash('Tenant updated successfully', 'success')
            return redirect(url_for('tenant_management.view_tenant', tenant_id=tenant.id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating tenant: {str(e)}', 'error')
    
    return render_template('tenant_management/edit.html',
        title=f'Edit Tenant - {tenant.tenant_name}',
        subtitle=f'Code: {tenant.tenant_code}',
        tenant=tenant
    )

@tenant_management_bp.route('/tenant/<tenant_id>/toggle-status', methods=['POST'])
@login_required
def toggle_tenant_status(tenant_id):
    """Toggle tenant active status"""
    if current_user.role.value != 'SUPER_ADMIN':
        flash('Access denied. Only Super Admins can change tenant status.', 'error')
        return redirect(url_for('tenant_management.index'))
    
    tenant = Tenant.query.get_or_404(tenant_id)
    
    try:
        tenant.is_active = not tenant.is_active
        tenant.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        status = 'activated' if tenant.is_active else 'deactivated'
        flash(f'Tenant "{tenant.tenant_name}" has been {status}', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating tenant status: {str(e)}', 'error')
    
    return redirect(url_for('tenant_management.view_tenant', tenant_id=tenant.id))

@tenant_management_bp.route('/tenant/<tenant_id>/users')
@login_required
def tenant_users(tenant_id):
    """View all tenant users"""
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
        flash('Access denied', 'error')
        return redirect(url_for('tenant_management.index'))
    
    tenant = Tenant.query.get_or_404(tenant_id)
    
    # Check access rights
    if current_user.role.value == 'ADMIN' and str(current_user.tenant_id) != str(tenant_id):
        flash('Access denied', 'error')
        return redirect(url_for('tenant_management.index'))
    
    users = User.query.filter_by(tenant_id=tenant.id).order_by(User.created_at.desc()).all()
    
    return render_template('tenant_management/users.html',
        title=f'Users - {tenant.tenant_name}',
        subtitle=f'Total Users: {len(users)}',
        tenant=tenant,
        users=users
    )
