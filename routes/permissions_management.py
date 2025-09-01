# routes/permission_management.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from models import (
    db, Permission, RolePermission, UserPermission, User, UserRoleType, Tenant
)
from datetime import datetime
from functools import wraps
import uuid

permissions_management_bp = Blueprint('permissions_management', __name__, url_prefix='/permissions')



# Role-based access decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role not in [UserRoleType.SUPER_ADMIN, UserRoleType.ADMIN]:
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('main.dashboard'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != UserRoleType.SUPER_ADMIN:
            flash('Access denied. Super Admin privileges required.', 'error')
            return redirect(url_for('main.dashboard'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# ============================================================================
# PERMISSION MANAGEMENT ROUTES
# ============================================================================

@permissions_management_bp.route('/')
@login_required
@admin_required
def list_permissions():
    """List all permissions with search and filter capabilities"""
    search = request.args.get('search', '')
    category = request.args.get('category', '')
    page = request.args.get('page', 1, type=int)
    per_page = 15
    
    query = Permission.query
    
    if search:
        query = query.filter(
            db.or_(
                Permission.name.ilike(f'%{search}%'),
                Permission.description.ilike(f'%{search}%')
            )
        )
    
    if category:
        query = query.filter(Permission.category == category)
    
    permissions = query.order_by(Permission.category, Permission.name).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Get unique categories for filter dropdown
    categories = db.session.query(Permission.category).distinct().filter(
        Permission.category.isnot(None)
    ).all()
    categories = [cat[0] for cat in categories if cat[0]]
    
    return render_template('permissions/list.html', 
                         permissions=permissions, 
                         categories=categories,
                         search=search,
                         selected_category=category)

@permissions_management_bp.route('/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_permission():
    """Create new permission"""
    if request.method == 'POST':
        try:
            name = request.form.get('name', '').strip().upper()
            description = request.form.get('description', '').strip()
            category = request.form.get('category', '').strip()
            is_system = request.form.get('is_system') == 'on'
            
            # Validation
            if not name:
                flash('Permission name is required', 'error')
                return render_template('permissions/create.html')
            
            # Check if permission already exists
            if Permission.query.filter_by(name=name).first():
                flash('Permission with this name already exists', 'error')
                return render_template('permissions/create.html')
            
            # Create new permission
            permission = Permission(
                name=name,
                description=description,
                category=category,
                is_system=is_system
            )
            
            db.session.add(permission)
            db.session.commit()
            
            flash(f'Permission "{name}" created successfully', 'success')
            return redirect(url_for('permissions.list_permissions'))
            
        except Exception as e:
            db.session.rollback()
            flash('Error creating permission', 'error')
    
    return render_template('permissions/create.html')

@permissions_management_bp.route('/edit/<permission_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_permission(permission_id):
    """Edit existing permission"""
    permission = Permission.query.get_or_404(permission_id)
    
    if request.method == 'POST':
        try:
            permission.name = request.form.get('name', '').strip().upper()
            permission.description = request.form.get('description', '').strip()
            permission.category = request.form.get('category', '').strip()
            permission.is_system = request.form.get('is_system') == 'on'
            
            if not permission.name:
                flash('Permission name is required', 'error')
                return render_template('permissions/edit.html', permission=permission)
            
            db.session.commit()
            flash(f'Permission "{permission.name}" updated successfully', 'success')
            return redirect(url_for('permissions.list_permissions'))
            
        except Exception as e:
            db.session.rollback()
            flash('Error updating permission', 'error')
    
    return render_template('permissions/edit.html', permission=permission)

@permissions_management_bp.route('/delete/<permission_id>', methods=['POST'])
@login_required
@super_admin_required
def delete_permission(permission_id):
    """Delete permission (Super Admin only)"""
    try:
        permission = Permission.query.get_or_404(permission_id)
        
        # Check if permission is system permission
        if permission.is_system:
            flash('Cannot delete system permissions', 'error')
            return redirect(url_for('permissions.list_permissions'))
        
        # Check if permission is in use
        role_perms = RolePermission.query.filter_by(permission_id=permission_id).count()
        user_perms = UserPermission.query.filter_by(permission_id=permission_id).count()
        
        if role_perms > 0 or user_perms > 0:
            flash('Cannot delete permission that is currently assigned', 'error')
            return redirect(url_for('permissions.list_permissions'))
        
        db.session.delete(permission)
        db.session.commit()
        
        flash(f'Permission "{permission.name}" deleted successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash('Error deleting permission', 'error')
    
    return redirect(url_for('permissions.list_permissions'))

# ============================================================================
# ROLE PERMISSION MANAGEMENT ROUTES
# ============================================================================

@permissions_management_bp.route('/roles')
@login_required
@admin_required
def role_permissions():
    """Manage role-based permissions"""
    selected_role = request.args.get('role')
    
    if selected_role:
        try:
            role_enum = UserRoleType(selected_role)
        except ValueError:
            flash('Invalid role selected', 'error')
            return redirect(url_for('permissions.role_permissions'))
        
        # Get all permissions
        all_permissions = Permission.query.order_by(Permission.category, Permission.name).all()
        
        # Get current role permissions
        role_perms = {}
        for rp in RolePermission.query.filter_by(
            role=role_enum, 
            tenant_id=current_user.tenant_id
        ).all():
            role_perms[rp.permission_id] = rp.is_granted
        
        return render_template('permissions/role_permissions.html',
                             role=role_enum,
                             all_permissions=all_permissions,
                             role_perms=role_perms,
                             roles=UserRoleType)
    
    return render_template('permissions/role_permissions.html', roles=UserRoleType)

@permissions_management_bp.route('/roles/update', methods=['POST'])
@login_required
@admin_required
def update_role_permissions():
    """Update role permissions"""
    try:
        role = request.form.get('role')
        role_enum = UserRoleType(role)
        
        # Get all permission IDs from form
        granted_permissions = request.form.getlist('permissions')
        
        # Delete existing role permissions for this role and tenant
        RolePermission.query.filter_by(
            role=role_enum,
            tenant_id=current_user.tenant_id
        ).delete()
        
        # Add new permissions
        for perm_id in granted_permissions:
            role_perm = RolePermission(
                role=role_enum,
                permission_id=perm_id,
                tenant_id=current_user.tenant_id,
                is_granted=True
            )
            db.session.add(role_perm)
        
        db.session.commit()
        flash(f'Permissions updated for {role_enum.value} role', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash('Error updating role permissions', 'error')
    
    return redirect(url_for('permissions.role_permissions', role=role))

# ============================================================================
# USER PERMISSION MANAGEMENT ROUTES
# ============================================================================

@permissions_management_bp.route('/users')
@login_required
@admin_required
def user_permissions():
    """Manage user-specific permissions"""
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = 15
    
    query = User.query.filter_by(tenant_id=current_user.tenant_id)
    
    if search:
        query = query.filter(
            db.or_(
                User.full_name.ilike(f'%{search}%'),
                User.username.ilike(f'%{search}%'),
                User.email.ilike(f'%{search}%')
            )
        )
    
    users = query.order_by(User.full_name).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('permissions/user_permissions.html', 
                         users=users, 
                         search=search)

@permissions_management_bp.route('/users/<user_id>')
@login_required
@admin_required
def edit_user_permissions(user_id):
    """Edit specific user permissions"""
    user = User.query.filter_by(
        id=user_id, 
        tenant_id=current_user.tenant_id
    ).first_or_404()
    
    # Get all permissions
    all_permissions = Permission.query.order_by(Permission.category, Permission.name).all()
    
    # Get user's current permissions
    user_perms = {}
    for up in UserPermission.query.filter_by(user_id=user_id).all():
        user_perms[up.permission_id] = up.is_granted
    
    # Get role-based permissions for reference
    role_perms = {}
    for rp in RolePermission.query.filter_by(
        role=user.role,
        tenant_id=current_user.tenant_id
    ).all():
        role_perms[rp.permission_id] = rp.is_granted
    
    return render_template('permissions/edit_user_permissions.html',
                         user=user,
                         all_permissions=all_permissions,
                         user_perms=user_perms,
                         role_perms=role_perms)

@permissions_management_bp.route('/users/<user_id>/update', methods=['POST'])
@login_required
@admin_required
def update_user_permissions(user_id):
    """Update user-specific permissions"""
    try:
        user = User.query.filter_by(
            id=user_id,
            tenant_id=current_user.tenant_id
        ).first_or_404()
        
        # Delete existing user permissions
        UserPermission.query.filter_by(user_id=user_id).delete()
        
        # Add granted permissions
        granted_permissions = request.form.getlist('granted_permissions')
        denied_permissions = request.form.getlist('denied_permissions')
        
        for perm_id in granted_permissions:
            user_perm = UserPermission(
                user_id=user_id,
                permission_id=perm_id,
                is_granted=True,
                granted_by=current_user.id
            )
            db.session.add(user_perm)
        
        for perm_id in denied_permissions:
            user_perm = UserPermission(
                user_id=user_id,
                permission_id=perm_id,
                is_granted=False,
                granted_by=current_user.id
            )
            db.session.add(user_perm)
        
        db.session.commit()
        flash(f'Permissions updated for {user.full_name}', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash('Error updating user permissions', 'error')
    
    return redirect(url_for('permissions.user_permissions'))

# ============================================================================
# API ENDPOINTS FOR AJAX FUNCTIONALITY
# ============================================================================

@permissions_management_bp.route('/api/check/<permission_name>')
@login_required
def check_permission_api(permission_name):
    """API endpoint to check if current user has specific permission"""
    has_permission = check_user_permission(current_user.id, permission_name)
    return jsonify({'has_permission': has_permission})

def check_user_permission(user_id, permission_name):
    """Helper function to check user permission"""
    user = User.query.get(user_id)
    if not user:
        return False
    
    permission = Permission.query.filter_by(name=permission_name.upper()).first()
    if not permission:
        return False
    
    # Check user-specific permission first
    user_perm = UserPermission.query.filter_by(
        user_id=user_id,
        permission_id=permission.id
    ).first()
    
    if user_perm:
        return user_perm.is_granted
    
    # Check role-based permission
    role_perm = RolePermission.query.filter_by(
        role=user.role,
        permission_id=permission.id,
        tenant_id=user.tenant_id
    ).first()
    
    return role_perm.is_granted if role_perm else False
