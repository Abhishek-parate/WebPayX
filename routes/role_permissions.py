# routes/role_permissions.py
from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for, make_response
from flask_login import login_required, current_user
from models import (
    Permission, RolePermission, UserPermission, UserRoleType, 
    User, Tenant, db
)
from datetime import datetime, timedelta
from decimal import Decimal
import uuid
import json
import csv
import io
from functools import wraps
from sqlalchemy import and_, or_, desc, func

role_permissions_bp = Blueprint('role_permissions', __name__, url_prefix='/role-permissions')

# =============================================================================
# DECORATORS AND UTILITIES
# =============================================================================

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role.name not in ['SUPER_ADMIN', 'ADMIN']:
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role.name != 'SUPER_ADMIN':
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

def validate_permission_data(data, required_fields=None):
    """Validate permission data"""
    if required_fields is None:
        required_fields = ['name', 'description']
    
    errors = []
    for field in required_fields:
        if not data.get(field) or not str(data.get(field)).strip():
            errors.append(f'{field.replace("_", " ").title()} is required')
    
    # Validate permission name format
    if 'name' in data:
        name = data['name'].strip().upper()
        if not name.replace('_', '').isalnum():
            errors.append('Permission name must contain only letters, numbers, and underscores')
        if len(name) < 3 or len(name) > 50:
            errors.append('Permission name must be between 3 and 50 characters')
    
    return errors

# =============================================================================
# PERMISSION MANAGEMENT PAGES
# =============================================================================

@role_permissions_bp.route('/')
@login_required
@admin_required
def index():
    """Enhanced Role and permissions dashboard"""
    try:
        # Get comprehensive statistics
        total_permissions = Permission.query.count()
        system_permissions = Permission.query.filter_by(is_system=True).count()
        custom_permissions = total_permissions - system_permissions
        
        # Role permission assignments
        role_assignments = db.session.query(
            RolePermission.role,
            func.count(RolePermission.id).label('permission_count')
        ).filter_by(
            tenant_id=current_user.tenant_id,
            is_granted=True
        ).group_by(RolePermission.role).all()
        
        # User-specific permissions
        user_specific_permissions = UserPermission.query.join(User).filter(
            User.tenant_id == current_user.tenant_id
        ).count()
        
        # Recent permission activities
        recent_role_changes = RolePermission.query.filter_by(
            tenant_id=current_user.tenant_id
        ).order_by(desc(RolePermission.created_at)).limit(5).all()
        
        recent_user_changes = UserPermission.query.join(User).filter(
            User.tenant_id == current_user.tenant_id
        ).order_by(desc(UserPermission.created_at)).limit(5).all()
        
        # Permission categories
        categories = db.session.query(
            Permission.category,
            func.count(Permission.id).label('count')
        ).group_by(Permission.category).all()
        
        stats = {
            'total_permissions': total_permissions,
            'system_permissions': system_permissions,
            'custom_permissions': custom_permissions,
            'role_assignments': {str(ra.role.value): ra.permission_count for ra in role_assignments},
            'user_specific_permissions': user_specific_permissions,
            'recent_role_changes': recent_role_changes,
            'recent_user_changes': recent_user_changes,
            'categories': {cat.category or 'GENERAL': cat.count for cat in categories}
        }
        
        return render_template('role_permissions/index.html',
            title='Role & Permissions Management',
            subtitle='Manage System Roles and Permissions',
            stats=stats
        )
        
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}', 'error')
        # Return safe dashboard with empty data
        empty_stats = {
            'total_permissions': 0,
            'system_permissions': 0,
            'custom_permissions': 0,
            'role_assignments': {},
            'user_specific_permissions': 0,
            'recent_role_changes': [],
            'recent_user_changes': [],
            'categories': {}
        }
        return render_template('role_permissions/index.html',
            title='Role & Permissions Management',
            subtitle='Manage System Roles and Permissions',
            stats=empty_stats
        )

@role_permissions_bp.route('/permissions')
@login_required
@admin_required
def permissions_page():
    """Enhanced permissions management page"""
    try:
        # Get filter parameters
        page = max(request.args.get('page', 1, type=int), 1)
        per_page = min(max(request.args.get('per_page', 20, type=int), 10), 100)
        category = request.args.get('category', '').strip()
        search = request.args.get('search', '').strip()
        permission_type = request.args.get('type', '').strip()  # system/custom
        
        # Base query
        query = Permission.query
        
        # Apply filters
        if category and category != 'all':
            query = query.filter(Permission.category == category)
        
        if search:
            search_pattern = f'%{search}%'
            query = query.filter(
                or_(
                    Permission.name.ilike(search_pattern),
                    Permission.description.ilike(search_pattern)
                )
            )
        
        if permission_type == 'system':
            query = query.filter(Permission.is_system == True)
        elif permission_type == 'custom':
            query = query.filter(Permission.is_system == False)
        
        # Execute query with pagination
        permissions = query.order_by(
            Permission.category,
            Permission.name
        ).paginate(
            page=page, per_page=per_page, error_out=False, max_per_page=100
        )
        
        # Get available categories
        categories = db.session.query(Permission.category).distinct().all()
        categories = [cat.category for cat in categories if cat.category]
        
        # Add usage statistics for each permission
        for permission in permissions.items:
            role_usage = RolePermission.query.filter_by(
                permission_id=permission.id,
                is_granted=True
            ).count()
            
            user_usage = UserPermission.query.filter_by(
                permission_id=permission.id,
                is_granted=True
            ).count()
            
            permission.role_usage_count = role_usage
            permission.user_usage_count = user_usage
            permission.total_usage = role_usage + user_usage
        
        return render_template('role_permissions/permissions.html',
            title='Permissions Management',
            subtitle='Manage System Permissions',
            permissions=permissions,
            categories=categories,
            current_category=category,
            current_search=search,
            current_type=permission_type
        )
        
    except Exception as e:
        flash(f'Error loading permissions: {str(e)}', 'error')
        return redirect(url_for('role_permissions.index'))

@role_permissions_bp.route('/role-config')
@login_required
@admin_required
def role_config_page():
    """Enhanced role configuration page"""
    try:
        role_filter = request.args.get('role', '').strip()
        
        # Get all permissions grouped by category
        permissions_query = Permission.query.order_by(Permission.category, Permission.name)
        all_permissions = permissions_query.all()
        
        # Group permissions by category
        permissions_by_category = {}
        for permission in all_permissions:
            category = permission.category or 'GENERAL'
            if category not in permissions_by_category:
                permissions_by_category[category] = []
            permissions_by_category[category].append(permission)
        
        # Get current role permissions if role is selected
        role_permissions = {}
        if role_filter:
            try:
                role_enum = UserRoleType[role_filter.upper()]
                role_perms = RolePermission.query.filter_by(
                    tenant_id=current_user.tenant_id,
                    role=role_enum
                ).all()
                role_permissions = {rp.permission_id: rp for rp in role_perms}
            except (KeyError, ValueError):
                flash(f'Invalid role: {role_filter}', 'warning')
        
        # Get role hierarchy information
        role_hierarchy = get_role_hierarchy()
        
        return render_template('role_permissions/role_config.html',
            title='Role Configuration',
            subtitle='Configure Role-Based Permissions',
            permissions_by_category=permissions_by_category,
            role_permissions=role_permissions,
            user_roles=UserRoleType,
            current_role=role_filter,
            role_hierarchy=role_hierarchy
        )
        
    except Exception as e:
        flash(f'Error loading role configuration: {str(e)}', 'error')
        return redirect(url_for('role_permissions.index'))

@role_permissions_bp.route('/user-permissions/<user_id>')
@login_required
@admin_required
def user_permissions_page(user_id):
    """User-specific permissions management page"""
    if not validate_uuid(user_id):
        flash('Invalid user ID', 'error')
        return redirect(url_for('role_permissions.index'))
    
    try:
        # Get user with tenant validation
        user = User.query.filter_by(id=user_id).first()
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('role_permissions.index'))
        
        # Check access permission
        if not can_manage_user(current_user, user):
            flash('Access denied', 'error')
            return redirect(url_for('role_permissions.index'))
        
        # Get user's effective permissions
        effective_permissions = get_user_effective_permissions(user)
        
        # Get all available permissions
        all_permissions = Permission.query.order_by(Permission.category, Permission.name).all()
        
        # Get user-specific permission overrides
        user_permission_overrides = UserPermission.query.filter_by(user_id=user_id).all()
        override_dict = {up.permission_id: up for up in user_permission_overrides}
        
        return render_template('role_permissions/user_permissions.html',
            title=f'User Permissions - {user.full_name}',
            subtitle='Manage User-Specific Permission Overrides',
            user=user,
            all_permissions=all_permissions,
            effective_permissions=effective_permissions,
            user_overrides=override_dict
        )
        
    except Exception as e:
        flash(f'Error loading user permissions: {str(e)}', 'error')
        return redirect(url_for('role_permissions.index'))

# =============================================================================
# PERMISSION CRUD API - ENHANCED
# =============================================================================

@role_permissions_bp.route('/api/permissions', methods=['GET'])
@login_required
@admin_required
def get_permissions():
    """Get all permissions with enhanced filtering"""
    try:
        # Get filter parameters
        category = request.args.get('category', '').strip()
        search = request.args.get('search', '').strip()
        permission_type = request.args.get('type', '').strip()
        include_usage = request.args.get('include_usage', 'false').lower() == 'true'
        
        # Base query
        query = Permission.query
        
        # Apply filters
        if category and category != 'all':
            query = query.filter(Permission.category == category)
        
        if search:
            search_pattern = f'%{search}%'
            query = query.filter(
                or_(
                    Permission.name.ilike(search_pattern),
                    Permission.description.ilike(search_pattern)
                )
            )
        
        if permission_type == 'system':
            query = query.filter(Permission.is_system == True)
        elif permission_type == 'custom':
            query = query.filter(Permission.is_system == False)
        
        permissions = query.order_by(Permission.category, Permission.name).all()
        
        # Prepare response data
        permissions_data = []
        permissions_by_category = {}
        
        for permission in permissions:
            perm_data = permission.to_dict()
            
            # Add usage statistics if requested
            if include_usage:
                role_usage = RolePermission.query.filter_by(
                    permission_id=permission.id,
                    is_granted=True
                ).count()
                
                user_usage = UserPermission.query.filter_by(
                    permission_id=permission.id,
                    is_granted=True
                ).count()
                
                perm_data['usage_stats'] = {
                    'role_assignments': role_usage,
                    'user_assignments': user_usage,
                    'total_usage': role_usage + user_usage
                }
            
            permissions_data.append(perm_data)
            
            # Group by category
            category_key = permission.category or 'GENERAL'
            if category_key not in permissions_by_category:
                permissions_by_category[category_key] = []
            permissions_by_category[category_key].append(perm_data)
        
        return jsonify({
            'success': True,
            'permissions': permissions_data,
            'permissions_by_category': permissions_by_category,
            'total': len(permissions_data),
            'categories': list(permissions_by_category.keys())
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@role_permissions_bp.route('/api/permissions', methods=['POST'])
@login_required
@super_admin_required
def create_permission():
    """Create a new permission with enhanced validation"""
    try:
        data = request.get_json()
        
        # Validate input data
        validation_errors = validate_permission_data(data)
        if validation_errors:
            return jsonify({'error': validation_errors[0]}), 400
        
        # Normalize permission name
        permission_name = data['name'].strip().upper().replace(' ', '_')
        
        # Check if permission already exists
        existing_permission = Permission.query.filter_by(name=permission_name).first()
        if existing_permission:
            return jsonify({'error': 'Permission with this name already exists'}), 409
        
        # Create permission
        permission = Permission(
            name=permission_name,
            description=data['description'].strip(),
            category=data.get('category', 'GENERAL').strip().upper(),
            is_system=data.get('is_system', False)
        )
        
        db.session.add(permission)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Permission created successfully',
            'permission': permission.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@role_permissions_bp.route('/api/permissions/<permission_id>', methods=['GET'])
@login_required
@admin_required
def get_permission(permission_id):
    """Get specific permission details"""
    if not validate_uuid(permission_id):
        return jsonify({'error': 'Invalid permission ID'}), 400
    
    try:
        permission = Permission.query.get(permission_id)
        if not permission:
            return jsonify({'error': 'Permission not found'}), 404
        
        # Get usage information
        role_assignments = RolePermission.query.filter_by(
            permission_id=permission.id,
            is_granted=True
        ).count()
        
        user_assignments = UserPermission.query.filter_by(
            permission_id=permission.id,
            is_granted=True
        ).count()
        
        # Get roles using this permission
        roles_using = db.session.query(RolePermission.role).filter_by(
            permission_id=permission.id,
            is_granted=True
        ).distinct().all()
        
        permission_data = permission.to_dict()
        permission_data['usage_stats'] = {
            'role_assignments': role_assignments,
            'user_assignments': user_assignments,
            'total_usage': role_assignments + user_assignments,
            'roles_using': [role.role.value for role in roles_using]
        }
        
        return jsonify({
            'success': True,
            'permission': permission_data
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@role_permissions_bp.route('/api/permissions/<permission_id>', methods=['PUT'])
@login_required
@super_admin_required
def update_permission(permission_id):
    """Update permission with enhanced validation"""
    if not validate_uuid(permission_id):
        return jsonify({'error': 'Invalid permission ID'}), 400
    
    try:
        permission = Permission.query.get(permission_id)
        if not permission:
            return jsonify({'error': 'Permission not found'}), 404
        
        # Prevent updating system permissions
        if permission.is_system:
            return jsonify({'error': 'Cannot update system permissions'}), 400
        
        data = request.get_json()
        
        # Validate updatable fields
        updatable_fields = ['description', 'category']
        for field in updatable_fields:
            if field in data and data[field] is not None:
                if field == 'description' and not data[field].strip():
                    return jsonify({'error': 'Description cannot be empty'}), 400
                setattr(permission, field, data[field].strip())
        
        permission.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Permission updated successfully',
            'permission': permission.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@role_permissions_bp.route('/api/permissions/<permission_id>', methods=['DELETE'])
@login_required
@super_admin_required
def delete_permission(permission_id):
    """Delete permission with enhanced validation"""
    if not validate_uuid(permission_id):
        return jsonify({'error': 'Invalid permission ID'}), 400
    
    try:
        permission = Permission.query.get(permission_id)
        if not permission:
            return jsonify({'error': 'Permission not found'}), 404
        
        # Prevent deleting system permissions
        if permission.is_system:
            return jsonify({'error': 'Cannot delete system permissions'}), 400
        
        # Check if permission is in use
        role_permissions_count = RolePermission.query.filter_by(permission_id=permission.id).count()
        user_permissions_count = UserPermission.query.filter_by(permission_id=permission.id).count()
        
        if role_permissions_count > 0 or user_permissions_count > 0:
            return jsonify({
                'error': f'Permission is in use by {role_permissions_count} roles and {user_permissions_count} users. Remove assignments first.'
            }), 400
        
        permission_name = permission.name
        db.session.delete(permission)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Permission "{permission_name}" deleted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# =============================================================================
# ROLE PERMISSIONS API - ENHANCED
# =============================================================================

@role_permissions_bp.route('/api/role-permissions', methods=['GET'])
@login_required
@admin_required
def get_role_permissions():
    """Get role permissions with enhanced filtering"""
    try:
        role = request.args.get('role', '').strip()
        tenant_id = request.args.get('tenant_id', '').strip()
        include_details = request.args.get('include_details', 'false').lower() == 'true'
        
        # Base query
        query = RolePermission.query.join(Permission)
        
        # Apply filters
        if role:
            try:
                role_enum = UserRoleType[role.upper()]
                query = query.filter(RolePermission.role == role_enum)
            except (KeyError, ValueError):
                return jsonify({'error': 'Invalid role specified'}), 400
        
        if tenant_id and validate_uuid(tenant_id):
            query = query.filter(RolePermission.tenant_id == tenant_id)
        else:
            # Default to current user's tenant
            query = query.filter(RolePermission.tenant_id == current_user.tenant_id)
        
        role_permissions = query.order_by(Permission.category, Permission.name).all()
        
        # Prepare response data
        permissions_by_role = {}
        role_permissions_data = []
        
        for rp in role_permissions:
            permission_data = rp.permission.to_dict()
            permission_data.update({
                'is_granted': rp.is_granted,
                'conditions': rp.conditions,
                'assigned_at': rp.created_at.isoformat() if rp.created_at else None
            })
            
            role_key = rp.role.value
            if role_key not in permissions_by_role:
                permissions_by_role[role_key] = {
                    'role': role_key,
                    'permissions': [],
                    'granted_count': 0,
                    'total_count': 0
                }
            
            permissions_by_role[role_key]['permissions'].append(permission_data)
            permissions_by_role[role_key]['total_count'] += 1
            if rp.is_granted:
                permissions_by_role[role_key]['granted_count'] += 1
            
            # Individual role permission data
            role_permission_data = {
                'id': str(rp.id),
                'permission': permission_data,
                'role': rp.role.value,
                'is_granted': rp.is_granted,
                'conditions': rp.conditions,
                'created_at': rp.created_at.isoformat() if rp.created_at else None
            }
            role_permissions_data.append(role_permission_data)
        
        return jsonify({
            'success': True,
            'role_permissions': role_permissions_data,
            'permissions_by_role': permissions_by_role,
            'total': len(role_permissions_data)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@role_permissions_bp.route('/api/role-permissions', methods=['POST'])
@login_required
@admin_required
def update_role_permissions():
    """Update role permissions with enhanced validation"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['role', 'permissions']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'{field} is required'}), 400
        
        # Validate role
        try:
            role_enum = UserRoleType[data['role'].upper()]
        except (KeyError, ValueError):
            return jsonify({'error': 'Invalid role specified'}), 400
        
        # Check if user can manage this role
        if not can_manage_role(current_user, role_enum):
            return jsonify({'error': f'Cannot manage permissions for role {role_enum.value}'}), 403
        
        # Clear existing role permissions for this tenant and role
        deleted_count = RolePermission.query.filter(
            RolePermission.tenant_id == current_user.tenant_id,
            RolePermission.role == role_enum
        ).delete()
        
        # Add new permissions
        updated_count = 0
        errors = []
        
        for permission_data in data['permissions']:
            permission_id = permission_data.get('permission_id')
            is_granted = permission_data.get('is_granted', True)
            conditions = permission_data.get('conditions', {})
            
            if not permission_id or not validate_uuid(permission_id):
                errors.append(f'Invalid permission ID: {permission_id}')
                continue
            
            # Verify permission exists
            permission = Permission.query.get(permission_id)
            if not permission:
                errors.append(f'Permission not found: {permission_id}')
                continue
            
            role_permission = RolePermission(
                role=role_enum,
                permission_id=permission_id,
                tenant_id=current_user.tenant_id,
                is_granted=is_granted,
                conditions=conditions
            )
            
            db.session.add(role_permission)
            updated_count += 1
        
        db.session.commit()
        
        response_data = {
            'success': True,
            'message': f'Updated {updated_count} permissions for role {role_enum.value}',
            'updated_count': updated_count,
            'deleted_count': deleted_count
        }
        
        if errors:
            response_data['warnings'] = errors
        
        return jsonify(response_data)
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# =============================================================================
# USER PERMISSIONS API - ENHANCED
# =============================================================================

@role_permissions_bp.route('/api/user-permissions/<user_id>', methods=['GET'])
@login_required
@admin_required
def get_user_permissions(user_id):
    """Get user-specific permissions with enhanced details"""
    if not validate_uuid(user_id):
        return jsonify({'error': 'Invalid user ID'}), 400
    
    try:
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Check access permission
        if not can_manage_user(current_user, user):
            return jsonify({'error': 'Access denied'}), 403
        
        # Get user's role permissions
        role_permissions = RolePermission.query.join(Permission).filter(
            RolePermission.tenant_id == user.tenant_id,
            RolePermission.role == user.role,
            RolePermission.is_granted == True
        ).all()
        
        # Get user-specific permission overrides
        user_permissions = UserPermission.query.join(Permission).filter(
            UserPermission.user_id == user_id
        ).all()
        
        # Combine and organize permissions
        effective_permissions = {}
        permission_sources = {}
        
        # Add role permissions
        for rp in role_permissions:
            perm_name = rp.permission.name
            effective_permissions[perm_name] = {
                'permission': rp.permission.to_dict(),
                'is_granted': True,
                'source': 'role',
                'conditions': rp.conditions,
                'inherited_from': user.role.value
            }
            permission_sources[perm_name] = 'role'
        
        # Override with user-specific permissions
        for up in user_permissions:
            perm_name = up.permission.name
            
            # Check if permission is expired
            is_expired = up.expires_at and up.expires_at < datetime.utcnow()
            
            effective_permissions[perm_name] = {
                'permission': up.permission.to_dict(),
                'is_granted': up.is_granted and not is_expired,
                'source': 'user',
                'expires_at': up.expires_at.isoformat() if up.expires_at else None,
                'granted_by': str(up.granted_by) if up.granted_by else None,
                'granted_at': up.created_at.isoformat() if up.created_at else None,
                'is_expired': is_expired
            }
            permission_sources[perm_name] = 'user_override'
        
        # Calculate statistics
        total_permissions = len(effective_permissions)
        granted_permissions = sum(1 for p in effective_permissions.values() if p['is_granted'])
        role_based_permissions = sum(1 for source in permission_sources.values() if source == 'role')
        user_overrides = sum(1 for source in permission_sources.values() if source == 'user_override')
        
        return jsonify({
            'success': True,
            'user': {
                'id': str(user.id),
                'username': user.username,
                'full_name': user.full_name,
                'email': user.email,
                'role': user.role.value,
                'is_active': user.is_active
            },
            'effective_permissions': list(effective_permissions.values()),
            'permission_summary': {
                'total_permissions': total_permissions,
                'granted_permissions': granted_permissions,
                'denied_permissions': total_permissions - granted_permissions,
                'role_based_permissions': role_based_permissions,
                'user_overrides': user_overrides
            },
            'role_permissions_count': len(role_permissions),
            'user_permissions_count': len(user_permissions)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@role_permissions_bp.route('/api/user-permissions/<user_id>', methods=['POST'])
@login_required
@admin_required
def update_user_permissions(user_id):
    """Update user-specific permissions with enhanced validation"""
    if not validate_uuid(user_id):
        return jsonify({'error': 'Invalid user ID'}), 400
    
    try:
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Check access permission
        if not can_manage_user(current_user, user):
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        permissions = data.get('permissions', [])
        
        # Remove existing user permissions
        deleted_count = UserPermission.query.filter_by(user_id=user_id).delete()
        
        updated_count = 0
        errors = []
        
        for permission_data in permissions:
            permission_id = permission_data.get('permission_id')
            is_granted = permission_data.get('is_granted', True)
            expires_at = permission_data.get('expires_at')
            
            if not permission_id or not validate_uuid(permission_id):
                errors.append(f'Invalid permission ID: {permission_id}')
                continue
            
            # Verify permission exists
            permission = Permission.query.get(permission_id)
            if not permission:
                errors.append(f'Permission not found: {permission_id}')
                continue
            
            # Parse expiration date
            expires_at_dt = None
            if expires_at:
                try:
                    expires_at_dt = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                    # Ensure expiration is in the future
                    if expires_at_dt <= datetime.utcnow():
                        errors.append(f'Expiration date must be in the future for permission: {permission.name}')
                        continue
                except ValueError:
                    errors.append(f'Invalid expiration date format for permission: {permission.name}')
                    continue
            
            user_permission = UserPermission(
                user_id=user_id,
                permission_id=permission_id,
                is_granted=is_granted,
                granted_by=current_user.id,
                expires_at=expires_at_dt
            )
            
            db.session.add(user_permission)
            updated_count += 1
        
        db.session.commit()
        
        response_data = {
            'success': True,
            'message': f'Updated {updated_count} user permissions',
            'updated_count': updated_count,
            'deleted_count': deleted_count
        }
        
        if errors:
            response_data['warnings'] = errors
        
        return jsonify(response_data)
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# =============================================================================
# PERMISSION CHECKING API - ENHANCED
# =============================================================================

@role_permissions_bp.route('/api/check-permission', methods=['POST'])
@login_required
def check_permission():
    """Check if current user has specific permission"""
    try:
        data = request.get_json()
        permission_name = data.get('permission_name', '').strip()
        
        if not permission_name:
            return jsonify({'error': 'Permission name is required'}), 400
        
        has_permission = has_user_permission(current_user, permission_name)
        
        return jsonify({
            'success': True,
            'permission_name': permission_name,
            'has_permission': has_permission,
            'user_role': current_user.role.value,
            'user_id': str(current_user.id)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@role_permissions_bp.route('/api/bulk-check-permissions', methods=['POST'])
@login_required
def bulk_check_permissions():
    """Check multiple permissions for current user"""
    try:
        data = request.get_json()
        permission_names = data.get('permission_names', [])
        
        if not permission_names or not isinstance(permission_names, list):
            return jsonify({'error': 'Permission names array is required'}), 400
        
        permissions_status = {}
        for permission_name in permission_names:
            if isinstance(permission_name, str) and permission_name.strip():
                permissions_status[permission_name] = has_user_permission(current_user, permission_name.strip())
        
        return jsonify({
            'success': True,
            'permissions': permissions_status,
            'user_role': current_user.role.value,
            'user_id': str(current_user.id),
            'checked_count': len(permissions_status)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@role_permissions_bp.route('/api/user/<user_id>/check-permission', methods=['POST'])
@login_required
@admin_required
def check_user_permission(user_id):
    """Check if specific user has permission"""
    if not validate_uuid(user_id):
        return jsonify({'error': 'Invalid user ID'}), 400
    
    try:
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Check access permission
        if not can_manage_user(current_user, user):
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        permission_name = data.get('permission_name', '').strip()
        
        if not permission_name:
            return jsonify({'error': 'Permission name is required'}), 400
        
        has_permission = has_user_permission(user, permission_name)
        
        return jsonify({
            'success': True,
            'user_id': str(user.id),
            'username': user.username,
            'permission_name': permission_name,
            'has_permission': has_permission,
            'user_role': user.role.value
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# ROLE CONFIGURATION API - ENHANCED
# =============================================================================

@role_permissions_bp.route('/api/roles', methods=['GET'])
@login_required
@admin_required
def get_roles():
    """Get all available roles with enhanced information"""
    try:
        include_stats = request.args.get('include_stats', 'false').lower() == 'true'
        
        roles = []
        for role in UserRoleType:
            role_data = {
                'value': role.value,
                'name': role.value.replace('_', ' ').title(),
                'level': get_role_level(role),
                'can_create': get_role_hierarchy()[role.value]['can_create'],
                'can_manage': get_role_hierarchy()[role.value]['can_manage'],
                'description': get_role_hierarchy()[role.value]['description']
            }
            
            # Add statistics if requested
            if include_stats:
                user_count = User.query.filter_by(
                    role=role,
                    tenant_id=current_user.tenant_id
                ).count()
                
                permission_count = RolePermission.query.filter_by(
                    role=role,
                    tenant_id=current_user.tenant_id,
                    is_granted=True
                ).count()
                
                role_data['stats'] = {
                    'user_count': user_count,
                    'permission_count': permission_count
                }
            
            roles.append(role_data)
        
        # Sort by level
        roles.sort(key=lambda x: x['level'])
        
        return jsonify({
            'success': True,
            'roles': roles,
            'current_user_role': current_user.role.value,
            'total_roles': len(roles)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@role_permissions_bp.route('/api/role-hierarchy', methods=['GET'])
@login_required
@admin_required
def get_role_hierarchy():
    """Get comprehensive role hierarchy information"""
    try:
        hierarchy = {
            'SUPER_ADMIN': {
                'level': 0,
                'can_create': ['ADMIN', 'WHITE_LABEL'],
                'can_manage': ['ADMIN', 'WHITE_LABEL', 'MASTER_DISTRIBUTOR', 'DISTRIBUTOR', 'RETAILER'],
                'description': 'System super administrator with full access to all features',
                'color': 'text-red-600',
                'icon': 'crown'
            },
            'ADMIN': {
                'level': 1,
                'can_create': ['MASTER_DISTRIBUTOR', 'DISTRIBUTOR', 'RETAILER'],
                'can_manage': ['MASTER_DISTRIBUTOR', 'DISTRIBUTOR', 'RETAILER'],
                'description': 'Organization administrator with management capabilities',
                'color': 'text-blue-600',
                'icon': 'shield-check'
            },
            'WHITE_LABEL': {
                'level': 1,
                'can_create': ['MASTER_DISTRIBUTOR', 'DISTRIBUTOR', 'RETAILER'],
                'can_manage': ['MASTER_DISTRIBUTOR', 'DISTRIBUTOR', 'RETAILER'],
                'description': 'White label partner with administrative rights',
                'color': 'text-purple-600',
                'icon': 'building-office'
            },
            'MASTER_DISTRIBUTOR': {
                'level': 2,
                'can_create': ['DISTRIBUTOR', 'RETAILER'],
                'can_manage': ['DISTRIBUTOR', 'RETAILER'],
                'description': 'Master distributor managing distributors and retailers',
                'color': 'text-green-600',
                'icon': 'user-group'
            },
            'DISTRIBUTOR': {
                'level': 3,
                'can_create': ['RETAILER'],
                'can_manage': ['RETAILER'],
                'description': 'Distributor managing retailers in their network',
                'color': 'text-yellow-600',
                'icon': 'user-plus'
            },
            'RETAILER': {
                'level': 4,
                'can_create': [],
                'can_manage': [],
                'description': 'End user providing services to customers',
                'color': 'text-gray-600',
                'icon': 'user'
            }
        }
        
        # Add current user context
        current_user_info = hierarchy.get(current_user.role.value, {})
        
        return jsonify({
            'success': True,
            'hierarchy': hierarchy,
            'current_user_role': current_user.role.value,
            'current_user_level': current_user_info.get('level', 999),
            'current_user_can_create': current_user_info.get('can_create', []),
            'current_user_can_manage': current_user_info.get('can_manage', [])
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# PERMISSION TEMPLATES - ENHANCED
# =============================================================================

@role_permissions_bp.route('/api/permission-templates', methods=['GET'])
@login_required
@admin_required
def get_permission_templates():
    """Get enhanced pre-defined permission templates"""
    try:
        # Define comprehensive permission templates
        templates = {
            'SUPER_ADMIN': {
                'name': 'Super Administrator',
                'description': 'Full system access with all permissions',
                'permissions': [
                    'USER_CREATE', 'USER_READ', 'USER_UPDATE', 'USER_DELETE',
                    'TRANSACTION_READ', 'TRANSACTION_PROCESS', 'TRANSACTION_REFUND', 'TRANSACTION_CANCEL',
                    'WALLET_READ', 'WALLET_CREDIT', 'WALLET_DEBIT', 'WALLET_TOPUP_APPROVE', 'WALLET_FREEZE',
                    'COMMISSION_SET', 'COMMISSION_VIEW', 'COMMISSION_MODIFY',
                    'REPORT_VIEW', 'REPORT_EXPORT', 'REPORT_CREATE',
                    'SYSTEM_CONFIG', 'BANK_ACCOUNT_MANAGE', 'PAYMENT_GATEWAY_MANAGE',
                    'ROLE_MANAGE', 'PERMISSION_MANAGE', 'AUDIT_VIEW'
                ],
                'category': 'ADMINISTRATIVE'
            },
            'ADMIN': {
                'name': 'Administrator',
                'description': 'Administrative access with user and transaction management',
                'permissions': [
                    'USER_CREATE', 'USER_READ', 'USER_UPDATE',
                    'TRANSACTION_READ', 'TRANSACTION_PROCESS', 'TRANSACTION_REFUND',
                    'WALLET_READ', 'WALLET_CREDIT', 'WALLET_DEBIT', 'WALLET_TOPUP_APPROVE',
                    'COMMISSION_SET', 'COMMISSION_VIEW',
                    'REPORT_VIEW', 'REPORT_EXPORT',
                    'BANK_ACCOUNT_MANAGE', 'PAYMENT_GATEWAY_VIEW'
                ],
                'category': 'ADMINISTRATIVE'
            },
            'WHITE_LABEL': {
                'name': 'White Label Partner',
                'description': 'Partner access with limited administrative capabilities',
                'permissions': [
                    'USER_CREATE', 'USER_READ', 'USER_UPDATE',
                    'TRANSACTION_READ', 'TRANSACTION_PROCESS',
                    'WALLET_READ', 'WALLET_CREDIT', 'WALLET_TOPUP_APPROVE',
                    'COMMISSION_VIEW',
                    'REPORT_VIEW', 'REPORT_EXPORT',
                    'PAYMENT_GATEWAY_VIEW'
                ],
                'category': 'PARTNER'
            },
            'MASTER_DISTRIBUTOR': {
                'name': 'Master Distributor',
                'description': 'Senior distributor with team management capabilities',
                'permissions': [
                    'USER_CREATE', 'USER_READ', 'USER_UPDATE',
                    'TRANSACTION_READ', 'TRANSACTION_VIEW_OWN',
                    'WALLET_READ', 'WALLET_TOPUP_REQUEST',
                    'COMMISSION_VIEW',
                    'REPORT_VIEW', 'REPORT_VIEW_OWN'
                ],
                'category': 'BUSINESS'
            },
            'DISTRIBUTOR': {
                'name': 'Distributor',
                'description': 'Distributor with limited user management',
                'permissions': [
                    'USER_CREATE', 'USER_READ',
                    'TRANSACTION_READ', 'TRANSACTION_VIEW_OWN',
                    'WALLET_READ', 'WALLET_TOPUP_REQUEST',
                    'COMMISSION_VIEW',
                    'REPORT_VIEW', 'REPORT_VIEW_OWN'
                ],
                'category': 'BUSINESS'
            },
            'RETAILER': {
                'name': 'Retailer',
                'description': 'Basic access for service operations',
                'permissions': [
                    'TRANSACTION_READ', 'TRANSACTION_VIEW_OWN', 'TRANSACTION_CREATE',
                    'WALLET_READ', 'WALLET_VIEW_OWN',
                    'REPORT_VIEW', 'REPORT_VIEW_OWN',
                    'SERVICE_USE'
                ],
                'category': 'OPERATIONAL'
            },
            
            # Additional template categories
            'BASIC_USER': {
                'name': 'Basic User',
                'description': 'Minimal permissions for basic operations',
                'permissions': [
                    'TRANSACTION_VIEW_OWN',
                    'WALLET_VIEW_OWN',
                    'REPORT_VIEW_OWN'
                ],
                'category': 'BASIC'
            },
            'FINANCIAL_ADMIN': {
                'name': 'Financial Administrator',
                'description': 'Financial operations and reporting access',
                'permissions': [
                    'TRANSACTION_READ', 'TRANSACTION_REFUND', 'TRANSACTION_RECONCILE',
                    'WALLET_READ', 'WALLET_CREDIT', 'WALLET_DEBIT',
                    'COMMISSION_VIEW', 'COMMISSION_SET',
                    'REPORT_VIEW', 'REPORT_EXPORT', 'REPORT_FINANCIAL',
                    'BANK_ACCOUNT_VIEW', 'SETTLEMENT_MANAGE'
                ],
                'category': 'FINANCIAL'
            },
            'SUPPORT_AGENT': {
                'name': 'Support Agent',
                'description': 'Customer support and assistance permissions',
                'permissions': [
                    'USER_READ', 'USER_UPDATE',
                    'TRANSACTION_READ', 'TRANSACTION_VIEW_DETAILS',
                    'WALLET_READ', 'WALLET_TOPUP_APPROVE',
                    'SUPPORT_TICKET_MANAGE', 'REFUND_REQUEST',
                    'REPORT_VIEW'
                ],
                'category': 'SUPPORT'
            }
        }
        
        # Get available permissions for validation
        available_permissions = [p.name for p in Permission.query.all()]
        
        # Filter templates based on current user's role
        accessible_templates = {}
        user_level = get_role_level(current_user.role)
        
        for template_key, template_data in templates.items():
            # Only show templates for roles the current user can manage
            if template_key in ['SUPER_ADMIN'] and current_user.role.name != 'SUPER_ADMIN':
                continue
            
            accessible_templates[template_key] = template_data
        
        return jsonify({
            'success': True,
            'templates': accessible_templates,
            'available_permissions': available_permissions,
            'template_categories': list(set(t['category'] for t in accessible_templates.values())),
            'current_user_level': user_level
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@role_permissions_bp.route('/api/apply-permission-template', methods=['POST'])
@login_required
@admin_required
def apply_permission_template():
    """Apply permission template to a role with enhanced validation"""
    try:
        data = request.get_json()
        role = data.get('role', '').strip()
        template_name = data.get('template_name', '').strip()
        merge_mode = data.get('merge_mode', 'replace')  # replace or merge
        
        if not role or not template_name:
            return jsonify({'error': 'Role and template name are required'}), 400
        
        # Validate role
        try:
            role_enum = UserRoleType[role.upper()]
        except (KeyError, ValueError):
            return jsonify({'error': 'Invalid role specified'}), 400
        
        # Check if user can manage this role
        if not can_manage_role(current_user, role_enum):
            return jsonify({'error': f'Cannot manage permissions for role {role_enum.value}'}), 403
        
        # Get template data
        templates_response = get_permission_templates()
        if templates_response[1] != 200:  # Check status code
            return jsonify({'error': 'Failed to load templates'}), 500
        
        templates_data = json.loads(templates_response[0].data)
        templates = templates_data.get('templates', {})
        
        if template_name not in templates:
            return jsonify({'error': 'Invalid template name'}), 400
        
        template = templates[template_name]
        permission_names = template.get('permissions', [])
        
        if not permission_names:
            return jsonify({'error': 'Template has no permissions defined'}), 400
        
        # Handle merge mode
        if merge_mode == 'replace':
            # Clear existing role permissions
            deleted_count = RolePermission.query.filter(
                RolePermission.tenant_id == current_user.tenant_id,
                RolePermission.role == role_enum
            ).delete()
        else:
            deleted_count = 0
        
        # Apply template permissions
        applied_count = 0
        skipped_count = 0
        errors = []
        
        for permission_name in permission_names:
            permission = Permission.query.filter_by(name=permission_name).first()
            if not permission:
                errors.append(f'Permission not found: {permission_name}')
                skipped_count += 1
                continue
            
            # Check if permission already exists (for merge mode)
            if merge_mode == 'merge':
                existing = RolePermission.query.filter_by(
                    tenant_id=current_user.tenant_id,
                    role=role_enum,
                    permission_id=permission.id
                ).first()
                if existing:
                    skipped_count += 1
                    continue
            
            role_permission = RolePermission(
                role=role_enum,
                permission_id=permission.id,
                tenant_id=current_user.tenant_id,
                is_granted=True
            )
            db.session.add(role_permission)
            applied_count += 1
        
        db.session.commit()
        
        response_data = {
            'success': True,
            'message': f'Applied "{template["name"]}" template to {role_enum.value}',
            'template_applied': template_name,
            'template_description': template['description'],
            'applied_count': applied_count,
            'skipped_count': skipped_count,
            'total_permissions': len(permission_names),
            'merge_mode': merge_mode
        }
        
        if merge_mode == 'replace':
            response_data['deleted_count'] = deleted_count
        
        if errors:
            response_data['warnings'] = errors
        
        return jsonify(response_data)
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# =============================================================================
# EXPORT FUNCTIONALITY
# =============================================================================

@role_permissions_bp.route('/export/permissions')
@login_required
@admin_required
def export_permissions():
    """Export permissions data to CSV"""
    try:
        permissions = Permission.query.order_by(Permission.category, Permission.name).all()
        
        # Create CSV
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Permission Name', 'Description', 'Category', 'Is System',
            'Role Assignments', 'User Assignments', 'Total Usage',
            'Created At', 'Updated At'
        ])
        
        # Write data
        for permission in permissions:
            role_usage = RolePermission.query.filter_by(
                permission_id=permission.id,
                is_granted=True
            ).count()
            
            user_usage = UserPermission.query.filter_by(
                permission_id=permission.id,
                is_granted=True
            ).count()
            
            writer.writerow([
                permission.name,
                permission.description,
                permission.category or 'GENERAL',
                'Yes' if permission.is_system else 'No',
                role_usage,
                user_usage,
                role_usage + user_usage,
                permission.created_at.strftime('%Y-%m-%d %H:%M:%S') if permission.created_at else '',
                permission.updated_at.strftime('%Y-%m-%d %H:%M:%S') if permission.updated_at else ''
            ])
        
        # Prepare response
        output.seek(0)
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv; charset=utf-8'
        response.headers['Content-Disposition'] = f'attachment; filename="permissions_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv"'
        
        return response
        
    except Exception as e:
        flash(f'Error exporting permissions: {str(e)}', 'error')
        return redirect(url_for('role_permissions.permissions_page'))

@role_permissions_bp.route('/export/role-permissions')
@login_required
@admin_required
def export_role_permissions():
    """Export role permissions data to CSV"""
    try:
        role_permissions = RolePermission.query.join(Permission).filter(
            RolePermission.tenant_id == current_user.tenant_id
        ).order_by(RolePermission.role, Permission.name).all()
        
        # Create CSV
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Role', 'Permission Name', 'Permission Description', 'Is Granted',
            'Conditions', 'Created At'
        ])
        
        # Write data
        for rp in role_permissions:
            writer.writerow([
                rp.role.value,
                rp.permission.name,
                rp.permission.description,
                'Yes' if rp.is_granted else 'No',
                json.dumps(rp.conditions) if rp.conditions else '',
                rp.created_at.strftime('%Y-%m-%d %H:%M:%S') if rp.created_at else ''
            ])
        
        # Prepare response
        output.seek(0)
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv; charset=utf-8'
        response.headers['Content-Disposition'] = f'attachment; filename="role_permissions_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv"'
        
        return response
        
    except Exception as e:
        flash(f'Error exporting role permissions: {str(e)}', 'error')
        return redirect(url_for('role_permissions.role_config_page'))

# =============================================================================
# UTILITY FUNCTIONS - ENHANCED
# =============================================================================

def has_user_permission(user, permission_name):
    """Enhanced check if user has specific permission"""
    try:
        # Check user-specific permission first
        user_permission = UserPermission.query.join(Permission).filter(
            UserPermission.user_id == user.id,
            Permission.name == permission_name
        ).first()
        
        if user_permission:
            # Check if permission is expired
            if user_permission.expires_at and user_permission.expires_at < datetime.utcnow():
                return False
            return user_permission.is_granted
        
        # Check role permission
        role_permission = RolePermission.query.join(Permission).filter(
            RolePermission.tenant_id == user.tenant_id,
            RolePermission.role == user.role,
            Permission.name == permission_name,
            RolePermission.is_granted == True
        ).first()
        
        return role_permission is not None
        
    except Exception:
        return False

def get_role_level(role):
    """Get numeric level for role hierarchy"""
    levels = {
        UserRoleType.SUPER_ADMIN: 0,
        UserRoleType.ADMIN: 1,
        UserRoleType.WHITE_LABEL: 1,
        UserRoleType.MASTER_DISTRIBUTOR: 2,
        UserRoleType.DISTRIBUTOR: 3,
        UserRoleType.RETAILER: 4
    }
    return levels.get(role, 999)

def get_user_effective_permissions(user):
    """Get all effective permissions for a user with enhanced details"""
    try:
        permissions = {}
        
        # Get role permissions
        role_permissions = RolePermission.query.join(Permission).filter(
            RolePermission.tenant_id == user.tenant_id,
            RolePermission.role == user.role,
            RolePermission.is_granted == True
        ).all()
        
        for rp in role_permissions:
            permissions[rp.permission.name] = {
                'name': rp.permission.name,
                'description': rp.permission.description,
                'category': rp.permission.category,
                'is_granted': True,
                'source': 'role',
                'conditions': rp.conditions
            }
        
        # Get user-specific permissions (overrides)
        user_permissions = UserPermission.query.join(Permission).filter(
            UserPermission.user_id == user.id
        ).all()
        
        for up in user_permissions:
            # Check if permission is expired
            is_expired = up.expires_at and up.expires_at < datetime.utcnow()
            
            permissions[up.permission.name] = {
                'name': up.permission.name,
                'description': up.permission.description,
                'category': up.permission.category,
                'is_granted': up.is_granted and not is_expired,
                'source': 'user_override',
                'expires_at': up.expires_at,
                'granted_by': up.granted_by,
                'is_expired': is_expired
            }
        
        return list(permissions.values())
        
    except Exception:
        return []

def can_manage_user(manager, target_user):
    """Check if manager can manage target user"""
    try:
        manager_level = get_role_level(manager.role)
        target_level = get_role_level(target_user.role)
        
        # Super admins can manage everyone
        if manager.role.name == 'SUPER_ADMIN':
            return True
        
        # Users can only manage users in their tenant
        if manager.tenant_id != target_user.tenant_id:
            return False
        
        # Users can only manage users at lower levels
        return manager_level < target_level
        
    except Exception:
        return False

def can_manage_role(manager, target_role):
    """Check if manager can manage specific role"""
    try:
        hierarchy = get_role_hierarchy()
        manager_role_info = hierarchy.get(manager.role.value, {})
        
        return target_role.value in manager_role_info.get('can_manage', [])
        
    except Exception:
        return False

# =============================================================================
# PERMISSION DECORATOR - ENHANCED
# =============================================================================

def require_permission(permission_name, check_conditions=None):
    """Enhanced decorator to require specific permission with optional conditions"""
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if not has_user_permission(current_user, permission_name):
                if request.is_json:
                    return jsonify({'error': f'Permission required: {permission_name}'}), 403
                else:
                    flash(f'Permission required: {permission_name}', 'error')
                    return redirect(url_for('dashboard.index'))
            
            # Check additional conditions if provided
            if check_conditions and callable(check_conditions):
                if not check_conditions(current_user, *args, **kwargs):
                    if request.is_json:
                        return jsonify({'error': 'Access denied - conditions not met'}), 403
                    else:
                        flash('Access denied', 'error')
                        return redirect(url_for('dashboard.index'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_any_permission(*permission_names):
    """Decorator to require any one of the specified permissions"""
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            has_any_permission = any(
                has_user_permission(current_user, perm) for perm in permission_names
            )
            
            if not has_any_permission:
                permission_list = ', '.join(permission_names)
                if request.is_json:
                    return jsonify({'error': f'One of these permissions required: {permission_list}'}), 403
                else:
                    flash(f'Insufficient permissions', 'error')
                    return redirect(url_for('dashboard.index'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator
