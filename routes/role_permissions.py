# routes/role_permissions.py
from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for
from flask_login import login_required, current_user
from models import (
    Permission, RolePermission, UserPermission, UserRoleType, 
    User, Tenant, db
)
from datetime import datetime
import uuid

role_permissions_bp = Blueprint('role_permissions', __name__, url_prefix='/role-permissions')

# =============================================================================
# PERMISSION MANAGEMENT PAGES
# =============================================================================

@role_permissions_bp.route('/')
@login_required
def index():
    """Role and permissions dashboard"""
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard.index'))
    
    return render_template('role_permissions/index.html',
        title='Role & Permissions',
        subtitle='Manage Roles and Permissions'
    )

@role_permissions_bp.route('/permissions')
@login_required
def permissions_page():
    """Permissions management page"""
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
        flash('Access denied', 'error')
        return redirect(url_for('role_permissions.index'))
    
    return render_template('role_permissions/permissions.html',
        title='Permissions',
        subtitle='Manage System Permissions'
    )

@role_permissions_bp.route('/role-config')
@login_required
def role_config_page():
    """Role configuration page"""
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
        flash('Access denied', 'error')
        return redirect(url_for('role_permissions.index'))
    
    return render_template('role_permissions/role_config.html',
        title='Role Configuration',
        subtitle='Configure Role Permissions'
    )

# =============================================================================
# PERMISSION CRUD API
# =============================================================================

@role_permissions_bp.route('/api/permissions', methods=['GET'])
@login_required
def get_permissions():
    """Get all permissions"""
    try:
        if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
            return jsonify({'error': 'Access denied'}), 403
        
        category = request.args.get('category')
        search = request.args.get('search', '')
        
        query = Permission.query
        
        if category:
            query = query.filter(Permission.category == category)
        
        if search:
            query = query.filter(
                db.or_(
                    Permission.name.ilike(f'%{search}%'),
                    Permission.description.ilike(f'%{search}%')
                )
            )
        
        permissions = query.order_by(Permission.category, Permission.name).all()
        
        # Group by category
        permissions_by_category = {}
        for permission in permissions:
            category = permission.category or 'GENERAL'
            if category not in permissions_by_category:
                permissions_by_category[category] = []
            permissions_by_category[category].append(permission.to_dict())
        
        return jsonify({
            'permissions': [p.to_dict() for p in permissions],
            'permissions_by_category': permissions_by_category,
            'total': len(permissions)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@role_permissions_bp.route('/api/permissions', methods=['POST'])
@login_required
def create_permission():
    """Create a new permission"""
    try:
        if current_user.role.value != 'SUPER_ADMIN':
            return jsonify({'error': 'Only super admin can create permissions'}), 403
        
        data = request.get_json()
        
        required_fields = ['name', 'description']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        # Check if permission already exists
        existing_permission = Permission.query.filter_by(name=data['name']).first()
        if existing_permission:
            return jsonify({'error': 'Permission already exists'}), 409
        
        permission = Permission(
            name=data['name'],
            description=data['description'],
            category=data.get('category', 'GENERAL'),
            is_system=data.get('is_system', False)
        )
        
        db.session.add(permission)
        db.session.commit()
        
        return jsonify({
            'message': 'Permission created successfully',
            'permission': permission.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@role_permissions_bp.route('/api/permissions/<permission_id>', methods=['PUT'])
@login_required
def update_permission(permission_id):
    """Update permission"""
    try:
        if current_user.role.value != 'SUPER_ADMIN':
            return jsonify({'error': 'Only super admin can update permissions'}), 403
        
        permission = Permission.query.get(permission_id)
        if not permission:
            return jsonify({'error': 'Permission not found'}), 404
        
        # Prevent updating system permissions
        if permission.is_system:
            return jsonify({'error': 'Cannot update system permissions'}), 400
        
        data = request.get_json()
        
        updatable_fields = ['description', 'category']
        for field in updatable_fields:
            if field in data:
                setattr(permission, field, data[field])
        
        permission.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'message': 'Permission updated successfully',
            'permission': permission.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@role_permissions_bp.route('/api/permissions/<permission_id>', methods=['DELETE'])
@login_required
def delete_permission(permission_id):
    """Delete permission"""
    try:
        if current_user.role.value != 'SUPER_ADMIN':
            return jsonify({'error': 'Only super admin can delete permissions'}), 403
        
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
            return jsonify({'error': 'Permission is in use and cannot be deleted'}), 400
        
        db.session.delete(permission)
        db.session.commit()
        
        return jsonify({'message': 'Permission deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# =============================================================================
# ROLE PERMISSIONS API
# =============================================================================

@role_permissions_bp.route('/api/role-permissions', methods=['GET'])
@login_required
def get_role_permissions():
    """Get role permissions"""
    try:
        if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
            return jsonify({'error': 'Access denied'}), 403
        
        role = request.args.get('role')
        tenant_id = request.args.get('tenant_id')
        
        query = RolePermission.query.join(Permission)
        
        if role:
            try:
                role_enum = UserRoleType(role.upper())
                query = query.filter(RolePermission.role == role_enum)
            except ValueError:
                return jsonify({'error': 'Invalid role specified'}), 400
        
        if tenant_id:
            query = query.filter(RolePermission.tenant_id == tenant_id)
        else:
            # Default to current user's tenant
            query = query.filter(RolePermission.tenant_id == current_user.tenant_id)
        
        role_permissions = query.order_by(Permission.category, Permission.name).all()
        
        # Group by role
        permissions_by_role = {}
        for rp in role_permissions:
            role_key = rp.role.value
            if role_key not in permissions_by_role:
                permissions_by_role[role_key] = []
            
            permission_data = rp.permission.to_dict()
            permission_data['is_granted'] = rp.is_granted
            permission_data['conditions'] = rp.conditions
            permissions_by_role[role_key].append(permission_data)
        
        return jsonify({
            'role_permissions': [
                {
                    'permission': rp.permission.to_dict(),
                    'role': rp.role.value,
                    'is_granted': rp.is_granted,
                    'conditions': rp.conditions
                } for rp in role_permissions
            ],
            'permissions_by_role': permissions_by_role,
            'total': len(role_permissions)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@role_permissions_bp.route('/api/role-permissions', methods=['POST'])
@login_required
def update_role_permissions():
    """Update role permissions"""
    try:
        if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        
        required_fields = ['role', 'permissions']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'{field} is required'}), 400
        
        try:
            role_enum = UserRoleType(data['role'].upper())
        except ValueError:
            return jsonify({'error': 'Invalid role specified'}), 400
        
        # Clear existing role permissions for this tenant and role
        RolePermission.query.filter(
            RolePermission.tenant_id == current_user.tenant_id,
            RolePermission.role == role_enum
        ).delete()
        
        # Add new permissions
        updated_count = 0
        for permission_data in data['permissions']:
            permission_id = permission_data.get('permission_id')
            is_granted = permission_data.get('is_granted', True)
            conditions = permission_data.get('conditions', {})
            
            if not permission_id:
                continue
            
            # Verify permission exists
            permission = Permission.query.get(permission_id)
            if not permission:
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
        
        return jsonify({
            'message': f'Updated {updated_count} permissions for role {role_enum.value}',
            'updated_count': updated_count
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# =============================================================================
# USER PERMISSIONS API
# =============================================================================

@role_permissions_bp.route('/api/user-permissions/<user_id>', methods=['GET'])
@login_required
def get_user_permissions(user_id):
    """Get user-specific permissions"""
    try:
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Check access permission
        if not current_user.can_access_user(user):
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
        
        # Combine permissions
        effective_permissions = {}
        
        # Add role permissions
        for rp in role_permissions:
            effective_permissions[rp.permission.name] = {
                'permission': rp.permission.to_dict(),
                'is_granted': True,
                'source': 'role',
                'conditions': rp.conditions
            }
        
        # Override with user-specific permissions
        for up in user_permissions:
            effective_permissions[up.permission.name] = {
                'permission': up.permission.to_dict(),
                'is_granted': up.is_granted,
                'source': 'user',
                'expires_at': up.expires_at.isoformat() if up.expires_at else None,
                'granted_by': str(up.granted_by) if up.granted_by else None
            }
        
        return jsonify({
            'user': {
                'id': str(user.id),
                'username': user.username,
                'full_name': user.full_name,
                'role': user.role.value
            },
            'effective_permissions': list(effective_permissions.values()),
            'role_permissions_count': len(role_permissions),
            'user_permissions_count': len(user_permissions)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@role_permissions_bp.route('/api/user-permissions/<user_id>', methods=['POST'])
@login_required
def update_user_permissions(user_id):
    """Update user-specific permissions"""
    try:
        if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
            return jsonify({'error': 'Access denied'}), 403
        
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Check access permission
        if not current_user.can_access_user(user):
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        permissions = data.get('permissions', [])
        
        # Remove existing user permissions
        UserPermission.query.filter_by(user_id=user_id).delete()
        
        updated_count = 0
        for permission_data in permissions:
            permission_id = permission_data.get('permission_id')
            is_granted = permission_data.get('is_granted', True)
            expires_at = permission_data.get('expires_at')
            
            if not permission_id:
                continue
            
            # Verify permission exists
            permission = Permission.query.get(permission_id)
            if not permission:
                continue
            
            user_permission = UserPermission(
                user_id=user_id,
                permission_id=permission_id,
                is_granted=is_granted,
                granted_by=current_user.id,
                expires_at=datetime.fromisoformat(expires_at) if expires_at else None
            )
            
            db.session.add(user_permission)
            updated_count += 1
        
        db.session.commit()
        
        return jsonify({
            'message': f'Updated {updated_count} user permissions',
            'updated_count': updated_count
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# =============================================================================
# PERMISSION CHECKING API
# =============================================================================

@role_permissions_bp.route('/api/check-permission', methods=['POST'])
@login_required
def check_permission():
    """Check if current user has specific permission"""
    try:
        data = request.get_json()
        permission_name = data.get('permission_name')
        
        if not permission_name:
            return jsonify({'error': 'Permission name is required'}), 400
        
        has_permission = has_user_permission(current_user, permission_name)
        
        return jsonify({
            'permission_name': permission_name,
            'has_permission': has_permission,
            'user_role': current_user.role.value
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
        
        if not permission_names:
            return jsonify({'error': 'Permission names are required'}), 400
        
        permissions_status = {}
        for permission_name in permission_names:
            permissions_status[permission_name] = has_user_permission(current_user, permission_name)
        
        return jsonify({
            'permissions': permissions_status,
            'user_role': current_user.role.value
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# ROLE CONFIGURATION API
# =============================================================================

@role_permissions_bp.route('/api/roles', methods=['GET'])
@login_required
def get_roles():
    """Get all available roles"""
    try:
        roles = []
        for role in UserRoleType:
            role_data = {
                'value': role.value,
                'name': role.value.replace('_', ' ').title(),
                'level': get_role_level(role)
            }
            roles.append(role_data)
        
        # Sort by level
        roles.sort(key=lambda x: x['level'])
        
        return jsonify({
            'roles': roles,
            'current_user_role': current_user.role.value
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@role_permissions_bp.route('/api/role-hierarchy', methods=['GET'])
@login_required
def get_role_hierarchy():
    """Get role hierarchy information"""
    try:
        hierarchy = {
            'SUPER_ADMIN': {
                'level': 0,
                'can_create': ['ADMIN', 'WHITE_LABEL'],
                'can_manage': ['ADMIN', 'WHITE_LABEL', 'MASTER_DISTRIBUTOR', 'DISTRIBUTOR', 'RETAILER'],
                'description': 'System super administrator with full access'
            },
            'ADMIN': {
                'level': 1,
                'can_create': ['MASTER_DISTRIBUTOR', 'DISTRIBUTOR', 'RETAILER'],
                'can_manage': ['MASTER_DISTRIBUTOR', 'DISTRIBUTOR', 'RETAILER'],
                'description': 'Organization administrator'
            },
            'WHITE_LABEL': {
                'level': 1,
                'can_create': ['MASTER_DISTRIBUTOR', 'DISTRIBUTOR', 'RETAILER'],
                'can_manage': ['MASTER_DISTRIBUTOR', 'DISTRIBUTOR', 'RETAILER'],
                'description': 'White label partner with admin rights'
            },
            'MASTER_DISTRIBUTOR': {
                'level': 2,
                'can_create': ['DISTRIBUTOR', 'RETAILER'],
                'can_manage': ['DISTRIBUTOR', 'RETAILER'],
                'description': 'Master distributor managing distributors and retailers'
            },
            'DISTRIBUTOR': {
                'level': 3,
                'can_create': ['RETAILER'],
                'can_manage': ['RETAILER'],
                'description': 'Distributor managing retailers'
            },
            'RETAILER': {
                'level': 4,
                'can_create': [],
                'can_manage': [],
                'description': 'End user providing services to customers'
            }
        }
        
        return jsonify({
            'hierarchy': hierarchy,
            'current_user_role': current_user.role.value,
            'current_user_level': hierarchy[current_user.role.value]['level']
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# PERMISSION TEMPLATES
# =============================================================================

@role_permissions_bp.route('/api/permission-templates', methods=['GET'])
@login_required
def get_permission_templates():
    """Get pre-defined permission templates for roles"""
    try:
        if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
            return jsonify({'error': 'Access denied'}), 403
        
        templates = {
            'SUPER_ADMIN': [
                'USER_CREATE', 'USER_READ', 'USER_UPDATE', 'USER_DELETE',
                'TRANSACTION_READ', 'TRANSACTION_PROCESS', 'TRANSACTION_REFUND',
                'WALLET_READ', 'WALLET_CREDIT', 'WALLET_DEBIT', 'WALLET_TOPUP_APPROVE',
                'COMMISSION_SET', 'COMMISSION_VIEW',
                'REPORT_VIEW', 'REPORT_EXPORT',
                'SYSTEM_CONFIG', 'BANK_ACCOUNT_MANAGE', 'PAYMENT_GATEWAY_MANAGE'
            ],
            'ADMIN': [
                'USER_CREATE', 'USER_READ', 'USER_UPDATE',
                'TRANSACTION_READ', 'TRANSACTION_PROCESS', 'TRANSACTION_REFUND',
                'WALLET_READ', 'WALLET_CREDIT', 'WALLET_DEBIT', 'WALLET_TOPUP_APPROVE',
                'COMMISSION_SET', 'COMMISSION_VIEW',
                'REPORT_VIEW', 'REPORT_EXPORT',
                'BANK_ACCOUNT_MANAGE'
            ],
            'WHITE_LABEL': [
                'USER_CREATE', 'USER_READ', 'USER_UPDATE',
                'TRANSACTION_READ', 'TRANSACTION_PROCESS',
                'WALLET_READ', 'WALLET_CREDIT', 'WALLET_TOPUP_APPROVE',
                'COMMISSION_VIEW',
                'REPORT_VIEW', 'REPORT_EXPORT'
            ],
            'MASTER_DISTRIBUTOR': [
                'USER_CREATE', 'USER_READ', 'USER_UPDATE',
                'TRANSACTION_READ',
                'WALLET_READ', 'WALLET_TOPUP_APPROVE',
                'COMMISSION_VIEW',
                'REPORT_VIEW'
            ],
            'DISTRIBUTOR': [
                'USER_CREATE', 'USER_READ',
                'TRANSACTION_READ',
                'WALLET_READ',
                'COMMISSION_VIEW',
                'REPORT_VIEW'
            ],
            'RETAILER': [
                'TRANSACTION_READ',
                'WALLET_READ',
                'REPORT_VIEW'
            ]
        }
        
        return jsonify({
            'templates': templates,
            'available_permissions': [p.name for p in Permission.query.all()]
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@role_permissions_bp.route('/api/apply-permission-template', methods=['POST'])
@login_required
def apply_permission_template():
    """Apply permission template to a role"""
    try:
        if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        role = data.get('role')
        template_name = data.get('template_name')
        
        if not role or not template_name:
            return jsonify({'error': 'Role and template name are required'}), 400
        
        try:
            role_enum = UserRoleType(role.upper())
        except ValueError:
            return jsonify({'error': 'Invalid role specified'}), 400
        
        # Get template permissions
        templates = {
            'BASIC': ['TRANSACTION_READ', 'WALLET_READ', 'REPORT_VIEW'],
            'STANDARD': ['USER_READ', 'TRANSACTION_READ', 'WALLET_READ', 'COMMISSION_VIEW', 'REPORT_VIEW'],
            'ADVANCED': ['USER_CREATE', 'USER_READ', 'USER_UPDATE', 'TRANSACTION_READ', 'WALLET_READ', 
                        'WALLET_TOPUP_APPROVE', 'COMMISSION_VIEW', 'REPORT_VIEW', 'REPORT_EXPORT'],
            'ADMIN': ['USER_CREATE', 'USER_READ', 'USER_UPDATE', 'TRANSACTION_READ', 'TRANSACTION_PROCESS',
                     'WALLET_READ', 'WALLET_CREDIT', 'WALLET_DEBIT', 'WALLET_TOPUP_APPROVE',
                     'COMMISSION_SET', 'COMMISSION_VIEW', 'REPORT_VIEW', 'REPORT_EXPORT']
        }
        
        permission_names = templates.get(template_name.upper(), [])
        if not permission_names:
            return jsonify({'error': 'Invalid template name'}), 400
        
        # Clear existing role permissions
        RolePermission.query.filter(
            RolePermission.tenant_id == current_user.tenant_id,
            RolePermission.role == role_enum
        ).delete()
        
        # Apply template permissions
        applied_count = 0
        for permission_name in permission_names:
            permission = Permission.query.filter_by(name=permission_name).first()
            if permission:
                role_permission = RolePermission(
                    role=role_enum,
                    permission_id=permission.id,
                    tenant_id=current_user.tenant_id,
                    is_granted=True
                )
                db.session.add(role_permission)
                applied_count += 1
        
        db.session.commit()
        
        return jsonify({
            'message': f'Applied {template_name} template to {role_enum.value}',
            'applied_count': applied_count,
            'total_permissions': len(permission_names)
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def has_user_permission(user, permission_name):
    """Check if user has specific permission"""
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
    """Get all effective permissions for a user"""
    try:
        permissions = set()
        
        # Get role permissions
        role_permissions = RolePermission.query.join(Permission).filter(
            RolePermission.tenant_id == user.tenant_id,
            RolePermission.role == user.role,
            RolePermission.is_granted == True
        ).all()
        
        for rp in role_permissions:
            permissions.add(rp.permission.name)
        
        # Get user-specific permissions
        user_permissions = UserPermission.query.join(Permission).filter(
            UserPermission.user_id == user.id
        ).all()
        
        for up in user_permissions:
            # Check if permission is expired
            if up.expires_at and up.expires_at < datetime.utcnow():
                continue
            
            if up.is_granted:
                permissions.add(up.permission.name)
            else:
                # User permission can revoke role permission
                permissions.discard(up.permission.name)
        
        return list(permissions)
        
    except Exception:
        return []

# =============================================================================
# PERMISSION DECORATOR
# =============================================================================

from functools import wraps

def require_permission(permission_name):
    """Decorator to require specific permission"""
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if not has_user_permission(current_user, permission_name):
                return jsonify({'error': f'Permission required: {permission_name}'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator