from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from models import Permission, RolePermission, db

permission_bp = Blueprint('permissions', __name__)

# ============================================
# CRUD for Permissions
# ============================================

@permission_bp.route('/permissions', methods=['POST'])
@login_required
def create_permission():
    """Create a permission"""
    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    permission = Permission(name=name, description=description)
    db.session.add(permission)
    db.session.commit()
    return jsonify({'message': 'Permission created', 'permission': permission.to_dict()})

@permission_bp.route('/permissions', methods=['GET'])
@login_required
def list_permissions():
    """List all permissions"""
    permissions = Permission.query.all()
    return jsonify({'permissions': [p.to_dict() for p in permissions]})

@permission_bp.route('/permissions/<int:permission_id>', methods=['PUT'])
@login_required
def update_permission(permission_id):
    """Update permission"""
    permission = Permission.query.get_or_404(permission_id)
    data = request.get_json()
    permission.name = data.get('name', permission.name)
    permission.description = data.get('description', permission.description)
    db.session.commit()
    return jsonify({'message': 'Permission updated', 'permission': permission.to_dict()})

@permission_bp.route('/permissions/<int:permission_id>', methods=['DELETE'])
@login_required
def delete_permission(permission_id):
    """Delete permission"""
    permission = Permission.query.get_or_404(permission_id)
    db.session.delete(permission)
    db.session.commit()
    return jsonify({'message': 'Permission deleted'})

# ============================================
# Role Permission Assignments
# ============================================

@permission_bp.route('/roles/<int:role_id>/permissions', methods=['POST'])
@login_required
def assign_permissions(role_id):
    """Assign permissions to a role"""
    data = request.get_json()
    permission_ids = data.get('permission_ids', [])
    # Implementation of assigning permissions to role
    for pid in permission_ids:
        role_permission = RolePermission(role_id=role_id, permission_id=pid)
        db.session.add(role_permission)
    db.session.commit()
    return jsonify({'message': 'Permissions assigned to role'})