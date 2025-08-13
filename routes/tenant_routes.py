from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from sqlalchemy import or_
from models import db, Tenant, OrganizationBankAccount
from datetime import datetime

tenant_bp = Blueprint('tenant', __name__)

# =============================================================================
# Tenant CRUD Operations
# =============================================================================

@tenant_bp.route('/tenants', methods=['POST'])
@login_required
def create_tenant():
    """Create a new tenant"""
    if not current_user.is_super_admin():
        return jsonify({'error': 'Permission denied'}), 403
    data = request.get_json()
    try:
        # Validate required fields
        required_fields = ['tenant_code', 'tenant_name', 'domain', 'subdomain']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        # Check existing tenant code or domain
        existing = Tenant.query.filter(
            or_(Tenant.tenant_code == data['tenant_code'], Tenant.domain == data['domain'])
        ).first()
        if existing:
            return jsonify({'error': 'Tenant code or domain already exists'}), 409

        # Create tenant object
        tenant = Tenant(
            tenant_code = data['tenant_code'],
            tenant_name = data['tenant_name'],
            domain = data['domain'],
            subdomain = data['subdomain'],
            is_active = data.get('is_active', True),
            theme_config = data.get('theme_config', {}),
            api_settings = data.get('api_settings', {}),
            created_at = datetime.utcnow(),
            updated_at = datetime.utcnow()
        )

        db.session.add(tenant)
        db.session.commit()

        return jsonify({'message': 'Tenant created', 'tenant': tenant.to_dict()}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@tenant_bp.route('/tenants/<tenant_id>', methods=['GET'])
@login_required
def get_tenant(tenant_id):
    """Retrieve tenant details"""
    tenant = Tenant.query.filter_by(id=tenant_id).first()
    if not tenant:
        return jsonify({'error': 'Tenant not found'}), 404
    # Permission check (e.g., only super admin can view all tenants)
    if not current_user.is_super_admin():
        return jsonify({'error': 'Permission denied'}), 403
    return jsonify({'tenant': tenant.to_dict()})

@tenant_bp.route('/tenants/<tenant_id>', methods=['PUT'])
@login_required
def update_tenant(tenant_id):
    """Update tenant details"""
    if not current_user.is_super_admin():
        return jsonify({'error': 'Permission denied'}), 403
    tenant = Tenant.query.filter_by(id=tenant_id).first()
    if not tenant:
        return jsonify({'error': 'Tenant not found'}), 404
    data = request.get_json()
    try:
        # Update allowed fields
        for key in ['tenant_name', 'domain', 'subdomain', 'is_active', 'theme_config', 'api_settings']:
            if key in data:
                setattr(tenant, key, data[key])
        tenant.updated_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'message': 'Tenant updated', 'tenant': tenant.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@tenant_bp.route('/tenants/<tenant_id>', methods=['DELETE'])
@login_required
def delete_tenant(tenant_id):
    """Deactivate or delete tenant"""
    if not current_user.is_super_admin():
        return jsonify({'error': 'Permission denied'}), 403
    tenant = Tenant.query.filter_by(id=tenant_id).first()
    if not tenant:
        return jsonify({'error': 'Tenant not found'}), 404
    try:
        tenant.is_active = False
        tenant.updated_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'message': 'Tenant deactivated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# =============================================================================
# Tenant Hierarchy Management
# =============================================================================

@tenant_bp.route('/tenants/<tenant_id>/children', methods=['GET'])
@login_required
def get_tenant_children(tenant_id):
    """Retrieve child tenants in hierarchy"""
    if not current_user.is_super_admin():
        return jsonify({'error': 'Permission denied'}), 403
    parent_tenant = Tenant.query.filter_by(id=tenant_id).first()
    if not parent_tenant:
        return jsonify({'error': 'Parent tenant not found'}), 404
    children = Tenant.query.filter_by(parent_id=tenant_id, is_active=True).all()
    return jsonify({'children': [child.to_dict() for child in children]})

@tenant_bp.route('/tenants/<tenant_id>/hierarchy', methods=['GET'])
@login_required
def get_tenant_hierarchy(tenant_id):
    """Retrieve full hierarchy starting from a tenant (recursive)"""
    def build_hierarchy(tenant):
        children = Tenant.query.filter_by(parent_id=tenant.id, is_active=True).all()
        return {
            'tenant': tenant.to_dict(),
            'children': [build_hierarchy(child) for child in children]
        }
    tenant = Tenant.query.filter_by(id=tenant_id).first()
    if not tenant:
        return jsonify({'error': 'Tenant not found'}), 404
    if not current_user.is_super_admin():
        return jsonify({'error': 'Permission denied'}), 403
    hierarchy = build_hierarchy(tenant)
    return jsonify(hierarchy)

# =============================================================================
# Additional Config Management Routes (e.g., bank accounts) can be added below as needed
# =============================================================================
