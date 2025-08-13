from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from models import User, Wallet, UserRoleType, KYCStatus, db
from sqlalchemy import or_, and_
import uuid

user_bp = Blueprint('user', __name__)

# =============================================================================
# USER CRUD OPERATIONS
# =============================================================================

@user_bp.route('/users', methods=['POST'])
@login_required
def create_user():
    """Create a new user with hierarchy validation"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['username', 'email', 'phone', 'password', 'full_name', 'role']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        # Validate role hierarchy
        user_role = UserRoleType(data['role'])
        if not can_create_role(current_user.role, user_role):
            return jsonify({'error': 'Cannot create user with this role'}), 403
        
        # Check for duplicate username/email/phone
        existing_user = User.query.filter(
            or_(
                User.username == data['username'],
                User.email == data['email'],
                User.phone == data['phone']
            )
        ).first()
        
        if existing_user:
            return jsonify({'error': 'User with these credentials already exists'}), 409
        
        # Generate user code
        user_code = generate_user_code(user_role)
        
        # Create user
        user = User(
            tenant_id=current_user.tenant_id,
            parent_id=current_user.id,
            user_code=user_code,
            username=data['username'],
            email=data['email'],
            phone=data['phone'],
            role=user_role,
            full_name=data['full_name'],
            business_name=data.get('business_name'),
            address=data.get('address', {}),
            kyc_status=KYCStatus.NOT_SUBMITTED,
            is_active=data.get('is_active', True),
            tree_path=f"{current_user.tree_path}.{user_code}",
            level=current_user.level + 1,
            settings=data.get('settings', {}),
            created_by=current_user.id
        )
        
        user.set_password(data['password'])
        user.generate_api_key()
        
        db.session.add(user)
        db.session.flush()
        
        # Create wallet for user
        wallet = Wallet(
            user_id=user.id,
            balance=0,
            daily_limit=data.get('daily_limit', 50000),
            monthly_limit=data.get('monthly_limit', 200000)
        )
        
        db.session.add(wallet)
        db.session.commit()
        
        return jsonify({
            'message': 'User created successfully',
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@user_bp.route('/users', methods=['GET'])
@login_required
def get_users():
    """Get users based on hierarchy"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        search = request.args.get('search', '')
        role = request.args.get('role')
        status = request.args.get('status')
        
        # Build query based on user hierarchy
        query = User.query.filter(
            User.tenant_id == current_user.tenant_id,
            User.tree_path.like(f"{current_user.tree_path}%")
        )
        
        # Apply filters
        if search:
            query = query.filter(
                or_(
                    User.full_name.ilike(f'%{search}%'),
                    User.username.ilike(f'%{search}%'),
                    User.email.ilike(f'%{search}%'),
                    User.user_code.ilike(f'%{search}%')
                )
            )
        
        if role:
            query = query.filter(User.role == UserRoleType(role))
        
        if status is not None:
            query = query.filter(User.is_active == (status.lower() == 'true'))
        
        # Paginate results
        users = query.order_by(User.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'users': [user.to_dict() for user in users.items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': users.total,
                'pages': users.pages
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@user_bp.route('/users/<user_id>', methods=['GET'])
@login_required
def get_user(user_id):
    """Get specific user details"""
    try:
        user = User.query.filter_by(id=user_id).first()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Check access permissions
        if not current_user.can_access_user(user):
            return jsonify({'error': 'Access denied'}), 403
        
        user_data = user.to_dict()
        
        # Add wallet information
        if user.wallet:
            user_data['wallet'] = {
                'balance': float(user.wallet.balance),
                'hold_balance': float(user.wallet.hold_balance),
                'available_balance': float(user.wallet.available_balance),
                'daily_limit': float(user.wallet.daily_limit),
                'monthly_limit': float(user.wallet.monthly_limit),
                'daily_used': float(user.wallet.daily_used),
                'monthly_used': float(user.wallet.monthly_used)
            }
        
        return jsonify({'user': user_data})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@user_bp.route('/users/<user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    """Update user information"""
    try:
        user = User.query.filter_by(id=user_id).first()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Check access permissions
        if not current_user.can_access_user(user):
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        
        # Update allowed fields
        updatable_fields = [
            'full_name', 'business_name', 'email', 'phone', 
            'address', 'is_active', 'settings'
        ]
        
        for field in updatable_fields:
            if field in data:
                setattr(user, field, data[field])
        
        # Handle role change (with permission check)
        if 'role' in data:
            new_role = UserRoleType(data['role'])
            if can_modify_role(current_user.role, user.role, new_role):
                user.role = new_role
            else:
                return jsonify({'error': 'Cannot change user role'}), 403
        
        # Handle password change
        if 'password' in data:
            user.set_password(data['password'])
        
        user.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'message': 'User updated successfully',
            'user': user.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@user_bp.route('/users/<user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    """Soft delete user (deactivate)"""
    try:
        user = User.query.filter_by(id=user_id).first()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Check access permissions
        if not current_user.can_access_user(user):
            return jsonify({'error': 'Access denied'}), 403
        
        # Check if user has children
        children_count = User.query.filter_by(parent_id=user.id).count()
        if children_count > 0:
            return jsonify({'error': 'Cannot delete user with sub-users'}), 400
        
        # Soft delete
        user.is_active = False
        user.updated_at = datetime.utcnow()
        
        # Deactivate wallet
        if user.wallet:
            user.wallet.is_active = False
        
        db.session.commit()
        
        return jsonify({'message': 'User deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# =============================================================================
# USER HIERARCHY OPERATIONS
# =============================================================================

@user_bp.route('/users/<user_id>/children', methods=['GET'])
@login_required
def get_user_children(user_id):
    """Get direct children of a user"""
    try:
        user = User.query.filter_by(id=user_id).first()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if not current_user.can_access_user(user):
            return jsonify({'error': 'Access denied'}), 403
        
        children = User.query.filter_by(
            parent_id=user.id,
            is_active=True
        ).order_by(User.created_at.desc()).all()
        
        return jsonify({
            'children': [child.to_dict() for child in children]
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@user_bp.route('/users/<user_id>/tree', methods=['GET'])
@login_required
def get_user_tree(user_id):
    """Get complete user tree/hierarchy"""
    try:
        user = User.query.filter_by(id=user_id).first()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if not current_user.can_access_user(user):
            return jsonify({'error': 'Access denied'}), 403
        
        # Get all descendants
        descendants = User.query.filter(
            User.tree_path.like(f"{user.tree_path}%"),
            User.is_active == True
        ).order_by(User.level, User.created_at).all()
        
        return jsonify({
            'tree': build_user_tree(descendants)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Helper functions
def can_create_role(creator_role, target_role):
    """Check if creator can create user with target role"""
    role_hierarchy = {
        UserRoleType.SUPER_ADMIN: 0,
        UserRoleType.ADMIN: 1,
        UserRoleType.WHITE_LABEL: 2,
        UserRoleType.MASTER_DISTRIBUTOR: 3,
        UserRoleType.DISTRIBUTOR: 4,
        UserRoleType.RETAILER: 5
    }
    
    return role_hierarchy[creator_role] < role_hierarchy[target_role]

def generate_user_code(role):
    """Generate unique user code based on role"""
    prefix_map = {
        UserRoleType.SUPER_ADMIN: 'SA',
        UserRoleType.ADMIN: 'AD',
        UserRoleType.WHITE_LABEL: 'WL',
        UserRoleType.MASTER_DISTRIBUTOR: 'MD',
        UserRoleType.DISTRIBUTOR: 'DT',
        UserRoleType.RETAILER: 'RT'
    }
    
    prefix = prefix_map[role]
    count = User.query.filter(User.user_code.like(f'{prefix}%')).count()
    return f"{prefix}{count + 1:06d}"
