# routes/user_management.py
from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for
from flask_login import login_required, current_user
from models import (
    User, UserRoleType, KYCStatus, Wallet, OrganizationBankAccount,
    WalletTopupRequest, TopupMethod, TransactionStatus, db
)
from sqlalchemy import or_, and_
from datetime import datetime
from decimal import Decimal
import uuid
import os
from werkzeug.utils import secure_filename

# user_management_bp = Blueprint('user_management', __name__, url_prefix='/user-management')
# user_management_bp = Blueprint('user_management', __name__, template_folder='templates', static_folder='static')
user_management_bp = Blueprint('user_management', __name__, url_prefix='/user-management', template_folder='templates', static_folder='static')


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_allowed_roles_for_creation(current_role):
    """Get roles that current user can create based on hierarchy"""
    role_hierarchy = {
        UserRoleType.SUPER_ADMIN: [UserRoleType.ADMIN, UserRoleType.WHITE_LABEL],
        UserRoleType.ADMIN: [UserRoleType.MASTER_DISTRIBUTOR, UserRoleType.DISTRIBUTOR, UserRoleType.RETAILER],
        UserRoleType.WHITE_LABEL: [UserRoleType.MASTER_DISTRIBUTOR, UserRoleType.DISTRIBUTOR, UserRoleType.RETAILER],
        UserRoleType.MASTER_DISTRIBUTOR: [UserRoleType.DISTRIBUTOR, UserRoleType.RETAILER],
        UserRoleType.DISTRIBUTOR: [UserRoleType.RETAILER],
        UserRoleType.RETAILER: []  # Cannot create any users
    }
    return role_hierarchy.get(current_role, [])

def can_create_role(creator_role, target_role):
    """Check if creator can create user with target role"""
    allowed_roles = get_allowed_roles_for_creation(creator_role)
    return target_role in allowed_roles

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

# =============================================================================
# USER MANAGEMENT PAGES
# =============================================================================

@user_management_bp.route('/')
@login_required
def index():
    """User management dashboard"""
    return render_template('user_management/index.html',
        title='User Management',
        subtitle='Manage Users & Hierarchy'
    )

@user_management_bp.route('/create-user')
@login_required
def create_user_page():
    """Create new user page"""
    allowed_roles = get_allowed_roles_for_creation(current_user.role)
    return render_template('user_management/create_user.html',
        title='Create User',
        subtitle='Add New User',
        allowed_roles=allowed_roles
    )

@user_management_bp.route('/user-list')
@login_required
def user_list_page():
    """User list page"""
    return render_template('user_management/user_list.html',
        title='User List',
        subtitle='Manage Users'
    )

@user_management_bp.route('/user/<user_id>')
@login_required
def user_profile_page(user_id):
    """User profile page"""
    user = User.query.filter_by(id=user_id).first()
    if not user or not current_user.can_access_user(user):
        flash('User not found or access denied', 'error')
        return redirect(url_for('user_management.user_list_page'))
    
    return render_template('user_management/user_profile.html',
        title=f'User Profile - {user.full_name}',
        subtitle='User Details',
        user=user
    )

# =============================================================================
# USER CRUD API ENDPOINTS
# =============================================================================

@user_management_bp.route('/api/users', methods=['POST'])
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
        try:
            user_role = UserRoleType(data['role'])
        except ValueError:
            return jsonify({'error': 'Invalid role specified'}), 400
            
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
            tree_path=f"{current_user.tree_path}.{user_code}" if current_user.tree_path else user_code,
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
            'user': user.to_dict(),
            'user_code': user_code
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@user_management_bp.route('/api/users', methods=['GET'])
@login_required
def get_users():
    """Get users based on hierarchy with advanced filtering"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        search = request.args.get('search', '')
        role = request.args.get('role')
        status = request.args.get('status')
        kyc_status = request.args.get('kyc_status')
        
        # Build query based on user hierarchy
        query = User.query.filter(
            User.tenant_id == current_user.tenant_id,
            User.tree_path.like(f"{current_user.tree_path}%") if current_user.tree_path else True
        )
        
        # Apply filters
        if search:
            query = query.filter(
                or_(
                    User.full_name.ilike(f'%{search}%'),
                    User.username.ilike(f'%{search}%'),
                    User.email.ilike(f'%{search}%'),
                    User.user_code.ilike(f'%{search}%'),
                    User.phone.ilike(f'%{search}%')
                )
            )
        
        if role:
            try:
                role_enum = UserRoleType(role)
                query = query.filter(User.role == role_enum)
            except ValueError:
                pass
        
        if status is not None:
            query = query.filter(User.is_active == (status.lower() == 'true'))
            
        if kyc_status:
            try:
                kyc_enum = KYCStatus(kyc_status)
                query = query.filter(User.kyc_status == kyc_enum)
            except ValueError:
                pass
        
        # Paginate results
        users = query.order_by(User.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        users_data = []
        for user in users.items:
            user_data = user.to_dict()
            # Add wallet information
            if user.wallet:
                user_data['wallet'] = {
                    'balance': float(user.wallet.balance),
                    'hold_balance': float(user.wallet.hold_balance),
                    'available_balance': float(user.wallet.available_balance)
                }
            # Add parent information
            if user.parent:
                user_data['parent'] = {
                    'id': user.parent.id,
                    'full_name': user.parent.full_name,
                    'user_code': user.parent.user_code
                }
            users_data.append(user_data)
        
        return jsonify({
            'users': users_data,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': users.total,
                'pages': users.pages,
                'has_next': users.has_next,
                'has_prev': users.has_prev
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@user_management_bp.route('/api/users/<user_id>', methods=['GET'])
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
        
        # Add hierarchy information
        children = User.query.filter_by(parent_id=user.id, is_active=True).all()
        user_data['children'] = [
            {
                'id': child.id,
                'full_name': child.full_name,
                'user_code': child.user_code,
                'role': child.role.value
            } for child in children
        ]
        
        # Add parent information
        if user.parent:
            user_data['parent'] = {
                'id': user.parent.id,
                'full_name': user.parent.full_name,
                'user_code': user.parent.user_code,
                'role': user.parent.role.value
            }
        
        return jsonify({'user': user_data})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@user_management_bp.route('/api/users/<user_id>', methods=['PUT'])
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
            try:
                new_role = UserRoleType(data['role'])
                if can_create_role(current_user.role, new_role):
                    user.role = new_role
                else:
                    return jsonify({'error': 'Cannot change user to this role'}), 403
            except ValueError:
                return jsonify({'error': 'Invalid role specified'}), 400
        
        # Handle password change
        if 'password' in data and data['password']:
            user.set_password(data['password'])
        
        # Handle wallet limits
        if 'wallet_limits' in data and user.wallet:
            wallet_data = data['wallet_limits']
            if 'daily_limit' in wallet_data:
                user.wallet.daily_limit = Decimal(str(wallet_data['daily_limit']))
            if 'monthly_limit' in wallet_data:
                user.wallet.monthly_limit = Decimal(str(wallet_data['monthly_limit']))
        
        user.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'message': 'User updated successfully',
            'user': user.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@user_management_bp.route('/api/users/<user_id>/toggle-status', methods=['POST'])
@login_required
def toggle_user_status(user_id):
    """Toggle user active status"""
    try:
        user = User.query.filter_by(id=user_id).first()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Check access permissions
        if not current_user.can_access_user(user):
            return jsonify({'error': 'Access denied'}), 403
        
        # Check if user has children and trying to deactivate
        if user.is_active:
            children_count = User.query.filter_by(parent_id=user.id, is_active=True).count()
            if children_count > 0:
                return jsonify({'error': 'Cannot deactivate user with active sub-users'}), 400
        
        user.is_active = not user.is_active
        user.updated_at = datetime.utcnow()
        
        # Also toggle wallet status
        if user.wallet:
            user.wallet.is_active = user.is_active
        
        db.session.commit()
        
        status = 'activated' if user.is_active else 'deactivated'
        return jsonify({'message': f'User {status} successfully', 'is_active': user.is_active})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# =============================================================================
# WALLET MANAGEMENT
# =============================================================================

@user_management_bp.route('/api/users/<user_id>/wallet/credit', methods=['POST'])
@login_required
def credit_user_wallet(user_id):
    """Credit amount to user wallet (Admin function)"""
    try:
        user = User.query.filter_by(id=user_id).first()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if not current_user.can_access_user(user):
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        amount = Decimal(str(data.get('amount', 0)))
        description = data.get('description', 'Admin credit')
        
        if amount <= 0:
            return jsonify({'error': 'Amount must be positive'}), 400
        
        if not user.wallet:
            return jsonify({'error': 'User wallet not found'}), 404
        
        # Credit wallet
        balance_before = user.wallet.balance
        user.wallet.balance += amount
        user.wallet.total_credited += amount
        user.wallet.last_transaction_at = datetime.utcnow()
        
        # Record transaction
        from models import WalletTransaction, WalletTransactionType
        transaction = WalletTransaction(
            wallet_id=user.wallet.id,
            transaction_type=WalletTransactionType.CREDIT,
            amount=amount,
            balance_before=balance_before,
            balance_after=user.wallet.balance,
            description=description,
            processed_by=current_user.id
        )
        
        db.session.add(transaction)
        db.session.commit()
        
        return jsonify({
            'message': 'Wallet credited successfully',
            'transaction': transaction.to_dict(),
            'new_balance': float(user.wallet.balance)
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@user_management_bp.route('/api/users/<user_id>/wallet/debit', methods=['POST'])
@login_required
def debit_user_wallet(user_id):
    """Debit amount from user wallet (Admin function)"""
    try:
        user = User.query.filter_by(id=user_id).first()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if not current_user.can_access_user(user):
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        amount = Decimal(str(data.get('amount', 0)))
        description = data.get('description', 'Admin debit')
        
        if amount <= 0:
            return jsonify({'error': 'Amount must be positive'}), 400
        
        if not user.wallet:
            return jsonify({'error': 'User wallet not found'}), 404
        
        if user.wallet.available_balance < amount:
            return jsonify({'error': 'Insufficient wallet balance'}), 400
        
        # Debit wallet
        balance_before = user.wallet.balance
        user.wallet.balance -= amount
        user.wallet.total_debited += amount
        user.wallet.last_transaction_at = datetime.utcnow()
        
        # Record transaction
        from models import WalletTransaction, WalletTransactionType
        transaction = WalletTransaction(
            wallet_id=user.wallet.id,
            transaction_type=WalletTransactionType.DEBIT,
            amount=amount,
            balance_before=balance_before,
            balance_after=user.wallet.balance,
            description=description,
            processed_by=current_user.id
        )
        
        db.session.add(transaction)
        db.session.commit()
        
        return jsonify({
            'message': 'Wallet debited successfully',
            'transaction': transaction.to_dict(),
            'new_balance': float(user.wallet.balance)
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# =============================================================================
# USER HIERARCHY
# =============================================================================

@user_management_bp.route('/api/users/<user_id>/children', methods=['GET'])
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
        
        children_data = []
        for child in children:
            child_data = child.to_dict()
            if child.wallet:
                child_data['wallet_balance'] = float(child.wallet.balance)
            children_data.append(child_data)
        
        return jsonify({
            'children': children_data,
            'total_children': len(children_data)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@user_management_bp.route('/api/users/<user_id>/tree', methods=['GET'])
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
            User.tree_path.like(f"{user.tree_path}%") if user.tree_path else True,
            User.is_active == True
        ).order_by(User.level, User.created_at).all()
        
        def build_user_tree(users, parent_id=None):
            """Recursively build user tree"""
            tree = []
            for user in users:
                if user.parent_id == parent_id:
                    user_data = user.to_dict()
                    if user.wallet:
                        user_data['wallet_balance'] = float(user.wallet.balance)
                    user_data['children'] = build_user_tree(users, user.id)
                    tree.append(user_data)
            return tree
        
        tree = build_user_tree(descendants, user_id)
        
        return jsonify({
            'tree': tree,
            'total_descendants': len(descendants)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# ROLE AND PERMISSION MANAGEMENT
# =============================================================================

@user_management_bp.route('/api/roles/allowed', methods=['GET'])
@login_required
def get_allowed_roles():
    """Get roles that current user can assign"""
    allowed_roles = get_allowed_roles_for_creation(current_user.role)
    return jsonify({
        'allowed_roles': [role.value for role in allowed_roles],
        'current_role': current_user.role.value
    })

# =============================================================================
# STATISTICS AND DASHBOARD
# =============================================================================

@user_management_bp.route('/api/stats', methods=['GET'])
@login_required
def get_user_stats():
    """Get user management statistics"""
    try:
        base_query = User.query.filter(
            User.tenant_id == current_user.tenant_id,
            User.tree_path.like(f"{current_user.tree_path}%") if current_user.tree_path else True
        )
        
        stats = {
            'total_users': base_query.count(),
            'active_users': base_query.filter(User.is_active == True).count(),
            'inactive_users': base_query.filter(User.is_active == False).count(),
            'by_role': {},
            'by_kyc_status': {},
            'recent_registrations': base_query.filter(
                User.created_at >= datetime.utcnow().replace(day=1)
            ).count()
        }
        
        # Stats by role
        for role in UserRoleType:
            count = base_query.filter(User.role == role).count()
            if count > 0:
                stats['by_role'][role.value] = count
        
        # Stats by KYC status
        for status in KYCStatus:
            count = base_query.filter(User.kyc_status == status).count()
            if count > 0:
                stats['by_kyc_status'][status.value] = count
        
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# BULK OPERATIONS
# =============================================================================

@user_management_bp.route('/api/users/bulk-update', methods=['POST'])
@login_required
def bulk_update_users():
    """Bulk update users (status, role, etc.)"""
    try:
        data = request.get_json()
        user_ids = data.get('user_ids', [])
        action = data.get('action')
        value = data.get('value')
        
        if not user_ids or not action:
            return jsonify({'error': 'User IDs and action are required'}), 400
        
        # Get users with permission check
        users = User.query.filter(
            User.id.in_(user_ids),
            User.tenant_id == current_user.tenant_id
        ).all()
        
        # Filter users that current user can access
        accessible_users = [user for user in users if current_user.can_access_user(user)]
        
        if not accessible_users:
            return jsonify({'error': 'No accessible users found'}), 404
        
        updated_count = 0
        
        for user in accessible_users:
            if action == 'activate':
                user.is_active = True
                updated_count += 1
            elif action == 'deactivate':
                # Check if user has active children
                children_count = User.query.filter_by(parent_id=user.id, is_active=True).count()
                if children_count == 0:
                    user.is_active = False
                    updated_count += 1
            elif action == 'update_role' and value:
                try:
                    new_role = UserRoleType(value)
                    if can_create_role(current_user.role, new_role):
                        user.role = new_role
                        updated_count += 1
                except ValueError:
                    continue
        
        db.session.commit()
        
        return jsonify({
            'message': f'Successfully updated {updated_count} users',
            'updated_count': updated_count,
            'total_requested': len(user_ids)
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500