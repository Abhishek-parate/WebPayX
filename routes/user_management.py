# routes/user_management.py
from flask import Blueprint, request, render_template, flash, redirect, url_for
from flask_login import login_required, current_user
from models import (
    User, UserRoleType, KYCStatus, Wallet, WalletTransaction, WalletTransactionType,
    OrganizationBankAccount, WalletTopupRequest, TopupMethod, TransactionStatus, db
)
from sqlalchemy import or_, and_
from sqlalchemy.orm import joinedload  # FIXED: Added missing import
from datetime import datetime
from decimal import Decimal
import uuid
import secrets
import string

user_management_bp = Blueprint('user_management', __name__, url_prefix='/user-management')

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_current_user():
    """Get current logged in user"""
    return current_user

def get_allowed_roles_for_creation(current_role):
    """Get roles that current user can create based on hierarchy"""
    role_hierarchy = {
        UserRoleType.SUPER_ADMIN: [UserRoleType.ADMIN, UserRoleType.WHITE_LABEL],
        UserRoleType.ADMIN: [UserRoleType.WHITE_LABEL, UserRoleType.MASTER_DISTRIBUTOR, UserRoleType.DISTRIBUTOR, UserRoleType.RETAILER],
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

def get_user_query_by_hierarchy():
    """Get users query filtered by current user's hierarchy"""
    if current_user.role == UserRoleType.SUPER_ADMIN:
        return User.query.filter(User.tenant_id == current_user.tenant_id)
    else:
        return User.query.filter(
            User.tenant_id == current_user.tenant_id,
            or_(
                User.id == current_user.id,
                User.tree_path.like(f"{current_user.tree_path}.%") if current_user.tree_path else False,
                User.parent_id == current_user.id
            )
        )

def get_user_downlines_only(user_id):
    """Get only downline users (excluding uplines) of the current user"""
    
    # Get current user
    user = User.query.get(user_id)
    if not user:
        return []
    
    # Only include current user and their descendants (no uplines)
    users_to_include = set([user.id])
    
    try:
        # Method 1: Get direct children using parent_id
        direct_children = User.query.filter(
            User.parent_id == user.id,
            User.tenant_id == user.tenant_id
        ).all()
        
        for child in direct_children:
            users_to_include.add(child.id)
        
        # Method 2: Recursive function to get all nested descendants
        def get_all_descendants(parent_id, collected_ids):
            """Recursively get all descendants of a user"""
            children = User.query.filter(
                User.parent_id == parent_id,
                User.tenant_id == user.tenant_id
            ).all()
            
            for child in children:
                if child.id not in collected_ids:
                    collected_ids.add(child.id)
                    # Recursively get children of this child
                    get_all_descendants(child.id, collected_ids)
        
        # Get all nested descendants starting from current user
        get_all_descendants(user.id, users_to_include)
        
        # Method 3: Also use tree_path as backup (but only for descendants)
        if str(user.id) in str(user.tree_path) or not user.tree_path:
            # Find users who have this user in their tree_path (descendants)
            descendants_by_path = User.query.filter(
                User.tree_path.like(f'%{user.id}%'),
                User.tenant_id == user.tenant_id,
                User.id != user.id  # Don't include current user again
            ).all()
            
            # Only include if this user is truly in their ancestry
            for desc in descendants_by_path:
                if desc.tree_path and (str(user.id) in desc.tree_path or str(user.user_code) in desc.tree_path):
                    users_to_include.add(desc.id)
                    
    except Exception as e:
        print(f"Error fetching descendants: {e}")
    
    # Fetch all users with their wallet relationships
    try:
        all_users = User.query.options(
            joinedload(User.wallet)
        ).filter(
            User.id.in_(users_to_include),
            User.tenant_id == user.tenant_id
        ).all()
    except Exception as e:
        print(f"Error fetching users: {e}")
        all_users = []
    
    # Build hierarchy tree starting from current user as root
    return build_hierarchy_tree(all_users, user.id)

def build_hierarchy_tree(users, focus_user_id):
    """Build hierarchical tree structure"""
    
    if not users:
        return []
    
    # Create user lookup
    users_dict = {u.id: u for u in users}
    
    # Group children by parent
    children_map = {}
    root_users = []
    
    for user in users:
        parent_id = user.parent_id
        if parent_id and parent_id in users_dict:
            children_map.setdefault(parent_id, []).append(user)
        else:
            # If parent not in our user set, this is a root user
            root_users.append(user)
    
    def build_node(user):
        children = children_map.get(user.id, [])
        # Sort children by level and name
        children.sort(key=lambda x: (x.level, x.full_name))
        
        return {
            'user': user,
            'children': [build_node(child) for child in children],
            'is_focus': user.id == focus_user_id
        }
    
    # Build tree from root users (sorted by level)
    root_users.sort(key=lambda x: (x.level, x.full_name))
    return [build_node(root) for root in root_users]

# =============================================================================
# USER MANAGEMENT PAGES
# =============================================================================

@user_management_bp.route('/')
@login_required
def index():
    """User management dashboard"""
    # Get user statistics
    base_query = get_user_query_by_hierarchy()
    
    total_users = base_query.count()
    active_users = base_query.filter(User.is_active == True).count()
    inactive_users = base_query.filter(User.is_active == False).count()
    
    # Role distribution
    role_stats = {}
    for role in UserRoleType:
        count = base_query.filter(User.role == role).count()
        if count > 0:
            role_stats[role.value] = count
    
    # Recent users (last 10)
    recent_users = base_query.order_by(User.created_at.desc()).limit(10).all()
    
    # Monthly registrations
    current_month = datetime.utcnow().replace(day=1)
    monthly_registrations = base_query.filter(User.created_at >= current_month).count()
    
    return render_template('user_management/index.html',
        title='User Management',
        subtitle='Manage Users & Hierarchy',
        total_users=total_users,
        active_users=active_users,
        inactive_users=inactive_users,
        role_stats=role_stats,
        recent_users=recent_users,
        monthly_registrations=monthly_registrations,
        allowed_roles=get_allowed_roles_for_creation(current_user.role)
    )

@user_management_bp.route('/create-user', methods=['GET', 'POST'])
@login_required
def create_user():
    """Create new user page"""
    if request.method == 'POST':
        try:
            # Get form data
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip()
            phone = request.form.get('phone', '').strip()
            password = request.form.get('password', '')
            full_name = request.form.get('full_name', '').strip()
            business_name = request.form.get('business_name', '').strip()
            role_str = request.form.get('role', '')
            is_active = request.form.get('is_active') == 'on'
            daily_limit = request.form.get('daily_limit', 50000, type=float)
            monthly_limit = request.form.get('monthly_limit', 200000, type=float)
            
            # Validation
            if not all([username, email, phone, password, full_name, role_str]):
                flash('All required fields must be filled', 'error')
                return redirect(url_for('user_management.create_user'))
            
            # Validate role
            try:
                user_role = UserRoleType(role_str)
            except ValueError:
                flash('Invalid role specified', 'error')
                return redirect(url_for('user_management.create_user'))
            
            if not can_create_role(current_user.role, user_role):
                flash('You cannot create users with this role', 'error')
                return redirect(url_for('user_management.create_user'))
            
            # Check for duplicates
            existing_user = User.query.filter(
                or_(
                    User.username == username,
                    User.email == email,
                    User.phone == phone
                )
            ).first()
            
            if existing_user:
                flash('User with these credentials already exists', 'error')
                return redirect(url_for('user_management.create_user'))
            
            # Generate user code
            user_code = generate_user_code(user_role)
            
            # Create user
            user = User(
                tenant_id=current_user.tenant_id,
                parent_id=current_user.id,
                user_code=user_code,
                username=username,
                email=email,
                phone=phone,
                role=user_role,
                full_name=full_name,
                business_name=business_name,
                kyc_status=KYCStatus.NOT_SUBMITTED,
                is_active=is_active,
                is_verified=False,
                email_verified=False,
                phone_verified=False,
                tree_path=f"{current_user.tree_path}/{user_code}" if current_user.tree_path else user_code,
                level=current_user.level + 1,
                created_by=current_user.id
            )
            
            user.set_password(password)
            user.generate_api_key()
            
            db.session.add(user)
            db.session.flush()
            
            # Create wallet for user
            wallet = Wallet(
                user_id=user.id,
                balance=0,
                daily_limit=Decimal(str(daily_limit)),
                monthly_limit=Decimal(str(monthly_limit))
            )
            
            db.session.add(wallet)
            db.session.commit()
            
            flash(f'User "{full_name}" created successfully with code: {user_code}', 'success')
            return redirect(url_for('user_management.user_profile', user_id=user.id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating user: {str(e)}', 'error')
            return redirect(url_for('user_management.create_user'))
    
    # GET request - show form
    allowed_roles = get_allowed_roles_for_creation(current_user.role)
    return render_template('user_management/create_user.html',
        title='Create User',
        subtitle='Add New User to Your Network',
        allowed_roles=allowed_roles
    )

@user_management_bp.route('/users')
@login_required
def user_list():
    """User list page with filtering and search"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '').strip()
    role_filter = request.args.get('role', '')
    status_filter = request.args.get('status', '')
    kyc_filter = request.args.get('kyc_status', '')
    
    # Base query with hierarchy
    query = get_user_query_by_hierarchy()
    
    # Apply filters
    if search:
        query = query.filter(
            or_(
                User.full_name.ilike(f'%{search}%'),
                User.username.ilike(f'%{search}%'),
                User.email.ilike(f'%{search}%'),
                User.user_code.ilike(f'%{search}%'),
                User.phone.ilike(f'%{search}%'),
                User.business_name.ilike(f'%{search}%')
            )
        )
    
    if role_filter:
        try:
            role_enum = UserRoleType(role_filter)
            query = query.filter(User.role == role_enum)
        except ValueError:
            pass
    
    if status_filter:
        if status_filter == 'active':
            query = query.filter(User.is_active == True)
        elif status_filter == 'inactive':
            query = query.filter(User.is_active == False)
    
    if kyc_filter:
        try:
            kyc_enum = KYCStatus(kyc_filter)
            query = query.filter(User.kyc_status == kyc_enum)
        except ValueError:
            pass
    
    # Paginate
    users = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=25, error_out=False
    )
    
    return render_template('user_management/user_list.html',
        title='User Management',
        subtitle=f'Total Users: {users.total}',
        users=users,
        search=search,
        role_filter=role_filter,
        status_filter=status_filter,
        kyc_filter=kyc_filter,
        all_roles=UserRoleType,
        all_kyc_status=KYCStatus
    )

@user_management_bp.route('/user/<user_id>')
@login_required
def user_profile(user_id):
    """User profile page"""
    user = User.query.get_or_404(user_id)
    
    # Check access permissions
    if not current_user.can_access_user(user):
        flash('Access denied', 'error')
        return redirect(url_for('user_management.user_list'))
    
    # Get user's children
    children = User.query.filter_by(parent_id=user.id).order_by(User.created_at.desc()).all()
    
    # Get recent wallet transactions
    recent_transactions = []
    if user.wallet:
        recent_transactions = WalletTransaction.query.filter_by(
            wallet_id=user.wallet.id
        ).order_by(WalletTransaction.created_at.desc()).limit(10).all()
    
    # Get topup requests
    recent_topups = WalletTopupRequest.query.filter_by(
        user_id=user.id
    ).order_by(WalletTopupRequest.created_at.desc()).limit(5).all()
    
    return render_template('user_management/user_profile.html',
        title=f'User Profile - {user.full_name}',
        subtitle=f'Code: {user.user_code}',
        user=user,
        children=children,
        recent_transactions=recent_transactions,
        recent_topups=recent_topups
    )

@user_management_bp.route('/user/<user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    """Edit user information"""
    user = User.query.get_or_404(user_id)
    
    # Check access permissions
    if not current_user.can_access_user(user):
        flash('Access denied', 'error')
        return redirect(url_for('user_management.user_list'))
    
    if request.method == 'POST':
        try:
            # Update user information
            user.full_name = request.form.get('full_name', user.full_name)
            user.business_name = request.form.get('business_name', user.business_name)
            user.email = request.form.get('email', user.email)
            user.phone = request.form.get('phone', user.phone)
            user.is_active = request.form.get('is_active') == 'on'
            
            # Handle role change
            new_role_str = request.form.get('role')
            if new_role_str:
                try:
                    new_role = UserRoleType(new_role_str)
                    if can_create_role(current_user.role, new_role):
                        user.role = new_role
                    else:
                        flash('Cannot change user to this role', 'error')
                        return redirect(url_for('user_management.edit_user', user_id=user_id))
                except ValueError:
                    flash('Invalid role specified', 'error')
                    return redirect(url_for('user_management.edit_user', user_id=user_id))
            
            # Handle password change
            new_password = request.form.get('password')
            if new_password:
                user.set_password(new_password)
            
            # Update wallet limits
            if user.wallet:
                daily_limit = request.form.get('daily_limit', type=float)
                monthly_limit = request.form.get('monthly_limit', type=float)
                
                if daily_limit:
                    user.wallet.daily_limit = Decimal(str(daily_limit))
                if monthly_limit:
                    user.wallet.monthly_limit = Decimal(str(monthly_limit))
            
            user.updated_at = datetime.utcnow()
            db.session.commit()
            
            flash('User updated successfully', 'success')
            return redirect(url_for('user_management.user_profile', user_id=user.id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating user: {str(e)}', 'error')
    
    allowed_roles = get_allowed_roles_for_creation(current_user.role)
    return render_template('user_management/edit_user.html',
        title=f'Edit User - {user.full_name}',
        subtitle=f'Code: {user.user_code}',
        user=user,
        allowed_roles=allowed_roles
    )

@user_management_bp.route('/user/<user_id>/toggle-status', methods=['POST'])
@login_required
def toggle_user_status(user_id):
    """Toggle user active status"""
    user = User.query.get_or_404(user_id)
    
    # Check access permissions
    if not current_user.can_access_user(user):
        flash('Access denied', 'error')
        return redirect(url_for('user_management.user_list'))
    
    try:
        # Check if user has children and trying to deactivate
        if user.is_active:
            children_count = User.query.filter_by(parent_id=user.id, is_active=True).count()
            if children_count > 0:
                flash('Cannot deactivate user with active sub-users', 'error')
                return redirect(url_for('user_management.user_profile', user_id=user.id))
        
        user.is_active = not user.is_active
        user.updated_at = datetime.utcnow()
        
        # Also toggle wallet status
        if user.wallet:
            user.wallet.is_active = user.is_active
        
        db.session.commit()
        
        status = 'activated' if user.is_active else 'deactivated'
        flash(f'User {status} successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating user status: {str(e)}', 'error')
    
    return redirect(url_for('user_management.user_profile', user_id=user.id))

# =============================================================================
# HIERARCHY AND TREE VIEW - UPDATED FOR DOWNLINES ONLY
# =============================================================================

@user_management_bp.route('/hierarchy')
@login_required
def user_hierarchy():
    """Display DOWNLINES ONLY hierarchy (no uplines shown)"""
    current_logged_user = get_current_user()
    
    # Get ONLY downlines (current user + all descendants)
    hierarchy_tree = get_user_downlines_only(current_logged_user.id)
    
    # Calculate statistics for downlines only
    downline_user_ids = set()
    
    def collect_user_ids(nodes):
        """Recursively collect all user IDs from hierarchy tree"""
        for node in nodes:
            downline_user_ids.add(node['user'].id)
            if node['children']:
                collect_user_ids(node['children'])
    
    collect_user_ids(hierarchy_tree)
    
    # Statistics for downlines only (excluding retailers)
    total_users = User.query.filter(
        User.id.in_(downline_user_ids),
        User.role != UserRoleType.RETAILER
    ).count() if downline_user_ids else 0
    
    active_users = User.query.filter(
        User.id.in_(downline_user_ids),
        User.is_active == True,
        User.role != UserRoleType.RETAILER  
    ).count() if downline_user_ids else 0
    
    # Role stats for downlines only
    role_stats = {}
    if downline_user_ids:
        for role in UserRoleType:
            if role != UserRoleType.RETAILER:
                count = User.query.filter(
                    User.id.in_(downline_user_ids),
                    User.role == role
                ).count()
                if count > 0:
                    role_stats[role.value] = count
    
    return render_template('user_management/hierarchy.html',
                         title='My Downline Network',
                         subtitle='View your complete downline network structure',
                         hierarchy_tree=hierarchy_tree,
                         total_users=total_users,
                         active_users=active_users,
                         role_stats=role_stats,
                         current_user=current_logged_user,
                         show_uplines=False  # Flag to indicate uplines are hidden
                         )

# =============================================================================
# WALLET MANAGEMENT
# =============================================================================

@user_management_bp.route('/user/<user_id>/wallet/credit', methods=['GET', 'POST'])
@login_required
def credit_user_wallet(user_id):
    """Credit amount to user wallet"""
    user = User.query.get_or_404(user_id)
    
    # Check access permissions
    if not current_user.can_access_user(user):
        flash('Access denied', 'error')
        return redirect(url_for('user_management.user_list'))
    
    if request.method == 'POST':
        try:
            amount = Decimal(str(request.form.get('amount', 0)))
            description = request.form.get('description', 'Admin credit')
            
            if amount <= 0:
                flash('Amount must be positive', 'error')
                return redirect(url_for('user_management.credit_user_wallet', user_id=user_id))
            
            if not user.wallet:
                flash('User wallet not found', 'error')
                return redirect(url_for('user_management.user_profile', user_id=user_id))
            
            # Credit wallet
            balance_before = user.wallet.balance
            user.wallet.balance += amount
            user.wallet.total_credited += amount
            user.wallet.last_transaction_at = datetime.utcnow()
            
            # Record transaction
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
            
            flash(f'₹{amount} credited successfully to {user.full_name}\'s wallet', 'success')
            return redirect(url_for('user_management.user_profile', user_id=user.id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error crediting wallet: {str(e)}', 'error')
    
    return render_template('user_management/wallet_credit.html',
        title=f'Credit Wallet - {user.full_name}',
        subtitle=f'Current Balance: ₹{user.wallet.balance if user.wallet else 0}',
        user=user
    )

@user_management_bp.route('/user/<user_id>/wallet/debit', methods=['GET', 'POST'])
@login_required
def debit_user_wallet(user_id):
    """Debit amount from user wallet"""
    user = User.query.get_or_404(user_id)
    
    # Check access permissions
    if not current_user.can_access_user(user):
        flash('Access denied', 'error')
        return redirect(url_for('user_management.user_list'))
    
    if request.method == 'POST':
        try:
            amount = Decimal(str(request.form.get('amount', 0)))
            description = request.form.get('description', 'Admin debit')
            
            if amount <= 0:
                flash('Amount must be positive', 'error')
                return redirect(url_for('user_management.debit_user_wallet', user_id=user_id))
            
            if not user.wallet:
                flash('User wallet not found', 'error')
                return redirect(url_for('user_management.user_profile', user_id=user_id))
            
            if user.wallet.available_balance < amount:
                flash('Insufficient wallet balance', 'error')
                return redirect(url_for('user_management.debit_user_wallet', user_id=user_id))
            
            # Debit wallet
            balance_before = user.wallet.balance
            user.wallet.balance -= amount
            user.wallet.total_debited += amount
            user.wallet.last_transaction_at = datetime.utcnow()
            
            # Record transaction
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
            
            flash(f'₹{amount} debited successfully from {user.full_name}\'s wallet', 'success')
            return redirect(url_for('user_management.user_profile', user_id=user.id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error debiting wallet: {str(e)}', 'error')
    
    return render_template('user_management/wallet_debit.html',
        title=f'Debit Wallet - {user.full_name}',
        subtitle=f'Available Balance: ₹{user.wallet.available_balance if user.wallet else 0}',
        user=user
    )

# =============================================================================
# BULK OPERATIONS
# =============================================================================

@user_management_bp.route('/bulk-operations', methods=['GET', 'POST'])
@login_required
def bulk_operations():
    """Bulk user operations"""
    if request.method == 'POST':
        try:
            user_ids = request.form.getlist('user_ids')
            action = request.form.get('action')
            
            if not user_ids or not action:
                flash('Please select users and action', 'error')
                return redirect(url_for('user_management.bulk_operations'))
            
            # Get users with permission check
            users = User.query.filter(
                User.id.in_(user_ids),
                User.tenant_id == current_user.tenant_id
            ).all()
            
            # Filter users that current user can access
            accessible_users = [user for user in users if current_user.can_access_user(user)]
            
            if not accessible_users:
                flash('No accessible users found', 'error')
                return redirect(url_for('user_management.bulk_operations'))
            
            updated_count = 0
            
            for user in accessible_users:
                if action == 'activate':
                    user.is_active = True
                    if user.wallet:
                        user.wallet.is_active = True
                    updated_count += 1
                elif action == 'deactivate':
                    # Check if user has active children
                    children_count = User.query.filter_by(parent_id=user.id, is_active=True).count()
                    if children_count == 0:
                        user.is_active = False
                        if user.wallet:
                            user.wallet.is_active = False
                        updated_count += 1
            
            db.session.commit()
            flash(f'Successfully updated {updated_count} users', 'success')
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error in bulk operation: {str(e)}', 'error')
        
        return redirect(url_for('user_management.user_list'))
    
    # GET request - show users for selection
    users = get_user_query_by_hierarchy().filter(User.id != current_user.id).all()
    
    return render_template('user_management/bulk_operations.html',
        title='Bulk Operations',
        subtitle='Manage Multiple Users',
        users=users
    )
