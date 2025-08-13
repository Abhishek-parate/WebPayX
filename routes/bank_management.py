# routes/bank_management.py
from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for
from flask_login import login_required, current_user
from models import (
    OrganizationBankAccount, BankAccountType, AccountPurpose, BankAccountStatus,
    RoleBankPermission, UserRoleType, BankAccountTransaction, db
)
from datetime import datetime
from decimal import Decimal
import uuid

bank_management_bp = Blueprint('bank_management', __name__, url_prefix='/bank-management')

# =============================================================================
# BANK MANAGEMENT PAGES
# =============================================================================

@bank_management_bp.route('/')
@login_required
def index():
    """Bank management dashboard"""
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN', 'WHITE_LABEL']:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard.index'))
    
    return render_template('bank_management/index.html',
        title='Bank Management',
        subtitle='Manage Organization Bank Accounts'
    )

@bank_management_bp.route('/accounts')
@login_required
def bank_accounts_page():
    """Bank accounts list page"""
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN', 'WHITE_LABEL']:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard.index'))
    
    return render_template('bank_management/accounts.html',
        title='Bank Accounts',
        subtitle='Manage Bank Accounts'
    )

@bank_management_bp.route('/add-account')
@login_required
def add_account_page():
    """Add new bank account page"""
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
        flash('Access denied', 'error')
        return redirect(url_for('bank_management.index'))
    
    return render_template('bank_management/add_account.html',
        title='Add Bank Account',
        subtitle='Add New Organization Bank Account'
    )

@bank_management_bp.route('/account/<account_id>')
@login_required
def account_details_page(account_id):
    """Bank account details page"""
    account = OrganizationBankAccount.query.filter(
        OrganizationBankAccount.id == account_id,
        OrganizationBankAccount.tenant_id == current_user.tenant_id
    ).first()
    
    if not account:
        flash('Bank account not found', 'error')
        return redirect(url_for('bank_management.bank_accounts_page'))
    
    return render_template('bank_management/account_details.html',
        title=f'Bank Account - {account.account_name}',
        subtitle='Account Details & Transactions',
        account=account
    )

# =============================================================================
# BANK ACCOUNT CRUD API
# =============================================================================

@bank_management_bp.route('/api/accounts', methods=['POST'])
@login_required
def create_bank_account():
    """Create a new organization bank account"""
    try:
        if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        
        # Validate required fields
        required_fields = [
            'account_name', 'account_number', 'ifsc_code', 'bank_name',
            'account_holder_name', 'account_type'
        ]
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        # Check for duplicate account number
        existing_account = OrganizationBankAccount.query.filter(
            OrganizationBankAccount.account_number == data['account_number'],
            OrganizationBankAccount.tenant_id == current_user.tenant_id
        ).first()
        
        if existing_account:
            return jsonify({'error': 'Account number already exists'}), 409
        
        # Generate account code
        account_count = OrganizationBankAccount.query.filter_by(tenant_id=current_user.tenant_id).count()
        account_code = f"BA{account_count + 1:06d}"
        
        # Create bank account
        account = OrganizationBankAccount(
            tenant_id=current_user.tenant_id,
            user_id=current_user.id,
            account_code=account_code,
            account_name=data['account_name'],
            account_number=data['account_number'],
            ifsc_code=data['ifsc_code'],
            bank_name=data['bank_name'],
            branch_name=data.get('branch_name'),
            branch_address=data.get('branch_address'),
            account_type=BankAccountType(data['account_type']),
            account_holder_name=data['account_holder_name'],
            pan_number=data.get('pan_number'),
            gstin=data.get('gstin'),
            status=BankAccountStatus.ACTIVE,
            purpose=data.get('purpose', [AccountPurpose.WALLET_TOPUP.value]),
            is_primary=data.get('is_primary', False),
            is_default_topup=data.get('is_default_topup', False),
            is_default_settlement=data.get('is_default_settlement', False),
            is_default_refund=data.get('is_default_refund', False),
            priority=data.get('priority', 1),
            daily_limit=Decimal(str(data.get('daily_limit', 500000))),
            monthly_limit=Decimal(str(data.get('monthly_limit', 10000000))),
            minimum_balance=Decimal(str(data.get('minimum_balance', 10000))),
            current_balance=Decimal(str(data.get('current_balance', 0))),
            upi_id=data.get('upi_id'),
            bank_charges=data.get('bank_charges', {}),
            auto_settlement=data.get('auto_settlement', False),
            settlement_schedule=data.get('settlement_schedule', 'DAILY'),
            is_visible_to_users=data.get('is_visible_to_users', True),
            display_order=data.get('display_order', 1),
            additional_info=data.get('additional_info', {}),
            created_by=current_user.id
        )
        
        # Handle primary account logic
        if account.is_primary:
            # Remove primary flag from other accounts
            OrganizationBankAccount.query.filter(
                OrganizationBankAccount.tenant_id == current_user.tenant_id,
                OrganizationBankAccount.is_primary == True
            ).update({'is_primary': False})
        
        # Handle default topup logic
        if account.is_default_topup:
            OrganizationBankAccount.query.filter(
                OrganizationBankAccount.tenant_id == current_user.tenant_id,
                OrganizationBankAccount.is_default_topup == True
            ).update({'is_default_topup': False})
        
        db.session.add(account)
        db.session.commit()
        
        return jsonify({
            'message': 'Bank account created successfully',
            'account': account.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@bank_management_bp.route('/api/accounts', methods=['GET'])
@login_required
def get_bank_accounts():
    """Get organization bank accounts"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        status_filter = request.args.get('status')
        purpose_filter = request.args.get('purpose')
        search = request.args.get('search', '')
        
        # Base query
        query = OrganizationBankAccount.query.filter(
            OrganizationBankAccount.tenant_id == current_user.tenant_id
        )
        
        # Apply filters
        if status_filter:
            try:
                status_enum = BankAccountStatus(status_filter.upper())
                query = query.filter(OrganizationBankAccount.status == status_enum)
            except ValueError:
                pass
        
        if purpose_filter:
            query = query.filter(
                OrganizationBankAccount.purpose.contains([purpose_filter])
            )
        
        if search:
            query = query.filter(
                db.or_(
                    OrganizationBankAccount.account_name.ilike(f'%{search}%'),
                    OrganizationBankAccount.account_number.ilike(f'%{search}%'),
                    OrganizationBankAccount.bank_name.ilike(f'%{search}%'),
                    OrganizationBankAccount.ifsc_code.ilike(f'%{search}%')
                )
            )
        
        # Paginate results
        accounts = query.order_by(OrganizationBankAccount.display_order, 
                                OrganizationBankAccount.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        accounts_data = []
        for account in accounts.items:
            account_data = account.to_dict()
            
            # Add transaction statistics
            total_transactions = BankAccountTransaction.query.filter_by(
                bank_account_id=account.id
            ).count()
            
            account_data['statistics'] = {
                'total_transactions': total_transactions,
                'available_daily_limit': float(account.daily_limit - account.daily_used),
                'available_monthly_limit': float(account.monthly_limit - account.monthly_used)
            }
            
            accounts_data.append(account_data)
        
        return jsonify({
            'accounts': accounts_data,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': accounts.total,
                'pages': accounts.pages,
                'has_next': accounts.has_next,
                'has_prev': accounts.has_prev
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bank_management_bp.route('/api/accounts/<account_id>', methods=['GET'])
@login_required
def get_bank_account(account_id):
    """Get specific bank account details"""
    try:
        account = OrganizationBankAccount.query.filter(
            OrganizationBankAccount.id == account_id,
            OrganizationBankAccount.tenant_id == current_user.tenant_id
        ).first()
        
        if not account:
            return jsonify({'error': 'Bank account not found'}), 404
        
        account_data = account.to_dict()
        
        # Add recent transactions
        recent_transactions = BankAccountTransaction.query.filter_by(
            bank_account_id=account.id
        ).order_by(BankAccountTransaction.created_at.desc()).limit(10).all()
        
        account_data['recent_transactions'] = [
            transaction.to_dict() for transaction in recent_transactions
        ]
        
        # Add statistics
        total_transactions = BankAccountTransaction.query.filter_by(
            bank_account_id=account.id
        ).count()
        
        total_credits = db.session.query(
            db.func.coalesce(db.func.sum(BankAccountTransaction.amount), 0)
        ).filter(
            BankAccountTransaction.bank_account_id == account.id,
            BankAccountTransaction.transaction_type == 'CREDIT'
        ).scalar()
        
        total_debits = db.session.query(
            db.func.coalesce(db.func.sum(BankAccountTransaction.amount), 0)
        ).filter(
            BankAccountTransaction.bank_account_id == account.id,
            BankAccountTransaction.transaction_type == 'DEBIT'
        ).scalar()
        
        account_data['statistics'] = {
            'total_transactions': total_transactions,
            'total_credits': float(total_credits),
            'total_debits': float(total_debits),
            'available_daily_limit': float(account.daily_limit - account.daily_used),
            'available_monthly_limit': float(account.monthly_limit - account.monthly_used)
        }
        
        return jsonify({'account': account_data})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bank_management_bp.route('/api/accounts/<account_id>', methods=['PUT'])
@login_required
def update_bank_account(account_id):
    """Update bank account information"""
    try:
        if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
            return jsonify({'error': 'Access denied'}), 403
        
        account = OrganizationBankAccount.query.filter(
            OrganizationBankAccount.id == account_id,
            OrganizationBankAccount.tenant_id == current_user.tenant_id
        ).first()
        
        if not account:
            return jsonify({'error': 'Bank account not found'}), 404
        
        data = request.get_json()
        
        # Update allowed fields
        updatable_fields = [
            'account_name', 'branch_name', 'branch_address', 'pan_number',
            'gstin', 'upi_id', 'priority', 'daily_limit', 'monthly_limit',
            'minimum_balance', 'current_balance', 'bank_charges',
            'auto_settlement', 'settlement_schedule', 'is_visible_to_users',
            'display_order', 'additional_info'
        ]
        
        for field in updatable_fields:
            if field in data:
                if field in ['daily_limit', 'monthly_limit', 'minimum_balance', 'current_balance']:
                    setattr(account, field, Decimal(str(data[field])))
                else:
                    setattr(account, field, data[field])
        
        # Handle status change
        if 'status' in data:
            try:
                new_status = BankAccountStatus(data['status'].upper())
                account.status = new_status
            except ValueError:
                return jsonify({'error': 'Invalid status specified'}), 400
        
        # Handle purpose change
        if 'purpose' in data:
            account.purpose = data['purpose']
        
        # Handle flags
        if 'is_primary' in data and data['is_primary']:
            # Remove primary flag from other accounts
            OrganizationBankAccount.query.filter(
                OrganizationBankAccount.tenant_id == current_user.tenant_id,
                OrganizationBankAccount.id != account.id,
                OrganizationBankAccount.is_primary == True
            ).update({'is_primary': False})
            account.is_primary = True
        
        if 'is_default_topup' in data and data['is_default_topup']:
            OrganizationBankAccount.query.filter(
                OrganizationBankAccount.tenant_id == current_user.tenant_id,
                OrganizationBankAccount.id != account.id,
                OrganizationBankAccount.is_default_topup == True
            ).update({'is_default_topup': False})
            account.is_default_topup = True
        
        account.last_updated_by = current_user.id
        account.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'message': 'Bank account updated successfully',
            'account': account.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@bank_management_bp.route('/api/accounts/<account_id>/toggle-status', methods=['POST'])
@login_required
def toggle_account_status(account_id):
    """Toggle bank account status"""
    try:
        if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
            return jsonify({'error': 'Access denied'}), 403
        
        account = OrganizationBankAccount.query.filter(
            OrganizationBankAccount.id == account_id,
            OrganizationBankAccount.tenant_id == current_user.tenant_id
        ).first()
        
        if not account:
            return jsonify({'error': 'Bank account not found'}), 404
        
        # Toggle status
        if account.status == BankAccountStatus.ACTIVE:
            account.status = BankAccountStatus.INACTIVE
        else:
            account.status = BankAccountStatus.ACTIVE
        
        account.last_updated_by = current_user.id
        account.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        status = 'activated' if account.status == BankAccountStatus.ACTIVE else 'deactivated'
        return jsonify({
            'message': f'Bank account {status} successfully',
            'status': account.status.value
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# =============================================================================
# BANK ACCOUNT TRANSACTIONS
# =============================================================================

@bank_management_bp.route('/api/accounts/<account_id>/transactions', methods=['GET'])
@login_required
def get_account_transactions(account_id):
    """Get bank account transactions"""
    try:
        account = OrganizationBankAccount.query.filter(
            OrganizationBankAccount.id == account_id,
            OrganizationBankAccount.tenant_id == current_user.tenant_id
        ).first()
        
        if not account:
            return jsonify({'error': 'Bank account not found'}), 404
        
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        transaction_type = request.args.get('type')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        
        query = BankAccountTransaction.query.filter_by(bank_account_id=account.id)
        
        # Apply filters
        if transaction_type:
            query = query.filter(BankAccountTransaction.transaction_type == transaction_type.upper())
        
        if date_from:
            try:
                from_date = datetime.strptime(date_from, '%Y-%m-%d')
                query = query.filter(BankAccountTransaction.created_at >= from_date)
            except ValueError:
                pass
        
        if date_to:
            try:
                to_date = datetime.strptime(date_to, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
                query = query.filter(BankAccountTransaction.created_at <= to_date)
            except ValueError:
                pass
        
        # Paginate results
        transactions = query.order_by(BankAccountTransaction.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'transactions': [transaction.to_dict() for transaction in transactions.items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': transactions.total,
                'pages': transactions.pages,
                'has_next': transactions.has_next,
                'has_prev': transactions.has_prev
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bank_management_bp.route('/api/accounts/<account_id>/transactions', methods=['POST'])
@login_required
def create_account_transaction(account_id):
    """Create a new bank account transaction (manual entry)"""
    try:
        if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
            return jsonify({'error': 'Access denied'}), 403
        
        account = OrganizationBankAccount.query.filter(
            OrganizationBankAccount.id == account_id,
            OrganizationBankAccount.tenant_id == current_user.tenant_id
        ).first()
        
        if not account:
            return jsonify({'error': 'Bank account not found'}), 404
        
        data = request.get_json()
        
        required_fields = ['transaction_type', 'amount', 'description']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        amount = Decimal(str(data['amount']))
        transaction_type = data['transaction_type'].upper()
        
        if amount <= 0:
            return jsonify({'error': 'Amount must be positive'}), 400
        
        if transaction_type not in ['CREDIT', 'DEBIT']:
            return jsonify({'error': 'Invalid transaction type'}), 400
        
        # Calculate new balance
        balance_before = account.current_balance
        if transaction_type == 'CREDIT':
            balance_after = balance_before + amount
        else:
            balance_after = balance_before - amount
            if balance_after < 0:
                return jsonify({'error': 'Insufficient balance'}), 400
        
        # Create transaction
        transaction = BankAccountTransaction(
            bank_account_id=account.id,
            transaction_type=transaction_type,
            amount=amount,
            balance_before=balance_before,
            balance_after=balance_after,
            reference_number=data.get('reference_number'),
            utr_number=data.get('utr_number'),
            description=data['description'],
            category=data.get('category', 'MANUAL_ENTRY'),
            counterparty_name=data.get('counterparty_name'),
            counterparty_account=data.get('counterparty_account'),
            counterparty_ifsc=data.get('counterparty_ifsc'),
            charges=Decimal(str(data.get('charges', 0))),
            gst_amount=Decimal(str(data.get('gst_amount', 0))),
            net_amount=amount - Decimal(str(data.get('charges', 0))),
            bank_reference=data.get('bank_reference'),
            meta_data=data.get('meta_data', {})
        )
        
        # Update account balance
        account.current_balance = balance_after
        account.updated_at = datetime.utcnow()
        
        db.session.add(transaction)
        db.session.commit()
        
        return jsonify({
            'message': 'Transaction created successfully',
            'transaction': transaction.to_dict(),
            'new_balance': float(account.current_balance)
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# =============================================================================
# ROLE-BASED BANK PERMISSIONS
# =============================================================================

@bank_management_bp.route('/api/role-permissions', methods=['GET'])
@login_required
def get_role_bank_permissions():
    """Get role-based bank permissions"""
    try:
        if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
            return jsonify({'error': 'Access denied'}), 403
        
        role = request.args.get('role')
        bank_account_id = request.args.get('bank_account_id')
        
        query = RoleBankPermission.query.filter(
            RoleBankPermission.tenant_id == current_user.tenant_id
        )
        
        if role:
            try:
                role_enum = UserRoleType(role.upper())
                query = query.filter(RoleBankPermission.role == role_enum)
            except ValueError:
                return jsonify({'error': 'Invalid role specified'}), 400
        
        if bank_account_id:
            query = query.filter(RoleBankPermission.bank_account_id == bank_account_id)
        
        permissions = query.all()
        
        permissions_data = []
        for permission in permissions:
            permission_data = permission.to_dict()
            
            # Add bank account info
            if permission.bank_account_id:
                account = OrganizationBankAccount.query.get(permission.bank_account_id)
                if account:
                    permission_data['bank_account'] = {
                        'id': account.id,
                        'account_name': account.account_name,
                        'account_number': account.account_number
                    }
            
            permissions_data.append(permission_data)
        
        return jsonify({
            'permissions': permissions_data,
            'total': len(permissions_data)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bank_management_bp.route('/api/role-permissions', methods=['POST'])
@login_required
def create_role_bank_permission():
    """Create or update role-based bank permission"""
    try:
        if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        
        required_fields = ['role', 'bank_account_id']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        try:
            role_enum = UserRoleType(data['role'].upper())
        except ValueError:
            return jsonify({'error': 'Invalid role specified'}), 400
        
        # Check if bank account exists
        bank_account = OrganizationBankAccount.query.filter(
            OrganizationBankAccount.id == data['bank_account_id'],
            OrganizationBankAccount.tenant_id == current_user.tenant_id
        ).first()
        
        if not bank_account:
            return jsonify({'error': 'Bank account not found'}), 404
        
        # Check if permission already exists
        existing_permission = RoleBankPermission.query.filter(
            RoleBankPermission.tenant_id == current_user.tenant_id,
            RoleBankPermission.role == role_enum,
            RoleBankPermission.bank_account_id == data['bank_account_id']
        ).first()
        
        if existing_permission:
            # Update existing permission
            permission = existing_permission
        else:
            # Create new permission
            permission = RoleBankPermission(
                tenant_id=current_user.tenant_id,
                role=role_enum,
                bank_account_id=data['bank_account_id'],
                created_by=current_user.id
            )
        
        # Update permission fields
        permission.can_view = data.get('can_view', True)
        permission.can_select_for_topup = data.get('can_select_for_topup', True)
        permission.can_modify = data.get('can_modify', False)
        permission.can_view_balance = data.get('can_view_balance', False)
        permission.can_reconcile = data.get('can_reconcile', False)
        permission.purpose_allowed = data.get('purpose_allowed', [AccountPurpose.WALLET_TOPUP.value])
        
        if 'amount_limit' in data:
            permission.amount_limit = Decimal(str(data['amount_limit']))
        
        if not existing_permission:
            db.session.add(permission)
        
        db.session.commit()
        
        return jsonify({
            'message': 'Role bank permission saved successfully',
            'permission': permission.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# =============================================================================
# BANK ACCOUNT STATISTICS
# =============================================================================

@bank_management_bp.route('/api/stats', methods=['GET'])
@login_required
def get_bank_stats():
    """Get bank account statistics"""
    try:
        if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN', 'WHITE_LABEL']:
            return jsonify({'error': 'Access denied'}), 403
        
        base_query = OrganizationBankAccount.query.filter(
            OrganizationBankAccount.tenant_id == current_user.tenant_id
        )
        
        total_accounts = base_query.count()
        active_accounts = base_query.filter(OrganizationBankAccount.status == BankAccountStatus.ACTIVE).count()
        inactive_accounts = base_query.filter(OrganizationBankAccount.status == BankAccountStatus.INACTIVE).count()
        
        # Calculate total balance across all accounts
        total_balance = db.session.query(
            db.func.coalesce(db.func.sum(OrganizationBankAccount.current_balance), 0)
        ).filter(
            OrganizationBankAccount.tenant_id == current_user.tenant_id,
            OrganizationBankAccount.status == BankAccountStatus.ACTIVE
        ).scalar()
        
        # Account types distribution
        account_types = {}
        for account_type in BankAccountType:
            count = base_query.filter(OrganizationBankAccount.account_type == account_type).count()
            if count > 0:
                account_types[account_type.value] = count
        
        # Today's transactions
        today = datetime.utcnow().date()
        today_transactions = BankAccountTransaction.query.join(OrganizationBankAccount).filter(
            OrganizationBankAccount.tenant_id == current_user.tenant_id,
            db.func.date(BankAccountTransaction.created_at) == today
        ).count()
        
        stats = {
            'total_accounts': total_accounts,
            'active_accounts': active_accounts,
            'inactive_accounts': inactive_accounts,
            'total_balance': float(total_balance),
            'account_types': account_types,
            'today_transactions': today_transactions
        }
        
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# BULK OPERATIONS
# =============================================================================

@bank_management_bp.route('/api/accounts/bulk-update', methods=['POST'])
@login_required
def bulk_update_accounts():
    """Bulk update bank accounts"""
    try:
        if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        account_ids = data.get('account_ids', [])
        action = data.get('action')
        value = data.get('value')
        
        if not account_ids or not action:
            return jsonify({'error': 'Account IDs and action are required'}), 400
        
        accounts = OrganizationBankAccount.query.filter(
            OrganizationBankAccount.id.in_(account_ids),
            OrganizationBankAccount.tenant_id == current_user.tenant_id
        ).all()
        
        if not accounts:
            return jsonify({'error': 'No accounts found'}), 404
        
        updated_count = 0
        
        for account in accounts:
            if action == 'activate':
                account.status = BankAccountStatus.ACTIVE
                updated_count += 1
            elif action == 'deactivate':
                account.status = BankAccountStatus.INACTIVE
                updated_count += 1
            elif action == 'update_priority' and value:
                try:
                    account.priority = int(value)
                    updated_count += 1
                except ValueError:
                    continue
            elif action == 'toggle_visibility':
                account.is_visible_to_users = not account.is_visible_to_users
                updated_count += 1
            
            account.last_updated_by = current_user.id
            account.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'message': f'Successfully updated {updated_count} accounts',
            'updated_count': updated_count,
            'total_requested': len(account_ids)
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500