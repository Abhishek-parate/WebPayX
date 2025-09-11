# routes/transaction_management.py
from flask import Blueprint, request, render_template, flash, redirect, url_for, jsonify, make_response
from flask_login import login_required, current_user
from models import (
    Transaction, Wallet, User, TransactionStatus, WalletTransactionType, 
    UserRoleType, db
)
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
import uuid
import json
import csv
import io
from functools import wraps
from sqlalchemy import and_, or_, desc, func

transaction_management_bp = Blueprint('transaction_management', __name__, url_prefix='/transaction-management')

# =============================================================================
# DECORATORS AND UTILITIES
# =============================================================================

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role.name not in ['SUPER_ADMIN', 'ADMIN', 'WHITE_LABEL']:
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role.name not in ['SUPER_ADMIN', 'ADMIN']:
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

def safe_decimal_conversion(value, default=Decimal('0')):
    """Safely convert value to Decimal"""
    try:
        return Decimal(str(value)) if value else default
    except (InvalidOperation, ValueError, TypeError):
        return default

def can_access_transaction(user, transaction):
    """Check if user can access transaction"""
    if user.role.name == 'SUPER_ADMIN':
        return True
    if user.role.name in ['ADMIN', 'WHITE_LABEL']:
        return transaction.wallet.user.tenant_id == user.tenant_id
    return transaction.wallet.user_id == user.id

# =============================================================================
# TRANSACTION MANAGEMENT PAGES
# =============================================================================

@transaction_management_bp.route('/')
@login_required
@admin_required
def index():
    """Enhanced transaction management dashboard"""
    try:
        # Base query with enhanced tenant filtering
        base_query = Transaction.query.join(Wallet).join(User)
        if current_user.role.name != 'SUPER_ADMIN':
            base_query = base_query.filter(User.tenant_id == current_user.tenant_id)
        
        # Additional role-based filtering
        if current_user.role.name == 'USER':
            base_query = base_query.filter(User.id == current_user.id)
        elif current_user.role.name in ['DISTRIBUTOR', 'MASTER_DISTRIBUTOR']:
            # Filter based on hierarchy (simplified)
            base_query = base_query.filter(User.created_by == current_user.id)
        
        # Comprehensive statistics
        total_transactions = base_query.count()
        
        # Status distribution with amounts
        status_stats = {}
        for status in TransactionStatus:
            status_query = base_query.filter(Transaction.status == status)
            count = status_query.count()
            if count > 0:
                total_amount = db.session.query(
                    func.coalesce(func.sum(Transaction.amount), 0)
                ).filter(
                    Transaction.id.in_([t.id for t in status_query.all()])
                ).scalar()
                
                status_stats[status.value] = {
                    'count': count,
                    'amount': float(total_amount or 0)
                }
        
        # Type distribution with amounts
        type_stats = {}
        for t_type in WalletTransactionType:
            type_query = base_query.filter(Transaction.type == t_type)
            count = type_query.count()
            if count > 0:
                total_amount = db.session.query(
                    func.coalesce(func.sum(Transaction.amount), 0)
                ).filter(
                    Transaction.id.in_([t.id for t in type_query.all()])
                ).scalar()
                
                type_stats[t_type.value] = {
                    'count': count,
                    'amount': float(total_amount or 0)
                }
        
        # Time-based statistics
        today = datetime.utcnow().date()
        yesterday = today - timedelta(days=1)
        week_ago = today - timedelta(days=7)
        month_ago = today - timedelta(days=30)
        
        today_transactions = base_query.filter(
            func.date(Transaction.created_at) == today
        ).count()
        
        yesterday_transactions = base_query.filter(
            func.date(Transaction.created_at) == yesterday
        ).count()
        
        week_transactions = base_query.filter(
            Transaction.created_at >= week_ago
        ).count()
        
        month_transactions = base_query.filter(
            Transaction.created_at >= month_ago
        ).count()
        
        # Total amounts
        today_amount = db.session.query(
            func.coalesce(func.sum(Transaction.amount), 0)
        ).select_from(Transaction).join(Wallet).join(User).filter(
            func.date(Transaction.created_at) == today,
            Transaction.status == TransactionStatus.COMPLETED
        )
        
        if current_user.role.name != 'SUPER_ADMIN':
            today_amount = today_amount.filter(User.tenant_id == current_user.tenant_id)
        
        today_amount = today_amount.scalar()
        
        # Recent transactions with enhanced data
        recent_transactions = base_query.order_by(
            desc(Transaction.created_at)
        ).limit(10).all()
        
        # Pending transactions requiring attention
        pending_transactions = base_query.filter(
            Transaction.status == TransactionStatus.PENDING
        ).order_by(desc(Transaction.created_at)).limit(5).all()
        
        # Failed transactions
        failed_transactions = base_query.filter(
            Transaction.status == TransactionStatus.FAILED
        ).filter(
            Transaction.created_at >= today - timedelta(days=1)
        ).count()
        
        stats = {
            'total_transactions': total_transactions,
            'status_stats': status_stats,
            'type_stats': type_stats,
            'today_transactions': today_transactions,
            'yesterday_transactions': yesterday_transactions,
            'week_transactions': week_transactions,
            'month_transactions': month_transactions,
            'today_amount': float(today_amount or 0),
            'recent_transactions': recent_transactions,
            'pending_transactions': pending_transactions,
            'failed_transactions': failed_transactions,
            'success_rate': ((status_stats.get('COMPLETED', {}).get('count', 0) / total_transactions * 100) 
                           if total_transactions > 0 else 0)
        }
        
        return render_template('transaction_management/index.html',
            title='Transaction Management',
            subtitle='Monitor & Manage All Transactions',
            stats=stats
        )
        
    except Exception as e:
        flash(f'Error loading transaction dashboard: {str(e)}', 'error')
        # Return safe dashboard with empty data
        empty_stats = {
            'total_transactions': 0, 'status_stats': {}, 'type_stats': {},
            'today_transactions': 0, 'yesterday_transactions': 0,
            'week_transactions': 0, 'month_transactions': 0, 'today_amount': 0.0,
            'recent_transactions': [], 'pending_transactions': [],
            'failed_transactions': 0, 'success_rate': 0.0
        }
        return render_template('transaction_management/index.html',
            title='Transaction Management',
            subtitle='Monitor & Manage All Transactions',
            stats=empty_stats
        )

@transaction_management_bp.route('/transactions')
@login_required
@admin_required
def transactions_page():
    """Enhanced transactions list with advanced filtering"""
    try:
        # Get filter parameters with validation
        page = max(request.args.get('page', 1, type=int), 1)
        per_page = min(max(request.args.get('per_page', 25, type=int), 10), 100)
        status_filter = request.args.get('status', '').strip()
        type_filter = request.args.get('type', '').strip()
        wallet_id = request.args.get('wallet_id', '').strip()
        user_id = request.args.get('user_id', '').strip()
        search = request.args.get('search', '').strip()
        date_from = request.args.get('date_from', '').strip()
        date_to = request.args.get('date_to', '').strip()
        amount_min = request.args.get('amount_min', '').strip()
        amount_max = request.args.get('amount_max', '').strip()
        sort_by = request.args.get('sort_by', 'created_at').strip()
        sort_order = request.args.get('sort_order', 'desc').strip()
        
        # Base query with proper joins
        query = Transaction.query.join(Wallet).join(User)
        
        # Apply tenant filtering
        if current_user.role.name != 'SUPER_ADMIN':
            query = query.filter(User.tenant_id == current_user.tenant_id)
        
        # Apply role-based filtering
        if current_user.role.name == 'USER':
            query = query.filter(User.id == current_user.id)
        elif current_user.role.name in ['DISTRIBUTOR', 'MASTER_DISTRIBUTOR']:
            # Filter based on user hierarchy
            query = query.filter(User.created_by == current_user.id)
        
        # Apply filters with validation
        if status_filter and status_filter != 'all':
            try:
                status_enum = TransactionStatus[status_filter.upper()]
                query = query.filter(Transaction.status == status_enum)
            except (KeyError, ValueError):
                flash(f'Invalid status filter: {status_filter}', 'warning')
        
        if type_filter and type_filter != 'all':
            try:
                type_enum = WalletTransactionType[type_filter.upper()]
                query = query.filter(Transaction.type == type_enum)
            except (KeyError, ValueError):
                flash(f'Invalid type filter: {type_filter}', 'warning')
        
        if wallet_id and validate_uuid(wallet_id):
            query = query.filter(Transaction.wallet_id == wallet_id)
        
        if user_id and validate_uuid(user_id):
            query = query.filter(Wallet.user_id == user_id)
        
        if search:
            search_pattern = f'%{search}%'
            query = query.filter(
                or_(
                    Transaction.reference_number.ilike(search_pattern),
                    Transaction.external_reference.ilike(search_pattern),
                    Transaction.description.ilike(search_pattern),
                    User.username.ilike(search_pattern),
                    User.email.ilike(search_pattern),
                    User.full_name.ilike(search_pattern)
                )
            )
        
        # Date range filtering
        if date_from:
            try:
                from_date = datetime.strptime(date_from, '%Y-%m-%d')
                query = query.filter(Transaction.created_at >= from_date)
            except ValueError:
                flash('Invalid from date format', 'warning')
        
        if date_to:
            try:
                to_date = datetime.strptime(date_to, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
                query = query.filter(Transaction.created_at <= to_date)
            except ValueError:
                flash('Invalid to date format', 'warning')
        
        # Amount range filtering
        if amount_min:
            try:
                min_amount = Decimal(amount_min)
                query = query.filter(Transaction.amount >= min_amount)
            except (InvalidOperation, ValueError):
                flash('Invalid minimum amount', 'warning')
        
        if amount_max:
            try:
                max_amount = Decimal(amount_max)
                query = query.filter(Transaction.amount <= max_amount)
            except (InvalidOperation, ValueError):
                flash('Invalid maximum amount', 'warning')
        
        # Apply sorting
        if sort_by in ['created_at', 'amount', 'status', 'type']:
            if sort_by == 'status':
                sort_column = Transaction.status
            elif sort_by == 'type':
                sort_column = Transaction.type
            elif sort_by == 'amount':
                sort_column = Transaction.amount
            else:
                sort_column = Transaction.created_at
            
            if sort_order == 'desc':
                sort_column = sort_column.desc()
            query = query.order_by(sort_column)
        else:
            query = query.order_by(desc(Transaction.created_at))
        
        # Execute query with pagination
        transactions = query.paginate(
            page=page, per_page=per_page, error_out=False, max_per_page=100
        )
        
        # Calculate summary statistics for current filter
        total_amount = db.session.query(
            func.coalesce(func.sum(Transaction.amount), 0)
        ).filter(
            Transaction.id.in_([t.id for t in query.all()])
        ).scalar()
        
        filter_summary = {
            'total_transactions': query.count(),
            'total_amount': float(total_amount or 0),
            'avg_amount': float(total_amount / query.count() if query.count() > 0 else 0)
        }
        
        return render_template('transaction_management/transactions.html',
            title='All Transactions',
            subtitle='View & Manage Transaction Records',
            transactions=transactions,
            filter_summary=filter_summary,
            current_filters={
                'status': status_filter, 'type': type_filter, 'wallet_id': wallet_id,
                'user_id': user_id, 'search': search, 'date_from': date_from,
                'date_to': date_to, 'amount_min': amount_min, 'amount_max': amount_max,
                'sort_by': sort_by, 'sort_order': sort_order
            },
            transaction_statuses=TransactionStatus,
            transaction_types=WalletTransactionType
        )
        
    except Exception as e:
        flash(f'Error loading transactions: {str(e)}', 'error')
        return redirect(url_for('transaction_management.index'))

@transaction_management_bp.route('/add-transaction', methods=['GET', 'POST'])
@login_required
@super_admin_required
def add_transaction_page():
    """Enhanced transaction creation with comprehensive validation"""
    if request.method == 'POST':
        try:
            # Extract and validate form data
            wallet_id = request.form.get('wallet_id', '').strip()
            amount = safe_decimal_conversion(request.form.get('amount', '0'))
            t_type = request.form.get('type', '').strip()
            status = request.form.get('status', TransactionStatus.PENDING.value).strip()
            description = request.form.get('description', '').strip()
            reference_number = request.form.get('reference_number', '').strip()
            external_reference = request.form.get('external_reference', '').strip()
            fees = safe_decimal_conversion(request.form.get('fees', '0'))
            tax_amount = safe_decimal_conversion(request.form.get('tax_amount', '0'))
            
            # Enhanced validation
            validation_errors = []
            
            if not wallet_id or not validate_uuid(wallet_id):
                validation_errors.append('Valid wallet ID is required')
            
            if amount <= 0:
                validation_errors.append('Amount must be greater than zero')
            
            if not t_type:
                validation_errors.append('Transaction type is required')
            
            if validation_errors:
                for error in validation_errors:
                    flash(error, 'error')
                return render_template('transaction_management/add_transaction.html',
                    title='Add Transaction',
                    subtitle='Create New Transaction Record',
                    wallets=get_available_wallets(),
                    transaction_types=WalletTransactionType,
                    transaction_statuses=TransactionStatus
                )
            
            # Validate wallet exists and access
            wallet = Wallet.query.get(wallet_id)
            if not wallet:
                flash('Wallet not found', 'error')
                return render_template('transaction_management/add_transaction.html',
                    title='Add Transaction',
                    subtitle='Create New Transaction Record',
                    wallets=get_available_wallets(),
                    transaction_types=WalletTransactionType,
                    transaction_statuses=TransactionStatus
                )
            
            # Permission check
            if not can_access_user(current_user, wallet.user):
                flash('Access denied to this wallet', 'error')
                return render_template('transaction_management/add_transaction.html',
                    title='Add Transaction',
                    subtitle='Create New Transaction Record',
                    wallets=get_available_wallets(),
                    transaction_types=WalletTransactionType,
                    transaction_statuses=TransactionStatus
                )
            
            # Validate transaction type
            try:
                transaction_type = WalletTransactionType[t_type.upper()]
            except (KeyError, ValueError):
                flash('Invalid transaction type', 'error')
                return render_template('transaction_management/add_transaction.html',
                    title='Add Transaction',
                    subtitle='Create New Transaction Record',
                    wallets=get_available_wallets(),
                    transaction_types=WalletTransactionType,
                    transaction_statuses=TransactionStatus
                )
            
            # Validate transaction status
            try:
                transaction_status = TransactionStatus[status.upper()]
            except (KeyError, ValueError):
                transaction_status = TransactionStatus.PENDING
            
            # Balance validation for withdrawal/transfer
            total_deduction = amount + fees + tax_amount
            if t_type.upper() in ['WITHDRAWAL', 'TRANSFER'] and wallet.available_balance < total_deduction:
                flash(f'Insufficient balance. Available: ₹{wallet.available_balance}, Required: ₹{total_deduction}', 'error')
                return render_template('transaction_management/add_transaction.html',
                    title='Add Transaction',
                    subtitle='Create New Transaction Record',
                    wallets=get_available_wallets(),
                    transaction_types=WalletTransactionType,
                    transaction_statuses=TransactionStatus
                )
            
            # Generate reference number if not provided
            if not reference_number:
                reference_number = f"TXN{datetime.utcnow().strftime('%Y%m%d%H%M%S')}{wallet.user.id}"
            
            # Check for duplicate reference number
            if Transaction.query.filter_by(reference_number=reference_number).first():
                flash('Reference number already exists', 'error')
                return render_template('transaction_management/add_transaction.html',
                    title='Add Transaction',
                    subtitle='Create New Transaction Record',
                    wallets=get_available_wallets(),
                    transaction_types=WalletTransactionType,
                    transaction_statuses=TransactionStatus
                )
            
            # Calculate balance changes
            balance_before = wallet.balance
            if t_type.upper() == 'DEPOSIT':
                balance_after = balance_before + amount
            elif t_type.upper() in ['WITHDRAWAL', 'TRANSFER']:
                balance_after = balance_before - total_deduction
            else:
                balance_after = balance_before
            
            # Create transaction record
            transaction = Transaction(
                wallet_id=wallet.id,
                type=transaction_type,
                amount=amount,
                balance_before=balance_before,
                balance_after=balance_after,
                status=transaction_status,
                description=description,
                reference_number=reference_number,
                external_reference=external_reference or None,
                fees=fees,
                tax_amount=tax_amount,
                net_amount=amount - fees - tax_amount,
                created_by=current_user.id
            )
            
            # Update wallet balance if transaction is completed
            if transaction_status == TransactionStatus.COMPLETED:
                if t_type.upper() == 'DEPOSIT':
                    wallet.balance += amount
                elif t_type.upper() in ['WITHDRAWAL', 'TRANSFER']:
                    wallet.balance -= total_deduction
                
                wallet.updated_at = datetime.utcnow()
            
            db.session.add(transaction)
            db.session.commit()
            
            flash(f'Transaction created successfully with reference: {reference_number}', 'success')
            return redirect(url_for('transaction_management.transaction_details_page', 
                                  transaction_id=transaction.id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating transaction: {str(e)}', 'error')
    
    # GET request - show form with available data
    return render_template('transaction_management/add_transaction.html',
        title='Add Transaction',
        subtitle='Create New Transaction Record',
        wallets=get_available_wallets(),
        transaction_types=WalletTransactionType,
        transaction_statuses=TransactionStatus
    )

@transaction_management_bp.route('/transaction/<transaction_id>')
@login_required
@admin_required
def transaction_details_page(transaction_id):
    """Enhanced transaction details with comprehensive information"""
    if not validate_uuid(transaction_id):
        flash('Invalid transaction ID', 'error')
        return redirect(url_for('transaction_management.transactions_page'))
    
    try:
        transaction = Transaction.query.get(transaction_id)
        if not transaction:
            flash('Transaction not found', 'error')
            return redirect(url_for('transaction_management.transactions_page'))
        
        # Permission check
        if not can_access_transaction(current_user, transaction):
            flash('Access denied', 'error')
            return redirect(url_for('transaction_management.transactions_page'))
        
        # Get related transactions (if any)
        related_transactions = []
        if transaction.external_reference:
            related_transactions = Transaction.query.filter(
                Transaction.external_reference == transaction.external_reference,
                Transaction.id != transaction.id
            ).all()
        
        # Calculate transaction timeline
        timeline = []
        if transaction.created_at:
            timeline.append({
                'event': 'Transaction Created',
                'timestamp': transaction.created_at,
                'description': f'Transaction initiated by {transaction.created_by_user.username if transaction.created_by_user else "System"}'
            })
        
        if transaction.updated_at and transaction.updated_at != transaction.created_at:
            timeline.append({
                'event': 'Transaction Updated',
                'timestamp': transaction.updated_at,
                'description': f'Transaction modified by {transaction.updated_by_user.username if transaction.updated_by_user else "System"}'
            })
        
        if transaction.status == TransactionStatus.COMPLETED and transaction.completed_at:
            timeline.append({
                'event': 'Transaction Completed',
                'timestamp': transaction.completed_at,
                'description': 'Transaction successfully processed'
            })
        
        # Sort timeline by timestamp
        timeline.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return render_template('transaction_management/transaction_details.html',
            title=f'Transaction - {transaction.reference_number}',
            subtitle='Detailed Transaction Information',
            transaction=transaction,
            related_transactions=related_transactions,
            timeline=timeline
        )
        
    except Exception as e:
        flash(f'Error loading transaction details: {str(e)}', 'error')
        return redirect(url_for('transaction_management.transactions_page'))

@transaction_management_bp.route('/transaction/<transaction_id>/edit', methods=['GET', 'POST'])
@login_required
@super_admin_required
def edit_transaction_page(transaction_id):
    """Enhanced transaction editing with validation"""
    if not validate_uuid(transaction_id):
        flash('Invalid transaction ID', 'error')
        return redirect(url_for('transaction_management.transactions_page'))
    
    try:
        transaction = Transaction.query.get(transaction_id)
        if not transaction:
            flash('Transaction not found', 'error')
            return redirect(url_for('transaction_management.transactions_page'))
        
        # Permission check
        if not can_access_transaction(current_user, transaction):
            flash('Access denied', 'error')
            return redirect(url_for('transaction_management.transactions_page'))
        
        if request.method == 'POST':
            # Validate if transaction can be edited
            if transaction.status in [TransactionStatus.COMPLETED, TransactionStatus.CANCELLED]:
                flash(f'Cannot edit {transaction.status.value.lower()} transaction', 'error')
                return redirect(url_for('transaction_management.transaction_details_page', 
                                      transaction_id=transaction.id))
            
            # Update allowed fields
            old_status = transaction.status
            transaction.description = request.form.get('description', transaction.description).strip()
            transaction.external_reference = request.form.get('external_reference', 
                                                            transaction.external_reference or '').strip() or None
            
            # Handle fees and tax with validation
            new_fees = safe_decimal_conversion(request.form.get('fees', str(transaction.fees)))
            new_tax = safe_decimal_conversion(request.form.get('tax_amount', str(transaction.tax_amount)))
            
            if new_fees >= 0:
                transaction.fees = new_fees
            if new_tax >= 0:
                transaction.tax_amount = new_tax
            
            # Handle status change with enhanced validation
            new_status = request.form.get('status', '').strip()
            if new_status and new_status.upper() != transaction.status.value:
                try:
                    new_status_enum = TransactionStatus[new_status.upper()]
                    
                    # Validate status transitions
                    valid_transitions = {
                        TransactionStatus.PENDING: [TransactionStatus.PROCESSING, TransactionStatus.COMPLETED, TransactionStatus.FAILED, TransactionStatus.CANCELLED],
                        TransactionStatus.PROCESSING: [TransactionStatus.COMPLETED, TransactionStatus.FAILED, TransactionStatus.CANCELLED],
                        TransactionStatus.FAILED: [TransactionStatus.PENDING, TransactionStatus.CANCELLED],
                        TransactionStatus.COMPLETED: [],  # No transitions from completed
                        TransactionStatus.CANCELLED: []   # No transitions from cancelled
                    }
                    
                    if new_status_enum not in valid_transitions.get(transaction.status, []):
                        flash(f'Invalid status transition from {transaction.status.value} to {new_status_enum.value}', 'error')
                        return render_template('transaction_management/edit_transaction.html',
                            title=f'Edit Transaction - {transaction.reference_number}',
                            subtitle='Modify Transaction Details',
                            transaction=transaction,
                            transaction_statuses=TransactionStatus
                        )
                    
                    # Update wallet balance if status changed to/from completed
                    if old_status != TransactionStatus.COMPLETED and new_status_enum == TransactionStatus.COMPLETED:
                        # Apply balance change
                        wallet = transaction.wallet
                        total_amount = transaction.amount + transaction.fees + transaction.tax_amount
                        
                        if transaction.type == WalletTransactionType.DEPOSIT:
                            wallet.balance += transaction.amount
                        elif transaction.type in [WalletTransactionType.WITHDRAWAL, WalletTransactionType.TRANSFER]:
                            if wallet.balance >= total_amount:
                                wallet.balance -= total_amount
                            else:
                                flash('Insufficient wallet balance to complete transaction', 'error')
                                return render_template('transaction_management/edit_transaction.html',
                                    title=f'Edit Transaction - {transaction.reference_number}',
                                    subtitle='Modify Transaction Details',
                                    transaction=transaction,
                                    transaction_statuses=TransactionStatus
                                )
                        
                        wallet.updated_at = datetime.utcnow()
                        transaction.completed_at = datetime.utcnow()
                    
                    elif old_status == TransactionStatus.COMPLETED and new_status_enum != TransactionStatus.COMPLETED:
                        # Reverse balance change
                        wallet = transaction.wallet
                        total_amount = transaction.amount + transaction.fees + transaction.tax_amount
                        
                        if transaction.type == WalletTransactionType.DEPOSIT:
                            wallet.balance -= transaction.amount
                        elif transaction.type in [WalletTransactionType.WITHDRAWAL, WalletTransactionType.TRANSFER]:
                            wallet.balance += total_amount
                        
                        wallet.updated_at = datetime.utcnow()
                        transaction.completed_at = None
                    
                    transaction.status = new_status_enum
                    
                except (KeyError, ValueError):
                    flash('Invalid status specified', 'error')
                    return render_template('transaction_management/edit_transaction.html',
                        title=f'Edit Transaction - {transaction.reference_number}',
                        subtitle='Modify Transaction Details',
                        transaction=transaction,
                        transaction_statuses=TransactionStatus
                    )
            
            # Update net amount
            transaction.net_amount = transaction.amount - transaction.fees - transaction.tax_amount
            transaction.updated_by = current_user.id
            transaction.updated_at = datetime.utcnow()
            
            db.session.commit()
            
            flash('Transaction updated successfully', 'success')
            return redirect(url_for('transaction_management.transaction_details_page', 
                                  transaction_id=transaction.id))
        
        return render_template('transaction_management/edit_transaction.html',
            title=f'Edit Transaction - {transaction.reference_number}',
            subtitle='Modify Transaction Details',
            transaction=transaction,
            transaction_statuses=TransactionStatus
        )
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating transaction: {str(e)}', 'error')
        return redirect(url_for('transaction_management.transaction_details_page', 
                              transaction_id=transaction_id))

@transaction_management_bp.route('/transaction/<transaction_id>/cancel', methods=['POST'])
@login_required
@super_admin_required
def cancel_transaction(transaction_id):
    """Enhanced transaction cancellation with proper validation"""
    if not validate_uuid(transaction_id):
        return jsonify({'error': 'Invalid transaction ID'}), 400
    
    try:
        transaction = Transaction.query.get(transaction_id)
        if not transaction:
            return jsonify({'error': 'Transaction not found'}), 404
        
        # Permission check
        if not can_access_transaction(current_user, transaction):
            return jsonify({'error': 'Access denied'}), 403
        
        # Validate if transaction can be cancelled
        if transaction.status in [TransactionStatus.COMPLETED, TransactionStatus.CANCELLED]:
            return jsonify({
                'error': f'Cannot cancel {transaction.status.value.lower()} transaction'
            }), 400
        
        # Reverse wallet balance changes if transaction was processing
        if transaction.status == TransactionStatus.PROCESSING:
            wallet = transaction.wallet
            total_amount = transaction.amount + transaction.fees + transaction.tax_amount
            
            if transaction.type == WalletTransactionType.DEPOSIT:
                wallet.balance -= transaction.amount
            elif transaction.type in [WalletTransactionType.WITHDRAWAL, WalletTransactionType.TRANSFER]:
                wallet.balance += total_amount
            
            wallet.updated_at = datetime.utcnow()
        
        # Mark transaction as cancelled
        transaction.status = TransactionStatus.CANCELLED
        transaction.updated_by = current_user.id
        transaction.updated_at = datetime.utcnow()
        transaction.cancelled_at = datetime.utcnow()
        
        db.session.commit()
        
        if request.is_json:
            return jsonify({
                'success': True,
                'message': 'Transaction cancelled successfully',
                'transaction_id': str(transaction.id),
                'new_status': transaction.status.value
            })
        else:
            flash('Transaction cancelled successfully', 'success')
            return redirect(url_for('transaction_management.transaction_details_page', 
                                  transaction_id=transaction.id))
        
    except Exception as e:
        db.session.rollback()
        error_msg = f'Error cancelling transaction: {str(e)}'
        
        if request.is_json:
            return jsonify({'error': error_msg}), 500
        else:
            flash(error_msg, 'error')
            return redirect(url_for('transaction_management.transaction_details_page', 
                                  transaction_id=transaction_id))

@transaction_management_bp.route('/reports')
@login_required
@admin_required
def reports_page():
    """Enhanced transaction reports with comprehensive analytics"""
    try:
        # Get report parameters
        date_from = request.args.get('date_from', '').strip()
        date_to = request.args.get('date_to', '').strip()
        status_filter = request.args.get('status', '').strip()
        type_filter = request.args.get('type', '').strip()
        user_id = request.args.get('user_id', '').strip()
        
        # Base query
        query = Transaction.query.join(Wallet).join(User)
        
        if current_user.role.name != 'SUPER_ADMIN':
            query = query.filter(User.tenant_id == current_user.tenant_id)
        
        # Apply filters
        if date_from:
            try:
                from_date = datetime.strptime(date_from, '%Y-%m-%d')
                query = query.filter(Transaction.created_at >= from_date)
            except ValueError:
                flash('Invalid from date format', 'warning')
        
        if date_to:
            try:
                to_date = datetime.strptime(date_to, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
                query = query.filter(Transaction.created_at <= to_date)
            except ValueError:
                flash('Invalid to date format', 'warning')
        
        if status_filter and status_filter != 'all':
            try:
                status_enum = TransactionStatus[status_filter.upper()]
                query = query.filter(Transaction.status == status_enum)
            except (KeyError, ValueError):
                pass
        
        if type_filter and type_filter != 'all':
            try:
                type_enum = WalletTransactionType[type_filter.upper()]
                query = query.filter(Transaction.type == type_enum)
            except (KeyError, ValueError):
                pass
        
        if user_id and validate_uuid(user_id):
            query = query.filter(Wallet.user_id == user_id)
        
        # Generate comprehensive summary
        all_transactions = query.all()
        
        summary = {
            'total_transactions': len(all_transactions),
            'total_volume': 0,
            'total_fees': 0,
            'total_tax': 0,
            'net_volume': 0,
            'by_status': {},
            'by_type': {},
            'by_date': {},
            'top_users': {},
            'hourly_distribution': {}
        }
        
        # Calculate comprehensive statistics
        for transaction in all_transactions:
            amount = float(transaction.amount)
            fees = float(transaction.fees or 0)
            tax = float(transaction.tax_amount or 0)
            
            summary['total_volume'] += amount
            summary['total_fees'] += fees
            summary['total_tax'] += tax
            summary['net_volume'] += float(transaction.net_amount or amount)
            
            # By status
            status = transaction.status.value
            if status not in summary['by_status']:
                summary['by_status'][status] = {'count': 0, 'volume': 0, 'fees': 0}
            summary['by_status'][status]['count'] += 1
            summary['by_status'][status]['volume'] += amount
            summary['by_status'][status]['fees'] += fees
            
            # By type
            t_type = transaction.type.value
            if t_type not in summary['by_type']:
                summary['by_type'][t_type] = {'count': 0, 'volume': 0, 'fees': 0}
            summary['by_type'][t_type]['count'] += 1
            summary['by_type'][t_type]['volume'] += amount
            summary['by_type'][t_type]['fees'] += fees
            
            # By date
            date_key = transaction.created_at.date().isoformat()
            if date_key not in summary['by_date']:
                summary['by_date'][date_key] = {'count': 0, 'volume': 0}
            summary['by_date'][date_key]['count'] += 1
            summary['by_date'][date_key]['volume'] += amount
            
            # Top users
            user_key = transaction.wallet.user.username
            if user_key not in summary['top_users']:
                summary['top_users'][user_key] = {'count': 0, 'volume': 0}
            summary['top_users'][user_key]['count'] += 1
            summary['top_users'][user_key]['volume'] += amount
            
            # Hourly distribution
            hour_key = transaction.created_at.hour
            if hour_key not in summary['hourly_distribution']:
                summary['hourly_distribution'][hour_key] = {'count': 0, 'volume': 0}
            summary['hourly_distribution'][hour_key]['count'] += 1
            summary['hourly_distribution'][hour_key]['volume'] += amount
        
        # Sort top users by volume
        summary['top_users'] = dict(sorted(
            summary['top_users'].items(),
            key=lambda x: x[1]['volume'],
            reverse=True
        )[:10])
        
        return render_template('transaction_management/reports.html',
            title='Transaction Reports',
            subtitle='Comprehensive Transaction Analytics',
            summary=summary,
            filters={
                'date_from': date_from, 'date_to': date_to,
                'status': status_filter, 'type': type_filter,
                'user_id': user_id
            },
            transaction_statuses=TransactionStatus,
            transaction_types=WalletTransactionType
        )
        
    except Exception as e:
        flash(f'Error generating report: {str(e)}', 'error')
        empty_summary = {
            'total_transactions': 0, 'total_volume': 0, 'total_fees': 0,
            'total_tax': 0, 'net_volume': 0, 'by_status': {}, 'by_type': {},
            'by_date': {}, 'top_users': {}, 'hourly_distribution': {}
        }
        return render_template('transaction_management/reports.html',
            title='Transaction Reports',
            subtitle='Comprehensive Transaction Analytics',
            summary=empty_summary,
            filters={
                'date_from': '', 'date_to': '', 'status': '', 'type': '', 'user_id': ''
            },
            transaction_statuses=TransactionStatus,
            transaction_types=WalletTransactionType
        )

# =============================================================================
# API ENDPOINTS
# =============================================================================

@transaction_management_bp.route('/api/transactions', methods=['GET'])
@login_required
@admin_required
def api_get_transactions():
    """API endpoint to get transactions list"""
    try:
        # Get parameters
        limit = min(int(request.args.get('limit', 50)), 100)
        offset = max(int(request.args.get('offset', 0)), 0)
        status = request.args.get('status', '')
        user_id = request.args.get('user_id', '')
        
        # Base query
        query = Transaction.query.join(Wallet).join(User)
        
        if current_user.role.name != 'SUPER_ADMIN':
            query = query.filter(User.tenant_id == current_user.tenant_id)
        
        # Apply filters
        if status:
            try:
                status_enum = TransactionStatus[status.upper()]
                query = query.filter(Transaction.status == status_enum)
            except (KeyError, ValueError):
                pass
        
        if user_id and validate_uuid(user_id):
            query = query.filter(Wallet.user_id == user_id)
        
        # Get transactions with pagination
        transactions = query.order_by(desc(Transaction.created_at)).offset(offset).limit(limit).all()
        total_count = query.count()
        
        transactions_data = []
        for txn in transactions:
            transaction_data = {
                'id': str(txn.id),
                'reference_number': txn.reference_number,
                'type': txn.type.value,
                'amount': float(txn.amount),
                'status': txn.status.value,
                'description': txn.description,
                'created_at': txn.created_at.isoformat() if txn.created_at else None,
                'wallet_id': str(txn.wallet_id),
                'user': {
                    'id': str(txn.wallet.user.id),
                    'username': txn.wallet.user.username,
                    'full_name': txn.wallet.user.full_name
                }
            }
            transactions_data.append(transaction_data)
        
        return jsonify({
            'success': True,
            'transactions': transactions_data,
            'total': total_count,
            'limit': limit,
            'offset': offset
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@transaction_management_bp.route('/api/transaction/<transaction_id>/status', methods=['PUT'])
@login_required
@super_admin_required
def api_update_transaction_status(transaction_id):
    """API endpoint to update transaction status"""
    if not validate_uuid(transaction_id):
        return jsonify({'error': 'Invalid transaction ID'}), 400
    
    try:
        data = request.get_json()
        new_status = data.get('status', '').strip().upper()
        
        if not new_status:
            return jsonify({'error': 'Status is required'}), 400
        
        try:
            status_enum = TransactionStatus[new_status]
        except (KeyError, ValueError):
            return jsonify({'error': 'Invalid status'}), 400
        
        transaction = Transaction.query.get(transaction_id)
        if not transaction:
            return jsonify({'error': 'Transaction not found'}), 404
        
        # Permission check
        if not can_access_transaction(current_user, transaction):
            return jsonify({'error': 'Access denied'}), 403
        
        old_status = transaction.status
        transaction.status = status_enum
        transaction.updated_by = current_user.id
        transaction.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Transaction status updated from {old_status.value} to {status_enum.value}',
            'transaction_id': str(transaction.id),
            'old_status': old_status.value,
            'new_status': status_enum.value
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# =============================================================================
# EXPORT FUNCTIONALITY
# =============================================================================

@transaction_management_bp.route('/export/transactions')
@login_required
@admin_required
def export_transactions():
    """Export transactions data to CSV"""
    try:
        # Get filter parameters
        status_filter = request.args.get('status', '')
        type_filter = request.args.get('type', '')
        date_from = request.args.get('date_from', '')
        date_to = request.args.get('date_to', '')
        
        # Base query
        query = Transaction.query.join(Wallet).join(User)
        
        if current_user.role.name != 'SUPER_ADMIN':
            query = query.filter(User.tenant_id == current_user.tenant_id)
        
        # Apply filters (same logic as reports_page)
        if status_filter and status_filter != 'all':
            try:
                status_enum = TransactionStatus[status_filter.upper()]
                query = query.filter(Transaction.status == status_enum)
            except (KeyError, ValueError):
                pass
        
        if type_filter and type_filter != 'all':
            try:
                type_enum = WalletTransactionType[type_filter.upper()]
                query = query.filter(Transaction.type == type_enum)
            except (KeyError, ValueError):
                pass
        
        if date_from:
            try:
                from_date = datetime.strptime(date_from, '%Y-%m-%d')
                query = query.filter(Transaction.created_at >= from_date)
            except ValueError:
                pass
        
        if date_to:
            try:
                to_date = datetime.strptime(date_to, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
                query = query.filter(Transaction.created_at <= to_date)
            except ValueError:
                pass
        
        transactions = query.order_by(desc(Transaction.created_at)).all()
        
        # Create CSV
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Reference Number', 'User', 'Type', 'Amount', 'Fees', 'Tax', 'Net Amount',
            'Status', 'Description', 'Balance Before', 'Balance After',
            'External Reference', 'Created At', 'Updated At'
        ])
        
        # Write data
        for txn in transactions:
            writer.writerow([
                txn.reference_number or '',
                txn.wallet.user.username,
                txn.type.value,
                float(txn.amount),
                float(txn.fees or 0),
                float(txn.tax_amount or 0),
                float(txn.net_amount or 0),
                txn.status.value,
                txn.description or '',
                float(txn.balance_before or 0),
                float(txn.balance_after or 0),
                txn.external_reference or '',
                txn.created_at.strftime('%Y-%m-%d %H:%M:%S') if txn.created_at else '',
                txn.updated_at.strftime('%Y-%m-%d %H:%M:%S') if txn.updated_at else ''
            ])
        
        # Prepare response
        output.seek(0)
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv; charset=utf-8'
        response.headers['Content-Disposition'] = f'attachment; filename="transactions_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv"'
        
        return response
        
    except Exception as e:
        flash(f'Error exporting transactions: {str(e)}', 'error')
        return redirect(url_for('transaction_management.reports_page'))

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_available_wallets():
    """Get wallets available to current user"""
    try:
        wallets_query = Wallet.query.join(User)
        
        if current_user.role.name != 'SUPER_ADMIN':
            wallets_query = wallets_query.filter(User.tenant_id == current_user.tenant_id)
        
        return wallets_query.order_by(User.username).all()
    except Exception:
        return []

def can_access_user(current_user, target_user):
    """Check if current user can access target user"""
    if current_user.role.name == 'SUPER_ADMIN':
        return True
    if current_user.role.name in ['ADMIN', 'WHITE_LABEL']:
        return target_user.tenant_id == current_user.tenant_id
    return target_user.id == current_user.id
