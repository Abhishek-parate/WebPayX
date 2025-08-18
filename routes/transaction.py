# routes/transaction_management.py
from flask import Blueprint, request, render_template, flash, redirect, url_for
from flask_login import login_required, current_user
from models import (
    Transaction, Wallet, User, TransactionStatus, WalletTransactionType, 
    UserRoleType, db
)
from datetime import datetime
from decimal import Decimal
import uuid

transaction_management_bp = Blueprint('transaction_management', __name__, url_prefix='/transaction')

# =================
# TRANSACTION MANAGEMENT PAGES
# =================

@transaction_management_bp.route('/')
@login_required
def index():
    """Transaction management dashboard"""
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN', 'WHITE_LABEL']:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard.index'))
    
    # Get transaction statistics for dashboard
    try:
        # Base query with tenant filtering
        base_query = Transaction.query.join(Wallet).join(User)
        if current_user.role.value not in ['SUPER_ADMIN']:
            base_query = base_query.filter(User.tenant_id == current_user.tenant_id)
        
        # Total transactions
        total_transactions = base_query.count()
        
        # Status distribution
        status_stats = {}
        for status in TransactionStatus:
            count = base_query.filter(Transaction.status == status).count()
            if count > 0:
                status_stats[status.value] = count
        
        # Type distribution
        type_stats = {}
        for t_type in WalletTransactionType:
            count = base_query.filter(Transaction.type == t_type).count()
            if count > 0:
                type_stats[t_type.value] = count
        
        # Today's transactions
        today = datetime.utcnow().date()
        today_transactions = base_query.filter(
            db.func.date(Transaction.created_at) == today
        ).count()
        
        # Recent transactions (last 10)
        recent_transactions = base_query.order_by(
            Transaction.created_at.desc()
        ).limit(10).all()
        
    except Exception as e:
        flash(f'Error loading dashboard data: {str(e)}', 'error')
        total_transactions = 0
        status_stats = {}
        type_stats = {}
        today_transactions = 0
        recent_transactions = []
    
    return render_template('transaction_management/index.html',
        title='Transaction Management',
        subtitle='Manage User Transactions',
        total_transactions=total_transactions,
        status_stats=status_stats,
        type_stats=type_stats,
        today_transactions=today_transactions,
        recent_transactions=recent_transactions
    )

@transaction_management_bp.route('/transactions')
@login_required
def transactions_page():
    """Transactions list page with filtering and pagination"""
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN', 'WHITE_LABEL']:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard.index'))
    
    # Get filter parameters
    page = request.args.get('page', 1, type=int)
    per_page = 25
    status_filter = request.args.get('status')
    type_filter = request.args.get('type')
    wallet_id = request.args.get('wallet_id')
    user_id = request.args.get('user_id')
    search = request.args.get('search', '')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    
    try:
        # Base query with joins
        query = Transaction.query.join(Wallet).join(User)
        
        # Apply tenant filtering based on user role
        if current_user.role.value not in ['SUPER_ADMIN']:
            query = query.filter(User.tenant_id == current_user.tenant_id)
        
        # Apply additional role-based filtering
        if current_user.role.value == 'USER':
            query = query.filter(User.id == current_user.id)
        elif current_user.role.value in ['AGENT', 'DISTRIBUTOR']:
            # Filter based on hierarchy if implemented
            pass
        
        # Apply filters
        if status_filter:
            try:
                status_enum = TransactionStatus(status_filter.upper())
                query = query.filter(Transaction.status == status_enum)
            except ValueError:
                pass
        
        if type_filter:
            try:
                type_enum = WalletTransactionType(type_filter.upper())
                query = query.filter(Transaction.type == type_enum)
            except ValueError:
                pass
        
        if wallet_id:
            query = query.filter(Transaction.wallet_id == wallet_id)
        
        if user_id:
            query = query.filter(Wallet.user_id == user_id)
        
        if search:
            query = query.filter(
                db.or_(
                    Transaction.reference_number.ilike(f'%{search}%'),
                    Transaction.external_reference.ilike(f'%{search}%'),
                    Transaction.description.ilike(f'%{search}%'),
                    User.username.ilike(f'%{search}%'),
                    User.email.ilike(f'%{search}%')
                )
            )
        
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
        
        # Paginate results
        transactions = query.order_by(Transaction.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
    except Exception as e:
        flash(f'Error loading transactions: {str(e)}', 'error')
        transactions = None
    
    return render_template('transaction_management/transactions.html',
        title='Transactions',
        subtitle='View & Manage Transactions',
        transactions=transactions,
        current_filters={
            'status': status_filter,
            'type': type_filter,
            'wallet_id': wallet_id,
            'user_id': user_id,
            'search': search,
            'date_from': date_from,
            'date_to': date_to
        },
        transaction_statuses=TransactionStatus,
        transaction_types=WalletTransactionType
    )

@transaction_management_bp.route('/add-transaction', methods=['GET', 'POST'])
@login_required
def add_transaction_page():
    """Add new transaction page"""
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
        flash('Access denied', 'error')
        return redirect(url_for('transaction_management.index'))
    
    if request.method == 'POST':
        try:
            # Get form data
            wallet_id = request.form.get('wallet_id')
            amount = Decimal(str(request.form.get('amount')))
            t_type = request.form.get('type')
            status = request.form.get('status', TransactionStatus.PENDING.value)
            description = request.form.get('description', '')
            reference_number = request.form.get('reference_number')
            external_reference = request.form.get('external_reference')
            fees = Decimal(str(request.form.get('fees') or '0'))
            tax_amount = Decimal(str(request.form.get('tax_amount') or '0'))
            
            # Validate required fields
            if not wallet_id or not amount or not t_type:
                flash('Wallet, amount, and type are required', 'error')
                return redirect(request.url)
            
            # Validate wallet exists
            wallet = Wallet.query.get(wallet_id)
            if not wallet:
                flash('Wallet not found', 'error')
                return redirect(request.url)
            
            # Permission check
            if not current_user.can_access_user(wallet.user):
                flash('Access denied to this wallet', 'error')
                return redirect(request.url)
            
            # Validate transaction amount
            if amount <= 0:
                flash('Amount must be positive', 'error')
                return redirect(request.url)
            
            # Validate transaction type
            try:
                transaction_type = WalletTransactionType(t_type)
            except ValueError:
                flash('Invalid transaction type', 'error')
                return redirect(request.url)
            
            # Balance validation for withdrawal/transfer
            if t_type in ['WITHDRAWAL', 'TRANSFER'] and wallet.available_balance < amount:
                flash('Insufficient balance', 'error')
                return redirect(request.url)
            
            # Calculate balance before and after
            balance_before = wallet.balance
            if t_type == 'DEPOSIT':
                balance_after = balance_before + amount
            elif t_type in ['WITHDRAWAL', 'TRANSFER']:
                balance_after = balance_before - amount
            else:
                balance_after = balance_before
            
            # Create transaction record
            transaction = Transaction(
                wallet_id=wallet.id,
                type=transaction_type,
                amount=amount,
                balance_before=balance_before,
                balance_after=balance_after,
                status=TransactionStatus(status),
                description=description,
                reference_number=reference_number,
                external_reference=external_reference,
                fees=fees,
                tax_amount=tax_amount,
                net_amount=amount - fees,
                created_by=current_user.id,
                created_at=datetime.utcnow()
            )
            
            # Update wallet balance accordingly
            if t_type == 'DEPOSIT':
                wallet.balance += amount
            elif t_type in ['WITHDRAWAL', 'TRANSFER']:
                wallet.balance -= amount
            
            wallet.updated_at = datetime.utcnow()
            
            db.session.add(transaction)
            db.session.commit()
            
            flash('Transaction created successfully', 'success')
            return redirect(url_for('transaction_management.transaction_details_page', 
                                  transaction_id=transaction.id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating transaction: {str(e)}', 'error')
            return redirect(request.url)
    
    # GET request - show form
    # Get available wallets for the dropdown
    try:
        wallets_query = Wallet.query.join(User)
        
        if current_user.role.value not in ['SUPER_ADMIN']:
            wallets_query = wallets_query.filter(User.tenant_id == current_user.tenant_id)
        
        wallets = wallets_query.all()
        
    except Exception as e:
        flash(f'Error loading wallets: {str(e)}', 'error')
        wallets = []
    
    return render_template('transaction_management/add_transaction.html',
        title='Add Transaction',
        subtitle='Create New Transaction',
        wallets=wallets,
        transaction_types=WalletTransactionType,
        transaction_statuses=TransactionStatus
    )

@transaction_management_bp.route('/transaction/<transaction_id>')
@login_required
def transaction_details_page(transaction_id):
    """Transaction details page"""
    try:
        transaction = Transaction.query.filter(
            Transaction.id == transaction_id
        ).first()
        
        if not transaction:
            flash('Transaction not found', 'error')
            return redirect(url_for('transaction_management.transactions_page'))
        
        # Permission check
        if not current_user.can_access_user(transaction.wallet.user):
            flash('Access denied', 'error')
            return redirect(url_for('transaction_management.transactions_page'))
        
    except Exception as e:
        flash(f'Error loading transaction: {str(e)}', 'error')
        return redirect(url_for('transaction_management.transactions_page'))
    
    return render_template('transaction_management/transaction_details.html',
        title=f'Transaction - {transaction.id}',
        subtitle='Transaction Details',
        transaction=transaction
    )

@transaction_management_bp.route('/transaction/<transaction_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_transaction_page(transaction_id):
    """Edit transaction page"""
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
        flash('Access denied', 'error')
        return redirect(url_for('transaction_management.transaction_details_page', 
                              transaction_id=transaction_id))
    
    try:
        transaction = Transaction.query.get(transaction_id)
        if not transaction:
            flash('Transaction not found', 'error')
            return redirect(url_for('transaction_management.transactions_page'))
        
        # Permission check
        if not current_user.can_access_user(transaction.wallet.user):
            flash('Access denied', 'error')
            return redirect(url_for('transaction_management.transactions_page'))
        
        if request.method == 'POST':
            # Update allowed fields
            transaction.description = request.form.get('description', transaction.description)
            transaction.external_reference = request.form.get('external_reference', 
                                                            transaction.external_reference)
            
            # Handle fees and tax
            if request.form.get('fees'):
                transaction.fees = Decimal(str(request.form.get('fees')))
            if request.form.get('tax_amount'):
                transaction.tax_amount = Decimal(str(request.form.get('tax_amount')))
            
            # Handle status change with validation
            new_status = request.form.get('status')
            if new_status and new_status != transaction.status.value:
                try:
                    new_status_enum = TransactionStatus(new_status.upper())
                    
                    # Validate status transitions
                    if transaction.status == TransactionStatus.COMPLETED and new_status_enum != TransactionStatus.COMPLETED:
                        flash('Cannot modify completed transaction status', 'error')
                        return redirect(request.url)
                    
                    if transaction.status == TransactionStatus.CANCELLED and new_status_enum != TransactionStatus.CANCELLED:
                        flash('Cannot modify cancelled transaction status', 'error')
                        return redirect(request.url)
                    
                    transaction.status = new_status_enum
                except ValueError:
                    flash('Invalid status specified', 'error')
                    return redirect(request.url)
            
            # Update net amount
            transaction.net_amount = transaction.amount - transaction.fees - transaction.tax_amount
            
            transaction.updated_by = current_user.id
            transaction.updated_at = datetime.utcnow()
            
            db.session.commit()
            
            flash('Transaction updated successfully', 'success')
            return redirect(url_for('transaction_management.transaction_details_page', 
                                  transaction_id=transaction.id))
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating transaction: {str(e)}', 'error')
        return redirect(url_for('transaction_management.transaction_details_page', 
                              transaction_id=transaction_id))
    
    return render_template('transaction_management/edit_transaction.html',
        title=f'Edit Transaction - {transaction.id}',
        subtitle='Edit Transaction Details',
        transaction=transaction,
        transaction_statuses=TransactionStatus
    )

@transaction_management_bp.route('/transaction/<transaction_id>/cancel', methods=['POST'])
@login_required
def cancel_transaction_page(transaction_id):
    """Cancel a transaction"""
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
        flash('Access denied', 'error')
        return redirect(url_for('transaction_management.transaction_details_page', 
                              transaction_id=transaction_id))
    
    try:
        transaction = Transaction.query.get(transaction_id)
        if not transaction:
            flash('Transaction not found', 'error')
            return redirect(url_for('transaction_management.transactions_page'))
        
        # Permission check
        if not current_user.can_access_user(transaction.wallet.user):
            flash('Access denied', 'error')
            return redirect(url_for('transaction_management.transactions_page'))
        
        # Validate if transaction can be cancelled
        if transaction.status in [TransactionStatus.COMPLETED, TransactionStatus.CANCELLED]:
            flash(f'Cannot cancel {transaction.status.value.lower()} transaction', 'error')
            return redirect(url_for('transaction_management.transaction_details_page', 
                                  transaction_id=transaction_id))
        
        # Reverse wallet balance changes if needed
        if transaction.status == TransactionStatus.PROCESSING:
            wallet = transaction.wallet
            if transaction.type == WalletTransactionType.DEPOSIT:
                wallet.balance -= transaction.amount
            elif transaction.type in [WalletTransactionType.WITHDRAWAL, WalletTransactionType.TRANSFER]:
                wallet.balance += transaction.amount
            
            wallet.updated_at = datetime.utcnow()
        
        # Mark transaction as cancelled
        transaction.status = TransactionStatus.CANCELLED
        transaction.updated_by = current_user.id
        transaction.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        flash('Transaction cancelled successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error cancelling transaction: {str(e)}', 'error')
    
    return redirect(url_for('transaction_management.transaction_details_page', 
                          transaction_id=transaction_id))

@transaction_management_bp.route('/reports')
@login_required
def reports_page():
    """Transaction reports page"""
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN', 'WHITE_LABEL']:
        flash('Access denied', 'error')
        return redirect(url_for('transaction_management.index'))
    
    # Get report parameters
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    
    try:
        # Base query
        query = Transaction.query.join(Wallet).join(User)
        
        if current_user.role.value not in ['SUPER_ADMIN']:
            query = query.filter(User.tenant_id == current_user.tenant_id)
        
        # Date filtering
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
        
        # Generate summary
        summary = {
            'total_transactions': query.count(),
            'total_volume': 0,
            'by_status': {},
            'by_type': {},
        }
        
        # Calculate totals by status and type
        for status in TransactionStatus:
            filtered_query = query.filter(Transaction.status == status)
            count = filtered_query.count()
            if count > 0:
                volume = db.session.query(
                    db.func.coalesce(db.func.sum(Transaction.amount), 0)
                ).filter(
                    Transaction.id.in_([t.id for t in filtered_query.all()])
                ).scalar()
                
                summary['by_status'][status.value] = {
                    'count': count,
                    'volume': float(volume or 0)
                }
                summary['total_volume'] += float(volume or 0)
        
        for t_type in WalletTransactionType:
            filtered_query = query.filter(Transaction.type == t_type)
            count = filtered_query.count()
            if count > 0:
                volume = db.session.query(
                    db.func.coalesce(db.func.sum(Transaction.amount), 0)
                ).filter(
                    Transaction.id.in_([t.id for t in filtered_query.all()])
                ).scalar()
                
                summary['by_type'][t_type.value] = {
                    'count': count,
                    'volume': float(volume or 0)
                }
        
    except Exception as e:
        flash(f'Error generating report: {str(e)}', 'error')
        summary = {
            'total_transactions': 0,
            'total_volume': 0,
            'by_status': {},
            'by_type': {},
        }
    
    return render_template('transaction_management/reports.html',
        title='Transaction Reports',
        subtitle='Transaction Analytics & Reports',
        summary=summary,
        date_from=date_from,
        date_to=date_to
    )