from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, make_response
from flask_login import login_required, current_user
from models import (
    db, Wallet, WalletTransaction, WalletTopupRequest, OrganizationBankAccount, 
    TransactionStatus, TopupMethod, UserRoleType, User, PaymentGateway, TransactionMode,
    WalletTransactionType
)
from datetime import datetime
from decimal import Decimal
import csv
import io
from sqlalchemy import or_
from werkzeug.utils import secure_filename
import os


wallet_management_bp = Blueprint('wallet_management', __name__, url_prefix='/wallet')

# File upload configuration
UPLOAD_FOLDER = 'uploads/receipts'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def can_request_topup(user):
    """Check if user role can request wallet top-up"""
    allowed_roles = [
        UserRoleType.MASTER_DISTRIBUTOR,
        UserRoleType.DISTRIBUTOR,
        UserRoleType.RETAILER
    ]
    return user.role in allowed_roles

def can_approve_topup(user, topup_request):
    """Check if user can approve/reject a top-up request"""
    # Only users above in hierarchy can approve
    if user.role in [UserRoleType.SUPER_ADMIN, UserRoleType.ADMIN, UserRoleType.WHITE_LABEL]:
        return True
    
    # Check if user is in the hierarchy path above the requester
    requester = User.query.get(topup_request.user_id)
    if requester and requester.tree_path and str(user.id) in requester.tree_path:
        return True
    
    return False

def get_hierarchical_users(user):
    """Get users in the hierarchy that this user can see"""
    if user.role in [UserRoleType.SUPER_ADMIN, UserRoleType.ADMIN]:
        # Admin can see all users in their tenant
        return User.query.filter_by(tenant_id=user.tenant_id)
    elif user.role == UserRoleType.WHITE_LABEL:
        # White label can see all users they created or below them
        return User.query.filter(
            or_(
                User.created_by == user.id,
                User.tree_path.contains(str(user.id))
            )
        )
    else:
        # Other roles can only see their direct children
        return User.query.filter_by(parent_id=user.id)

@wallet_management_bp.route('/')
@login_required
def dashboard():
    """Wallet dashboard with overview"""
    wallet = current_user.wallet
    if not wallet:
        flash('Wallet not found. Please contact administrator.', 'error')
        return redirect(url_for('main.index'))
    
    # Recent transactions
    recent_transactions = WalletTransaction.query.filter_by(
        wallet_id=wallet.id
    ).order_by(WalletTransaction.created_at.desc()).limit(5).all()
    
    # Stats
    stats = {
        'total_credit': db.session.query(db.func.sum(WalletTransaction.amount)).filter_by(
            wallet_id=wallet.id, 
            transaction_type=WalletTransactionType.CREDIT
        ).scalar() or 0,
        'total_debit': db.session.query(db.func.sum(WalletTransaction.amount)).filter_by(
            wallet_id=wallet.id, 
            transaction_type=WalletTransactionType.DEBIT
        ).scalar() or 0,
        'transaction_count': WalletTransaction.query.filter_by(wallet_id=wallet.id).count(),
        'pending_topups': WalletTopupRequest.query.filter_by(
            user_id=current_user.id, 
            status=TransactionStatus.PENDING
        ).count()
    }
    
    # For admin/white_label - show pending approvals
    pending_approvals = []
    if current_user.role in [UserRoleType.SUPER_ADMIN, UserRoleType.ADMIN, UserRoleType.WHITE_LABEL]:
        hierarchical_user_ids = [u.id for u in get_hierarchical_users(current_user).all()]
        pending_approvals = WalletTopupRequest.query.filter(
            WalletTopupRequest.user_id.in_(hierarchical_user_ids),
            WalletTopupRequest.status == TransactionStatus.PENDING
        ).order_by(WalletTopupRequest.created_at.desc()).limit(10).all()
    
    return render_template('wallet/dashboard.html', 
                         wallet=wallet, 
                         recent_transactions=recent_transactions,
                         stats=stats,
                         pending_approvals=pending_approvals,
                         can_request=can_request_topup(current_user))

@wallet_management_bp.route('/topup', methods=['GET', 'POST'])
@login_required
def topup():
    """Enhanced wallet top-up with file upload and detailed form"""
    if not can_request_topup(current_user):
        flash('Your role is not authorized to request wallet top-up. Only Master Distributors, Distributors, and Retailers can request top-up.', 'error')
        return redirect(url_for('wallet_management.dashboard'))
    
    if request.method == 'POST':
        try:
            # Extract form data
            amount = Decimal(str(request.form.get('amount', '0')))
            method = request.form.get('topup_method')
            bank_account_id = request.form.get('bank_account_id')
            payment_gateway_id = request.form.get('payment_gateway_id')
            transaction_mode = request.form.get('transaction_mode')
            utr_number = request.form.get('utr_number', '').strip()
            bank_reference = request.form.get('bank_reference', '').strip()
            upi_ref = request.form.get('upi_ref', '').strip()
            external_transaction_id = request.form.get('external_transaction_id', '').strip()
            remarks = request.form.get('remarks', '').strip()
            depositor_name = request.form.get('depositor_name', '').strip()
            depositor_phone = request.form.get('depositor_phone', '').strip()
            
            # Validation
            if amount < Decimal('100') or amount > Decimal('100000'):
                flash('Amount must be between ₹100 and ₹1,00,000', 'error')
                return redirect(url_for('wallet_management.topup'))
            
            if method not in [e.value for e in TopupMethod]:
                flash('Invalid top-up method selected', 'error')
                return redirect(url_for('wallet_management.topup'))
            
            # File upload handling for manual payments
            proof_document_path = None
            if method == 'MANUAL_REQUEST':
                if 'payment_receipt' not in request.files:
                    flash('Payment receipt is required for manual requests', 'error')
                    return redirect(url_for('wallet_management.topup'))
                
                file = request.files['payment_receipt']
                if file.filename == '':
                    flash('Please select a receipt file', 'error')
                    return redirect(url_for('wallet_management.topup'))
                
                if file and allowed_file(file.filename):
                    # Check file size
                    file.seek(0, 2)  # Seek to end
                    file_length = file.tell()
                    file.seek(0)  # Reset to beginning
                    
                    if file_length > MAX_FILE_SIZE:
                        flash('File size must be less than 5MB', 'error')
                        return redirect(url_for('wallet_management.topup'))
                    
                    # Create uploads directory if it doesn't exist
                    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
                    
                    # Save file with secure filename
                    filename = secure_filename(file.filename)
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    filename = f"{current_user.user_code}_{timestamp}_{filename}"
                    proof_document_path = os.path.join(UPLOAD_FOLDER, filename)
                    file.save(proof_document_path)
                else:
                    flash('Invalid file type. Please upload JPG, PNG, or PDF files only', 'error')
                    return redirect(url_for('wallet_management.topup'))
                
                if not transaction_mode:
                    flash('Transaction mode is required for manual payments', 'error')
                    return redirect(url_for('wallet_management.topup'))
            
            # Validate bank account or payment gateway
            selected_bank = None
            selected_gateway = None
            
            if method == 'MANUAL_REQUEST' and bank_account_id:
                selected_bank = OrganizationBankAccount.query.get(bank_account_id)
                if not selected_bank or selected_bank.tenant_id != current_user.tenant_id:
                    flash('Invalid bank account selected', 'error')
                    return redirect(url_for('wallet_management.topup'))
            
            if method == 'PAYMENT_GATEWAY' and payment_gateway_id:
                selected_gateway = PaymentGateway.query.get(payment_gateway_id)
                if not selected_gateway or selected_gateway.tenant_id != current_user.tenant_id:
                    flash('Invalid payment gateway selected', 'error')
                    return redirect(url_for('wallet_management.topup'))
            
            # Prepare payment details
            payment_details = {
                'depositor_name': depositor_name,
                'depositor_phone': depositor_phone,
                'transaction_mode': transaction_mode,
                'utr_number': utr_number,
                'bank_reference': bank_reference,
                'upi_ref': upi_ref,
                'external_transaction_id': external_transaction_id
            }
            
            # Create top-up request
            new_request = WalletTopupRequest(
                request_id=f"TOPUP-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{current_user.user_code}",
                user_id=current_user.id,
                requested_by=current_user.id,
                amount=amount,
                net_amount=amount,
                topup_method=TopupMethod(method),
                transaction_mode=TransactionMode(transaction_mode) if transaction_mode else None,
                selected_bank_account_id=bank_account_id if bank_account_id else None,
                payment_gateway_id=payment_gateway_id if payment_gateway_id else None,
                utr_number=utr_number if utr_number else None,
                bank_reference=bank_reference if bank_reference else None,
                upi_ref=upi_ref if upi_ref else None,
                external_transaction_id=external_transaction_id if external_transaction_id else None,
                request_remarks=remarks,
                proof_document=proof_document_path,
                payment_details=payment_details,
                status=TransactionStatus.PENDING,
                expires_at=datetime.utcnow().replace(hour=23, minute=59, second=59)
            )
            
            db.session.add(new_request)
            db.session.commit()
            
            success_message = 'Top-up request submitted successfully!'
            if method == 'MANUAL_REQUEST':
                success_message += ' Your request will be processed within 2-24 hours after verification.'
            else:
                success_message += ' You will be redirected to the payment gateway shortly.'
            
            flash(success_message, 'success')
            return redirect(url_for('wallet_management.topup_status'))
            
        except ValueError:
            flash('Invalid amount entered', 'error')
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while processing your request. Please try again.', 'error')
            print(f"Topup error: {str(e)}")  # For debugging
            
        return redirect(url_for('wallet_management.topup'))
    
    # GET method - fetch required data
    bank_accounts = OrganizationBankAccount.query.filter_by(
        tenant_id=current_user.tenant_id, 
        status='ACTIVE', 
        is_visible_to_users=True
    ).order_by(OrganizationBankAccount.is_primary.desc(), OrganizationBankAccount.priority.asc()).all()
    
    payment_gateways = PaymentGateway.query.filter_by(
        tenant_id=current_user.tenant_id,
        status='ACTIVE'
    ).order_by(PaymentGateway.priority.asc()).all()
    
    return render_template('wallet/topup.html', 
                         bank_accounts=bank_accounts, 
                         payment_gateways=payment_gateways)

@wallet_management_bp.route('/topup/status')
@login_required
def topup_status():
    """View top-up request status"""
    # Users can see their own requests
    requests = WalletTopupRequest.query.filter_by(
        user_id=current_user.id
    ).order_by(WalletTopupRequest.created_at.desc()).all()
    
    return render_template('wallet/topup_status.html', 
                         requests=requests,
                         can_request=can_request_topup(current_user))


@wallet_management_bp.route('/all-transactions')
@login_required
def all_transactions():
    """View all transactions in hierarchy (Admin/White Label only)"""
    if current_user.role not in [UserRoleType.SUPER_ADMIN, UserRoleType.ADMIN, UserRoleType.WHITE_LABEL]:
        flash('Access denied. Only administrators can view all transactions.', 'error')
        return redirect(url_for('wallet_management.dashboard'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 25
    
    # Get hierarchical users
    hierarchical_users = get_hierarchical_users(current_user).all()
    hierarchical_user_ids = [u.id for u in hierarchical_users]
    
    # Get wallet IDs
    wallet_ids = [w.id for w in Wallet.query.filter(Wallet.user_id.in_(hierarchical_user_ids)).all()]
    
    # Build query
    query = WalletTransaction.query.filter(WalletTransaction.wallet_id.in_(wallet_ids))
    
    # Apply filters
    user_filter = request.args.get('user_id')
    txn_type = request.args.get('type')
    from_date = request.args.get('from_date')
    to_date = request.args.get('to_date')
    
    if user_filter and user_filter != 'all':
        user_wallet = Wallet.query.filter_by(user_id=user_filter).first()
        if user_wallet:
            query = query.filter(WalletTransaction.wallet_id == user_wallet.id)
    
    if txn_type:
        query = query.filter(WalletTransaction.transaction_type == txn_type)
    
    if from_date:
        try:
            from_dt = datetime.strptime(from_date, '%Y-%m-%d')
            query = query.filter(WalletTransaction.created_at >= from_dt)
        except ValueError:
            flash('Invalid from date format', 'error')
    
    if to_date:
        try:
            to_dt = datetime.strptime(to_date, '%Y-%m-%d')
            to_dt = to_dt.replace(hour=23, minute=59, second=59)
            query = query.filter(WalletTransaction.created_at <= to_dt)
        except ValueError:
            flash('Invalid to date format', 'error')
    
    # Export to CSV if requested
    if request.args.get('export') == 'csv':
        return export_all_transactions_csv(query)
    
    # Paginate
    transactions = query.order_by(WalletTransaction.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Add user details to transactions
    for txn in transactions.items:
        wallet = Wallet.query.get(txn.wallet_id)
        if wallet:
            txn.user = User.query.get(wallet.user_id)
    
    return render_template('wallet/all_transactions.html', 
                         transactions=transactions,
                         hierarchical_users=hierarchical_users)


def export_all_transactions_csv(query):
    """Export all transactions to CSV for admins"""
    transactions = query.order_by(WalletTransaction.created_at.desc()).all()
    
    csv_io = io.StringIO()
    writer = csv.writer(csv_io)
    
    # Write header
    writer.writerow([
        'Date', 'Time', 'User Code', 'User Name', 'Type', 'Amount', 
        'Balance Before', 'Balance After', 'Description', 'Reference ID'
    ])
    
    # Write data
    for txn in transactions:
        wallet = Wallet.query.get(txn.wallet_id)
        user = User.query.get(wallet.user_id) if wallet else None
        
        writer.writerow([
            txn.created_at.strftime('%Y-%m-%d') if txn.created_at else '',
            txn.created_at.strftime('%H:%M:%S') if txn.created_at else '',
            user.user_code if user else '',
            user.full_name if user else '',
            txn.transaction_type.value if txn.transaction_type else '',
            f"{txn.amount:.2f}",
            f"{txn.balance_before:.2f}",
            f"{txn.balance_after:.2f}",
            txn.description or '',
            str(txn.reference_id) if txn.reference_id else ''
        ])
    
    output = make_response(csv_io.getvalue())
    output.headers["Content-Disposition"] = f"attachment; filename=all_wallet_transactions_{datetime.now().strftime('%Y%m%d')}.csv"
    output.headers["Content-type"] = "text/csv"
    
    return output


@wallet_management_bp.route('/topup/approve/<request_id>', methods=['POST'])
@login_required
def approve_topup(request_id):
    """Approve/Reject top-up request"""
    topup_request = WalletTopupRequest.query.get_or_404(request_id)
    
    # Check permission
    if not can_approve_topup(current_user, topup_request):
        flash('You are not authorized to approve this request', 'error')
        return redirect(url_for('wallet_management.pending_approvals'))
    
    action = request.form.get('action')
    admin_remarks = request.form.get('admin_remarks', '')
    
    try:
        if action == 'approve':
            topup_request.status = TransactionStatus.SUCCESS
            topup_request.approved_by = current_user.id
            topup_request.processed_at = datetime.utcnow()
            topup_request.admin_remarks = admin_remarks
            
            # Credit wallet
            user_wallet = Wallet.query.filter_by(user_id=topup_request.user_id).first()
            if user_wallet:
                old_balance = user_wallet.balance
                user_wallet.balance += topup_request.net_amount
                user_wallet.total_credited += topup_request.net_amount
                user_wallet.last_transaction_at = datetime.utcnow()
                
                # Create wallet transaction
                wallet_txn = WalletTransaction(
                    wallet_id=user_wallet.id,
                    transaction_type=WalletTransactionType.CREDIT,
                    amount=topup_request.net_amount,
                    balance_before=old_balance,
                    balance_after=user_wallet.balance,
                    reference_id=topup_request.id,
                    reference_type='WALLET_TOPUP',
                    description=f'Wallet top-up approved by {current_user.full_name}',
                    processed_by=current_user.id
                )
                db.session.add(wallet_txn)
            
            flash('Top-up request approved successfully', 'success')
            
        elif action == 'reject':
            topup_request.status = TransactionStatus.FAILED
            topup_request.approved_by = current_user.id
            topup_request.processed_at = datetime.utcnow()
            topup_request.admin_remarks = admin_remarks
            topup_request.failure_reason = 'Rejected by approver'
            
            flash('Top-up request rejected', 'info')
        
        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while processing the request', 'error')
    
    return redirect(url_for('wallet_management.pending_approvals'))

@wallet_management_bp.route('/pending-approvals')
@login_required
def pending_approvals():
    """View pending approval requests (Admin/White Label only)"""
    if current_user.role not in [UserRoleType.SUPER_ADMIN, UserRoleType.ADMIN, UserRoleType.WHITE_LABEL]:
        flash('Access denied. Only administrators can view pending approvals.', 'error')
        return redirect(url_for('wallet_management.dashboard'))
    
    # Get hierarchical users
    hierarchical_user_ids = [u.id for u in get_hierarchical_users(current_user).all()]
    
    # Get pending requests
    pending_requests = WalletTopupRequest.query.filter(
        WalletTopupRequest.user_id.in_(hierarchical_user_ids),
        WalletTopupRequest.status == TransactionStatus.PENDING
    ).order_by(WalletTopupRequest.created_at.desc()).all()
    
    # Include user details
    for req in pending_requests:
        req.requesting_user = User.query.get(req.user_id)
        if req.selected_bank_account_id:
            req.selected_bank = OrganizationBankAccount.query.get(req.selected_bank_account_id)
    
    return render_template('wallet/pending_approvals.html', 
                         pending_requests=pending_requests)

# Rest of your existing methods...
@wallet_management_bp.route('/transactions')
@login_required
def transactions():
    """View own transaction history"""
    if not current_user.wallet:
        flash('Wallet not found. Please contact administrator.', 'error')
        return redirect(url_for('main.index'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    query = WalletTransaction.query.filter_by(wallet_id=current_user.wallet.id)
    
    # Apply filters
    txn_type = request.args.get('type')
    from_date = request.args.get('from_date')
    to_date = request.args.get('to_date')
    
    if txn_type:
        query = query.filter(WalletTransaction.transaction_type == txn_type)
    if from_date:
        try:
            from_dt = datetime.strptime(from_date, '%Y-%m-%d')
            query = query.filter(WalletTransaction.created_at >= from_dt)
        except ValueError:
            flash('Invalid from date format', 'error')
    if to_date:
        try:
            to_dt = datetime.strptime(to_date, '%Y-%m-%d')
            to_dt = to_dt.replace(hour=23, minute=59, second=59)
            query = query.filter(WalletTransaction.created_at <= to_dt)
        except ValueError:
            flash('Invalid to date format', 'error')
    
    if request.args.get('export') == 'csv':
        return export_transactions_csv(query)
    
    transactions = query.order_by(WalletTransaction.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('wallet/transactions.html', transactions=transactions)

def export_transactions_csv(query):
    """Export transactions to CSV"""
    transactions = query.order_by(WalletTransaction.created_at.desc()).all()
    
    csv_io = io.StringIO()
    writer = csv.writer(csv_io)
    
    writer.writerow([
        'Date', 'Time', 'Type', 'Amount', 'Balance Before', 
        'Balance After', 'Description', 'Reference ID'
    ])
    
    for txn in transactions:
        writer.writerow([
            txn.created_at.strftime('%Y-%m-%d') if txn.created_at else '',
            txn.created_at.strftime('%H:%M:%S') if txn.created_at else '',
            txn.transaction_type.value if txn.transaction_type else '',
            f"{txn.amount:.2f}",
            f"{txn.balance_before:.2f}",
            f"{txn.balance_after:.2f}",
            txn.description or '',
            str(txn.reference_id) if txn.reference_id else ''
        ])
    
    output = make_response(csv_io.getvalue())
    output.headers["Content-Disposition"] = f"attachment; filename=wallet_transactions_{datetime.now().strftime('%Y%m%d')}.csv"
    output.headers["Content-type"] = "text/csv"
    
    return output

# Utility routes
@wallet_management_bp.route('/balance')
@login_required
def get_balance():
    """Get current wallet balance (AJAX endpoint)"""
    if not current_user.wallet:
        return jsonify({'error': 'Wallet not found'}), 404
    
    wallet = current_user.wallet
    return jsonify({
        'balance': float(wallet.balance),
        'hold_balance': float(wallet.hold_balance),
        'available_balance': float(wallet.available_balance),
        'daily_remaining': float(wallet.daily_remaining),
        'monthly_remaining': float(wallet.monthly_remaining)
    })

@wallet_management_bp.route('/limits')
@login_required
def limits():
    """View wallet limits and usage"""
    if not current_user.wallet:
        flash('Wallet not found. Please contact administrator.', 'error')
        return redirect(url_for('main.index'))
    
    wallet = current_user.wallet
    return render_template('wallet/limits.html', wallet=wallet)
