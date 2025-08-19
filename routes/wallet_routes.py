# routes/wallet_topup.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app
from flask_login import login_required, current_user
from sqlalchemy import desc, or_
from models import (
    db, User, UserRoleType, WalletTopupRequest, TopupMethod,
    TransactionStatus, TransactionMode, Wallet, WalletTransaction,
    WalletTransactionType, OrganizationBankAccount, BankAccountStatus
)
from datetime import datetime, timedelta
import uuid
from decimal import Decimal
import os
from werkzeug.utils import secure_filename

# Create the blueprint
wallet_topup_bp = Blueprint('wallet_topup', __name__, url_prefix='/wallet')

# Helper function to check if user can make topup requests
def can_request_topup(user):
    return user.role in [
        UserRoleType.MASTER_DISTRIBUTOR,
        UserRoleType.DISTRIBUTOR,
        UserRoleType.RETAILER
    ]

# Helper function to check if user can approve topup requests
def can_approve_topup(user):
    return user.role in [
        UserRoleType.SUPER_ADMIN,
        UserRoleType.ADMIN,
        UserRoleType.WHITE_LABEL
    ]

# Helper function to get available bank accounts for user
def get_available_bank_accounts(user):
    """Get bank accounts available for the user based on role"""
    if user.role in [UserRoleType.SUPER_ADMIN, UserRoleType.ADMIN]:
        # Admins can see all active bank accounts
        return OrganizationBankAccount.query.filter(
            OrganizationBankAccount.tenant_id == user.tenant_id,
            OrganizationBankAccount.status == BankAccountStatus.ACTIVE,
            OrganizationBankAccount.is_visible_to_users == True
        ).order_by(OrganizationBankAccount.display_order).all()
    
    elif user.role == UserRoleType.WHITE_LABEL:
        # White label can see accounts assigned to their tenant
        return OrganizationBankAccount.query.filter(
            OrganizationBankAccount.tenant_id == user.tenant_id,
            OrganizationBankAccount.status == BankAccountStatus.ACTIVE,
            OrganizationBankAccount.is_visible_to_users == True
        ).order_by(OrganizationBankAccount.display_order).all()
    
    else:
        # Others can only see accounts their parent has made available
        if not user.parent_id:
            return []
        
        # Get parent user
        parent = User.query.get(user.parent_id)
        if not parent:
            return []
            
        return OrganizationBankAccount.query.filter(
            OrganizationBankAccount.tenant_id == user.tenant_id,
            OrganizationBankAccount.status == BankAccountStatus.ACTIVE,
            OrganizationBankAccount.is_visible_to_users == True
        ).order_by(OrganizationBankAccount.display_order).all()

# Helper function to get users who can be requested for topup
def get_topup_requestable_users(user):
    """Get users that the current user can request topups from"""
    if not user.tree_path:
        return []
    
    # Get parent hierarchy from tree path
    parent_ids = user.tree_path.split('/')
    if len(parent_ids) <= 1:  # Only has self in path
        return []
    
    # Get immediate parent and higher level parents
    parent_users = User.query.filter(
        User.id.in_(parent_ids),
        User.id != user.id,
        User.is_active == True
    ).all()
    
    return parent_users

# Routes
@wallet_topup_bp.route('/')
@login_required
def index():
    """Wallet dashboard"""
    return redirect(url_for('wallet_topup.topup_request'))

@wallet_topup_bp.route('/topup-request', methods=['GET'])
@login_required
def topup_request():
    """Wallet top-up request page"""
    if not can_request_topup(current_user):
        flash('You do not have permission to make topup requests.', 'error')
        return redirect(url_for('dashboard.index'))
    
    # Get available bank accounts
    bank_accounts = get_available_bank_accounts(current_user)
    
    # Get users who can be requested for topup
    requestable_users = get_topup_requestable_users(current_user)
    
    # Get available payment methods
    payment_modes = [mode.value for mode in TransactionMode]
    
    return render_template(
        'wallet/topup_request.html',
        title='Wallet Top-up Request',
        bank_accounts=bank_accounts,
        requestable_users=requestable_users,
        payment_modes=payment_modes
    )

@wallet_topup_bp.route('/topup-request', methods=['POST'])
@login_required
def submit_topup_request():
    """Submit a wallet top-up request"""
    if not can_request_topup(current_user):
        return jsonify({'success': False, 'message': 'You do not have permission to make topup requests.'}), 403
    
    try:
        # Get form data
        topup_method = request.form.get('topup_method')
        amount = request.form.get('amount')
        transaction_mode = request.form.get('transaction_mode')
        bank_account_id = request.form.get('bank_account_id')
        remarks = request.form.get('remarks', '')
        external_transaction_id = request.form.get('external_transaction_id', '')
        utr_number = request.form.get('utr_number', '')
        
        # Validate data
        if not amount or not topup_method:
            return jsonify({'success': False, 'message': 'Please provide all required fields.'}), 400
        
        # Validate amount
        try:
            amount = Decimal(amount)
            if amount <= 0:
                return jsonify({'success': False, 'message': 'Amount must be greater than zero.'}), 400
        except:
            return jsonify({'success': False, 'message': 'Invalid amount.'}), 400
            
        # Create topup request object
        topup_request = WalletTopupRequest(
            request_id=f"TOPUP-{uuid.uuid4().hex[:8].upper()}",
            user_id=current_user.id,
            requested_by=current_user.id,
            topup_method=TopupMethod(topup_method),
            amount=amount,
            net_amount=amount,  # Adjusted if there are fees
            transaction_mode=TransactionMode(transaction_mode) if transaction_mode else None,
            external_transaction_id=external_transaction_id,
            utr_number=utr_number,
            status=TransactionStatus.PENDING,
            request_remarks=remarks,
            ip_address=request.remote_addr,
            device_info={'user_agent': request.user_agent.string},
            expires_at=datetime.utcnow() + timedelta(days=2)
        )
        
        # Set bank account if provided
        if bank_account_id:
            topup_request.selected_bank_account_id = bank_account_id
        
        # Handle file upload for proof document
        if 'proof_document' in request.files:
            file = request.files['proof_document']
            if file and file.filename:
                # Create upload directory if it doesn't exist
                upload_dir = os.path.join(current_app.static_folder, 'uploads', 'topup_proofs')
                os.makedirs(upload_dir, exist_ok=True)
                
                # Generate a secure filename
                filename = secure_filename(f"{current_user.id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
                file_path = os.path.join(upload_dir, filename)
                
                # Save the file
                file.save(file_path)
                
                # Store the relative path
                topup_request.proof_document = f'/static/uploads/topup_proofs/{filename}'
        
        # Save to database
        db.session.add(topup_request)
        db.session.commit()
        
        flash('Top-up request submitted successfully!', 'success')
        return jsonify({'success': True, 'message': 'Top-up request submitted successfully!', 'request_id': topup_request.request_id})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'An error occurred: {str(e)}'}), 500

@wallet_topup_bp.route('/my-requests')
@login_required
def my_requests():
    """View user's own topup requests"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    status = request.args.get('status', None)
    
    # Build query
    query = WalletTopupRequest.query.filter_by(user_id=current_user.id)
    
    # Apply status filter if provided
    if status:
        query = query.filter_by(status=TransactionStatus(status))
    
    # Order by created date, newest first
    query = query.order_by(desc(WalletTopupRequest.created_at))
    
    # Paginate results
    topup_requests = query.paginate(page=page, per_page=per_page)
    
    return render_template(
        'wallet/my_requests.html',
        title='My Top-up Requests',
        topup_requests=topup_requests,
        TransactionStatus=TransactionStatus
    )

@wallet_topup_bp.route('/request-details/<request_id>')
@login_required
def request_details(request_id):
    """View details of a specific topup request"""
    topup_request = WalletTopupRequest.query.filter_by(request_id=request_id).first_or_404()
    
    # Check if user has permission to view this request
    if topup_request.user_id != current_user.id and not can_approve_topup(current_user):
        flash('You do not have permission to view this request.', 'error')
        return redirect(url_for('wallet_topup.my_requests'))
    
    return render_template(
        'wallet/request_details.html',
        title='Top-up Request Details',
        topup_request=topup_request,
        TransactionStatus=TransactionStatus
    )

@wallet_topup_bp.route('/pending-approvals')
@login_required
def pending_approvals():
    """View topup requests pending approval (for admins/white labels)"""
    if not can_approve_topup(current_user):
        flash('You do not have permission to view pending approvals.', 'error')
        return redirect(url_for('dashboard.index'))
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    # Build query based on user's role and tree path
    if current_user.role == UserRoleType.SUPER_ADMIN:
        # Super admin can see all pending requests
        query = WalletTopupRequest.query.filter_by(status=TransactionStatus.PENDING)
    else:
        # Others can only see requests from their downline
        query = WalletTopupRequest.query.join(User, WalletTopupRequest.user_id == User.id)
        
        if current_user.tree_path:
            # Filter by tree path (users who have current user in their path)
            query = query.filter(User.tree_path.like(f"{current_user.tree_path}%"))
        else:
            # Fallback if tree path is not set
            query = query.filter(User.parent_id == current_user.id)
        
        query = query.filter(WalletTopupRequest.status == TransactionStatus.PENDING)
    
    # Order by created date, oldest first (FIFO)
    query = query.order_by(WalletTopupRequest.created_at)
    
    # Paginate results
    pending_requests = query.paginate(page=page, per_page=per_page)
    
    return render_template(
        'wallet/pending_approvals.html',
        title='Pending Top-up Approvals',
        pending_requests=pending_requests
    )

@wallet_topup_bp.route('/approve-request/<request_id>', methods=['POST'])
@login_required
def approve_request(request_id):
    """Approve a topup request"""
    if not can_approve_topup(current_user):
        return jsonify({'success': False, 'message': 'You do not have permission to approve requests.'}), 403
    
    topup_request = WalletTopupRequest.query.filter_by(request_id=request_id).first_or_404()
    
    # Check if request is pending
    if topup_request.status != TransactionStatus.PENDING:
        return jsonify({'success': False, 'message': 'This request is not in pending state.'}), 400
    
    # Check if user has permission to approve this request
    user = User.query.get(topup_request.user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'}), 404
    
    # Check if user is in downline (has current user in their tree path)
    if current_user.role != UserRoleType.SUPER_ADMIN:
        if not user.tree_path or current_user.id not in user.tree_path.split('/'):
            return jsonify({'success': False, 'message': 'You do not have permission to approve this request.'}), 403
    
    try:
        # Get admin remarks
        admin_remarks = request.form.get('admin_remarks', '')
        
        # Update request status
        topup_request.status = TransactionStatus.SUCCESS
        topup_request.approved_by = current_user.id
        topup_request.admin_remarks = admin_remarks
        topup_request.processed_at = datetime.utcnow()
        
        # Update user's wallet
        wallet = Wallet.query.filter_by(user_id=topup_request.user_id).first()
        if not wallet:
            return jsonify({'success': False, 'message': 'User wallet not found.'}), 404
        
        # Record balance before
        balance_before = wallet.balance
        
        # Update wallet balance
        wallet.balance += topup_request.net_amount
        wallet.total_credited += topup_request.net_amount
        wallet.last_transaction_at = datetime.utcnow()
        
        # Create wallet transaction record
        wallet_transaction = WalletTransaction(
            wallet_id=wallet.id,
            transaction_type=WalletTransactionType.CREDIT,
            amount=topup_request.net_amount,
            balance_before=balance_before,
            balance_after=wallet.balance,
            reference_id=topup_request.id,
            reference_type='WalletTopupRequest',
            description=f"Wallet top-up of {topup_request.net_amount} via {topup_request.topup_method.value}",
            processed_by=current_user.id
        )
        
        db.session.add(wallet_transaction)
        db.session.commit()
        
        flash('Top-up request approved successfully!', 'success')
        return jsonify({'success': True, 'message': 'Top-up request approved successfully!'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'An error occurred: {str(e)}'}), 500

@wallet_topup_bp.route('/reject-request/<request_id>', methods=['POST'])
@login_required
def reject_request(request_id):
    """Reject a topup request"""
    if not can_approve_topup(current_user):
        return jsonify({'success': False, 'message': 'You do not have permission to reject requests.'}), 403
    
    topup_request = WalletTopupRequest.query.filter_by(request_id=request_id).first_or_404()
    
    # Check if request is pending
    if topup_request.status != TransactionStatus.PENDING:
        return jsonify({'success': False, 'message': 'This request is not in pending state.'}), 400
    
    # Check if user has permission to reject this request
    user = User.query.get(topup_request.user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'}), 404
    
    # Check if user is in downline (has current user in their tree path)
    if current_user.role != UserRoleType.SUPER_ADMIN:
        if not user.tree_path or current_user.id not in user.tree_path.split('/'):
            return jsonify({'success': False, 'message': 'You do not have permission to reject this request.'}), 403
    
    try:
        # Get rejection reason
        reason = request.form.get('rejection_reason', '')
        if not reason:
            return jsonify({'success': False, 'message': 'Please provide a rejection reason.'}), 400
        
        # Update request status
        topup_request.status = TransactionStatus.FAILED
        topup_request.approved_by = current_user.id
        topup_request.admin_remarks = reason
        topup_request.failure_reason = reason
        topup_request.processed_at = datetime.utcnow()
        
        db.session.commit()
        
        flash('Top-up request rejected.', 'warning')
        return jsonify({'success': True, 'message': 'Top-up request rejected.'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'An error occurred: {str(e)}'}), 500

@wallet_topup_bp.route('/all-requests')
@login_required
def all_requests():
    """View all topup requests (for admins)"""
    if not can_approve_topup(current_user):
        flash('You do not have permission to view all requests.', 'error')
        return redirect(url_for('dashboard.index'))
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    status = request.args.get('status', None)
    search = request.args.get('search', '')
    
    # Build query based on user's role and tree path
    if current_user.role == UserRoleType.SUPER_ADMIN:
        # Super admin can see all requests
        query = WalletTopupRequest.query
    else:
        # Others can only see requests from their downline
        query = WalletTopupRequest.query.join(User, WalletTopupRequest.user_id == User.id)
        
        if current_user.tree_path:
            # Filter by tree path (users who have current user in their path)
            query = query.filter(User.tree_path.like(f"{current_user.tree_path}%"))
        else:
            # Fallback if tree path is not set
            query = query.filter(User.parent_id == current_user.id)
    
    # Apply status filter if provided
    if status:
        query = query.filter(WalletTopupRequest.status == TransactionStatus(status))
    
    # Apply search filter if provided
    if search:
        query = query.join(User, WalletTopupRequest.user_id == User.id)
        query = query.filter(or_(
            WalletTopupRequest.request_id.like(f"%{search}%"),
            WalletTopupRequest.external_transaction_id.like(f"%{search}%"),
            WalletTopupRequest.utr_number.like(f"%{search}%"),
            User.full_name.like(f"%{search}%"),
            User.username.like(f"%{search}%"),
            User.phone.like(f"%{search}%")
        ))
    
    # Order by created date, newest first
    query = query.order_by(desc(WalletTopupRequest.created_at))
    
    # Paginate results
    all_requests = query.paginate(page=page, per_page=per_page)
    
    return render_template(
        'wallet/all_requests.html',
        title='All Top-up Requests',
        all_requests=all_requests,
        status=status,
        search=search,
        TransactionStatus=TransactionStatus
    )

@wallet_topup_bp.route('/cancel-request/<request_id>', methods=['POST'])
@login_required
def cancel_request(request_id):
    """Cancel a pending topup request"""
    topup_request = WalletTopupRequest.query.filter_by(request_id=request_id).first_or_404()
    
    # Check if request belongs to current user
    if topup_request.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'You do not have permission to cancel this request.'}), 403
    
    # Check if request is pending
    if topup_request.status != TransactionStatus.PENDING:
        return jsonify({'success': False, 'message': 'Only pending requests can be cancelled.'}), 400
    
    try:
        # Update request status
        topup_request.status = TransactionStatus.CANCELLED
        topup_request.processed_at = datetime.utcnow()
        
        db.session.commit()
        
        flash('Top-up request cancelled.', 'info')
        return jsonify({'success': True, 'message': 'Top-up request cancelled.'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'An error occurred: {str(e)}'}), 500

@wallet_topup_bp.route('/get-bank-details/<bank_id>')
@login_required
def get_bank_details(bank_id):
    """Get bank account details"""
    bank_account = OrganizationBankAccount.query.get(bank_id)
    
    if not bank_account or bank_account.tenant_id != current_user.tenant_id:
        return jsonify({'success': False, 'message': 'Bank account not found.'}), 404
    
    return jsonify({
        'success': True,
        'bank_account': {
            'id': bank_account.id,
            'account_name': bank_account.account_name,
            'account_number': bank_account.account_number,
            'ifsc_code': bank_account.ifsc_code,
            'bank_name': bank_account.bank_name,
            'branch_name': bank_account.branch_name,
            'account_holder_name': bank_account.account_holder_name,
            'upi_id': bank_account.upi_id
        }
    })

# API routes for front-end integration
@wallet_topup_bp.route('/api/pending-count')
@login_required
def api_pending_count():
    """Get count of pending requests for the navbar badge"""
    try:
        if can_approve_topup(current_user):
            # For admins - count pending requests from downline
            if current_user.role == UserRoleType.SUPER_ADMIN:
                count = WalletTopupRequest.query.filter_by(status=TransactionStatus.PENDING).count()
            else:
                # Get users in downline
                if current_user.tree_path:
                    count = WalletTopupRequest.query.join(User, WalletTopupRequest.user_id == User.id)\
                        .filter(User.tree_path.like(f"{current_user.tree_path}%"))\
                        .filter(WalletTopupRequest.status == TransactionStatus.PENDING)\
                        .count()
                else:
                    count = 0
        else:
            # For regular users - count their own pending requests
            count = WalletTopupRequest.query.filter_by(
                user_id=current_user.id,
                status=TransactionStatus.PENDING
            ).count()
        
        return jsonify({'success': True, 'count': count})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@wallet_topup_bp.route('/api/requests-summary')
@login_required
def api_requests_summary():
    """Get summary of requests for dashboard widgets"""
    try:
        if can_approve_topup(current_user):
            # For admins - count requests from downline
            if current_user.role == UserRoleType.SUPER_ADMIN:
                pending_count = WalletTopupRequest.query.filter_by(status=TransactionStatus.PENDING).count()
                today_count = WalletTopupRequest.query.filter(
                    func.date(WalletTopupRequest.created_at) == datetime.utcnow().date()
                ).count()
                success_count = WalletTopupRequest.query.filter_by(status=TransactionStatus.SUCCESS).count()
                failed_count = WalletTopupRequest.query.filter(
                    WalletTopupRequest.status.in_([TransactionStatus.FAILED, TransactionStatus.CANCELLED])
                ).count()
            else:
                # Get users in downline
                if current_user.tree_path:
                    base_query = WalletTopupRequest.query.join(User, WalletTopupRequest.user_id == User.id)\
                        .filter(User.tree_path.like(f"{current_user.tree_path}%"))
                    
                    pending_count = base_query.filter(WalletTopupRequest.status == TransactionStatus.PENDING).count()
                    today_count = base_query.filter(
                        func.date(WalletTopupRequest.created_at) == datetime.utcnow().date()
                    ).count()
                    success_count = base_query.filter(WalletTopupRequest.status == TransactionStatus.SUCCESS).count()
                    failed_count = base_query.filter(
                        WalletTopupRequest.status.in_([TransactionStatus.FAILED, TransactionStatus.CANCELLED])
                    ).count()
                else:
                    pending_count = today_count = success_count = failed_count = 0
        else:
            # For regular users - count their own requests
            base_query = WalletTopupRequest.query.filter_by(user_id=current_user.id)
            
            pending_count = base_query.filter_by(status=TransactionStatus.PENDING).count()
            today_count = base_query.filter(
                func.date(WalletTopupRequest.created_at) == datetime.utcnow().date()
            ).count()
            success_count = base_query.filter_by(status=TransactionStatus.SUCCESS).count()
            failed_count = base_query.filter(
                WalletTopupRequest.status.in_([TransactionStatus.FAILED, TransactionStatus.CANCELLED])
            ).count()
        
        return jsonify({
            'success': True,
            'summary': {
                'pending': pending_count,
                'today': today_count,
                'success': success_count,
                'failed': failed_count
            }
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500