# routes/enhanced_topup.py
from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for
from flask_login import login_required, current_user
from models import (
    Wallet, WalletTopupRequest, WalletTransaction, WalletTransactionType,
    OrganizationBankAccount, TopupMethod, TransactionStatus, User, db
)
from datetime import datetime
from decimal import Decimal
import uuid
import os
from werkzeug.utils import secure_filename

enhanced_topup_bp = Blueprint('enhanced_topup', __name__, url_prefix='/topup')

# =============================================================================
# CONFIGURATION
# =============================================================================

UPLOAD_FOLDER = 'uploads/topup_proofs'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS




# =============================================================================
# TOPUP REQUEST PAGES
# =============================================================================

@enhanced_topup_bp.route('/api/request', methods=['POST'])
@login_required
def create_topup_request():
    """Create a new wallet top-up request"""
    try:
        data = request.form.to_dict()
        amount = Decimal(str(data.get('amount', 0)))
        topup_method = data.get('topup_method', TopupMethod.MANUAL_REQUEST.value)
        bank_account_id = data.get('bank_account_id')
        transaction_id = data.get('transaction_id', '')
        remarks = data.get('remarks', '')
        
        # Validate amount
        if amount <= 0:
            return jsonify({'error': 'Amount must be positive'}), 400
        
        if amount < 10:  # Minimum top-up amount
            return jsonify({'error': 'Minimum top-up amount is ₹10'}), 400
        
        if amount > 100000:  # Maximum top-up amount
            return jsonify({'error': 'Maximum top-up amount is ₹100,000'}), 400
        
        # Get user's wallet
        wallet = Wallet.query.filter_by(user_id=current_user.id).first()
        if not wallet:
            return jsonify({'error': 'Wallet not found'}), 404
        
        # Validate bank account if provided
        selected_bank_account = None
        if bank_account_id:
            selected_bank_account = OrganizationBankAccount.query.filter(
                OrganizationBankAccount.id == bank_account_id,
                OrganizationBankAccount.tenant_id == current_user.tenant_id,
                OrganizationBankAccount.status == 'ACTIVE'
            ).first()
            
            if not selected_bank_account:
                return jsonify({'error': 'Invalid bank account selected'}), 400
        
        # Generate unique request ID
        request_id = f"TOP{datetime.now().strftime('%Y%m%d%H%M%S')}{str(uuid.uuid4())[:8].upper()}"
        
        # Handle file upload (proof document)
        proof_document_path = None
        if 'proof_document' in request.files:
            file = request.files['proof_document']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(f"{request_id}_{file.filename}")
                
                # Create upload directory if it doesn't exist
                os.makedirs(UPLOAD_FOLDER, exist_ok=True)
                
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                file.save(file_path)
                proof_document_path = file_path
        
        # Create top-up request
        topup_request = WalletTopupRequest(
            request_id=request_id,
            user_id=current_user.id,
            requested_by=current_user.id,
            selected_bank_account_id=selected_bank_account.id if selected_bank_account else None,
            topup_method=TopupMethod(topup_method),
            amount=amount,
            net_amount=amount,  # No processing fee for manual requests
            external_transaction_id=transaction_id,
            status=TransactionStatus.PENDING,
            request_remarks=remarks,
            proof_document=proof_document_path,
            ip_address=request.remote_addr,
            device_info={
                'user_agent': request.headers.get('User-Agent', ''),
                'accept_language': request.headers.get('Accept-Language', '')
            },
            expires_at=datetime.utcnow().replace(hour=23, minute=59, second=59),  # Expires at end of day
            expected_deposit_info={
                'bank_account': selected_bank_account.to_dict() if selected_bank_account else None,
                'amount': float(amount),
                'reference': request_id
            }
        )
        
        db.session.add(topup_request)
        db.session.commit()
        
        # Prepare response data
        response_data = {
            'message': 'Top-up request submitted successfully',
            'request_id': request_id,
            'amount': float(amount),
            'status': 'PENDING',
            'bank_details': selected_bank_account.to_dict() if selected_bank_account else None
        }
        
        return jsonify(response_data), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@enhanced_topup_bp.route('/api/requests', methods=['GET'])
@login_required
def get_topup_requests():
    """Get top-up requests (user's own or all if admin)"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        status_filter = request.args.get('status')
        user_id = request.args.get('user_id')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        
        # Base query
        if current_user.role.value in ['SUPER_ADMIN', 'ADMIN', 'WHITE_LABEL']:
            # Admin users can see all requests in their hierarchy
            query = WalletTopupRequest.query.join(User).filter(
                User.tenant_id == current_user.tenant_id,
                User.tree_path.like(f"{current_user.tree_path}%") if current_user.tree_path else True
            )
        else:
            # Regular users can only see their own requests
            query = WalletTopupRequest.query.filter(
                WalletTopupRequest.user_id == current_user.id
            )
        
        # Apply filters
        if status_filter:
            try:
                status_enum = TransactionStatus(status_filter.upper())
                query = query.filter(WalletTopupRequest.status == status_enum)
            except ValueError:
                pass
        
        if user_id and current_user.role.value in ['SUPER_ADMIN', 'ADMIN', 'WHITE_LABEL']:
            query = query.filter(WalletTopupRequest.user_id == user_id)
        
        if date_from:
            try:
                from_date = datetime.strptime(date_from, '%Y-%m-%d')
                query = query.filter(WalletTopupRequest.created_at >= from_date)
            except ValueError:
                pass
        
        if date_to:
            try:
                to_date = datetime.strptime(date_to, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
                query = query.filter(WalletTopupRequest.created_at <= to_date)
            except ValueError:
                pass
        
        # Paginate results
        topups = query.order_by(WalletTopupRequest.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        topups_data = []
        for topup in topups.items:
            topup_data = topup.to_dict()
            
            # Add user information
            user = User.query.get(topup.user_id)
            if user:
                topup_data['user'] = {
                    'id': user.id,
                    'full_name': user.full_name,
                    'user_code': user.user_code,
                    'phone': user.phone
                }
            
            # Add bank account information
            if topup.selected_bank_account:
                topup_data['bank_account'] = {
                    'account_name': topup.selected_bank_account.account_name,
                    'account_number': topup.selected_bank_account.account_number,
                    'ifsc_code': topup.selected_bank_account.ifsc_code,
                    'bank_name': topup.selected_bank_account.bank_name
                }
            
            topups_data.append(topup_data)
        
        return jsonify({
            'topups': topups_data,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': topups.total,
                'pages': topups.pages,
                'has_next': topups.has_next,
                'has_prev': topups.has_prev
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@enhanced_topup_bp.route('/api/requests/<request_id>', methods=['GET'])
@login_required
def get_topup_request(request_id):
    """Get specific top-up request details"""
    try:
        topup = WalletTopupRequest.query.filter_by(request_id=request_id).first()
        
        if not topup:
            return jsonify({'error': 'Top-up request not found'}), 404
        
        # Check access permissions
        if (topup.user_id != current_user.id and 
            current_user.role.value not in ['SUPER_ADMIN', 'ADMIN', 'WHITE_LABEL']):
            return jsonify({'error': 'Access denied'}), 403
        
        topup_data = topup.to_dict()
        
        # Add user information
        user = User.query.get(topup.user_id)
        if user:
            topup_data['user'] = {
                'id': user.id,
                'full_name': user.full_name,
                'user_code': user.user_code,
                'phone': user.phone,
                'email': user.email
            }
        
        # Add bank account information
        if topup.selected_bank_account:
            topup_data['bank_account'] = topup.selected_bank_account.to_dict()
        
        return jsonify({'topup_request': topup_data})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# ADMIN OPERATIONS
# =============================================================================

@enhanced_topup_bp.route('/api/requests/<request_id>/approve', methods=['POST'])
@login_required
def approve_topup_request(request_id):
    """Approve a top-up request (Admin only)"""
    try:
        # Check admin permissions
        if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN', 'WHITE_LABEL']:
            return jsonify({'error': 'Access denied'}), 403
        
        topup = WalletTopupRequest.query.filter_by(request_id=request_id).first()
        
        if not topup:
            return jsonify({'error': 'Top-up request not found'}), 404
        
        if topup.status != TransactionStatus.PENDING:
            return jsonify({'error': 'Request already processed'}), 400
        
        # Check if user is in current user's hierarchy
        user = User.query.get(topup.user_id)
        if not user or not current_user.can_access_user(user):
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        admin_remarks = data.get('admin_remarks', '')
        
        # Get user's wallet
        wallet = Wallet.query.filter_by(user_id=topup.user_id).first()
        if not wallet:
            return jsonify({'error': 'User wallet not found'}), 404
        
        # Update wallet balance
        balance_before = wallet.balance
        wallet.balance += topup.amount
        wallet.total_credited += topup.amount
        wallet.last_transaction_at = datetime.utcnow()
        
        # Update top-up request
        topup.status = TransactionStatus.SUCCESS
        topup.approved_by = current_user.id
        topup.admin_remarks = admin_remarks
        topup.processed_at = datetime.utcnow()
        
        # Record wallet transaction
        wallet_transaction = WalletTransaction(
            wallet_id=wallet.id,
            transaction_type=WalletTransactionType.CREDIT,
            amount=topup.amount,
            balance_before=balance_before,
            balance_after=wallet.balance,
            reference_id=topup.id,
            reference_type='topup_request',
            description=f'Wallet top-up approved - {request_id}',
            processed_by=current_user.id
        )
        
        db.session.add(wallet_transaction)
        db.session.commit()
        
        return jsonify({
            'message': 'Top-up request approved successfully',
            'request_id': request_id,
            'amount': float(topup.amount),
            'new_balance': float(wallet.balance)
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@enhanced_topup_bp.route('/api/requests/<request_id>/reject', methods=['POST'])
@login_required
def reject_topup_request(request_id):
    """Reject a top-up request (Admin only)"""
    try:
        # Check admin permissions
        if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN', 'WHITE_LABEL']:
            return jsonify({'error': 'Access denied'}), 403
        
        topup = WalletTopupRequest.query.filter_by(request_id=request_id).first()
        
        if not topup:
            return jsonify({'error': 'Top-up request not found'}), 404
        
        if topup.status != TransactionStatus.PENDING:
            return jsonify({'error': 'Request already processed'}), 400
        
        # Check if user is in current user's hierarchy
        user = User.query.get(topup.user_id)
        if not user or not current_user.can_access_user(user):
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        admin_remarks = data.get('admin_remarks', '')
        failure_reason = data.get('failure_reason', 'Rejected by admin')
        
        # Update top-up request
        topup.status = TransactionStatus.FAILED
        topup.approved_by = current_user.id
        topup.admin_remarks = admin_remarks
        topup.failure_reason = failure_reason
        topup.processed_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'message': 'Top-up request rejected',
            'request_id': request_id,
            'reason': failure_reason
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# =============================================================================
# BANK ACCOUNT MANAGEMENT
# =============================================================================

@enhanced_topup_bp.route('/api/bank-accounts', methods=['GET'])
@login_required
def get_bank_accounts():
    """Get available bank accounts for top-up"""
    try:
        # Get bank accounts available for the user's role
        bank_accounts = OrganizationBankAccount.query.filter(
            OrganizationBankAccount.tenant_id == current_user.tenant_id,
            OrganizationBankAccount.status == 'ACTIVE',
            OrganizationBankAccount.is_visible_to_users == True
        ).order_by(OrganizationBankAccount.display_order).all()
        
        accounts_data = []
        for account in bank_accounts:
            account_data = {
                'id': account.id,
                'account_name': account.account_name,
                'account_number': account.account_number,
                'ifsc_code': account.ifsc_code,
                'bank_name': account.bank_name,
                'branch_name': account.branch_name,
                'account_type': account.account_type.value,
                'upi_id': account.upi_id,
                'is_default_topup': account.is_default_topup,
                'daily_limit': float(account.daily_limit) if account.daily_limit else None,
                'monthly_limit': float(account.monthly_limit) if account.monthly_limit else None
            }
            accounts_data.append(account_data)
        
        return jsonify({
            'bank_accounts': accounts_data,
            'total': len(accounts_data)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# STATISTICS AND REPORTING
# =============================================================================

@enhanced_topup_bp.route('/api/stats', methods=['GET'])
@login_required
def get_topup_stats():
    """Get top-up statistics"""
    try:
        if current_user.role.value in ['SUPER_ADMIN', 'ADMIN', 'WHITE_LABEL']:
            # Admin users get stats for their hierarchy
            base_query = WalletTopupRequest.query.join(User).filter(
                User.tenant_id == current_user.tenant_id,
                User.tree_path.like(f"{current_user.tree_path}%") if current_user.tree_path else True
            )
        else:
            # Regular users get their own stats
            base_query = WalletTopupRequest.query.filter(
                WalletTopupRequest.user_id == current_user.id
            )
        
        # Calculate various statistics
        total_requests = base_query.count()
        pending_requests = base_query.filter(WalletTopupRequest.status == TransactionStatus.PENDING).count()
        approved_requests = base_query.filter(WalletTopupRequest.status == TransactionStatus.SUCCESS).count()
        rejected_requests = base_query.filter(WalletTopupRequest.status == TransactionStatus.FAILED).count()
        
        # Calculate amounts
        total_amount = db.session.query(db.func.coalesce(db.func.sum(WalletTopupRequest.amount), 0)).filter(
            WalletTopupRequest.id.in_([r.id for r in base_query.all()])
        ).scalar()
        
        approved_amount = db.session.query(db.func.coalesce(db.func.sum(WalletTopupRequest.amount), 0)).filter(
            WalletTopupRequest.id.in_([r.id for r in base_query.filter(WalletTopupRequest.status == TransactionStatus.SUCCESS).all()])
        ).scalar()
        
        # Today's stats
        today = datetime.utcnow().date()
        today_requests = base_query.filter(
            db.func.date(WalletTopupRequest.created_at) == today
        ).count()
        
        stats = {
            'total_requests': total_requests,
            'pending_requests': pending_requests,
            'approved_requests': approved_requests,
            'rejected_requests': rejected_requests,
            'total_amount': float(total_amount),
            'approved_amount': float(approved_amount),
            'today_requests': today_requests,
            'approval_rate': round((approved_requests / total_requests * 100) if total_requests > 0 else 0, 2)
        }
        
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# BULK OPERATIONS
# =============================================================================

@enhanced_topup_bp.route('/api/requests/bulk-approve', methods=['POST'])
@login_required
def bulk_approve_requests():
    """Bulk approve top-up requests (Admin only)"""
    try:
        # Check admin permissions
        if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN', 'WHITE_LABEL']:
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        request_ids = data.get('request_ids', [])
        admin_remarks = data.get('admin_remarks', 'Bulk approval')
        
        if not request_ids:
            return jsonify({'error': 'No request IDs provided'}), 400
        
        # Get pending requests
        topups = WalletTopupRequest.query.filter(
            WalletTopupRequest.request_id.in_(request_ids),
            WalletTopupRequest.status == TransactionStatus.PENDING
        ).all()
        
        approved_count = 0
        total_amount = Decimal('0')
        
        for topup in topups:
            # Check if user is in current user's hierarchy
            user = User.query.get(topup.user_id)
            if not user or not current_user.can_access_user(user):
                continue
            
            # Get user's wallet
            wallet = Wallet.query.filter_by(user_id=topup.user_id).first()
            if not wallet:
                continue
            
            # Update wallet balance
            balance_before = wallet.balance
            wallet.balance += topup.amount
            wallet.total_credited += topup.amount
            wallet.last_transaction_at = datetime.utcnow()
            
            # Update top-up request
            topup.status = TransactionStatus.SUCCESS
            topup.approved_by = current_user.id
            topup.admin_remarks = admin_remarks
            topup.processed_at = datetime.utcnow()
            
            # Record wallet transaction
            wallet_transaction = WalletTransaction(
                wallet_id=wallet.id,
                transaction_type=WalletTransactionType.CREDIT,
                amount=topup.amount,
                balance_before=balance_before,
                balance_after=wallet.balance,
                reference_id=topup.id,
                reference_type='topup_request',
                description=f'Bulk wallet top-up approved - {topup.request_id}',
                processed_by=current_user.id
            )
            
            db.session.add(wallet_transaction)
            approved_count += 1
            total_amount += topup.amount
        
        db.session.commit()
        
        return jsonify({
            'message': f'Successfully approved {approved_count} requests',
            'approved_count': approved_count,
            'total_amount': float(total_amount),
            'requested_count': len(request_ids)
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# =============================================================================
# FILE DOWNLOAD
# =============================================================================

@enhanced_topup_bp.route('/api/requests/<request_id>/download-proof')
@login_required
def download_proof_document(request_id):
    """Download proof document for a top-up request"""
    try:
        topup = WalletTopupRequest.query.filter_by(request_id=request_id).first()
        
        if not topup:
            return jsonify({'error': 'Top-up request not found'}), 404
        
        # Check access permissions
        if (topup.user_id != current_user.id and 
            current_user.role.value not in ['SUPER_ADMIN', 'ADMIN', 'WHITE_LABEL']):
            return jsonify({'error': 'Access denied'}), 403
        
        if not topup.proof_document or not os.path.exists(topup.proof_document):
            return jsonify({'error': 'Proof document not found'}), 404
        
        from flask import send_file
        return send_file(topup.proof_document, as_attachment=True)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@login_required
def topup_dashboard():
    """Wallet top-up dashboard"""
    return render_template('topup/dashboard.html',
        title='Wallet Top-up',
        subtitle='Manage Wallet Top-up Requests'
    )

@enhanced_topup_bp.route('/request')
@login_required
def topup_request_page():
    """Top-up request page"""
    # Get available bank accounts for the user's role
    bank_accounts = OrganizationBankAccount.query.filter(
        OrganizationBankAccount.tenant_id == current_user.tenant_id,
        OrganizationBankAccount.status == 'ACTIVE',
        OrganizationBankAccount.is_visible_to_users == True
    ).order_by(OrganizationBankAccount.display_order).all()
    
    return render_template('topup/request_topup.html',
        title='Add Fund',
        subtitle='Request Wallet Top-up',
        bank_accounts=bank_accounts
    )

@enhanced_topup_bp.route('/history')
@login_required
def topup_history_page():
    """Top-up history page"""
    return render_template('topup/history.html',
        title='Top-up History',
        subtitle='Your Top-up Requests'
    )

@enhanced_topup_bp.route('/admin/requests')
@login_required
def admin_topup_requests():
    """Admin page to manage top-up requests"""
    # Check if user has permission to approve top-ups
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN', 'WHITE_LABEL']:
        flash('Access denied', 'error')
        return redirect(url_for('enhanced_topup.topup_dashboard'))
    
    return render_template('topup/admin_requests.html',
        title='Manage Top-up Requests',
        subtitle='Approve/Reject Top-up Requests'
    )

# =============================================================================
# TOPUP REQUEST API
# =============================================================================

@enhanced_topup_bp.route('/api/request/<request_id>', methods=['PUT'])
@login_required
def update_topup_request(request_id):
    """Update a top-up request (only if pending and belongs to user)"""
    try:
        topup = WalletTopupRequest.query.filter_by(request_id=request_id).first()
        if not topup:
            return jsonify({'error': 'Top-up request not found'}), 404

        # Only allow update if request is pending and belongs to current user
        if topup.status != TransactionStatus.PENDING or topup.user_id != current_user.id:
            return jsonify({'error': 'Cannot update this request'}), 403

        data = request.form.to_dict()
        amount = Decimal(str(data.get('amount', topup.amount)))
        remarks = data.get('remarks', topup.request_remarks)
        transaction_id = data.get('transaction_id', topup.external_transaction_id)

        # Validate amount
        if amount <= 0:
            return jsonify({'error': 'Amount must be positive'}), 400
        if amount < 10:
            return jsonify({'error': 'Minimum top-up amount is ₹10'}), 400
        if amount > 100000:
            return jsonify({'error': 'Maximum top-up amount is ₹100,000'}), 400

        topup.amount = amount
        topup.net_amount = amount
        topup.request_remarks = remarks
        topup.external_transaction_id = transaction_id

        # Handle file upload (proof document)
        if 'proof_document' in request.files:
            file = request.files['proof_document']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(f"{topup.request_id}_{file.filename}")
                os.makedirs(UPLOAD_FOLDER, exist_ok=True)
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                file.save(file_path)
                topup.proof_document = file_path

        db.session.commit()
        return jsonify({'message': 'Top-up request updated successfully', 'request_id': request_id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
