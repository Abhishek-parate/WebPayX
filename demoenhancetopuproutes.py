# routes/enhanced_topup.py
from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for
from flask_login import login_required, current_user
from models import (
    Wallet, WalletTopupRequest, WalletTransaction, WalletTransactionType,
    OrganizationBankAccount, TopupMethod, TransactionStatus, User, PaymentGateway, db
)
from datetime import datetime
from decimal import Decimal
import uuid
import os
import json
from werkzeug.utils import secure_filename

enhanced_topup_bp = Blueprint('enhanced_topup', __name__, url_prefix='/topup')

# =============================================================================
# CONFIGURATION
# =============================================================================

UPLOAD_FOLDER = 'uploads/topup_proofs'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_qr_code(amount, upi_id, reference_id):
    """Generate UPI QR code data"""
    # UPI payment string format
    upi_string = f"upi://pay?pa={upi_id}&pn=Company&am={amount}&tr={reference_id}&tn=Wallet Topup"
    
    # In production, you would use a QR code library like qrcode
    # For now, return the UPI string and mock QR data
    return {
        'upi_string': upi_string,
        'qr_data': f"QR_DATA_{reference_id}",
        'amount': amount,
        'reference_id': reference_id
    }

# =============================================================================
# TOPUP REQUEST PAGES
# =============================================================================

@enhanced_topup_bp.route('/request')
@login_required
def topup_request_page():
    """Top-up request page with dual payment methods"""
    # Get available bank accounts for manual payments
    bank_accounts = OrganizationBankAccount.query.filter(
        OrganizationBankAccount.tenant_id == current_user.tenant_id,
        OrganizationBankAccount.status == 'ACTIVE',
        OrganizationBankAccount.is_visible_to_users == True,
        OrganizationBankAccount.purpose.any(lambda x: 'WALLET_TOPUP' in x)
    ).order_by(OrganizationBankAccount.display_order).all()
    
    # Get default payment gateway for online payments
    payment_gateway = PaymentGateway.query.filter(
        PaymentGateway.tenant_id == current_user.tenant_id,
        PaymentGateway.status == 'ACTIVE',
        PaymentGateway.is_default == True
    ).first()
    
    return render_template('topup/request_topup.html',
        title='Add Fund',
        subtitle='Request Wallet Top-up',
        bank_accounts=bank_accounts,
        payment_gateway=payment_gateway
    )

# =============================================================================
# ENHANCED TOPUP REQUEST API
# =============================================================================

@enhanced_topup_bp.route('/api/request', methods=['POST'])
@login_required
def create_topup_request():
    """Create a new wallet top-up request with dual payment method support"""
    try:
        # Determine if request is JSON (online) or form data (manual)
        if request.is_json:
            data = request.get_json()
            is_online_payment = True
        else:
            data = request.form.to_dict()
            is_online_payment = False
        
        amount = Decimal(str(data.get('amount', 0)))
        topup_method = data.get('topup_method', TopupMethod.MANUAL_REQUEST.value)
        
        # Validate amount
        if amount <= 0:
            return jsonify({'error': 'Amount must be positive'}), 400
        
        if amount < 10:
            return jsonify({'error': 'Minimum top-up amount is ₹10'}), 400
        
        if amount > 100000:
            return jsonify({'error': 'Maximum top-up amount is ₹100,000'}), 400
        
        # Get user's wallet
        wallet = Wallet.query.filter_by(user_id=current_user.id).first()
        if not wallet:
            return jsonify({'error': 'Wallet not found'}), 404
        
        # Generate unique request ID
        request_id = f"TOP{datetime.now().strftime('%Y%m%d%H%M%S')}{str(uuid.uuid4())[:8].upper()}"
        
        # Initialize common fields
        topup_request_data = {
            'request_id': request_id,
            'user_id': current_user.id,
            'requested_by': current_user.id,
            'amount': amount,
            'net_amount': amount,
            'status': TransactionStatus.PENDING,
            'ip_address': request.remote_addr,
            'device_info': {
                'user_agent': request.headers.get('User-Agent', ''),
                'accept_language': request.headers.get('Accept-Language', '')
            },
            'expires_at': datetime.utcnow().replace(hour=23, minute=59, second=59),
        }
        
        if is_online_payment and topup_method == 'PAYMENT_GATEWAY':
            # Handle online payment
            return handle_online_payment_request(topup_request_data, data)
        else:
            # Handle manual payment
            return handle_manual_payment_request(topup_request_data, data)
            
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

def handle_manual_payment_request(topup_request_data, form_data):
    """Handle manual payment request processing"""
    try:
        bank_account_id = form_data.get('bank_account_id')
        transaction_id = form_data.get('transaction_id', '')
        remarks = form_data.get('remarks', '')
        
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
        
        # Handle file upload (proof document)
        proof_document_path = None
        if 'proof_document' in request.files:
            file = request.files['proof_document']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(f"{topup_request_data['request_id']}_{file.filename}")
                
                # Create upload directory if it doesn't exist
                os.makedirs(UPLOAD_FOLDER, exist_ok=True)
                
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                file.save(file_path)
                proof_document_path = file_path
            else:
                return jsonify({'error': 'Valid proof document is required for manual payments'}), 400
        else:
            return jsonify({'error': 'Proof document is required for manual payments'}), 400
        
        # Create manual top-up request
        topup_request = WalletTopupRequest(
            **topup_request_data,
            selected_bank_account_id=selected_bank_account.id if selected_bank_account else None,
            topup_method=TopupMethod.MANUAL_REQUEST,
            external_transaction_id=transaction_id,
            request_remarks=remarks,
            proof_document=proof_document_path,
            expected_deposit_info={
                'bank_account': selected_bank_account.to_dict() if selected_bank_account else None,
                'amount': float(topup_request_data['amount']),
                'reference': topup_request_data['request_id'],
                'payment_type': 'manual_transfer'
            }
        )
        
        db.session.add(topup_request)
        db.session.commit()
        
        return jsonify({
            'message': 'Manual payment request submitted successfully',
            'request_id': topup_request_data['request_id'],
            'amount': float(topup_request_data['amount']),
            'status': 'PENDING',
            'payment_type': 'manual',
            'bank_details': selected_bank_account.to_dict() if selected_bank_account else None
        }), 201
        
    except Exception as e:
        db.session.rollback()
        raise e

def handle_online_payment_request(topup_request_data, payment_data):
    """Handle online payment request processing"""
    try:
        payment_type = payment_data.get('payment_type', 'UPI')
        
        # Get default payment gateway
        payment_gateway = PaymentGateway.query.filter(
            PaymentGateway.tenant_id == current_user.tenant_id,
            PaymentGateway.status == 'ACTIVE',
            PaymentGateway.is_default == True
        ).first()
        
        if not payment_gateway:
            return jsonify({'error': 'Payment gateway not configured'}), 500
        
        # Generate UPI payment details
        company_upi_id = "payment@company.upi"  # This should come from payment gateway config
        qr_code_data = generate_qr_code(
            amount=topup_request_data['amount'],
            upi_id=company_upi_id,
            reference_id=topup_request_data['request_id']
        )
        
        # Create online top-up request
        topup_request = WalletTopupRequest(
            **topup_request_data,
            payment_gateway_id=payment_gateway.id,
            topup_method=TopupMethod.PAYMENT_GATEWAY,
            payment_method=payment_type,
            payment_details={
                'upi_id': company_upi_id,
                'qr_code_data': qr_code_data['qr_data'],
                'upi_string': qr_code_data['upi_string']
            },
            expected_deposit_info={
                'payment_gateway': payment_gateway.gateway_name,
                'amount': float(topup_request_data['amount']),
                'reference': topup_request_data['request_id'],
                'payment_type': 'online_upi',
                'upi_id': company_upi_id
            },
            # Online payments have shorter expiry (30 minutes)
            expires_at=datetime.utcnow() + datetime.timedelta(minutes=30)
        )
        
        db.session.add(topup_request)
        db.session.commit()
        
        return jsonify({
            'message': 'Online payment request created successfully',
            'request_id': topup_request_data['request_id'],
            'amount': float(topup_request_data['amount']),
            'status': 'PENDING',
            'payment_type': 'online',
            'upi_details': {
                'upi_id': company_upi_id,
                'qr_code_data': qr_code_data['qr_data'],
                'upi_string': qr_code_data['upi_string']
            },
            'expires_at': topup_request.expires_at.isoformat()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        raise e

# =============================================================================
# PAYMENT STATUS AND VERIFICATION
# =============================================================================

@enhanced_topup_bp.route('/api/payment-status/<request_id>', methods=['GET'])
@login_required
def check_payment_status(request_id):
    """Check payment status for online payments"""
    try:
        topup = WalletTopupRequest.query.filter_by(
            request_id=request_id,
            user_id=current_user.id
        ).first()
        
        if not topup:
            return jsonify({'error': 'Payment request not found'}), 404
        
        # Check if payment is expired
        if topup.is_expired:
            if topup.status == TransactionStatus.PENDING:
                topup.status = TransactionStatus.FAILED
                topup.failure_reason = "Payment expired"
                topup.processed_at = datetime.utcnow()
                db.session.commit()
        
        return jsonify({
            'request_id': request_id,
            'status': topup.status.value,
            'amount': float(topup.amount),
            'payment_method': topup.topup_method.value,
            'created_at': topup.created_at.isoformat(),
            'expires_at': topup.expires_at.isoformat() if topup.expires_at else None,
            'is_expired': topup.is_expired,
            'failure_reason': topup.failure_reason
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@enhanced_topup_bp.route('/api/simulate-payment/<request_id>', methods=['POST'])
@login_required
def simulate_online_payment(request_id):
    """Simulate online payment completion (for testing purposes)"""
    try:
        topup = WalletTopupRequest.query.filter_by(
            request_id=request_id,
            user_id=current_user.id,
            topup_method=TopupMethod.PAYMENT_GATEWAY
        ).first()
        
        if not topup:
            return jsonify({'error': 'Online payment request not found'}), 404
        
        if topup.status != TransactionStatus.PENDING:
            return jsonify({'error': 'Payment already processed'}), 400
        
        if topup.is_expired:
            return jsonify({'error': 'Payment request has expired'}), 400
        
        # Get user's wallet
        wallet = Wallet.query.filter_by(user_id=current_user.id).first()
        if not wallet:
            return jsonify({'error': 'Wallet not found'}), 404
        
        # Process payment (simulate successful payment)
        balance_before = wallet.balance
        wallet.balance += topup.amount
        wallet.total_credited += topup.amount
        wallet.last_transaction_at = datetime.utcnow()
        
        # Update topup request
        topup.status = TransactionStatus.SUCCESS
        topup.processed_at = datetime.utcnow()
        topup.gateway_response = {
            'transaction_id': f"TXN{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'status': 'SUCCESS',
            'message': 'Payment completed successfully',
            'payment_method': 'UPI',
            'simulated': True
        }
        
        # Record wallet transaction
        wallet_transaction = WalletTransaction(
            wallet_id=wallet.id,
            transaction_type=WalletTransactionType.CREDIT,
            amount=topup.amount,
            balance_before=balance_before,
            balance_after=wallet.balance,
            reference_id=topup.id,
            reference_type='topup_request',
            description=f'Online wallet top-up - {request_id}',
            processed_by=current_user.id
        )
        
        db.session.add(wallet_transaction)
        db.session.commit()
        
        return jsonify({
            'message': 'Payment completed successfully',
            'request_id': request_id,
            'amount': float(topup.amount),
            'new_balance': float(wallet.balance),
            'transaction_id': topup.gateway_response['transaction_id']
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# =============================================================================
# EXISTING METHODS (UPDATED FOR COMPATIBILITY)
# =============================================================================

@enhanced_topup_bp.route('/api/requests', methods=['GET'])
@login_required
def get_topup_requests():
    """Get top-up requests (user's own or all if admin)"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        status_filter = request.args.get('status')
        payment_method_filter = request.args.get('payment_method')
        user_id = request.args.get('user_id')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        
        # Base query
        if current_user.role.value in ['SUPER_ADMIN', 'ADMIN', 'WHITE_LABEL']:
            query = WalletTopupRequest.query.join(User).filter(
                User.tenant_id == current_user.tenant_id,
                User.tree_path.like(f"{current_user.tree_path}%") if current_user.tree_path else True
            )
        else:
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
        
        if payment_method_filter:
            try:
                method_enum = TopupMethod(payment_method_filter.upper())
                query = query.filter(WalletTopupRequest.topup_method == method_enum)
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
            
            # Add bank account information for manual payments
            if topup.selected_bank_account:
                topup_data['bank_account'] = {
                    'account_name': topup.selected_bank_account.account_name,
                    'account_number': topup.selected_bank_account.account_number,
                    'ifsc_code': topup.selected_bank_account.ifsc_code,
                    'bank_name': topup.selected_bank_account.bank_name
                }
            
            # Add payment method specific information
            topup_data['is_manual_payment'] = topup.topup_method == TopupMethod.MANUAL_REQUEST
            topup_data['is_online_payment'] = topup.topup_method == TopupMethod.PAYMENT_GATEWAY
            
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
        
        # Add bank account information for manual payments
        if topup.selected_bank_account:
            topup_data['bank_account'] = topup.selected_bank_account.to_dict()
        
        # Add payment gateway information for online payments
        if topup.payment_gateway:
            topup_data['payment_gateway'] = {
                'id': topup.payment_gateway.id,
                'gateway_name': topup.payment_gateway.gateway_name,
                'gateway_type': topup.payment_gateway.gateway_type.value
            }
        
        # Add payment method specific flags
        topup_data['is_manual_payment'] = topup.topup_method == TopupMethod.MANUAL_REQUEST
        topup_data['is_online_payment'] = topup.topup_method == TopupMethod.PAYMENT_GATEWAY
        
        return jsonify({'topup_request': topup_data})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# ADMIN OPERATIONS (UPDATED)
# =============================================================================

@enhanced_topup_bp.route('/api/requests/<request_id>/approve', methods=['POST'])
@login_required
def approve_topup_request(request_id):
    """Approve a top-up request (Admin only) - works for both manual and online"""
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
        
        data = request.get_json() or {}
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
            description=f'Wallet top-up approved - {request_id} ({topup.topup_method.value})',
            processed_by=current_user.id
        )
        
        db.session.add(wallet_transaction)
        db.session.commit()
        
        return jsonify({
            'message': 'Top-up request approved successfully',
            'request_id': request_id,
            'amount': float(topup.amount),
            'payment_method': topup.topup_method.value,
            'new_balance': float(wallet.balance)
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@enhanced_topup_bp.route('/api/requests/<request_id>/reject', methods=['POST'])
@login_required
def reject_topup_request(request_id):
    """Reject a top-up request (Admin only) - works for both manual and online"""
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
        
        data = request.get_json() or {}
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
            'payment_method': topup.topup_method.value,
            'reason': failure_reason
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# =============================================================================
# BANK ACCOUNT MANAGEMENT (UNCHANGED)
# =============================================================================

@enhanced_topup_bp.route('/api/bank-accounts', methods=['GET'])
@login_required
def get_bank_accounts():
    """Get available bank accounts for top-up"""
    try:
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
# PAGE ROUTES (UPDATED)
# =============================================================================

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
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN', 'WHITE_LABEL']:
        flash('Access denied', 'error')
        return redirect(url_for('enhanced_topup.topup_request_page'))
    
    return render_template('topup/admin_requests.html',
        title='Manage Top-up Requests',
        subtitle='Approve/Reject Top-up Requests'
    )

# =============================================================================
# STATISTICS (UPDATED FOR DUAL METHODS)
# =============================================================================

@enhanced_topup_bp.route('/api/stats', methods=['GET'])
@login_required
def get_topup_stats():
    """Get top-up statistics with payment method breakdown"""
    try:
        if current_user.role.value in ['SUPER_ADMIN', 'ADMIN', 'WHITE_LABEL']:
            base_query = WalletTopupRequest.query.join(User).filter(
                User.tenant_id == current_user.tenant_id,
                User.tree_path.like(f"{current_user.tree_path}%") if current_user.tree_path else True
            )
        else:
            base_query = WalletTopupRequest.query.filter(
                WalletTopupRequest.user_id == current_user.id
            )
        
        # Calculate overall statistics
        total_requests = base_query.count()
        pending_requests = base_query.filter(WalletTopupRequest.status == TransactionStatus.PENDING).count()
        approved_requests = base_query.filter(WalletTopupRequest.status == TransactionStatus.SUCCESS).count()
        rejected_requests = base_query.filter(WalletTopupRequest.status == TransactionStatus.FAILED).count()
        
        # Payment method breakdown
        manual_requests = base_query.filter(WalletTopupRequest.topup_method == TopupMethod.MANUAL_REQUEST).count()
        online_requests = base_query.filter(WalletTopupRequest.topup_method == TopupMethod.PAYMENT_GATEWAY).count()
        
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
            'manual_requests': manual_requests,
            'online_requests': online_requests,
            'total_amount': float(total_amount),
            'approved_amount': float(approved_amount),
            'today_requests': today_requests,
            'approval_rate': round((approved_requests / total_requests * 100) if total_requests > 0 else 0, 2),
            'manual_vs_online_ratio': {
                'manual_percentage': round((manual_requests / total_requests * 100) if total_requests > 0 else 0, 1),
                'online_percentage': round((online_requests / total_requests * 100) if total_requests > 0 else 0, 1)
            }
        }
        
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# FILE DOWNLOAD (UNCHANGED)
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
        
        # Only manual payments have proof documents
        if topup.topup_method != TopupMethod.MANUAL_REQUEST:
            return jsonify({'error': 'Proof document not available for online payments'}), 400
        
        if not topup.proof_document or not os.path.exists(topup.proof_document):
            return jsonify({'error': 'Proof document not found'}), 404
        
        from flask import send_file
        return send_file(topup.proof_document, as_attachment=True)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500