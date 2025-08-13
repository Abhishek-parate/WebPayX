# routes/topup_routes.py
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from models import Wallet, WalletTopupRequest, WalletTransaction, WalletTransactionType, db
from datetime import datetime
from decimal import Decimal

topup_bp = Blueprint('topup', __name__)

# ============================================
# Wallet Top-up Requests
# ============================================

@topup_bp.route('/topups', methods=['POST'])
@login_required
def request_topup():
    """Request wallet top-up"""
    try:
        data = request.get_json()
        amount = Decimal(str(data.get('amount', 0)))
        wallet_id = data.get('wallet_id')
        
        # Validate wallet
        wallet = Wallet.query.join(models.User).filter(
            Wallet.id == wallet_id,
            models.User.tenant_id == current_user.tenant_id
        ).first()
        if not wallet or not current_user.can_access_user(wallet.user):
            return jsonify({'error': 'Wallet not found or access denied'}), 404

        if amount <= 0:
            return jsonify({'error': 'Amount must be positive'}), 400

        # Create top-up request
        topup_request = WalletTopupRequest(
            wallet_id=wallet.id,
            amount=amount,
            requested_by=current_user.id,
            status='PENDING',
            requested_at=datetime.utcnow()
        )
        db.session.add(topup_request)
        db.session.commit()

        return jsonify({'message': 'Top-up request submitted', 'topup_request': topup_request.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@topup_bp.route('/topups/<int:request_id>/approve', methods=['POST'])
@login_required
def approve_topup(request_id):
    """Approve a top-up request"""
    try:
        topup = WalletTopupRequest.query.get(request_id)
        if not topup or topup.status != 'PENDING':
            return jsonify({'error': 'Top-up request not found or already processed'}), 404

        # Check permissions
        wallet = Wallet.query.get(topup.wallet_id)
        if not wallet or not current_user.can_access_user(wallet.user):
            return jsonify({'error': 'Access denied'}), 403

        # Update wallet balance
        wallet.balance += topup.amount
        topup.status = 'COMPLETED'
        topup.completed_at = datetime.utcnow()

        # Record transaction
        transaction = WalletTransaction(
            wallet_id=wallet.id,
            transaction_type=WalletTransactionType.CREDIT,
            amount=topup.amount,
            balance_before=wallet.balance - topup.amount,
            balance_after=wallet.balance,
            description='Wallet top-up approved',
            processed_by=current_user.id
        )
        db.session.add(transaction)
        db.session.commit()

        return jsonify({'message': 'Top-up approved', 'transaction': transaction.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@topup_bp.route('/topups/<int:request_id>/reject', methods=['POST'])
@login_required
def reject_topup(request_id):
    """Reject a top-up request"""
    try:
        topup = WalletTopupRequest.query.get(request_id)
        if not topup or topup.status != 'PENDING':
            return jsonify({'error': 'Top-up request not found or already processed'}), 404
        # Permission check
        wallet = Wallet.query.get(topup.wallet_id)
        if not wallet or not current_user.can_access_user(wallet.user):
            return jsonify({'error': 'Access denied'}), 403
        topup.status = 'REJECTED'
        topup.completed_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'message': 'Top-up rejected'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# ============================================
# Wallet Top-Up History & Stats
# ============================================

@topup_bp.route('/topups', methods=['GET'])
@login_required
def get_topup_requests():
    """List all top-up requests with filtering"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        status_filter = request.args.get('status')
        wallet_id = request.args.get('wallet_id')

        query = WalletTopupRequest.query.join(models.Wallet).join(models.User).filter(
            models.User.tenant_id == current_user.tenant_id
        )

        if wallet_id:
            query = query.filter(Wallet.id == wallet_id)

        if status_filter:
            query = query.filter(WalletTopupRequest.status == status_filter.upper())

        topups = query.order_by(WalletTopupRequest.requested_at.desc()).paginate(page, per_page, error_out=False)

        return jsonify({
            'topups': [t.to_dict() for t in topups.items],
            'pagination': {'page': page, 'per_page': per_page, 'total': topups.total}
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500