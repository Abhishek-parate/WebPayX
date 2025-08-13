from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from models import Wallet, WalletTransaction, User, WalletTransactionType, db
from decimal import Decimal
from datetime import datetime

wallet_bp = Blueprint('wallet', __name__)

# =============================================================================
# WALLET CRUD OPERATIONS
# =============================================================================

@wallet_bp.route('/wallets', methods=['GET'])
@login_required
def get_wallets():
    """Get wallets for users in hierarchy"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        user_id = request.args.get('user_id')
        
        # Base query
        query = db.session.query(Wallet).join(User).filter(
            User.tenant_id == current_user.tenant_id,
            User.tree_path.like(f"{current_user.tree_path}%")
        )
        
        if user_id:
            query = query.filter(Wallet.user_id == user_id)
        
        wallets = query.order_by(Wallet.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        wallet_data = []
        for wallet in wallets.items:
            wallet_dict = wallet.to_dict()
            wallet_dict['user'] = {
                'id': str(wallet.user.id),
                'username': wallet.user.username,
                'full_name': wallet.user.full_name,
                'user_code': wallet.user.user_code
            }
            wallet_data.append(wallet_dict)
        
        return jsonify({
            'wallets': wallet_data,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': wallets.total,
                'pages': wallets.pages
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@wallet_bp.route('/wallets/<wallet_id>', methods=['GET'])
@login_required
def get_wallet(wallet_id):
    """Get specific wallet details"""
    try:
        wallet = Wallet.query.join(User).filter(
            Wallet.id == wallet_id,
            User.tenant_id == current_user.tenant_id
        ).first()
        
        if not wallet:
            return jsonify({'error': 'Wallet not found'}), 404
        
        if not current_user.can_access_user(wallet.user):
            return jsonify({'error': 'Access denied'}), 403
        
        wallet_data = wallet.to_dict()
        wallet_data['user'] = wallet.user.to_dict()
        
        return jsonify({'wallet': wallet_data})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@wallet_bp.route('/wallets/<wallet_id>/balance', methods=['PUT'])
@login_required
def update_wallet_balance(wallet_id):
    """Admin function to credit/debit wallet"""
    try:
        wallet = Wallet.query.join(User).filter(
            Wallet.id == wallet_id,
            User.tenant_id == current_user.tenant_id
        ).first()
        
        if not wallet:
            return jsonify({'error': 'Wallet not found'}), 404
        
        if not current_user.can_access_user(wallet.user):
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        transaction_type = data.get('transaction_type')  # CREDIT or DEBIT
        amount = Decimal(str(data.get('amount', 0)))
        description = data.get('description', '')
        
        if amount <= 0:
            return jsonify({'error': 'Amount must be positive'}), 400
        
        if transaction_type not in ['CREDIT', 'DEBIT']:
            return jsonify({'error': 'Invalid transaction type'}), 400
        
        # Check if debit is possible
        if transaction_type == 'DEBIT' and wallet.available_balance < amount:
            return jsonify({'error': 'Insufficient balance'}), 400
        
        # Record balance before transaction
        balance_before = wallet.balance
        
        # Update wallet balance
        if transaction_type == 'CREDIT':
            wallet.balance += amount
            wallet.total_credited += amount
        else:
            wallet.balance -= amount
            wallet.total_debited += amount
        
        wallet.last_transaction_at = datetime.utcnow()
        
        # Create transaction record
        wallet_transaction = WalletTransaction(
            wallet_id=wallet.id,
            transaction_type=WalletTransactionType(transaction_type),
            amount=amount,
            balance_before=balance_before,
            balance_after=wallet.balance,
            description=description,
            processed_by=current_user.id
        )
        
        db.session.add(wallet_transaction)
        db.session.commit()
        
        return jsonify({
            'message': f'Wallet {transaction_type.lower()} successful',
            'wallet': wallet.to_dict(),
            'transaction': wallet_transaction.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@wallet_bp.route('/wallets/<wallet_id>/transactions', methods=['GET'])
@login_required
def get_wallet_transactions(wallet_id):
    """Get wallet transaction history"""
    try:
        wallet = Wallet.query.join(User).filter(
            Wallet.id == wallet_id,
            User.tenant_id == current_user.tenant_id
        ).first()
        
        if not wallet:
            return jsonify({'error': 'Wallet not found'}), 404
        
        if not current_user.can_access_user(wallet.user):
            return jsonify({'error': 'Access denied'}), 403
        
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        transaction_type = request.args.get('type')
        
        query = WalletTransaction.query.filter_by(wallet_id=wallet.id)
        
        if transaction_type:
            query = query.filter_by(transaction_type=WalletTransactionType(transaction_type))
        
        transactions = query.order_by(WalletTransaction.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'transactions': [txn.to_dict() for txn in transactions.items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': transactions.total,
                'pages': transactions.pages
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@wallet_bp.route('/wallets/<wallet_id>/limits', methods=['PUT'])
@login_required
def update_wallet_limits(wallet_id):
    """Update wallet transaction limits"""
    try:
        wallet = Wallet.query.join(User).filter(
            Wallet.id == wallet_id,
            User.tenant_id == current_user.tenant_id
        ).first()
        
        if not wallet:
            return jsonify({'error': 'Wallet not found'}), 404
        
        if not current_user.can_access_user(wallet.user):
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        
        if 'daily_limit' in data:
            wallet.daily_limit = Decimal(str(data['daily_limit']))
        
        if 'monthly_limit' in data:
            wallet.monthly_limit = Decimal(str(data['monthly_limit']))
        
        wallet.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'message': 'Wallet limits updated successfully',
            'wallet': wallet.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# =============================================================================
# WALLET STATISTICS
# =============================================================================

@wallet_bp.route('/wallets/stats', methods=['GET'])
@login_required
def get_wallet_stats():
    """Get wallet statistics for current user's hierarchy"""
    try:
        # Get all wallets in hierarchy
        wallets = db.session.query(Wallet).join(User).filter(
            User.tenant_id == current_user.tenant_id,
            User.tree_path.like(f"{current_user.tree_path}%"),
            Wallet.is_active == True
        ).all()
        
        total_balance = sum(wallet.balance for wallet in wallets)
        total_hold_balance = sum(wallet.hold_balance for wallet in wallets)
        active_wallets = len(wallets)
        
        # Get today's transactions
        from datetime import date
        today_transactions = db.session.query(WalletTransaction).join(Wallet).join(User).filter(
            User.tenant_id == current_user.tenant_id,
            User.tree_path.like(f"{current_user.tree_path}%"),
            WalletTransaction.created_at >= datetime.combine(date.today(), datetime.min.time())
        ).count()
        
        return jsonify({
            'stats': {
                'total_balance': float(total_balance),
                'total_hold_balance': float(total_hold_balance),
                'available_balance': float(total_balance - total_hold_balance),
                'active_wallets': active_wallets,
                'today_transactions': today_transactions
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
