from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from models import Transaction, Wallet, User, TransactionStatus, TransactionType, db
from sqlalchemy import or_, and_
from datetime import datetime

transaction_bp = Blueprint('transactions', __name__)

# CRUD for transactions
@transaction_bp.route('/transactions', methods=['POST'])
@login_required
def create_transaction():
    """Create a new transaction (e.g., deposit, withdrawal, transfer)"""
    data = request.get_json()
    try:
        wallet_id = data.get('wallet_id')
        amount = float(data.get('amount'))
        t_type = data.get('type')  # 'DEPOSIT', 'WITHDRAWAL', 'TRANSFER'
        status = data.get('status', TransactionStatus.PENDING.value)
        description = data.get('description', '')

        wallet = Wallet.query.get(wallet_id)
        if not wallet:
            return jsonify({'error': 'Wallet not found'}), 404
        # Permission check
        if not current_user.can_access_user(wallet.user):
            return jsonify({'error': 'Access denied'}), 403

        # Validate transaction amount
        if amount <= 0:
            return jsonify({'error': 'Amount must be positive'}), 400

        # Balance validation for withdrawal/transfer
        if t_type in ['WITHDRAWAL', 'TRANSFER'] and wallet.available_balance < amount:
            return jsonify({'error': 'Insufficient balance'}), 400

        # Create transaction record
        new_txn = Transaction(
            wallet_id=wallet.id,
            type=TransactionType(t_type),
            amount=amount,
            status=TransactionStatus(status),
            description=description,
            created_at=datetime.utcnow()
        )

        # Update wallet balance accordingly
        if t_type == 'DEPOSIT':
            wallet.balance += amount
        elif t_type in ['WITHDRAWAL', 'TRANSFER']:
            wallet.balance -= amount

        db.session.add(new_txn)
        db.session.commit()

        return jsonify({'message': 'Transaction successfully created', 'transaction': new_txn.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@transaction_bp.route('/transactions/<txn_id>', methods=['GET'])
@login_required
def get_transaction(txn_id):
    """Get specific transaction details"""
    txn = Transaction.query.get(txn_id)
    if not txn:
        return jsonify({'error': 'Transaction not found'}), 404
    if not current_user.can_access_user(txn.wallet.user):
        return jsonify({'error': 'Access denied'}), 403
    return jsonify({'transaction': txn.to_dict()})

@transaction_bp.route('/transactions/<txn_id>', methods=['PUT'])
@login_required
def update_transaction(txn_id):
    """Update transaction details if permissible"""
    txn = Transaction.query.get(txn_id)
    if not txn:
        return jsonify({'error': 'Transaction not found'}), 404
    if not current_user.can_access_user(txn.wallet.user):
        return jsonify({'error': 'Access denied'}), 403
    data = request.get_json()
    try:
        if 'status' in data:
            txn.status = TransactionStatus(data['status'])
        if 'description' in data:
            txn.description = data['description']
        db.session.commit()
        return jsonify({'message': 'Transaction updated', 'transaction': txn.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@transaction_bp.route('/transactions/<txn_id>', methods=['DELETE'])
@login_required
def delete_transaction(txn_id):
    """Cancel or delete a transaction if allowed"""
    txn = Transaction.query.get(txn_id)
    if not txn:
        return jsonify({'error': 'Transaction not found'}), 404
    if not current_user.can_access_user(txn.wallet.user):
        return jsonify({'error': 'Access denied'}), 403
    try:
        # For soft delete, mark as canceled
        txn.status = TransactionStatus.CANCELLED
        db.session.commit()
        return jsonify({'message': 'Transaction canceled'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
