from flask import Blueprint, request, jsonify
from sqlalchemy import func
from models import Transaction, Wallet, User, db

report_bp = Blueprint('reports', __name__)

@report_bp.route('/reports/transactions', methods=['GET'])
@login_required
def transaction_report():
    """Generate transaction report with filters"""
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    status = request.args.get('status')  # pending, success, failed, etc.

    query = Transaction.query

    if start_date:
        query = query.filter(Transaction.created_at >= start_date)
    if end_date:
        query = query.filter(Transaction.created_at <= end_date)
    if status:
        query = query.filter(Transaction.status == TransactionStatus(status))

    transactions = query.all()
    total_amount = sum(txn.amount for txn in transactions)

    return jsonify({
        'total_transactions': len(transactions),
        'total_amount': total_amount,
        'transactions': [txn.to_dict() for txn in transactions]
    })

@report_bp.route('/reports/wallets', methods=['GET'])
@login_required
def wallet_stats():
    """Generate wallet balance and activity report"""
    total_balance = db.session.query(func.sum(Wallet.balance)).scalar() or 0
    total_active_wallets = db.session.query(Wallet).filter_by(is_active=True).count()

    return jsonify({
        'total_balance': total_balance,
        'active_wallets': total_active_wallets
    })
