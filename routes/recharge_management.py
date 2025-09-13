# routes/recharge_management.py
from flask import Blueprint, request, render_template, flash, redirect, url_for
from flask_login import login_required, current_user
from models import (
    db, Transaction, RechargeTransaction, Wallet, User, 
    ServiceType, TransactionStatus, WalletTransactionType, 
    WalletTransaction, UserRoleType
)
from datetime import datetime
from decimal import Decimal
import uuid

recharge_management_bp = Blueprint('recharge_management', __name__, url_prefix='/recharge-management')

@recharge_management_bp.route('/')
@login_required
def index():
    """Recharge management dashboard with stats"""
    allowed_roles = [
        UserRoleType.SUPER_ADMIN, UserRoleType.ADMIN, UserRoleType.WHITE_LABEL, 
        UserRoleType.DISTRIBUTOR, UserRoleType.RETAILER
    ]
    
    if current_user.role not in allowed_roles:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard.index'))

    # Define recharge services
    recharge_services = [ServiceType.MOBILE_RECHARGE, ServiceType.DTH_RECHARGE, ServiceType.BILL_PAYMENT]

    # Base query with role-based filtering
    base_query = Transaction.query.filter(
        Transaction.tenant_id == current_user.tenant_id,
        Transaction.service_type.in_(recharge_services)
    )

    if current_user.role == UserRoleType.RETAILER:
        base_query = base_query.filter(Transaction.user_id == current_user.id)
    elif current_user.role == UserRoleType.DISTRIBUTOR:
        distributor_users = User.query.filter(
            User.parent_id == current_user.id,
            User.tenant_id == current_user.tenant_id
        ).all()
        user_ids = [u.id for u in distributor_users] + [current_user.id]
        base_query = base_query.filter(Transaction.user_id.in_(user_ids))

    # Calculate statistics
    total_transactions = base_query.count()
    successful_transactions = base_query.filter(Transaction.status == TransactionStatus.SUCCESS).count()
    pending_transactions = base_query.filter(Transaction.status == TransactionStatus.PROCESSING).count()
    failed_transactions = base_query.filter(Transaction.status == TransactionStatus.FAILED).count()

    # Service type distribution
    service_stats = {}
    for service_type in recharge_services:
        count = base_query.filter(Transaction.service_type == service_type).count()
        if count > 0:
            service_stats[service_type.value] = count

    # Today's statistics
    today = datetime.utcnow().date()
    today_transactions = base_query.filter(
        db.func.date(Transaction.created_at) == today
    ).count()

    # Today's amount calculation
    today_amount_query = db.session.query(
        db.func.coalesce(db.func.sum(Transaction.amount), 0)
    ).filter(
        Transaction.tenant_id == current_user.tenant_id,
        Transaction.status == TransactionStatus.SUCCESS,
        db.func.date(Transaction.created_at) == today,
        Transaction.service_type.in_(recharge_services)
    )

    if current_user.role == UserRoleType.RETAILER:
        today_amount_query = today_amount_query.filter(Transaction.user_id == current_user.id)
    elif current_user.role == UserRoleType.DISTRIBUTOR:
        distributor_users = User.query.filter(
            User.parent_id == current_user.id,
            User.tenant_id == current_user.tenant_id
        ).all()
        user_ids = [u.id for u in distributor_users] + [current_user.id]
        today_amount_query = today_amount_query.filter(Transaction.user_id.in_(user_ids))

    today_amount = today_amount_query.scalar() or 0

    # Recent transactions
    recent_transactions = base_query.order_by(
        Transaction.created_at.desc()
    ).limit(5).all()

    # Get wallet balance
    user_wallet = Wallet.query.filter_by(user_id=current_user.id).first()

    stats = {
        'total_transactions': total_transactions,
        'successful_transactions': successful_transactions,
        'pending_transactions': pending_transactions,
        'failed_transactions': failed_transactions,
        'success_rate': (successful_transactions / total_transactions * 100) if total_transactions > 0 else 0,
        'service_stats': service_stats,
        'today_transactions': today_transactions,
        'today_amount': float(today_amount),
        'recent_transactions': recent_transactions,
        'wallet_balance': float(user_wallet.available_balance) if user_wallet else 0
    }

    return render_template('recharge_management/index.html',
        title='Recharge Management',
        subtitle='Mobile Recharge, DTH & Bill Payment Services',
        stats=stats
    )

@recharge_management_bp.route('/mobile-recharge', methods=['GET', 'POST'])
@login_required
def mobile_recharge():
    """Mobile recharge page with direct form handling"""
    if request.method == 'POST':
        try:
            # Get form data
            mobile = request.form.get('mobile')
            operator = request.form.get('operator')
            circle = request.form.get('circle')
            amount = request.form.get('amount')
            plan_id = request.form.get('plan_id')
            plan_description = request.form.get('plan_description', '')

            # Validate required fields
            if not all([mobile, operator, circle, amount]):
                flash('All fields are required', 'error')
                return redirect(request.url)

            amount = Decimal(amount)

            # Check wallet balance
            user_wallet = Wallet.query.filter_by(user_id=current_user.id).first()
            if not user_wallet or user_wallet.available_balance < amount:
                flash('Insufficient wallet balance', 'error')
                return redirect(request.url)

            # Generate unique transaction ID
            transaction_id = str(uuid.uuid4())[:20].replace('-', '')

            # Create transaction record
            transaction = Transaction(
                tenant_id=current_user.tenant_id,
                user_id=current_user.id,
                transaction_id=transaction_id,
                service_type=ServiceType.MOBILE_RECHARGE,
                amount=amount,
                net_amount=amount,
                status=TransactionStatus.SUCCESS,  # Direct success for demo
                customer_details={
                    "mobile": mobile,
                    "operator": operator,
                    "circle": circle
                },
                service_details={
                    "plan_id": plan_id,
                    "plan_description": plan_description
                },
                ip_address=request.remote_addr
            )

            db.session.add(transaction)
            db.session.flush()

            # Create recharge transaction details
            recharge_transaction = RechargeTransaction(
                transaction_id=transaction.id,
                operator_name=get_operator_name(operator),
                circle=get_circle_name(circle),
                mobile_number=mobile,
                plan_id=plan_id,
                plan_description=plan_description
            )

            db.session.add(recharge_transaction)

            # Update wallet balance
            user_wallet.balance -= amount

            # Create wallet transaction
            wallet_transaction = WalletTransaction(
                wallet_id=user_wallet.id,
                transaction_type=WalletTransactionType.DEBIT,
                amount=amount,
                balance_before=user_wallet.balance + amount,
                balance_after=user_wallet.balance,
                reference_id=transaction.id,
                reference_type='RECHARGE',
                description=f'Mobile recharge for {mobile}'
            )

            db.session.add(wallet_transaction)
            db.session.commit()

            flash('Mobile recharge processed successfully!', 'success')
            return redirect(url_for('recharge_management.transaction_details', transaction_id=transaction.id))

        except Exception as e:
            db.session.rollback()
            flash(f'Error processing recharge: {str(e)}', 'error')

    # Get data for template
    operators = get_operators_list()
    circles = get_circles_list()
    user_wallet = Wallet.query.filter_by(user_id=current_user.id).first()

    return render_template('recharge_management/mobile_recharge.html',
        title='Mobile Recharge',
        subtitle='Prepaid & Postpaid Mobile Recharge',
        operators=operators,
        circles=circles,
        wallet_balance=float(user_wallet.available_balance) if user_wallet else 0
    )

@recharge_management_bp.route('/dth-recharge', methods=['GET', 'POST'])
@login_required
def dth_recharge():
    """DTH recharge page with direct form handling"""
    if request.method == 'POST':
        try:
            customer_id = request.form.get('customer_id')
            operator = request.form.get('operator')
            amount = request.form.get('amount')

            if not all([customer_id, operator, amount]):
                flash('All fields are required', 'error')
                return redirect(request.url)

            amount = Decimal(amount)

            # Check wallet balance
            user_wallet = Wallet.query.filter_by(user_id=current_user.id).first()
            if not user_wallet or user_wallet.available_balance < amount:
                flash('Insufficient wallet balance', 'error')
                return redirect(request.url)

            transaction_id = str(uuid.uuid4())[:20].replace('-', '')

            transaction = Transaction(
                tenant_id=current_user.tenant_id,
                user_id=current_user.id,
                transaction_id=transaction_id,
                service_type=ServiceType.DTH_RECHARGE,
                amount=amount,
                net_amount=amount,
                status=TransactionStatus.SUCCESS,
                customer_details={
                    "customer_id": customer_id,
                    "operator": operator
                },
                ip_address=request.remote_addr
            )

            # Update wallet
            user_wallet.balance -= amount

            db.session.add(transaction)
            db.session.commit()

            flash('DTH recharge processed successfully!', 'success')
            return redirect(url_for('recharge_management.transaction_details', transaction_id=transaction.id))

        except Exception as e:
            db.session.rollback()
            flash(f'Error processing DTH recharge: {str(e)}', 'error')

    dth_operators = get_dth_operators_list()
    user_wallet = Wallet.query.filter_by(user_id=current_user.id).first()

    return render_template('recharge_management/dth_recharge.html',
        title='DTH Recharge',
        subtitle='Direct-to-Home Television Recharge',
        dth_operators=dth_operators,
        wallet_balance=float(user_wallet.available_balance) if user_wallet else 0
    )

@recharge_management_bp.route('/bill-payment', methods=['GET', 'POST'])
@login_required
def bill_payment():
    """Bill payment page with direct form handling"""
    if request.method == 'POST':
        try:
            connection_number = request.form.get('connection_number')
            operator = request.form.get('operator')
            amount = request.form.get('amount')

            if not all([connection_number, operator, amount]):
                flash('All fields are required', 'error')
                return redirect(request.url)

            amount = Decimal(amount)

            user_wallet = Wallet.query.filter_by(user_id=current_user.id).first()
            if not user_wallet or user_wallet.available_balance < amount:
                flash('Insufficient wallet balance', 'error')
                return redirect(request.url)

            transaction_id = str(uuid.uuid4())[:20].replace('-', '')

            transaction = Transaction(
                tenant_id=current_user.tenant_id,
                user_id=current_user.id,
                transaction_id=transaction_id,
                service_type=ServiceType.BILL_PAYMENT,
                amount=amount,
                net_amount=amount,
                status=TransactionStatus.SUCCESS,
                customer_details={
                    "connection_number": connection_number,
                    "operator": operator
                },
                ip_address=request.remote_addr
            )

            # Update wallet
            user_wallet.balance -= amount

            db.session.add(transaction)
            db.session.commit()

            flash('Bill payment processed successfully!', 'success')
            return redirect(url_for('recharge_management.transaction_details', transaction_id=transaction.id))

        except Exception as e:
            db.session.rollback()
            flash(f'Error processing bill payment: {str(e)}', 'error')

    bill_operators = get_bill_operators_list()
    user_wallet = Wallet.query.filter_by(user_id=current_user.id).first()

    return render_template('recharge_management/bill_payment.html',
        title='Bill Payment',
        subtitle='Electricity, Gas, Water & Other Bill Payments',
        bill_operators=bill_operators,
        wallet_balance=float(user_wallet.available_balance) if user_wallet else 0
    )

@recharge_management_bp.route('/transactions')
@login_required
def transactions():
    """Transactions list page with search and filters"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    status_filter = request.args.get('status', '')
    service_filter = request.args.get('service', '')
    search = request.args.get('search', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')

    # Base query
    recharge_services = [ServiceType.MOBILE_RECHARGE, ServiceType.DTH_RECHARGE, ServiceType.BILL_PAYMENT]

    query = Transaction.query.filter(
        Transaction.tenant_id == current_user.tenant_id,
        Transaction.service_type.in_(recharge_services)
    )

    # Role-based filtering
    if current_user.role == UserRoleType.RETAILER:
        query = query.filter(Transaction.user_id == current_user.id)
    elif current_user.role == UserRoleType.DISTRIBUTOR:
        distributor_users = User.query.filter(
            User.parent_id == current_user.id,
            User.tenant_id == current_user.tenant_id
        ).all()
        user_ids = [u.id for u in distributor_users] + [current_user.id]
        query = query.filter(Transaction.user_id.in_(user_ids))

    # Apply filters
    if status_filter and status_filter != 'all':
        try:
            if hasattr(TransactionStatus, status_filter.upper()):
                status_enum = getattr(TransactionStatus, status_filter.upper())
                query = query.filter(Transaction.status == status_enum)
        except:
            pass

    if service_filter and service_filter != 'all':
        try:
            if hasattr(ServiceType, service_filter.upper()):
                service_enum = getattr(ServiceType, service_filter.upper())
                query = query.filter(Transaction.service_type == service_enum)
        except:
            pass

    if search:
        query = query.filter(
            db.or_(
                Transaction.transaction_id.ilike(f'%{search}%'),
                Transaction.customer_details.op('->>')('mobile').ilike(f'%{search}%'),
                Transaction.customer_details.op('->>')('customer_id').ilike(f'%{search}%'),
                Transaction.customer_details.op('->>')('connection_number').ilike(f'%{search}%')
            )
        )

    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d').date()
            query = query.filter(db.func.date(Transaction.created_at) >= date_from_obj)
        except ValueError:
            pass

    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d').date()
            query = query.filter(db.func.date(Transaction.created_at) <= date_to_obj)
        except ValueError:
            pass

    transactions = query.order_by(Transaction.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template('recharge_management/transactions.html',
        title='Transaction History',
        subtitle='View and manage all recharge transactions',
        transactions=transactions,
        service_types=ServiceType,
        transaction_statuses=TransactionStatus,
        current_status=status_filter,
        current_service=service_filter,
        current_search=search,
        current_date_from=date_from,
        current_date_to=date_to
    )

@recharge_management_bp.route('/transaction/<transaction_id>')
@login_required
def transaction_details(transaction_id):
    """Transaction details page"""
    transaction = Transaction.query.filter(
        Transaction.id == transaction_id,
        Transaction.tenant_id == current_user.tenant_id
    ).first()

    if not transaction:
        flash('Transaction not found', 'error')
        return redirect(url_for('recharge_management.transactions'))

    # Check access permissions
    if current_user.role == UserRoleType.RETAILER and transaction.user_id != current_user.id:
        flash('Access denied', 'error')
        return redirect(url_for('recharge_management.transactions'))

    # Get recharge details
    recharge_details = None
    if transaction.service_type in [ServiceType.MOBILE_RECHARGE, ServiceType.DTH_RECHARGE]:
        recharge_details = RechargeTransaction.query.filter_by(
            transaction_id=transaction.id
        ).first()

    # Get wallet transactions
    wallet_transactions = WalletTransaction.query.filter(
        WalletTransaction.reference_id == transaction.id,
        WalletTransaction.reference_type.in_(['RECHARGE', 'BILL_PAYMENT'])
    ).all()

    return render_template('recharge_management/transaction_details.html',
        title=f'Transaction Details - {transaction.transaction_id}',
        subtitle='View complete transaction information',
        transaction=transaction,
        recharge_details=recharge_details,
        wallet_transactions=wallet_transactions
    )

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_operators_list():
    """Get list of mobile operators"""
    return [
        {'id': '1', 'name': 'Airtel', 'type': 'mobile'},
        {'id': '2', 'name': 'Jio', 'type': 'mobile'},
        {'id': '3', 'name': 'Vi (Vodafone Idea)', 'type': 'mobile'},
        {'id': '4', 'name': 'BSNL', 'type': 'mobile'},
    ]

def get_circles_list():
    """Get list of telecom circles"""
    return [
        {'id': '1', 'name': 'Andhra Pradesh'},
        {'id': '5', 'name': 'Delhi & NCR'},
        {'id': '10', 'name': 'Karnataka'},
        {'id': '15', 'name': 'Mumbai'},
        {'id': '20', 'name': 'Tamil Nadu'},
    ]

def get_dth_operators_list():
    """Get list of DTH operators"""
    return [
        {'id': '32', 'name': 'Dish TV'},
        {'id': '33', 'name': 'Tata Sky'},
        {'id': '34', 'name': 'Airtel Digital TV'},
        {'id': '35', 'name': 'Sun Direct'},
    ]

def get_bill_operators_list():
    """Get list of bill payment operators"""
    return [
        {'id': '59', 'name': 'BESCOM (Karnataka)', 'type': 'electricity'},
        {'id': '31', 'name': 'MSEDCL (Maharashtra)', 'type': 'electricity'},
        {'id': '132', 'name': 'TNEB (Tamil Nadu)', 'type': 'electricity'},
    ]

def get_operator_name(operator_id):
    """Get operator name by ID"""
    operators = {
        '1': 'Airtel', '2': 'Jio', '3': 'Vi', '4': 'BSNL',
        '32': 'Dish TV', '33': 'Tata Sky', '34': 'Airtel Digital TV'
    }
    return operators.get(operator_id, 'Unknown')

def get_circle_name(circle_id):
    """Get circle name by ID"""
    circles = {
        '1': 'Andhra Pradesh', '5': 'Delhi & NCR', '10': 'Karnataka',
        '15': 'Mumbai', '20': 'Tamil Nadu'
    }
    return circles.get(circle_id, 'Unknown')
