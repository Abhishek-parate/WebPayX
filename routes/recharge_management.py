# routes/recharge_management.py
from flask import Blueprint, request, render_template, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user
from sqlalchemy import and_, or_, func, desc
from models import (
    db, Transaction, RechargeTransaction, BillPaymentTransaction, Wallet, User, 
    ServiceType, TransactionStatus, WalletTransactionType, 
    WalletTransaction, UserRoleType, CommissionDistribution
)
from datetime import datetime, timedelta
from decimal import Decimal
import uuid
import logging
import requests
import json
from typing import Dict, List, Optional

# Configure logging
logger = logging.getLogger(__name__)

recharge_management_bp = Blueprint('recharge_management', __name__, url_prefix='/recharge-management')

# =============================================================================
# DASHBOARD & OVERVIEW
# =============================================================================

@recharge_management_bp.route('/')
@login_required
def index():
    """Enhanced recharge management dashboard with comprehensive stats"""
    allowed_roles = [
        UserRoleType.SUPER_ADMIN, UserRoleType.ADMIN, UserRoleType.WHITE_LABEL, 
        UserRoleType.MASTER_DISTRIBUTOR, UserRoleType.DISTRIBUTOR, UserRoleType.RETAILER
    ]
    
    if current_user.role not in allowed_roles:
        flash('Access denied. Insufficient permissions.', 'error')
        return redirect(url_for('dashboard.index'))

    try:
        # Define recharge services
        recharge_services = [ServiceType.MOBILE_RECHARGE, ServiceType.DTH_RECHARGE, ServiceType.BILL_PAYMENT]

        # Get accessible user IDs based on role hierarchy
        accessible_user_ids = get_accessible_user_ids(current_user)

        # Base query with role-based filtering
        base_query = Transaction.query.filter(
            Transaction.tenant_id == current_user.tenant_id,
            Transaction.service_type.in_(recharge_services),
            Transaction.user_id.in_(accessible_user_ids)
        )

        # Calculate comprehensive statistics
        stats = calculate_recharge_stats(base_query, recharge_services)
        
        # Get recent transactions
        recent_transactions = base_query.order_by(desc(Transaction.created_at)).limit(10).all()

        # Get wallet information
        user_wallet = Wallet.query.filter_by(user_id=current_user.id).first()
        
        # Get service performance data for charts
        service_performance = get_service_performance_data(base_query, recharge_services)
        
        # Get monthly trend data
        monthly_trends = get_monthly_trend_data(base_query)

        return render_template('recharge_management/dashboard.html',
            title='Recharge Management Dashboard',
            subtitle='Mobile Recharge, DTH & Bill Payment Services',
            stats=stats,
            recent_transactions=recent_transactions,
            wallet_balance=float(user_wallet.available_balance) if user_wallet else 0,
            wallet=user_wallet,
            service_performance=service_performance,
            monthly_trends=monthly_trends,
            user_role=current_user.role,
            ServiceType=ServiceType,
            TransactionStatus=TransactionStatus
        )
    except Exception as e:
        logger.error(f"Dashboard error for user {current_user.id}: {str(e)}")
        flash('Error loading dashboard. Please try again.', 'error')
        return redirect(url_for('dashboard.index'))

# =============================================================================
# MOBILE RECHARGE
# =============================================================================

@recharge_management_bp.route('/mobile-recharge', methods=['GET', 'POST'])
@login_required
def mobile_recharge():
    """Enhanced mobile recharge with operator plans and validation"""
    if request.method == 'POST':
        return process_mobile_recharge()

    try:
        # Get operators and circles
        operators = get_mobile_operators()
        circles = get_telecom_circles()
        
        # Get user wallet
        user_wallet = Wallet.query.filter_by(user_id=current_user.id).first()
        
        # Get recent recharges for this user
        recent_recharges = Transaction.query.filter(
            Transaction.user_id == current_user.id,
            Transaction.service_type == ServiceType.MOBILE_RECHARGE,
            Transaction.tenant_id == current_user.tenant_id
        ).order_by(desc(Transaction.created_at)).limit(5).all()

        return render_template('recharge_management/mobile_recharge.html',
            title='Mobile Recharge',
            subtitle='Prepaid & Postpaid Mobile Recharge',
            operators=operators,
            circles=circles,
            wallet_balance=float(user_wallet.available_balance) if user_wallet else 0,
            recent_recharges=recent_recharges,
            wallet=user_wallet
        )
    except Exception as e:
        logger.error(f"Mobile recharge page error: {str(e)}")
        flash('Error loading mobile recharge page', 'error')
        return redirect(url_for('recharge_management.index'))

def process_mobile_recharge():
    """Process mobile recharge transaction"""
    try:
        # Get and validate form data
        form_data = {
            'mobile': request.form.get('mobile', '').strip(),
            'operator': request.form.get('operator', '').strip(),
            'circle': request.form.get('circle', '').strip(),
            'amount': request.form.get('amount', '').strip(),
            'plan_id': request.form.get('plan_id', '').strip(),
            'plan_description': request.form.get('plan_description', '').strip(),
            'plan_validity': request.form.get('plan_validity', '').strip(),
            'plan_benefits': request.form.get('plan_benefits', '').strip()
        }

        # Validate required fields
        required_fields = ['mobile', 'operator', 'circle', 'amount']
        for field in required_fields:
            if not form_data[field]:
                flash(f'{field.title()} is required', 'error')
                return redirect(url_for('recharge_management.mobile_recharge'))

        # Validate mobile number
        if not validate_mobile_number(form_data['mobile']):
            flash('Please enter a valid 10-digit mobile number', 'error')
            return redirect(url_for('recharge_management.mobile_recharge'))

        # Validate and convert amount
        try:
            amount = Decimal(form_data['amount'])
            if amount <= 0 or amount > 5000:
                flash('Amount must be between ₹1 and ₹5000', 'error')
                return redirect(url_for('recharge_management.mobile_recharge'))
        except (ValueError, TypeError):
            flash('Please enter a valid amount', 'error')
            return redirect(url_for('recharge_management.mobile_recharge'))

        # Check wallet balance
        user_wallet = Wallet.query.filter_by(user_id=current_user.id).first()
        if not user_wallet:
            flash('Wallet not found. Please contact support.', 'error')
            return redirect(url_for('recharge_management.mobile_recharge'))
        
        if user_wallet.available_balance < amount:
            flash(f'Insufficient wallet balance. Available: ₹{user_wallet.available_balance}', 'error')
            return redirect(url_for('recharge_management.mobile_recharge'))

        # Check daily limits
        if not check_daily_transaction_limit(current_user.id, amount):
            flash('Daily transaction limit exceeded', 'error')
            return redirect(url_for('recharge_management.mobile_recharge'))

        # Generate unique transaction ID
        transaction_id = generate_transaction_id('MR')

        # Create transaction record
        transaction = Transaction(
            tenant_id=current_user.tenant_id,
            user_id=current_user.id,
            transaction_id=transaction_id,
            service_type=ServiceType.MOBILE_RECHARGE,
            amount=amount,
            net_amount=amount,
            status=TransactionStatus.PROCESSING,
            customer_details={
                "mobile": form_data['mobile'],
                "operator": form_data['operator'],
                "circle": form_data['circle']
            },
            service_details={
                "plan_id": form_data['plan_id'],
                "plan_description": form_data['plan_description'],
                "plan_validity": form_data['plan_validity'],
                "plan_benefits": form_data['plan_benefits']
            },
            ip_address=request.remote_addr,
            device_info=get_device_info()
        )

        db.session.add(transaction)
        db.session.flush()

        # Create recharge transaction details
        recharge_transaction = RechargeTransaction(
            transaction_id=transaction.id,
            operator_name=get_operator_name(form_data['operator']),
            circle=get_circle_name(form_data['circle']),
            mobile_number=form_data['mobile'],
            plan_id=form_data['plan_id'],
            plan_description=form_data['plan_description'],
            validity=form_data['plan_validity']
        )
        db.session.add(recharge_transaction)

        # Update wallet balance (hold amount)
        user_wallet.hold_balance += amount

        # Create wallet transaction
        wallet_transaction = WalletTransaction(
            wallet_id=user_wallet.id,
            transaction_type=WalletTransactionType.HOLD,
            amount=amount,
            balance_before=user_wallet.balance,
            balance_after=user_wallet.balance,
            reference_id=transaction.id,
            reference_type='MOBILE_RECHARGE',
            description=f'Mobile recharge for {form_data["mobile"]} - Amount held',
            processed_by=current_user.id
        )
        db.session.add(wallet_transaction)

        # Commit the transaction
        db.session.commit()

        # Process recharge (simulate API call for now)
        success = process_recharge_with_operator(transaction, recharge_transaction)
        
        if success:
            # Update transaction status
            transaction.status = TransactionStatus.SUCCESS
            transaction.processed_at = datetime.utcnow()
            
            # Release hold and debit actual amount
            user_wallet.hold_balance -= amount
            user_wallet.balance -= amount
            
            # Update wallet transaction
            release_transaction = WalletTransaction(
                wallet_id=user_wallet.id,
                transaction_type=WalletTransactionType.DEBIT,
                amount=amount,
                balance_before=user_wallet.balance + amount,
                balance_after=user_wallet.balance,
                reference_id=transaction.id,
                reference_type='MOBILE_RECHARGE',
                description=f'Mobile recharge successful for {form_data["mobile"]}',
                processed_by=current_user.id
            )
            db.session.add(release_transaction)
            
            db.session.commit()
            
            flash('Mobile recharge processed successfully!', 'success')
            return redirect(url_for('recharge_management.transaction_details', transaction_id=transaction.id))
        else:
            # Release hold amount
            user_wallet.hold_balance -= amount
            transaction.status = TransactionStatus.FAILED
            transaction.failure_reason = "Operator processing failed"
            
            db.session.commit()
            
            flash('Recharge failed. Please try again or contact support.', 'error')
            return redirect(url_for('recharge_management.mobile_recharge'))

    except Exception as e:
        db.session.rollback()
        logger.error(f"Mobile recharge error for user {current_user.id}: {str(e)}")
        flash('Error processing recharge. Please try again.', 'error')
        return redirect(url_for('recharge_management.mobile_recharge'))

# =============================================================================
# DTH RECHARGE
# =============================================================================

@recharge_management_bp.route('/dth-recharge', methods=['GET', 'POST'])
@login_required
def dth_recharge():
    """Enhanced DTH recharge with validation"""
    if request.method == 'POST':
        return process_dth_recharge()

    try:
        dth_operators = get_dth_operators()
        user_wallet = Wallet.query.filter_by(user_id=current_user.id).first()
        
        # Get recent DTH recharges
        recent_recharges = Transaction.query.filter(
            Transaction.user_id == current_user.id,
            Transaction.service_type == ServiceType.DTH_RECHARGE,
            Transaction.tenant_id == current_user.tenant_id
        ).order_by(desc(Transaction.created_at)).limit(5).all()

        return render_template('recharge_management/dth_recharge.html',
            title='DTH Recharge',
            subtitle='Direct-to-Home Television Recharge',
            dth_operators=dth_operators,
            wallet_balance=float(user_wallet.available_balance) if user_wallet else 0,
            recent_recharges=recent_recharges,
            wallet=user_wallet
        )
    except Exception as e:
        logger.error(f"DTH recharge page error: {str(e)}")
        flash('Error loading DTH recharge page', 'error')
        return redirect(url_for('recharge_management.index'))

def process_dth_recharge():
    """Process DTH recharge transaction"""
    try:
        customer_id = request.form.get('customer_id', '').strip()
        operator = request.form.get('operator', '').strip()
        amount = request.form.get('amount', '').strip()

        # Validation
        if not all([customer_id, operator, amount]):
            flash('All fields are required', 'error')
            return redirect(url_for('recharge_management.dth_recharge'))

        if not validate_dth_customer_id(customer_id):
            flash('Please enter a valid customer ID', 'error')
            return redirect(url_for('recharge_management.dth_recharge'))

        try:
            amount = Decimal(amount)
            if amount <= 0 or amount > 10000:
                flash('Amount must be between ₹1 and ₹10000', 'error')
                return redirect(url_for('recharge_management.dth_recharge'))
        except (ValueError, TypeError):
            flash('Please enter a valid amount', 'error')
            return redirect(url_for('recharge_management.dth_recharge'))

        # Check wallet balance
        user_wallet = Wallet.query.filter_by(user_id=current_user.id).first()
        if not user_wallet or user_wallet.available_balance < amount:
            flash('Insufficient wallet balance', 'error')
            return redirect(url_for('recharge_management.dth_recharge'))

        transaction_id = generate_transaction_id('DTH')

        transaction = Transaction(
            tenant_id=current_user.tenant_id,
            user_id=current_user.id,
            transaction_id=transaction_id,
            service_type=ServiceType.DTH_RECHARGE,
            amount=amount,
            net_amount=amount,
            status=TransactionStatus.SUCCESS,  # Simulate success
            customer_details={
                "customer_id": customer_id,
                "operator": operator
            },
            service_details={
                "operator_name": get_dth_operator_name(operator)
            },
            ip_address=request.remote_addr,
            device_info=get_device_info(),
            processed_at=datetime.utcnow()
        )

        # Update wallet
        user_wallet.balance -= amount

        # Create wallet transaction
        wallet_transaction = WalletTransaction(
            wallet_id=user_wallet.id,
            transaction_type=WalletTransactionType.DEBIT,
            amount=amount,
            balance_before=user_wallet.balance + amount,
            balance_after=user_wallet.balance,
            reference_id=transaction.id,
            reference_type='DTH_RECHARGE',
            description=f'DTH recharge for {customer_id}',
            processed_by=current_user.id
        )

        db.session.add(transaction)
        db.session.add(wallet_transaction)
        db.session.commit()

        flash('DTH recharge processed successfully!', 'success')
        return redirect(url_for('recharge_management.transaction_details', transaction_id=transaction.id))

    except Exception as e:
        db.session.rollback()
        logger.error(f"DTH recharge error: {str(e)}")
        flash('Error processing DTH recharge', 'error')
        return redirect(url_for('recharge_management.dth_recharge'))

# =============================================================================
# BILL PAYMENT
# =============================================================================

@recharge_management_bp.route('/bill-payment', methods=['GET', 'POST'])
@login_required
def bill_payment():
    """Enhanced bill payment with view bill feature"""
    if request.method == 'POST':
        return process_bill_payment()

    try:
        bill_operators = get_bill_operators()
        user_wallet = Wallet.query.filter_by(user_id=current_user.id).first()
        
        # Get recent bill payments
        recent_payments = Transaction.query.filter(
            Transaction.user_id == current_user.id,
            Transaction.service_type == ServiceType.BILL_PAYMENT,
            Transaction.tenant_id == current_user.tenant_id
        ).order_by(desc(Transaction.created_at)).limit(5).all()

        return render_template('recharge_management/bill_payment.html',
            title='Bill Payment',
            subtitle='Electricity, Gas, Water & Other Bill Payments',
            bill_operators=bill_operators,
            wallet_balance=float(user_wallet.available_balance) if user_wallet else 0,
            recent_payments=recent_payments,
            wallet=user_wallet
        )
    except Exception as e:
        logger.error(f"Bill payment page error: {str(e)}")
        flash('Error loading bill payment page', 'error')
        return redirect(url_for('recharge_management.index'))

@recharge_management_bp.route('/api/view-bill', methods=['POST'])
@login_required
def view_bill():
    """API endpoint to fetch bill details"""
    try:
        data = request.get_json()
        connection_number = data.get('connection_number')
        operator_id = data.get('operator_id')
        
        if not connection_number or not operator_id:
            return jsonify({
                'success': False,
                'message': 'Connection number and operator are required'
            }), 400

        # Simulate bill fetch (in real implementation, call operator API)
        bill_data = fetch_bill_details(connection_number, operator_id)
        
        return jsonify({
            'success': True,
            'data': bill_data
        })
    
    except Exception as e:
        logger.error(f"View bill error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Error fetching bill details'
        }), 500

def process_bill_payment():
    """Process bill payment transaction"""
    try:
        connection_number = request.form.get('connection_number', '').strip()
        operator = request.form.get('operator', '').strip()
        amount = request.form.get('amount', '').strip()
        customer_name = request.form.get('customer_name', '').strip()
        due_date = request.form.get('due_date', '').strip()

        if not all([connection_number, operator, amount]):
            flash('Connection number, operator and amount are required', 'error')
            return redirect(url_for('recharge_management.bill_payment'))

        try:
            amount = Decimal(amount)
            if amount <= 0 or amount > 50000:
                flash('Amount must be between ₹1 and ₹50000', 'error')
                return redirect(url_for('recharge_management.bill_payment'))
        except (ValueError, TypeError):
            flash('Please enter a valid amount', 'error')
            return redirect(url_for('recharge_management.bill_payment'))

        user_wallet = Wallet.query.filter_by(user_id=current_user.id).first()
        if not user_wallet or user_wallet.available_balance < amount:
            flash('Insufficient wallet balance', 'error')
            return redirect(url_for('recharge_management.bill_payment'))

        transaction_id = generate_transaction_id('BP')

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
                "operator": operator,
                "customer_name": customer_name,
                "due_date": due_date
            },
            service_details={
                "operator_name": get_bill_operator_name(operator),
                "bill_category": get_bill_category(operator)
            },
            ip_address=request.remote_addr,
            device_info=get_device_info(),
            processed_at=datetime.utcnow()
        )

        db.session.add(transaction)
        db.session.flush()

        # Create bill payment details
        bill_payment = BillPaymentTransaction(
            transaction_id=transaction.id,
            category=get_bill_category(operator),
            biller_name=get_bill_operator_name(operator),
            biller_id=operator,
            customer_name=customer_name,
            customer_number=connection_number,
            bill_amount=amount,
            due_date=datetime.strptime(due_date, '%Y-%m-%d').date() if due_date else None
        )
        db.session.add(bill_payment)

        # Update wallet
        user_wallet.balance -= amount

        # Create wallet transaction
        wallet_transaction = WalletTransaction(
            wallet_id=user_wallet.id,
            transaction_type=WalletTransactionType.DEBIT,
            amount=amount,
            balance_before=user_wallet.balance + amount,
            balance_after=user_wallet.balance,
            reference_id=transaction.id,
            reference_type='BILL_PAYMENT',
            description=f'Bill payment for {connection_number}',
            processed_by=current_user.id
        )
        db.session.add(wallet_transaction)

        db.session.commit()

        flash('Bill payment processed successfully!', 'success')
        return redirect(url_for('recharge_management.transaction_details', transaction_id=transaction.id))

    except Exception as e:
        db.session.rollback()
        logger.error(f"Bill payment error: {str(e)}")
        flash('Error processing bill payment', 'error')
        return redirect(url_for('recharge_management.bill_payment'))

# =============================================================================
# TRANSACTIONS & REPORTS
# =============================================================================

@recharge_management_bp.route('/transactions')
@login_required
def transactions():
    """Enhanced transactions list with advanced filtering"""
    try:
        # Get filter parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        status_filter = request.args.get('status', '')
        service_filter = request.args.get('service', '')
        search = request.args.get('search', '')
        date_from = request.args.get('date_from', '')
        date_to = request.args.get('date_to', '')
        amount_from = request.args.get('amount_from', '')
        amount_to = request.args.get('amount_to', '')

        # Get accessible user IDs
        accessible_user_ids = get_accessible_user_ids(current_user)
        recharge_services = [ServiceType.MOBILE_RECHARGE, ServiceType.DTH_RECHARGE, ServiceType.BILL_PAYMENT]

        # Base query
        query = Transaction.query.filter(
            Transaction.tenant_id == current_user.tenant_id,
            Transaction.service_type.in_(recharge_services),
            Transaction.user_id.in_(accessible_user_ids)
        )

        # Apply filters
        query = apply_transaction_filters(query, {
            'status': status_filter,
            'service': service_filter,
            'search': search,
            'date_from': date_from,
            'date_to': date_to,
            'amount_from': amount_from,
            'amount_to': amount_to
        })

        # Get paginated results
        transactions = query.order_by(desc(Transaction.created_at)).paginate(
            page=page, per_page=per_page, error_out=False
        )

        # Calculate summary stats for filtered results
        filtered_stats = calculate_filtered_stats(query)

        return render_template('recharge_management/transactions.html',
            title='Transaction History',
            subtitle='View and manage all recharge transactions',
            transactions=transactions,
            filtered_stats=filtered_stats,
            service_types=ServiceType,
            transaction_statuses=TransactionStatus,
            filters={
                'status': status_filter,
                'service': service_filter,
                'search': search,
                'date_from': date_from,
                'date_to': date_to,
                'amount_from': amount_from,
                'amount_to': amount_to
            }
        )
    except Exception as e:
        logger.error(f"Transactions page error: {str(e)}")
        flash('Error loading transactions', 'error')
        return redirect(url_for('recharge_management.index'))

@recharge_management_bp.route('/transaction/<transaction_id>')
@login_required
def transaction_details(transaction_id):
    """Enhanced transaction details with complete information"""
    try:
        transaction = Transaction.query.filter(
            Transaction.id == transaction_id,
            Transaction.tenant_id == current_user.tenant_id
        ).first()

        if not transaction:
            flash('Transaction not found', 'error')
            return redirect(url_for('recharge_management.transactions'))

        # Check access permissions
        accessible_user_ids = get_accessible_user_ids(current_user)
        if transaction.user_id not in accessible_user_ids:
            flash('Access denied', 'error')
            return redirect(url_for('recharge_management.transactions'))

        # Get service-specific details
        service_details = get_transaction_service_details(transaction)
        
        # Get wallet transactions
        wallet_transactions = WalletTransaction.query.filter(
            WalletTransaction.reference_id == transaction.id
        ).order_by(desc(WalletTransaction.created_at)).all()

        # Get commission details
        commissions = CommissionDistribution.query.filter(
            CommissionDistribution.transaction_id == transaction.id
        ).all()

        # Get transaction user details
        transaction_user = User.query.get(transaction.user_id)

        return render_template('recharge_management/transaction_details.html',
            title=f'Transaction Details - {transaction.transaction_id}',
            subtitle='Complete transaction information',
            transaction=transaction,
            service_details=service_details,
            wallet_transactions=wallet_transactions,
            commissions=commissions,
            transaction_user=transaction_user
        )
    except Exception as e:
        logger.error(f"Transaction details error: {str(e)}")
        flash('Error loading transaction details', 'error')
        return redirect(url_for('recharge_management.transactions'))

# =============================================================================
# API ENDPOINTS
# =============================================================================

@recharge_management_bp.route('/api/operators/<service_type>')
@login_required
def get_operators_api(service_type):
    """API to get operators for a service type"""
    try:
        if service_type == 'mobile':
            operators = get_mobile_operators()
        elif service_type == 'dth':
            operators = get_dth_operators()
        elif service_type == 'bill':
            operators = get_bill_operators()
        else:
            return jsonify({'success': False, 'message': 'Invalid service type'}), 400
            
        return jsonify({'success': True, 'data': operators})
    except Exception as e:
        logger.error(f"Get operators API error: {str(e)}")
        return jsonify({'success': False, 'message': 'Error fetching operators'}), 500

@recharge_management_bp.route('/api/plans/<operator_id>/<circle_id>')
@login_required
def get_plans_api(operator_id, circle_id):
    """API to get recharge plans"""
    try:
        plans = fetch_recharge_plans(operator_id, circle_id)
        return jsonify({'success': True, 'data': plans})
    except Exception as e:
        logger.error(f"Get plans API error: {str(e)}")
        return jsonify({'success': False, 'message': 'Error fetching plans'}), 500

@recharge_management_bp.route('/api/validate-number', methods=['POST'])
@login_required
def validate_number_api():
    """API to validate mobile/connection numbers"""
    try:
        data = request.get_json()
        number = data.get('number')
        service_type = data.get('service_type')
        operator_id = data.get('operator_id')
        
        if service_type == 'mobile':
            is_valid = validate_mobile_number(number)
        elif service_type == 'dth':
            is_valid = validate_dth_customer_id(number)
        else:
            is_valid = validate_connection_number(number, operator_id)
        
        return jsonify({
            'success': True,
            'valid': is_valid,
            'message': 'Valid' if is_valid else 'Invalid number format'
        })
    except Exception as e:
        logger.error(f"Validate number API error: {str(e)}")
        return jsonify({'success': False, 'message': 'Validation error'}), 500

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_accessible_user_ids(user):
    """Get list of user IDs accessible to current user based on role hierarchy"""
    if user.role in [UserRoleType.SUPER_ADMIN, UserRoleType.ADMIN]:
        # Super admin and admin can see all users in tenant
        users = User.query.filter_by(tenant_id=user.tenant_id).all()
        return [u.id for u in users]
    elif user.role == UserRoleType.WHITE_LABEL:
        # White label can see their hierarchy
        users = User.query.filter(
            User.tenant_id == user.tenant_id,
            or_(User.id == user.id, User.tree_path.like(f'%{user.id}%'))
        ).all()
        return [u.id for u in users]
    elif user.role in [UserRoleType.MASTER_DISTRIBUTOR, UserRoleType.DISTRIBUTOR]:
        # Distributors can see their children and their own
        children = User.query.filter(
            User.parent_id == user.id,
            User.tenant_id == user.tenant_id
        ).all()
        return [u.id for u in children] + [user.id]
    else:
        # Retailers can only see their own
        return [user.id]

def calculate_recharge_stats(base_query, recharge_services):
    """Calculate comprehensive recharge statistics"""
    total_transactions = base_query.count()
    successful_transactions = base_query.filter(Transaction.status == TransactionStatus.SUCCESS).count()
    pending_transactions = base_query.filter(Transaction.status == TransactionStatus.PROCESSING).count()
    failed_transactions = base_query.filter(Transaction.status == TransactionStatus.FAILED).count()

    # Service type distribution
    service_stats = {}
    for service_type in recharge_services:
        count = base_query.filter(Transaction.service_type == service_type).count()
        volume = db.session.query(func.coalesce(func.sum(Transaction.amount), 0)).filter(
            Transaction.tenant_id == current_user.tenant_id,
            Transaction.service_type == service_type,
            Transaction.status == TransactionStatus.SUCCESS
        ).scalar()
        service_stats[service_type.value] = {
            'count': count,
            'volume': float(volume or 0)
        }

    # Today's statistics
    today = datetime.utcnow().date()
    today_transactions = base_query.filter(
        func.date(Transaction.created_at) == today
    ).count()

    # Today's volume
    today_volume = db.session.query(
        func.coalesce(func.sum(Transaction.amount), 0)
    ).filter(
        Transaction.tenant_id == current_user.tenant_id,
        Transaction.status == TransactionStatus.SUCCESS,
        func.date(Transaction.created_at) == today,
        Transaction.service_type.in_(recharge_services)
    ).scalar()

    return {
        'total_transactions': total_transactions,
        'successful_transactions': successful_transactions,
        'pending_transactions': pending_transactions,
        'failed_transactions': failed_transactions,
        'success_rate': (successful_transactions / total_transactions * 100) if total_transactions > 0 else 0,
        'service_stats': service_stats,
        'today_transactions': today_transactions,
        'today_volume': float(today_volume or 0)
    }

def get_service_performance_data(base_query, recharge_services):
    """Get service performance data for charts"""
    performance_data = []
    for service_type in recharge_services:
        service_query = base_query.filter(Transaction.service_type == service_type)
        total = service_query.count()
        successful = service_query.filter(Transaction.status == TransactionStatus.SUCCESS).count()
        
        performance_data.append({
            'service': service_type.value,
            'total': total,
            'successful': successful,
            'success_rate': (successful / total * 100) if total > 0 else 0
        })
    
    return performance_data

def get_monthly_trend_data(base_query):
    """Get monthly trend data"""
    # Get data for last 6 months
    months = []
    for i in range(5, -1, -1):
        month_start = datetime.now().replace(day=1) - timedelta(days=i*30)
        month_end = month_start.replace(day=28) + timedelta(days=4)
        month_end = month_end.replace(day=1) - timedelta(days=1)
        
        month_transactions = base_query.filter(
            Transaction.created_at >= month_start,
            Transaction.created_at <= month_end,
            Transaction.status == TransactionStatus.SUCCESS
        ).count()
        
        month_volume = db.session.query(
            func.coalesce(func.sum(Transaction.amount), 0)
        ).filter(
            Transaction.created_at >= month_start,
            Transaction.created_at <= month_end,
            Transaction.status == TransactionStatus.SUCCESS
        ).scalar()
        
        months.append({
            'month': month_start.strftime('%b %Y'),
            'transactions': month_transactions,
            'volume': float(month_volume or 0)
        })
    
    return months

# Add more helper functions as needed...
def generate_transaction_id(prefix):
    """Generate unique transaction ID"""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    random_suffix = str(uuid.uuid4())[:8].upper()
    return f"{prefix}{timestamp}{random_suffix}"

def get_device_info():
    """Get device information from request"""
    return {
        'user_agent': request.headers.get('User-Agent', ''),
        'ip_address': request.remote_addr,
        'timestamp': datetime.utcnow().isoformat()
    }

def validate_mobile_number(mobile):
    """Validate mobile number format"""
    import re
    pattern = re.compile(r'^[6-9]\d{9}$')
    return bool(pattern.match(mobile))

def validate_dth_customer_id(customer_id):
    """Validate DTH customer ID"""
    return len(customer_id) >= 8 and customer_id.isalnum()

def validate_connection_number(number, operator_id):
    """Validate connection number based on operator"""
    # Add operator-specific validation logic
    return len(number) >= 6

def check_daily_transaction_limit(user_id, amount):
    """Check if user has reached daily transaction limit"""
    today = datetime.utcnow().date()
    daily_total = db.session.query(
        func.coalesce(func.sum(Transaction.amount), 0)
    ).filter(
        Transaction.user_id == user_id,
        Transaction.status == TransactionStatus.SUCCESS,
        func.date(Transaction.created_at) == today
    ).scalar()
    
    # Default daily limit is 50000, can be made configurable
    return (daily_total or 0) + amount <= 50000

def process_recharge_with_operator(transaction, recharge_transaction):
    """Process recharge with operator (simulate for now)"""
    # In production, this would call actual operator APIs
    # For now, simulate success/failure based on some logic
    import random
    return random.choice([True, True, True, False])  # 75% success rate

def get_mobile_operators():
    """Get mobile operators list"""
    return [
        {'id': '1', 'name': 'Airtel', 'type': 'prepaid_postpaid'},
        {'id': '2', 'name': 'Jio', 'type': 'prepaid'},
        {'id': '3', 'name': 'Vi (Vodafone Idea)', 'type': 'prepaid_postpaid'},
        {'id': '4', 'name': 'BSNL', 'type': 'prepaid_postpaid'},
    ]

def get_telecom_circles():
    """Get telecom circles"""
    return [
        {'id': '1', 'name': 'Andhra Pradesh'},
        {'id': '5', 'name': 'Delhi & NCR'},
        {'id': '10', 'name': 'Karnataka'},
        {'id': '13', 'name': 'Maharashtra & Goa'},
        {'id': '15', 'name': 'Mumbai'},
        {'id': '20', 'name': 'Tamil Nadu'},
        {'id': '23', 'name': 'West Bengal'},
    ]

def get_dth_operators():
    """Get DTH operators"""
    return [
        {'id': '32', 'name': 'Dish TV', 'logo': 'dish-tv.png'},
        {'id': '33', 'name': 'Tata Sky', 'logo': 'tata-sky.png'},
        {'id': '34', 'name': 'Airtel Digital TV', 'logo': 'airtel-dth.png'},
        {'id': '35', 'name': 'Sun Direct', 'logo': 'sun-direct.png'},
    ]

def get_bill_operators():
    """Get bill operators"""
    return [
        {'id': '59', 'name': 'BESCOM', 'state': 'Karnataka', 'type': 'electricity'},
        {'id': '31', 'name': 'MSEDCL', 'state': 'Maharashtra', 'type': 'electricity'},
        {'id': '132', 'name': 'TNEB', 'state': 'Tamil Nadu', 'type': 'electricity'},
        {'id': '175', 'name': 'DHBVN', 'state': 'Haryana', 'type': 'electricity'},
    ]

def get_operator_name(operator_id):
    """Get operator name by ID"""
    operators = {
        '1': 'Airtel', '2': 'Jio', '3': 'Vi', '4': 'BSNL'
    }
    return operators.get(operator_id, 'Unknown')

def get_circle_name(circle_id):
    """Get circle name by ID"""
    circles = {
        '1': 'Andhra Pradesh', '5': 'Delhi & NCR', '10': 'Karnataka',
        '13': 'Maharashtra & Goa', '15': 'Mumbai', '20': 'Tamil Nadu',
        '23': 'West Bengal'
    }
    return circles.get(circle_id, 'Unknown')

def get_dth_operator_name(operator_id):
    """Get DTH operator name"""
    operators = {
        '32': 'Dish TV', '33': 'Tata Sky', 
        '34': 'Airtel Digital TV', '35': 'Sun Direct'
    }
    return operators.get(operator_id, 'Unknown')

def get_bill_operator_name(operator_id):
    """Get bill operator name"""
    operators = {
        '59': 'BESCOM', '31': 'MSEDCL', 
        '132': 'TNEB', '175': 'DHBVN'
    }
    return operators.get(operator_id, 'Unknown')

def get_bill_category(operator_id):
    """Get bill category"""
    # All sample operators are electricity for now
    return 'electricity'

def fetch_bill_details(connection_number, operator_id):
    """Fetch bill details (simulate)"""
    import random
    return {
        'billAmount': str(random.randint(500, 5000)),
        'dueDate': (datetime.now() + timedelta(days=random.randint(1, 30))).strftime('%Y-%m-%d'),
        'billDate': (datetime.now() - timedelta(days=random.randint(1, 30))).strftime('%Y-%m-%d'),
        'customerName': 'Sample Customer',
        'acceptPayment': True
    }

def fetch_recharge_plans(operator_id, circle_id):
    """Fetch recharge plans (simulate)"""
    # Return sample plans
    return [
        {
            'id': '1001',
            'amount': 199,
            'validity': '28 days',
            'description': 'Unlimited calls + 1.5GB/day',
            'category': 'Special'
        },
        {
            'id': '1002',
            'amount': 299,
            'validity': '28 days',
            'description': 'Unlimited calls + 2GB/day',
            'category': 'Popular'
        }
    ]

def apply_transaction_filters(query, filters):
    """Apply filters to transaction query"""
    if filters['status'] and filters['status'] != 'all':
        try:
            status_enum = getattr(TransactionStatus, filters['status'].upper())
            query = query.filter(Transaction.status == status_enum)
        except:
            pass

    if filters['service'] and filters['service'] != 'all':
        try:
            service_enum = getattr(ServiceType, filters['service'].upper())
            query = query.filter(Transaction.service_type == service_enum)
        except:
            pass

    if filters['search']:
        search_term = f"%{filters['search']}%"
        query = query.filter(
            or_(
                Transaction.transaction_id.ilike(search_term),
                Transaction.customer_details.op('->>')('mobile').ilike(search_term),
                Transaction.customer_details.op('->>')('customer_id').ilike(search_term),
                Transaction.customer_details.op('->>')('connection_number').ilike(search_term)
            )
        )

    if filters['date_from']:
        try:
            date_from_obj = datetime.strptime(filters['date_from'], '%Y-%m-%d').date()
            query = query.filter(func.date(Transaction.created_at) >= date_from_obj)
        except ValueError:
            pass

    if filters['date_to']:
        try:
            date_to_obj = datetime.strptime(filters['date_to'], '%Y-%m-%d').date()
            query = query.filter(func.date(Transaction.created_at) <= date_to_obj)
        except ValueError:
            pass

    if filters['amount_from']:
        try:
            amount_from = Decimal(filters['amount_from'])
            query = query.filter(Transaction.amount >= amount_from)
        except:
            pass

    if filters['amount_to']:
        try:
            amount_to = Decimal(filters['amount_to'])
            query = query.filter(Transaction.amount <= amount_to)
        except:
            pass

    return query

def calculate_filtered_stats(query):
    """Calculate stats for filtered results"""
    total = query.count()
    successful = query.filter(Transaction.status == TransactionStatus.SUCCESS).count()
    total_amount = query.filter(Transaction.status == TransactionStatus.SUCCESS).with_entities(
        func.coalesce(func.sum(Transaction.amount), 0)
    ).scalar()

    return {
        'total_transactions': total,
        'successful_transactions': successful,
        'success_rate': (successful / total * 100) if total > 0 else 0,
        'total_amount': float(total_amount or 0)
    }

def get_transaction_service_details(transaction):
    """Get service-specific transaction details"""
    if transaction.service_type == ServiceType.MOBILE_RECHARGE:
        return RechargeTransaction.query.filter_by(transaction_id=transaction.id).first()
    elif transaction.service_type == ServiceType.BILL_PAYMENT:
        return BillPaymentTransaction.query.filter_by(transaction_id=transaction.id).first()
    return None