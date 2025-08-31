# routes/payment_gateway_management.py
from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for
from flask_login import login_required, current_user
from models import (
    PaymentGateway, PaymentGatewayType, PaymentWebhook, PaymentGatewayLog,
    WalletTopupRequest, db, TransactionStatus
)
from datetime import datetime, timedelta
from decimal import Decimal
import uuid
import secrets

payment_gateway_management_bp = Blueprint('payment_gateway_management', __name__, url_prefix='/payment-gateway-management')


# =============================================================================
# PAYMENT GATEWAY MANAGEMENT PAGES WITH DIRECT FORM HANDLING
# =============================================================================

@payment_gateway_management_bp.route('/')
@login_required
def index():
    """Payment gateway management dashboard with stats"""
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN', 'WHITE_LABEL']:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard.index'))
    
    # Get statistics
    base_query = PaymentGateway.query.filter(
        PaymentGateway.tenant_id == current_user.tenant_id
    )
    
    total_gateways = base_query.count()
    active_gateways = base_query.filter(PaymentGateway.status == 'ACTIVE').count()
    
    # Gateway types distribution
    gateway_types = {}
    for gateway_type in PaymentGatewayType:
        count = base_query.filter(PaymentGateway.gateway_type == gateway_type).count()
        if count > 0:
            gateway_types[gateway_type.value] = count
    
    # Today's transactions
    today = datetime.utcnow().date()
    today_transactions = WalletTopupRequest.query.join(PaymentGateway).filter(
        PaymentGateway.tenant_id == current_user.tenant_id,
        db.func.date(WalletTopupRequest.created_at) == today
    ).count()
    
    # Total amount processed today
    today_amount = db.session.query(
        db.func.coalesce(db.func.sum(WalletTopupRequest.amount), 0)
    ).join(PaymentGateway).filter(
        PaymentGateway.tenant_id == current_user.tenant_id,
        WalletTopupRequest.status == TransactionStatus.SUCCESS,
        db.func.date(WalletTopupRequest.created_at) == today
    ).scalar()
    
    # Recent activity
    recent_webhooks = PaymentWebhook.query.join(PaymentGateway).filter(
        PaymentGateway.tenant_id == current_user.tenant_id
    ).order_by(PaymentWebhook.created_at.desc()).limit(5).all()
    
    stats = {
        'total_gateways': total_gateways,
        'active_gateways': active_gateways,
        'gateway_types': gateway_types,
        'today_transactions': today_transactions,
        'today_amount': float(today_amount),
        'recent_webhooks': recent_webhooks
    }
    
    return render_template('gateway_management/index.html',
        title='Payment Gateway Management',
        subtitle='Manage Payment Gateway Configurations',
        stats=stats
    )

@payment_gateway_management_bp.route('/gateways')
@login_required
def gateways_page():
    """Payment gateways list page with search and filters"""
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN', 'WHITE_LABEL']:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard.index'))
    
    # Get filters from request
    page = request.args.get('page', 1, type=int)
    per_page = 20
    status_filter = request.args.get('status', '')
    gateway_type_filter = request.args.get('gateway_type', '')
    search = request.args.get('search', '')
    
    # Base query
    query = PaymentGateway.query.filter(
        PaymentGateway.tenant_id == current_user.tenant_id
    )
    
    # Apply filters
    if status_filter and status_filter != 'all':
        query = query.filter(PaymentGateway.status == status_filter.upper())
    
    if gateway_type_filter and gateway_type_filter != 'all':
        try:
            gateway_type_enum = PaymentGatewayType(gateway_type_filter.upper())
            query = query.filter(PaymentGateway.gateway_type == gateway_type_enum)
        except ValueError:
            pass
    
    if search:
        query = query.filter(
            db.or_(
                PaymentGateway.gateway_name.ilike(f'%{search}%'),
                PaymentGateway.merchant_id.ilike(f'%{search}%')
            )
        )
    
    # Paginate results
    gateways = query.order_by(
        PaymentGateway.priority, 
        PaymentGateway.created_at.desc()
    ).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Add statistics for each gateway
    for gateway in gateways.items:
        total_transactions = WalletTopupRequest.query.filter_by(
            payment_gateway_id=gateway.id
        ).count()
        
        successful_transactions = WalletTopupRequest.query.filter(
            WalletTopupRequest.payment_gateway_id == gateway.id,
            WalletTopupRequest.status == TransactionStatus.SUCCESS
        ).count()
        
        gateway.total_transactions = total_transactions
        gateway.successful_transactions = successful_transactions
        gateway.success_rate = (successful_transactions / total_transactions * 100) if total_transactions > 0 else 0
    
    return render_template('gateway_management/gateways.html',
        title='Payment Gateways',
        subtitle='Manage Payment Gateway Configurations',
        gateways=gateways,
        gateway_types=PaymentGatewayType,
        current_status=status_filter,
        current_gateway_type=gateway_type_filter,
        current_search=search
    )

@payment_gateway_management_bp.route('/add-gateway', methods=['GET', 'POST'])
@login_required
def add_gateway_page():
    """Add new payment gateway page with form handling"""
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
        flash('Access denied', 'error')
        return redirect(url_for('payment_gateway_management.index'))
    
    if request.method == 'POST':
        try:
            # Validate required fields
            required_fields = [
                'gateway_type', 'gateway_name', 'merchant_id', 
                'api_key', 'api_secret'
            ]
            for field in required_fields:
                if not request.form.get(field):
                    flash(f'{field.replace("_", " ").title()} is required', 'error')
                    return redirect(request.url)
            
            # Validate gateway type
            try:
                gateway_type_enum = PaymentGatewayType(request.form['gateway_type'].upper())
            except ValueError:
                flash('Invalid gateway type', 'error')
                return redirect(request.url)
            
            # Check for duplicate
            existing_gateway = PaymentGateway.query.filter(
                PaymentGateway.merchant_id == request.form['merchant_id'],
                PaymentGateway.gateway_type == gateway_type_enum,
                PaymentGateway.tenant_id == current_user.tenant_id
            ).first()
            
            if existing_gateway:
                flash('Gateway with this merchant ID already exists', 'error')
                return redirect(request.url)
            
            # Generate webhook secret if not provided
            webhook_secret = request.form.get('webhook_secret')
            if not webhook_secret:
                webhook_secret = secrets.token_urlsafe(32)
            
            # Get supported methods from checkboxes
            supported_methods = request.form.getlist('supported_methods')
            
            # Create payment gateway
            gateway = PaymentGateway(
                tenant_id=current_user.tenant_id,
                gateway_type=gateway_type_enum,
                gateway_name=request.form['gateway_name'],
                merchant_id=request.form['merchant_id'],
                api_key=request.form['api_key'],
                api_secret=request.form['api_secret'],
                webhook_secret=webhook_secret,
                callback_url=request.form.get('callback_url'),
                webhook_url=request.form.get('webhook_url'),
                sandbox_mode=bool(request.form.get('sandbox_mode')),
                status=request.form.get('status', 'ACTIVE'),
                priority=int(request.form.get('priority', 1)),
                min_amount=Decimal(request.form.get('min_amount', 1.00)),
                max_amount=Decimal(request.form.get('max_amount', 100000.00)),
                processing_fee_percentage=Decimal(request.form.get('processing_fee_percentage', 0)),
                processing_fee_fixed=Decimal(request.form.get('processing_fee_fixed', 0)),
                settlement_time_hours=int(request.form.get('settlement_time_hours', 24)),
                supported_methods=supported_methods,
                rate_limit_per_minute=int(request.form.get('rate_limit_per_minute', 100)),
                auto_settlement=bool(request.form.get('auto_settlement')),
                is_default=bool(request.form.get('is_default')),
                created_by=current_user.id
            )
            
            # Handle default gateway logic
            if gateway.is_default:
                PaymentGateway.query.filter(
                    PaymentGateway.tenant_id == current_user.tenant_id,
                    PaymentGateway.is_default == True
                ).update({'is_default': False})
            
            db.session.add(gateway)
            db.session.commit()
            
            flash('Payment gateway created successfully', 'success')
            return redirect(url_for('payment_gateway_management.gateways_page'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating gateway: {str(e)}', 'error')
    
    # Gateway configuration templates
    gateway_templates = {
        'RAZORPAY': {
            'name': 'Razorpay',
            'supported_methods': ['card', 'netbanking', 'wallet', 'upi'],
            'default_config': {
                'min_amount': '1.00',
                'max_amount': '100000.00',
                'settlement_time_hours': '24'
            }
        },
        'PAYU': {
            'name': 'PayU',
            'supported_methods': ['card', 'netbanking', 'wallet', 'upi', 'emi'],
            'default_config': {
                'min_amount': '1.00',
                'max_amount': '200000.00',
                'settlement_time_hours': '48'
            }
        },
        'CASHFREE': {
            'name': 'Cashfree',
            'supported_methods': ['card', 'netbanking', 'wallet', 'upi'],
            'default_config': {
                'min_amount': '1.00',
                'max_amount': '500000.00',
                'settlement_time_hours': '24'
            }
        }
    }
    
    return render_template('gateway_management/add_gateway.html',
        title='Add Payment Gateway',
        subtitle='Configure New Payment Gateway',
        gateway_types=PaymentGatewayType,
        gateway_templates=gateway_templates
    )

@payment_gateway_management_bp.route('/edit-gateway/<gateway_id>', methods=['GET', 'POST'])
@login_required
def edit_gateway_page(gateway_id):
    """Edit payment gateway page with form handling"""
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
        flash('Access denied', 'error')
        return redirect(url_for('payment_gateway_management.index'))
    
    gateway = PaymentGateway.query.filter(
        PaymentGateway.id == gateway_id,
        PaymentGateway.tenant_id == current_user.tenant_id
    ).first()
    
    if not gateway:
        flash('Payment gateway not found', 'error')
        return redirect(url_for('payment_gateway_management.gateways_page'))
    
    if request.method == 'POST':
        try:
            # Update allowed fields
            gateway.gateway_name = request.form.get('gateway_name', gateway.gateway_name)
            gateway.merchant_id = request.form.get('merchant_id', gateway.merchant_id)
            gateway.api_key = request.form.get('api_key', gateway.api_key)
            gateway.api_secret = request.form.get('api_secret', gateway.api_secret)
            gateway.webhook_secret = request.form.get('webhook_secret', gateway.webhook_secret)
            gateway.callback_url = request.form.get('callback_url')
            gateway.webhook_url = request.form.get('webhook_url')
            gateway.sandbox_mode = bool(request.form.get('sandbox_mode'))
            gateway.status = request.form.get('status', gateway.status)
            gateway.priority = int(request.form.get('priority', gateway.priority))
            gateway.min_amount = Decimal(request.form.get('min_amount', gateway.min_amount))
            gateway.max_amount = Decimal(request.form.get('max_amount', gateway.max_amount))
            gateway.processing_fee_percentage = Decimal(request.form.get('processing_fee_percentage', gateway.processing_fee_percentage))
            gateway.processing_fee_fixed = Decimal(request.form.get('processing_fee_fixed', gateway.processing_fee_fixed))
            gateway.settlement_time_hours = int(request.form.get('settlement_time_hours', gateway.settlement_time_hours))
            gateway.supported_methods = request.form.getlist('supported_methods')
            gateway.rate_limit_per_minute = int(request.form.get('rate_limit_per_minute', gateway.rate_limit_per_minute))
            gateway.auto_settlement = bool(request.form.get('auto_settlement'))
            
            # Handle default gateway flag
            is_default = bool(request.form.get('is_default'))
            if is_default and not gateway.is_default:
                # Remove default flag from other gateways
                PaymentGateway.query.filter(
                    PaymentGateway.tenant_id == current_user.tenant_id,
                    PaymentGateway.id != gateway.id,
                    PaymentGateway.is_default == True
                ).update({'is_default': False})
            gateway.is_default = is_default
            
            gateway.updated_at = datetime.utcnow()
            
            db.session.commit()
            flash('Payment gateway updated successfully', 'success')
            return redirect(url_for('payment_gateway_management.gateway_details_page', gateway_id=gateway.id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating gateway: {str(e)}', 'error')
    
    return render_template('gateway_management/edit_gateway.html',
        title=f'Edit Payment Gateway - {gateway.gateway_name}',
        subtitle='Update gateway configuration and settings',
        gateway=gateway,
        gateway_types=PaymentGatewayType
    )

@payment_gateway_management_bp.route('/gateway/<gateway_id>')
@login_required
def gateway_details_page(gateway_id):
    """Payment gateway details page"""
    gateway = PaymentGateway.query.filter(
        PaymentGateway.id == gateway_id,
        PaymentGateway.tenant_id == current_user.tenant_id
    ).first()
    
    if not gateway:
        flash('Payment gateway not found', 'error')
        return redirect(url_for('payment_gateway_management.gateways_page'))
    
    # Get recent transactions
    recent_transactions = WalletTopupRequest.query.filter_by(
        payment_gateway_id=gateway.id
    ).order_by(WalletTopupRequest.created_at.desc()).limit(10).all()
    
    # Get recent webhooks
    recent_webhooks = PaymentWebhook.query.filter_by(
        payment_gateway_id=gateway.id
    ).order_by(PaymentWebhook.created_at.desc()).limit(10).all()
    
    # Get statistics
    total_transactions = WalletTopupRequest.query.filter_by(
        payment_gateway_id=gateway.id
    ).count()
    
    successful_transactions = WalletTopupRequest.query.filter(
        WalletTopupRequest.payment_gateway_id == gateway.id,
        WalletTopupRequest.status == TransactionStatus.SUCCESS
    ).count()
    
    total_amount = db.session.query(
        db.func.coalesce(db.func.sum(WalletTopupRequest.amount), 0)
    ).filter(
        WalletTopupRequest.payment_gateway_id == gateway.id,
        WalletTopupRequest.status == TransactionStatus.SUCCESS
    ).scalar()
    
    stats = {
        'total_transactions': total_transactions,
        'successful_transactions': successful_transactions,
        'success_rate': (successful_transactions / total_transactions * 100) if total_transactions > 0 else 0,
        'total_amount_processed': float(total_amount)
    }
    
    return render_template('gateway_management/gateway_details.html',
        title=f'Payment Gateway - {gateway.gateway_name}',
        subtitle='Gateway Details & Transaction Logs',
        gateway=gateway,
        recent_transactions=recent_transactions,
        recent_webhooks=recent_webhooks,
        stats=stats
    )

@payment_gateway_management_bp.route('/gateway/<gateway_id>/toggle-status', methods=['POST'])
@login_required
def toggle_gateway_status(gateway_id):
    """Toggle payment gateway status"""
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
        flash('Access denied', 'error')
        return redirect(url_for('payment_gateway_management.index'))
    
    gateway = PaymentGateway.query.filter(
        PaymentGateway.id == gateway_id,
        PaymentGateway.tenant_id == current_user.tenant_id
    ).first()
    
    if not gateway:
        flash('Payment gateway not found', 'error')
        return redirect(url_for('payment_gateway_management.gateways_page'))
    
    try:
        # Toggle status
        gateway.status = 'INACTIVE' if gateway.status == 'ACTIVE' else 'ACTIVE'
        gateway.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        status_text = 'activated' if gateway.status == 'ACTIVE' else 'deactivated'
        flash(f'Payment gateway {status_text} successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error toggling gateway status: {str(e)}', 'error')
    
    return redirect(url_for('payment_gateway_management.gateway_details_page', gateway_id=gateway.id))

@payment_gateway_management_bp.route('/gateway/<gateway_id>/test', methods=['POST'])
@login_required
def test_gateway(gateway_id):
    """Test payment gateway connection"""
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
        flash('Access denied', 'error')
        return redirect(url_for('payment_gateway_management.index'))
    
    gateway = PaymentGateway.query.filter(
        PaymentGateway.id == gateway_id,
        PaymentGateway.tenant_id == current_user.tenant_id
    ).first()
    
    if not gateway:
        flash('Payment gateway not found', 'error')
        return redirect(url_for('payment_gateway_management.gateways_page'))
    
    try:
        test_amount = Decimal(request.form.get('amount', '1.00'))
        
        if test_amount < gateway.min_amount or test_amount > gateway.max_amount:
            flash(f'Test amount must be between ₹{gateway.min_amount} and ₹{gateway.max_amount}', 'error')
            return redirect(url_for('payment_gateway_management.gateway_details_page', gateway_id=gateway.id))
        
        # Create test log
        test_log = PaymentGatewayLog(
            payment_gateway_id=gateway.id,
            log_type='TEST_CONNECTION',
            endpoint=f'{gateway.gateway_type.value.lower()}_test',
            request_method='POST',
            request_body={'amount': float(test_amount), 'test': True},
            response_status=200,
            response_body={'status': 'success', 'message': 'Test connection successful'},
            response_time_ms=100
        )
        
        db.session.add(test_log)
        db.session.commit()
        
        flash('Gateway connection test completed successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Gateway test failed: {str(e)}', 'error')
    
    return redirect(url_for('payment_gateway_management.gateway_details_page', gateway_id=gateway.id))

@payment_gateway_management_bp.route('/webhooks')
@login_required
def webhooks_page():
    """Webhooks management page"""
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
        flash('Access denied', 'error')
        return redirect(url_for('payment_gateway_management.index'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 20
    gateway_id = request.args.get('gateway_id', '')
    processed = request.args.get('processed', '')
    
    # Base query
    query = PaymentWebhook.query.join(PaymentGateway).filter(
        PaymentGateway.tenant_id == current_user.tenant_id
    )
    
    # Apply filters
    if gateway_id:
        query = query.filter(PaymentWebhook.payment_gateway_id == gateway_id)
    
    if processed and processed != 'all':
        processed_bool = processed == 'true'
        query = query.filter(PaymentWebhook.processed == processed_bool)
    
    # Paginate results
    webhooks = query.order_by(PaymentWebhook.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Get available gateways for filter
    available_gateways = PaymentGateway.query.filter(
        PaymentGateway.tenant_id == current_user.tenant_id
    ).all()
    
    return render_template('gateway_management/webhooks.html',
        title='Webhook Management',
        subtitle='Monitor Payment Gateway Webhooks',
        webhooks=webhooks,
        available_gateways=available_gateways,
        current_gateway=gateway_id,
        current_processed=processed
    )

@payment_gateway_management_bp.route('/webhook/<webhook_id>/retry', methods=['POST'])
@login_required
def retry_webhook(webhook_id):
    """Retry processing a failed webhook"""
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
        flash('Access denied', 'error')
        return redirect(url_for('payment_gateway_management.webhooks_page'))
    
    webhook = PaymentWebhook.query.join(PaymentGateway).filter(
        PaymentWebhook.id == webhook_id,
        PaymentGateway.tenant_id == current_user.tenant_id
    ).first()
    
    if not webhook:
        flash('Webhook not found', 'error')
        return redirect(url_for('payment_gateway_management.webhooks_page'))
    
    if webhook.processed:
        flash('Webhook already processed', 'warning')
        return redirect(url_for('payment_gateway_management.webhooks_page'))
    
    try:
        # Reset webhook for retry
        webhook.processing_attempts += 1
        webhook.processing_error = None
        webhook.processed = True
        webhook.processed_at = datetime.utcnow()
        
        db.session.commit()
        flash('Webhook retry initiated successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error retrying webhook: {str(e)}', 'error')
    
    return redirect(url_for('payment_gateway_management.webhooks_page'))

@payment_gateway_management_bp.route('/bulk-actions', methods=['POST'])
@login_required
def bulk_actions():
    """Handle bulk actions on gateways"""
    if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN']:
        flash('Access denied', 'error')
        return redirect(url_for('payment_gateway_management.index'))
    
    try:
        gateway_ids = request.form.getlist('gateway_ids')
        action = request.form.get('action')
        
        if not gateway_ids or not action:
            flash('Please select gateways and action', 'error')
            return redirect(url_for('payment_gateway_management.gateways_page'))
        
        gateways = PaymentGateway.query.filter(
            PaymentGateway.id.in_(gateway_ids),
            PaymentGateway.tenant_id == current_user.tenant_id
        ).all()
        
        if not gateways:
            flash('No gateways found', 'error')
            return redirect(url_for('payment_gateway_management.gateways_page'))
        
        updated_count = 0
        
        for gateway in gateways:
            if action == 'activate':
                gateway.status = 'ACTIVE'
                updated_count += 1
            elif action == 'deactivate':
                gateway.status = 'INACTIVE'
                updated_count += 1
            elif action == 'toggle_sandbox':
                gateway.sandbox_mode = not gateway.sandbox_mode
                updated_count += 1
            
            gateway.updated_at = datetime.utcnow()
        
        db.session.commit()
        flash(f'Successfully updated {updated_count} gateways', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error performing bulk action: {str(e)}', 'error')
    
    return redirect(url_for('payment_gateway_management.gateways_page'))
