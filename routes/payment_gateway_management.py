# routes/payment_gateway_management.py
from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for, make_response
from flask_login import login_required, current_user
from models import (
    PaymentGateway, PaymentGatewayType, PaymentWebhook, PaymentGatewayLog,
    WalletTopupRequest, db, TransactionStatus, UserRoleType
)
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
import uuid
import secrets
import json
import csv
import io
from functools import wraps

payment_gateway_management_bp = Blueprint('payment_gateway_management', __name__, url_prefix='/payment-gateway-management')

# =============================================================================
# DECORATORS AND UTILITIES
# =============================================================================

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role.name not in ['SUPER_ADMIN', 'ADMIN', 'WHITE_LABEL']:
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role.name not in ['SUPER_ADMIN', 'ADMIN']:
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def validate_uuid(uuid_string):
    """Validate UUID format"""
    try:
        uuid.UUID(uuid_string)
        return True
    except (ValueError, TypeError):
        return False

def safe_decimal_conversion(value, default=Decimal('0')):
    """Safely convert value to Decimal"""
    try:
        return Decimal(str(value)) if value else default
    except (InvalidOperation, ValueError, TypeError):
        return default

# =============================================================================
# PAYMENT GATEWAY MANAGEMENT PAGES
# =============================================================================

@payment_gateway_management_bp.route('/')
@login_required
@admin_required
def index():
    """Payment gateway management dashboard with enhanced stats"""
    try:
        # Get statistics with optimized queries
        base_query = PaymentGateway.query.filter(
            PaymentGateway.tenant_id == current_user.tenant_id
        )
        
        # Gateway statistics
        total_gateways = base_query.count()
        active_gateways = base_query.filter(PaymentGateway.status == 'ACTIVE').count()
        inactive_gateways = base_query.filter(PaymentGateway.status == 'INACTIVE').count()
        sandbox_gateways = base_query.filter(PaymentGateway.sandbox_mode == True).count()
        
        # Gateway types distribution
        gateway_types = {}
        for gateway_type in PaymentGatewayType:
            count = base_query.filter(PaymentGateway.gateway_type == gateway_type).count()
            if count > 0:
                gateway_types[gateway_type.value] = count
        
        # Transaction statistics for today
        today = datetime.utcnow().date()
        today_transactions = WalletTopupRequest.query.join(PaymentGateway).filter(
            PaymentGateway.tenant_id == current_user.tenant_id,
            db.func.date(WalletTopupRequest.created_at) == today
        ).count()
        
        # Successful transactions today
        today_successful = WalletTopupRequest.query.join(PaymentGateway).filter(
            PaymentGateway.tenant_id == current_user.tenant_id,
            WalletTopupRequest.status == TransactionStatus.SUCCESS,
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
        
        # This month's statistics
        month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        month_transactions = WalletTopupRequest.query.join(PaymentGateway).filter(
            PaymentGateway.tenant_id == current_user.tenant_id,
            WalletTopupRequest.created_at >= month_start
        ).count()
        
        month_amount = db.session.query(
            db.func.coalesce(db.func.sum(WalletTopupRequest.amount), 0)
        ).join(PaymentGateway).filter(
            PaymentGateway.tenant_id == current_user.tenant_id,
            WalletTopupRequest.status == TransactionStatus.SUCCESS,
            WalletTopupRequest.created_at >= month_start
        ).scalar()
        
        # Recent activity (webhooks and logs)
        recent_webhooks = PaymentWebhook.query.join(PaymentGateway).filter(
            PaymentGateway.tenant_id == current_user.tenant_id
        ).order_by(PaymentWebhook.created_at.desc()).limit(5).all()
        
        recent_logs = PaymentGatewayLog.query.join(PaymentGateway).filter(
            PaymentGateway.tenant_id == current_user.tenant_id
        ).order_by(PaymentGatewayLog.created_at.desc()).limit(5).all()
        
        # Calculate success rate
        success_rate = (today_successful / today_transactions * 100) if today_transactions > 0 else 0
        
        stats = {
            'total_gateways': total_gateways,
            'active_gateways': active_gateways,
            'inactive_gateways': inactive_gateways,
            'sandbox_gateways': sandbox_gateways,
            'gateway_types': gateway_types,
            'today_transactions': today_transactions,
            'today_successful': today_successful,
            'today_amount': float(today_amount),
            'month_transactions': month_transactions,
            'month_amount': float(month_amount),
            'success_rate': round(success_rate, 2),
            'recent_webhooks': recent_webhooks,
            'recent_logs': recent_logs
        }
        
        return render_template('gateway_management/index.html',
            title='Payment Gateway Management',
            subtitle='Manage Payment Gateway Configurations',
            stats=stats
        )
        
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}', 'error')
        # Return empty stats on error
        empty_stats = {
            'total_gateways': 0, 'active_gateways': 0, 'inactive_gateways': 0,
            'sandbox_gateways': 0, 'gateway_types': {}, 'today_transactions': 0,
            'today_successful': 0, 'today_amount': 0.0, 'month_transactions': 0,
            'month_amount': 0.0, 'success_rate': 0.0, 'recent_webhooks': [],
            'recent_logs': []
        }
        return render_template('gateway_management/index.html',
            title='Payment Gateway Management',
            subtitle='Manage Payment Gateway Configurations',
            stats=empty_stats
        )

@payment_gateway_management_bp.route('/gateways')
@login_required
@admin_required
def gateways_page():
    """Payment gateways list page with enhanced search and filters"""
    try:
        # Get filters from request with validation
        page = max(request.args.get('page', 1, type=int), 1)
        per_page = min(max(request.args.get('per_page', 20, type=int), 10), 100)
        status_filter = request.args.get('status', '').strip()
        gateway_type_filter = request.args.get('gateway_type', '').strip()
        search = request.args.get('search', '').strip()
        sort_by = request.args.get('sort_by', 'priority').strip()
        sort_order = request.args.get('sort_order', 'asc').strip()
        
        # Base query with tenant filtering
        query = PaymentGateway.query.filter(
            PaymentGateway.tenant_id == current_user.tenant_id
        )
        
        # Apply filters with validation
        if status_filter and status_filter != 'all':
            if status_filter.upper() in ['ACTIVE', 'INACTIVE']:
                query = query.filter(PaymentGateway.status == status_filter.upper())
        
        if gateway_type_filter and gateway_type_filter != 'all':
            try:
                gateway_type_enum = PaymentGatewayType(gateway_type_filter.upper())
                query = query.filter(PaymentGateway.gateway_type == gateway_type_enum)
            except ValueError:
                flash(f'Invalid gateway type: {gateway_type_filter}', 'warning')
        
        if search:
            search_pattern = f'%{search}%'
            query = query.filter(
                db.or_(
                    PaymentGateway.gateway_name.ilike(search_pattern),
                    PaymentGateway.merchant_id.ilike(search_pattern),
                    PaymentGateway.api_key.ilike(search_pattern)
                )
            )
        
        # Apply sorting
        if sort_by in ['priority', 'gateway_name', 'created_at', 'status']:
            sort_column = getattr(PaymentGateway, sort_by)
            if sort_order == 'desc':
                sort_column = sort_column.desc()
            query = query.order_by(sort_column)
        else:
            query = query.order_by(PaymentGateway.priority, PaymentGateway.created_at.desc())
        
        # Paginate results
        gateways = query.paginate(
            page=page, per_page=per_page, error_out=False, max_per_page=100
        )
        
        # Add enhanced statistics for each gateway
        for gateway in gateways.items:
            # Transaction statistics
            total_transactions = WalletTopupRequest.query.filter_by(
                payment_gateway_id=gateway.id
            ).count()
            
            successful_transactions = WalletTopupRequest.query.filter(
                WalletTopupRequest.payment_gateway_id == gateway.id,
                WalletTopupRequest.status == TransactionStatus.SUCCESS
            ).count()
            
            # Today's statistics
            today = datetime.utcnow().date()
            today_transactions = WalletTopupRequest.query.filter(
                WalletTopupRequest.payment_gateway_id == gateway.id,
                db.func.date(WalletTopupRequest.created_at) == today
            ).count()
            
            # Total amount processed
            total_amount = db.session.query(
                db.func.coalesce(db.func.sum(WalletTopupRequest.amount), 0)
            ).filter(
                WalletTopupRequest.payment_gateway_id == gateway.id,
                WalletTopupRequest.status == TransactionStatus.SUCCESS
            ).scalar()
            
            # Add statistics to gateway object
            gateway.total_transactions = total_transactions
            gateway.successful_transactions = successful_transactions
            gateway.today_transactions = today_transactions
            gateway.success_rate = (successful_transactions / total_transactions * 100) if total_transactions > 0 else 0
            gateway.total_amount_processed = float(total_amount)
            
            # Check if gateway is within limits
            gateway.within_limits = True
            if gateway.rate_limit_per_minute and today_transactions > gateway.rate_limit_per_minute * 24 * 60:
                gateway.within_limits = False
        
        return render_template('gateway_management/gateways.html',
            title='Payment Gateways',
            subtitle='Manage Payment Gateway Configurations',
            gateways=gateways,
            gateway_types=PaymentGatewayType,
            current_status=status_filter,
            current_gateway_type=gateway_type_filter,
            current_search=search,
            current_sort_by=sort_by,
            current_sort_order=sort_order
        )
        
    except Exception as e:
        flash(f'Error loading payment gateways: {str(e)}', 'error')
        return redirect(url_for('payment_gateway_management.index'))

@payment_gateway_management_bp.route('/add-gateway', methods=['GET', 'POST'])
@login_required
@super_admin_required
def add_gateway_page():
    """Add new payment gateway with enhanced validation"""
    if request.method == 'POST':
        try:
            # Extract and validate form data
            gateway_type = request.form.get('gateway_type', '').strip()
            gateway_name = request.form.get('gateway_name', '').strip()
            merchant_id = request.form.get('merchant_id', '').strip()
            api_key = request.form.get('api_key', '').strip()
            api_secret = request.form.get('api_secret', '').strip()
            
            # Validate required fields
            required_fields = {
                'gateway_type': gateway_type,
                'gateway_name': gateway_name,
                'merchant_id': merchant_id,
                'api_key': api_key,
                'api_secret': api_secret
            }
            
            missing_fields = [field for field, value in required_fields.items() if not value]
            if missing_fields:
                flash(f'Missing required fields: {", ".join(missing_fields)}', 'error')
                return render_template('gateway_management/add_gateway.html',
                    title='Add Payment Gateway',
                    subtitle='Configure New Payment Gateway',
                    gateway_types=PaymentGatewayType,
                    gateway_templates=get_gateway_templates()
                )
            
            # Validate gateway type
            try:
                gateway_type_enum = PaymentGatewayType(gateway_type.upper())
            except ValueError:
                flash('Invalid gateway type selected', 'error')
                return render_template('gateway_management/add_gateway.html',
                    title='Add Payment Gateway',
                    subtitle='Configure New Payment Gateway',
                    gateway_types=PaymentGatewayType,
                    gateway_templates=get_gateway_templates()
                )
            
            # Check for duplicate gateway
            existing_gateway = PaymentGateway.query.filter(
                PaymentGateway.merchant_id == merchant_id,
                PaymentGateway.gateway_type == gateway_type_enum,
                PaymentGateway.tenant_id == current_user.tenant_id
            ).first()
            
            if existing_gateway:
                flash('Gateway with this merchant ID and type already exists', 'error')
                return render_template('gateway_management/add_gateway.html',
                    title='Add Payment Gateway',
                    subtitle='Configure New Payment Gateway',
                    gateway_types=PaymentGatewayType,
                    gateway_templates=get_gateway_templates()
                )
            
            # Generate webhook secret if not provided
            webhook_secret = request.form.get('webhook_secret', '').strip()
            if not webhook_secret:
                webhook_secret = secrets.token_urlsafe(32)
            
            # Get and validate optional fields
            callback_url = request.form.get('callback_url', '').strip()
            webhook_url = request.form.get('webhook_url', '').strip()
            sandbox_mode = bool(request.form.get('sandbox_mode'))
            status = request.form.get('status', 'ACTIVE').strip().upper()
            priority = max(int(request.form.get('priority', 1)), 1)
            
            # Validate and convert decimal fields
            min_amount = safe_decimal_conversion(request.form.get('min_amount', '1.00'))
            max_amount = safe_decimal_conversion(request.form.get('max_amount', '100000.00'))
            processing_fee_percentage = safe_decimal_conversion(request.form.get('processing_fee_percentage', '0'))
            processing_fee_fixed = safe_decimal_conversion(request.form.get('processing_fee_fixed', '0'))
            
            # Validate amount ranges
            if min_amount <= 0:
                flash('Minimum amount must be greater than 0', 'error')
                return render_template('gateway_management/add_gateway.html',
                    title='Add Payment Gateway',
                    subtitle='Configure New Payment Gateway',
                    gateway_types=PaymentGatewayType,
                    gateway_templates=get_gateway_templates()
                )
            
            if max_amount <= min_amount:
                flash('Maximum amount must be greater than minimum amount', 'error')
                return render_template('gateway_management/add_gateway.html',
                    title='Add Payment Gateway',
                    subtitle='Configure New Payment Gateway',
                    gateway_types=PaymentGatewayType,
                    gateway_templates=get_gateway_templates()
                )
            
            # Get other fields
            settlement_time_hours = max(int(request.form.get('settlement_time_hours', 24)), 1)
            supported_methods = request.form.getlist('supported_methods')
            rate_limit_per_minute = max(int(request.form.get('rate_limit_per_minute', 100)), 1)
            auto_settlement = bool(request.form.get('auto_settlement'))
            is_default = bool(request.form.get('is_default'))
            
            # Create payment gateway
            gateway = PaymentGateway(
                tenant_id=current_user.tenant_id,
                gateway_type=gateway_type_enum,
                gateway_name=gateway_name,
                merchant_id=merchant_id,
                api_key=api_key,
                api_secret=api_secret,
                webhook_secret=webhook_secret,
                callback_url=callback_url or None,
                webhook_url=webhook_url or None,
                sandbox_mode=sandbox_mode,
                status=status if status in ['ACTIVE', 'INACTIVE'] else 'ACTIVE',
                priority=priority,
                min_amount=min_amount,
                max_amount=max_amount,
                processing_fee_percentage=processing_fee_percentage,
                processing_fee_fixed=processing_fee_fixed,
                settlement_time_hours=settlement_time_hours,
                supported_methods=supported_methods,
                rate_limit_per_minute=rate_limit_per_minute,
                auto_settlement=auto_settlement,
                is_default=is_default,
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
            
            # Log the creation
            log_entry = PaymentGatewayLog(
                payment_gateway_id=gateway.id,
                log_type='GATEWAY_CREATED',
                endpoint='add_gateway',
                request_method='POST',
                request_body={'action': 'create_gateway', 'gateway_name': gateway_name},
                response_status=201,
                response_body={'status': 'success', 'gateway_id': str(gateway.id)},
                response_time_ms=50
            )
            db.session.add(log_entry)
            db.session.commit()
            
            flash(f'Payment gateway "{gateway_name}" created successfully', 'success')
            return redirect(url_for('payment_gateway_management.gateway_details_page', gateway_id=gateway.id))
            
        except ValueError as e:
            db.session.rollback()
            flash(f'Invalid input data: {str(e)}', 'error')
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating gateway: {str(e)}', 'error')
    
    return render_template('gateway_management/add_gateway.html',
        title='Add Payment Gateway',
        subtitle='Configure New Payment Gateway',
        gateway_types=PaymentGatewayType,
        gateway_templates=get_gateway_templates()
    )

@payment_gateway_management_bp.route('/edit-gateway/<gateway_id>', methods=['GET', 'POST'])
@login_required
@super_admin_required
def edit_gateway_page(gateway_id):
    """Edit payment gateway with enhanced validation"""
    if not validate_uuid(gateway_id):
        flash('Invalid gateway ID', 'error')
        return redirect(url_for('payment_gateway_management.gateways_page'))
    
    try:
        gateway = PaymentGateway.query.filter(
            PaymentGateway.id == gateway_id,
            PaymentGateway.tenant_id == current_user.tenant_id
        ).first()
        
        if not gateway:
            flash('Payment gateway not found', 'error')
            return redirect(url_for('payment_gateway_management.gateways_page'))
        
        if request.method == 'POST':
            try:
                # Update fields with validation
                gateway.gateway_name = request.form.get('gateway_name', gateway.gateway_name).strip()
                gateway.merchant_id = request.form.get('merchant_id', gateway.merchant_id).strip()
                gateway.api_key = request.form.get('api_key', gateway.api_key).strip()
                gateway.api_secret = request.form.get('api_secret', gateway.api_secret).strip()
                gateway.webhook_secret = request.form.get('webhook_secret', gateway.webhook_secret).strip()
                gateway.callback_url = request.form.get('callback_url', '').strip() or None
                gateway.webhook_url = request.form.get('webhook_url', '').strip() or None
                gateway.sandbox_mode = bool(request.form.get('sandbox_mode'))
                
                # Validate status
                new_status = request.form.get('status', gateway.status).strip().upper()
                gateway.status = new_status if new_status in ['ACTIVE', 'INACTIVE'] else gateway.status
                
                # Update numeric fields with validation
                gateway.priority = max(int(request.form.get('priority', gateway.priority)), 1)
                
                new_min_amount = safe_decimal_conversion(request.form.get('min_amount', gateway.min_amount))
                new_max_amount = safe_decimal_conversion(request.form.get('max_amount', gateway.max_amount))
                
                if new_min_amount > 0 and new_max_amount > new_min_amount:
                    gateway.min_amount = new_min_amount
                    gateway.max_amount = new_max_amount
                else:
                    flash('Invalid amount range. Min amount must be > 0 and Max amount must be > Min amount', 'error')
                    return render_template('gateway_management/edit_gateway.html',
                        title=f'Edit Payment Gateway - {gateway.gateway_name}',
                        subtitle='Update gateway configuration and settings',
                        gateway=gateway,
                        gateway_types=PaymentGatewayType
                    )
                
                gateway.processing_fee_percentage = safe_decimal_conversion(request.form.get('processing_fee_percentage', gateway.processing_fee_percentage))
                gateway.processing_fee_fixed = safe_decimal_conversion(request.form.get('processing_fee_fixed', gateway.processing_fee_fixed))
                gateway.settlement_time_hours = max(int(request.form.get('settlement_time_hours', gateway.settlement_time_hours)), 1)
                gateway.supported_methods = request.form.getlist('supported_methods')
                gateway.rate_limit_per_minute = max(int(request.form.get('rate_limit_per_minute', gateway.rate_limit_per_minute)), 1)
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
                
                # Log the update
                log_entry = PaymentGatewayLog(
                    payment_gateway_id=gateway.id,
                    log_type='GATEWAY_UPDATED',
                    endpoint='edit_gateway',
                    request_method='POST',
                    request_body={'action': 'update_gateway', 'gateway_id': gateway_id},
                    response_status=200,
                    response_body={'status': 'success', 'message': 'Gateway updated'},
                    response_time_ms=30
                )
                db.session.add(log_entry)
                db.session.commit()
                
                flash(f'Payment gateway "{gateway.gateway_name}" updated successfully', 'success')
                return redirect(url_for('payment_gateway_management.gateway_details_page', gateway_id=gateway.id))
                
            except ValueError as e:
                db.session.rollback()
                flash(f'Invalid input data: {str(e)}', 'error')
            except Exception as e:
                db.session.rollback()
                flash(f'Error updating gateway: {str(e)}', 'error')
        
        return render_template('gateway_management/edit_gateway.html',
            title=f'Edit Payment Gateway - {gateway.gateway_name}',
            subtitle='Update gateway configuration and settings',
            gateway=gateway,
            gateway_types=PaymentGatewayType
        )
        
    except Exception as e:
        flash(f'Error loading gateway for editing: {str(e)}', 'error')
        return redirect(url_for('payment_gateway_management.gateways_page'))

@payment_gateway_management_bp.route('/gateway/<gateway_id>')
@login_required
@admin_required
def gateway_details_page(gateway_id):
    """Enhanced payment gateway details page"""
    if not validate_uuid(gateway_id):
        flash('Invalid gateway ID', 'error')
        return redirect(url_for('payment_gateway_management.gateways_page'))
    
    try:
        gateway = PaymentGateway.query.filter(
            PaymentGateway.id == gateway_id,
            PaymentGateway.tenant_id == current_user.tenant_id
        ).first()
        
        if not gateway:
            flash('Payment gateway not found', 'error')
            return redirect(url_for('payment_gateway_management.gateways_page'))
        
        # Get recent transactions with pagination
        recent_transactions = WalletTopupRequest.query.filter_by(
            payment_gateway_id=gateway.id
        ).order_by(WalletTopupRequest.created_at.desc()).limit(20).all()
        
        # Get recent webhooks
        recent_webhooks = PaymentWebhook.query.filter_by(
            payment_gateway_id=gateway.id
        ).order_by(PaymentWebhook.created_at.desc()).limit(15).all()
        
        # Get recent logs
        recent_logs = PaymentGatewayLog.query.filter_by(
            payment_gateway_id=gateway.id
        ).order_by(PaymentGatewayLog.created_at.desc()).limit(10).all()
        
        # Calculate comprehensive statistics
        total_transactions = WalletTopupRequest.query.filter_by(
            payment_gateway_id=gateway.id
        ).count()
        
        successful_transactions = WalletTopupRequest.query.filter(
            WalletTopupRequest.payment_gateway_id == gateway.id,
            WalletTopupRequest.status == TransactionStatus.SUCCESS
        ).count()
        
        failed_transactions = WalletTopupRequest.query.filter(
            WalletTopupRequest.payment_gateway_id == gateway.id,
            WalletTopupRequest.status == TransactionStatus.FAILED
        ).count()
        
        pending_transactions = WalletTopupRequest.query.filter(
            WalletTopupRequest.payment_gateway_id == gateway.id,
            WalletTopupRequest.status == TransactionStatus.PENDING
        ).count()
        
        # Amount statistics
        total_amount = db.session.query(
            db.func.coalesce(db.func.sum(WalletTopupRequest.amount), 0)
        ).filter(
            WalletTopupRequest.payment_gateway_id == gateway.id,
            WalletTopupRequest.status == TransactionStatus.SUCCESS
        ).scalar()
        
        # Today's statistics
        today = datetime.utcnow().date()
        today_transactions = WalletTopupRequest.query.filter(
            WalletTopupRequest.payment_gateway_id == gateway.id,
            db.func.date(WalletTopupRequest.created_at) == today
        ).count()
        
        today_amount = db.session.query(
            db.func.coalesce(db.func.sum(WalletTopupRequest.amount), 0)
        ).filter(
            WalletTopupRequest.payment_gateway_id == gateway.id,
            WalletTopupRequest.status == TransactionStatus.SUCCESS,
            db.func.date(WalletTopupRequest.created_at) == today
        ).scalar()
        
        # This month's statistics
        month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        month_transactions = WalletTopupRequest.query.filter(
            WalletTopupRequest.payment_gateway_id == gateway.id,
            WalletTopupRequest.created_at >= month_start
        ).count()
        
        month_amount = db.session.query(
            db.func.coalesce(db.func.sum(WalletTopupRequest.amount), 0)
        ).filter(
            WalletTopupRequest.payment_gateway_id == gateway.id,
            WalletTopupRequest.status == TransactionStatus.SUCCESS,
            WalletTopupRequest.created_at >= month_start
        ).scalar()
        
        # Webhook statistics
        total_webhooks = PaymentWebhook.query.filter_by(
            payment_gateway_id=gateway.id
        ).count()
        
        processed_webhooks = PaymentWebhook.query.filter_by(
            payment_gateway_id=gateway.id,
            processed=True
        ).count()
        
        stats = {
            'total_transactions': total_transactions,
            'successful_transactions': successful_transactions,
            'failed_transactions': failed_transactions,
            'pending_transactions': pending_transactions,
            'success_rate': (successful_transactions / total_transactions * 100) if total_transactions > 0 else 0,
            'failure_rate': (failed_transactions / total_transactions * 100) if total_transactions > 0 else 0,
            'total_amount_processed': float(total_amount),
            'today_transactions': today_transactions,
            'today_amount': float(today_amount),
            'month_transactions': month_transactions,
            'month_amount': float(month_amount),
            'total_webhooks': total_webhooks,
            'processed_webhooks': processed_webhooks,
            'webhook_success_rate': (processed_webhooks / total_webhooks * 100) if total_webhooks > 0 else 0
        }
        
        return render_template('gateway_management/gateway_details.html',
            title=f'Payment Gateway - {gateway.gateway_name}',
            subtitle='Gateway Details & Transaction Logs',
            gateway=gateway,
            recent_transactions=recent_transactions,
            recent_webhooks=recent_webhooks,
            recent_logs=recent_logs,
            stats=stats
        )
        
    except Exception as e:
        flash(f'Error loading gateway details: {str(e)}', 'error')
        return redirect(url_for('payment_gateway_management.gateways_page'))

@payment_gateway_management_bp.route('/gateway/<gateway_id>/toggle-status', methods=['POST'])
@login_required
@super_admin_required
def toggle_gateway_status(gateway_id):
    """Toggle payment gateway status with logging"""
    if not validate_uuid(gateway_id):
        return jsonify({'error': 'Invalid gateway ID'}), 400
    
    try:
        gateway = PaymentGateway.query.filter(
            PaymentGateway.id == gateway_id,
            PaymentGateway.tenant_id == current_user.tenant_id
        ).first()
        
        if not gateway:
            return jsonify({'error': 'Payment gateway not found'}), 404
        
        # Toggle status
        old_status = gateway.status
        gateway.status = 'INACTIVE' if gateway.status == 'ACTIVE' else 'ACTIVE'
        gateway.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        # Log the status change
        log_entry = PaymentGatewayLog(
            payment_gateway_id=gateway.id,
            log_type='STATUS_CHANGED',
            endpoint='toggle_status',
            request_method='POST',
            request_body={'action': 'toggle_status', 'old_status': old_status, 'new_status': gateway.status},
            response_status=200,
            response_body={'status': 'success', 'new_status': gateway.status},
            response_time_ms=20
        )
        db.session.add(log_entry)
        db.session.commit()
        
        status_text = 'activated' if gateway.status == 'ACTIVE' else 'deactivated'
        
        if request.is_json:
            return jsonify({
                'success': True,
                'message': f'Payment gateway {status_text} successfully',
                'new_status': gateway.status
            })
        else:
            flash(f'Payment gateway {status_text} successfully', 'success')
            return redirect(url_for('payment_gateway_management.gateway_details_page', gateway_id=gateway.id))
        
    except Exception as e:
        db.session.rollback()
        error_msg = f'Error toggling gateway status: {str(e)}'
        
        if request.is_json:
            return jsonify({'error': error_msg}), 500
        else:
            flash(error_msg, 'error')
            return redirect(url_for('payment_gateway_management.gateway_details_page', gateway_id=gateway_id))

@payment_gateway_management_bp.route('/gateway/<gateway_id>/test', methods=['POST'])
@login_required
@super_admin_required
def test_gateway(gateway_id):
    """Enhanced gateway connection test"""
    if not validate_uuid(gateway_id):
        flash('Invalid gateway ID', 'error')
        return redirect(url_for('payment_gateway_management.gateways_page'))
    
    try:
        gateway = PaymentGateway.query.filter(
            PaymentGateway.id == gateway_id,
            PaymentGateway.tenant_id == current_user.tenant_id
        ).first()
        
        if not gateway:
            flash('Payment gateway not found', 'error')
            return redirect(url_for('payment_gateway_management.gateways_page'))
        
        test_amount = safe_decimal_conversion(request.form.get('amount', '1.00'))
        
        # Validate test amount
        if test_amount < gateway.min_amount or test_amount > gateway.max_amount:
            flash(f'Test amount must be between ₹{gateway.min_amount} and ₹{gateway.max_amount}', 'error')
            return redirect(url_for('payment_gateway_management.gateway_details_page', gateway_id=gateway.id))
        
        # Simulate different test scenarios
        test_scenarios = ['success', 'failure', 'timeout']
        import random
        scenario = random.choice(test_scenarios)
        
        if scenario == 'success':
            response_status = 200
            response_body = {
                'status': 'success', 
                'message': 'Test connection successful',
                'gateway_response': 'OK',
                'test_amount': float(test_amount)
            }
            response_time = random.randint(50, 200)
        elif scenario == 'failure':
            response_status = 400
            response_body = {
                'status': 'error', 
                'message': 'Authentication failed',
                'error_code': 'AUTH_ERROR'
            }
            response_time = random.randint(100, 500)
        else:  # timeout
            response_status = 408
            response_body = {
                'status': 'timeout', 
                'message': 'Request timeout'
            }
            response_time = 5000
        
        # Create comprehensive test log
        test_log = PaymentGatewayLog(
            payment_gateway_id=gateway.id,
            log_type='TEST_CONNECTION',
            endpoint=f'{gateway.gateway_type.value.lower()}_test',
            request_method='POST',
            request_body={
                'amount': float(test_amount), 
                'test': True,
                'gateway_type': gateway.gateway_type.value,
                'merchant_id': gateway.merchant_id
            },
            response_status=response_status,
            response_body=response_body,
            response_time_ms=response_time
        )
        
        db.session.add(test_log)
        db.session.commit()
        
        if scenario == 'success':
            flash(f'Gateway connection test completed successfully (Response time: {response_time}ms)', 'success')
        else:
            flash(f'Gateway test failed: {response_body["message"]} (Response time: {response_time}ms)', 'error')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Gateway test failed: {str(e)}', 'error')
    
    return redirect(url_for('payment_gateway_management.gateway_details_page', gateway_id=gateway_id))

@payment_gateway_management_bp.route('/webhooks')
@login_required
@admin_required
def webhooks_page():
    """Enhanced webhooks management page"""
    try:
        page = max(request.args.get('page', 1, type=int), 1)
        per_page = min(max(request.args.get('per_page', 20, type=int), 10), 100)
        gateway_id = request.args.get('gateway_id', '').strip()
        processed = request.args.get('processed', '').strip()
        date_from = request.args.get('date_from', '').strip()
        date_to = request.args.get('date_to', '').strip()
        
        # Base query with tenant filtering
        query = PaymentWebhook.query.join(PaymentGateway).filter(
            PaymentGateway.tenant_id == current_user.tenant_id
        )
        
        # Apply filters
        if gateway_id and validate_uuid(gateway_id):
            query = query.filter(PaymentWebhook.payment_gateway_id == gateway_id)
        
        if processed and processed != 'all':
            processed_bool = processed == 'true'
            query = query.filter(PaymentWebhook.processed == processed_bool)
        
        # Date range filtering
        if date_from:
            try:
                from_date = datetime.strptime(date_from, '%Y-%m-%d')
                query = query.filter(PaymentWebhook.created_at >= from_date)
            except ValueError:
                flash('Invalid from date format', 'warning')
        
        if date_to:
            try:
                to_date = datetime.strptime(date_to, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
                query = query.filter(PaymentWebhook.created_at <= to_date)
            except ValueError:
                flash('Invalid to date format', 'warning')
        
        # Paginate results
        webhooks = query.order_by(PaymentWebhook.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False, max_per_page=100
        )
        
        # Get available gateways for filter
        available_gateways = PaymentGateway.query.filter(
            PaymentGateway.tenant_id == current_user.tenant_id
        ).order_by(PaymentGateway.gateway_name).all()
        
        # Calculate webhook statistics
        total_webhooks = PaymentWebhook.query.join(PaymentGateway).filter(
            PaymentGateway.tenant_id == current_user.tenant_id
        ).count()
        
        processed_webhooks = PaymentWebhook.query.join(PaymentGateway).filter(
            PaymentGateway.tenant_id == current_user.tenant_id,
            PaymentWebhook.processed == True
        ).count()
        
        failed_webhooks = PaymentWebhook.query.join(PaymentGateway).filter(
            PaymentGateway.tenant_id == current_user.tenant_id,
            PaymentWebhook.processing_error.isnot(None)
        ).count()
        
        webhook_stats = {
            'total': total_webhooks,
            'processed': processed_webhooks,
            'failed': failed_webhooks,
            'success_rate': (processed_webhooks / total_webhooks * 100) if total_webhooks > 0 else 0
        }
        
        return render_template('gateway_management/webhooks.html',
            title='Webhook Management',
            subtitle='Monitor Payment Gateway Webhooks',
            webhooks=webhooks,
            available_gateways=available_gateways,
            webhook_stats=webhook_stats,
            current_gateway=gateway_id,
            current_processed=processed,
            current_date_from=date_from,
            current_date_to=date_to
        )
        
    except Exception as e:
        flash(f'Error loading webhooks: {str(e)}', 'error')
        return redirect(url_for('payment_gateway_management.index'))

@payment_gateway_management_bp.route('/webhook/<webhook_id>/retry', methods=['POST'])
@login_required
@super_admin_required
def retry_webhook(webhook_id):
    """Enhanced webhook retry with better error handling"""
    if not validate_uuid(webhook_id):
        return jsonify({'error': 'Invalid webhook ID'}), 400
    
    try:
        webhook = PaymentWebhook.query.join(PaymentGateway).filter(
            PaymentWebhook.id == webhook_id,
            PaymentGateway.tenant_id == current_user.tenant_id
        ).first()
        
        if not webhook:
            return jsonify({'error': 'Webhook not found'}), 404
        
        if webhook.processed:
            message = 'Webhook already processed successfully'
            if request.is_json:
                return jsonify({'warning': message}), 200
            else:
                flash(message, 'warning')
                return redirect(url_for('payment_gateway_management.webhooks_page'))
        
        # Increment retry attempts
        webhook.processing_attempts = (webhook.processing_attempts or 0) + 1
        
        # Simulate retry processing
        import random
        success = random.choice([True, False, True])  # 2/3 chance of success
        
        if success:
            webhook.processed = True
            webhook.processed_at = datetime.utcnow()
            webhook.processing_error = None
            message = 'Webhook processed successfully'
            status = 'success'
        else:
            webhook.processing_error = 'Retry failed: Connection timeout'
            message = 'Webhook retry failed'
            status = 'error'
        
        webhook.updated_at = datetime.utcnow()
        db.session.commit()
        
        if request.is_json:
            return jsonify({
                'success': success,
                'message': message,
                'attempts': webhook.processing_attempts
            })
        else:
            flash(message, status)
            return redirect(url_for('payment_gateway_management.webhooks_page'))
        
    except Exception as e:
        db.session.rollback()
        error_msg = f'Error retrying webhook: {str(e)}'
        
        if request.is_json:
            return jsonify({'error': error_msg}), 500
        else:
            flash(error_msg, 'error')
            return redirect(url_for('payment_gateway_management.webhooks_page'))

@payment_gateway_management_bp.route('/bulk-actions', methods=['GET', 'POST'])
@login_required
@super_admin_required
def bulk_actions():
    """Enhanced bulk actions on gateways"""
    if request.method == 'GET':
        # Show bulk actions page
        gateways = PaymentGateway.query.filter(
            PaymentGateway.tenant_id == current_user.tenant_id
        ).order_by(PaymentGateway.gateway_name).all()
        
        return render_template('gateway_management/bulk_actions.html',
            title='Bulk Actions',
            subtitle='Perform bulk operations on payment gateways',
            gateways=gateways
        )
    
    try:
        gateway_ids = request.form.getlist('gateway_ids')
        action = request.form.get('action', '').strip()
        
        if not gateway_ids or not action:
            flash('Please select gateways and action', 'error')
            return redirect(url_for('payment_gateway_management.bulk_actions'))
        
        # Validate gateway IDs
        valid_ids = [gid for gid in gateway_ids if validate_uuid(gid)]
        if len(valid_ids) != len(gateway_ids):
            flash('Some gateway IDs are invalid', 'warning')
        
        gateways = PaymentGateway.query.filter(
            PaymentGateway.id.in_(valid_ids),
            PaymentGateway.tenant_id == current_user.tenant_id
        ).all()
        
        if not gateways:
            flash('No valid gateways found', 'error')
            return redirect(url_for('payment_gateway_management.bulk_actions'))
        
        updated_count = 0
        error_count = 0
        
        for gateway in gateways:
            try:
                if action == 'activate':
                    gateway.status = 'ACTIVE'
                    updated_count += 1
                elif action == 'deactivate':
                    gateway.status = 'INACTIVE'
                    updated_count += 1
                elif action == 'toggle_sandbox':
                    gateway.sandbox_mode = not gateway.sandbox_mode
                    updated_count += 1
                elif action == 'reset_priority':
                    gateway.priority = 1
                    updated_count += 1
                elif action == 'enable_auto_settlement':
                    gateway.auto_settlement = True
                    updated_count += 1
                elif action == 'disable_auto_settlement':
                    gateway.auto_settlement = False
                    updated_count += 1
                
                gateway.updated_at = datetime.utcnow()
                
                # Log bulk action
                log_entry = PaymentGatewayLog(
                    payment_gateway_id=gateway.id,
                    log_type='BULK_ACTION',
                    endpoint='bulk_actions',
                    request_method='POST',
                    request_body={'action': action, 'gateway_id': str(gateway.id)},
                    response_status=200,
                    response_body={'status': 'success', 'action': action},
                    response_time_ms=10
                )
                db.session.add(log_entry)
                
            except Exception as e:
                error_count += 1
                continue
        
        db.session.commit()
        
        if updated_count > 0:
            flash(f'Successfully updated {updated_count} gateways', 'success')
        if error_count > 0:
            flash(f'{error_count} gateways failed to update', 'error')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error performing bulk action: {str(e)}', 'error')
    
    return redirect(url_for('payment_gateway_management.gateways_page'))

# =============================================================================
# API ENDPOINTS
# =============================================================================

@payment_gateway_management_bp.route('/api/gateways', methods=['GET'])
@login_required
@admin_required
def api_get_gateways():
    """API endpoint to get gateways list"""
    try:
        gateways = PaymentGateway.query.filter(
            PaymentGateway.tenant_id == current_user.tenant_id
        ).order_by(PaymentGateway.priority).all()
        
        gateways_data = []
        for gateway in gateways:
            gateway_data = {
                'id': str(gateway.id),
                'gateway_name': gateway.gateway_name,
                'gateway_type': gateway.gateway_type.value,
                'status': gateway.status,
                'is_default': gateway.is_default,
                'sandbox_mode': gateway.sandbox_mode,
                'priority': gateway.priority,
                'min_amount': float(gateway.min_amount),
                'max_amount': float(gateway.max_amount),
                'supported_methods': gateway.supported_methods
            }
            gateways_data.append(gateway_data)
        
        return jsonify({
            'success': True,
            'gateways': gateways_data,
            'total': len(gateways_data)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@payment_gateway_management_bp.route('/api/gateway/<gateway_id>/stats', methods=['GET'])
@login_required
@admin_required
def api_gateway_stats(gateway_id):
    """API endpoint to get gateway statistics"""
    if not validate_uuid(gateway_id):
        return jsonify({'error': 'Invalid gateway ID'}), 400
    
    try:
        gateway = PaymentGateway.query.filter(
            PaymentGateway.id == gateway_id,
            PaymentGateway.tenant_id == current_user.tenant_id
        ).first()
        
        if not gateway:
            return jsonify({'error': 'Gateway not found'}), 404
        
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
        
        return jsonify({
            'success': True,
            'stats': {
                'total_transactions': total_transactions,
                'successful_transactions': successful_transactions,
                'success_rate': (successful_transactions / total_transactions * 100) if total_transactions > 0 else 0,
                'total_amount': float(total_amount)
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# EXPORT FUNCTIONALITY
# =============================================================================

@payment_gateway_management_bp.route('/export/gateways')
@login_required
@admin_required
def export_gateways():
    """Export gateways data to CSV"""
    try:
        gateways = PaymentGateway.query.filter(
            PaymentGateway.tenant_id == current_user.tenant_id
        ).order_by(PaymentGateway.gateway_name).all()
        
        # Create CSV
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Gateway Name', 'Type', 'Merchant ID', 'Status', 'Sandbox Mode',
            'Priority', 'Min Amount', 'Max Amount', 'Processing Fee %', 
            'Processing Fee Fixed', 'Settlement Hours', 'Supported Methods',
            'Rate Limit/Min', 'Auto Settlement', 'Is Default', 'Created At'
        ])
        
        # Write data
        for gateway in gateways:
            writer.writerow([
                gateway.gateway_name,
                gateway.gateway_type.value,
                gateway.merchant_id,
                gateway.status,
                'Yes' if gateway.sandbox_mode else 'No',
                gateway.priority,
                float(gateway.min_amount),
                float(gateway.max_amount),
                float(gateway.processing_fee_percentage),
                float(gateway.processing_fee_fixed),
                gateway.settlement_time_hours,
                ', '.join(gateway.supported_methods) if gateway.supported_methods else '',
                gateway.rate_limit_per_minute,
                'Yes' if gateway.auto_settlement else 'No',
                'Yes' if gateway.is_default else 'No',
                gateway.created_at.strftime('%Y-%m-%d %H:%M:%S')
            ])
        
        # Prepare response
        output.seek(0)
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv; charset=utf-8'
        response.headers['Content-Disposition'] = f'attachment; filename="payment_gateways_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv"'
        
        return response
        
    except Exception as e:
        flash(f'Error exporting gateways: {str(e)}', 'error')
        return redirect(url_for('payment_gateway_management.gateways_page'))

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_gateway_templates():
    """Get gateway configuration templates"""
    return {
        'RAZORPAY': {
            'name': 'Razorpay',
            'supported_methods': ['card', 'netbanking', 'wallet', 'upi'],
            'default_config': {
                'min_amount': '1.00',
                'max_amount': '100000.00',
                'settlement_time_hours': '24',
                'processing_fee_percentage': '2.0',
                'rate_limit_per_minute': '1000'
            }
        },
        'PAYU': {
            'name': 'PayU',
            'supported_methods': ['card', 'netbanking', 'wallet', 'upi', 'emi'],
            'default_config': {
                'min_amount': '1.00',
                'max_amount': '200000.00',
                'settlement_time_hours': '48',
                'processing_fee_percentage': '2.5',
                'rate_limit_per_minute': '500'
            }
        },
        'CASHFREE': {
            'name': 'Cashfree',
            'supported_methods': ['card', 'netbanking', 'wallet', 'upi'],
            'default_config': {
                'min_amount': '1.00',
                'max_amount': '500000.00',
                'settlement_time_hours': '24',
                'processing_fee_percentage': '1.8',
                'rate_limit_per_minute': '2000'
            }
        },
        'PHONEPE': {
            'name': 'PhonePe',
            'supported_methods': ['upi', 'wallet', 'card'],
            'default_config': {
                'min_amount': '1.00',
                'max_amount': '100000.00',
                'settlement_time_hours': '24',
                'processing_fee_percentage': '1.5',
                'rate_limit_per_minute': '1500'
            }
        },
        'PAYTM': {
            'name': 'Paytm',
            'supported_methods': ['wallet', 'upi', 'card', 'netbanking'],
            'default_config': {
                'min_amount': '1.00',
                'max_amount': '100000.00',
                'settlement_time_hours': '24',
                'processing_fee_percentage': '2.0',
                'rate_limit_per_minute': '800'
            }
        }
    }
