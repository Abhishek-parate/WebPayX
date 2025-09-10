# api_management.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, make_response
from flask_login import login_required, current_user
from models import (
    db, APIConfiguration, APIRequestLog, User, UserRoleType, 
    ServiceType, Tenant
)
from datetime import datetime, timedelta
from functools import wraps
import uuid
import csv
import io
import json
import requests
from sqlalchemy import and_, or_, desc, func
from decimal import Decimal


api_management_bp = Blueprint('api_management', __name__, url_prefix='/api-management')


# UPDATED: Only SUPER_ADMIN can access API management
def super_admin_only_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != UserRoleType.SUPER_ADMIN:
            flash('Access denied. Super Admin privileges required.', 'error')
            return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function


# ============================================================================
# API MANAGEMENT ROUTES - SUPER ADMIN ONLY
# ============================================================================


@api_management_bp.route('/')
@login_required
@super_admin_only_required  # Changed to super admin only
def dashboard():
    """API Management Dashboard - Super Admin Only"""
    try:
        # No tenant filtering for super admin - show all data
        base_query = APIConfiguration.query
        
        stats = {
            'total_configs': base_query.count(),
            'active_configs': base_query.filter_by(is_active=True).count(),
            'inactive_configs': base_query.filter_by(is_active=False).count(),
            'service_types': base_query.distinct(APIConfiguration.service_type).count(),
        }
        
        # Service type distribution - no tenant filtering
        service_stats = db.session.query(
            APIConfiguration.service_type, 
            func.count(APIConfiguration.id).label('count')
        ).group_by(APIConfiguration.service_type).all()
        
        # Provider distribution - no tenant filtering
        provider_stats = db.session.query(
            APIConfiguration.provider, 
            func.count(APIConfiguration.id).label('count')
        ).group_by(APIConfiguration.provider).limit(10).all()
        
        # Recent configurations
        recent_configs = base_query.order_by(desc(APIConfiguration.created_at)).limit(5).all()
        
        # Request logs count (last 24 hours) - no tenant filtering
        yesterday = datetime.utcnow() - timedelta(hours=24)
        recent_requests = db.session.query(APIRequestLog).filter(
            APIRequestLog.created_at >= yesterday
        ).count()
        
        return render_template('api_management/dashboard.html',
                             stats=stats,
                             service_stats=service_stats,
                             provider_stats=provider_stats,
                             recent_configs=recent_configs,
                             recent_requests=recent_requests)
    
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}', 'error')
        return render_template('api_management/dashboard.html',
                             stats={'total_configs': 0, 'active_configs': 0, 'inactive_configs': 0, 'service_types': 0},
                             service_stats=[],
                             provider_stats=[],
                             recent_configs=[],
                             recent_requests=0)


@api_management_bp.route('/configurations')
@login_required
@super_admin_only_required  # Changed to super admin only
def api_configurations():
    """List all API configurations - Super Admin Only"""
    try:
        # Get filter parameters
        search = request.args.get('search', '').strip()
        service_type = request.args.get('service_type', '').strip()
        provider = request.args.get('provider', '').strip()
        status = request.args.get('status', '').strip()
        tenant_id = request.args.get('tenant_id', '').strip()
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        # Base query - no tenant filtering for super admin
        query = APIConfiguration.query
        
        # Apply filters
        if search:
            query = query.filter(
                or_(
                    APIConfiguration.provider.ilike(f'%{search}%'),
                    APIConfiguration.api_url.ilike(f'%{search}%')
                )
            )
        
        if service_type:
            try:
                query = query.filter_by(service_type=ServiceType(service_type))
            except ValueError:
                pass
        
        if provider:
            query = query.filter(APIConfiguration.provider.ilike(f'%{provider}%'))
        
        if status:
            query = query.filter_by(is_active=(status == 'active'))
        
        if tenant_id:
            try:
                uuid.UUID(tenant_id)
                query = query.filter_by(tenant_id=tenant_id)
            except ValueError:
                pass
        
        # Execute query with pagination
        configs = query.order_by(desc(APIConfiguration.created_at)).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        # Get all tenants for filter dropdown
        tenants = Tenant.query.order_by(Tenant.tenant_name).all()
        
        return render_template('api_management/configurations.html',
                             configs=configs,
                             service_types=ServiceType,
                             tenants=tenants,
                             filters={
                                 'search': search,
                                 'service_type': service_type,
                                 'provider': provider,
                                 'status': status,
                                 'tenant_id': tenant_id
                             })
    
    except Exception as e:
        flash(f'Error loading API configurations: {str(e)}', 'error')
        return redirect(url_for('api_management.dashboard'))


@api_management_bp.route('/configurations/create', methods=['GET', 'POST'])
@login_required
@super_admin_only_required  # Changed to super admin only
def create_configuration():
    """Create new API configuration - Super Admin Only"""
    if request.method == 'POST':
        try:
            # Get form data
            tenant_id = request.form.get('tenant_id', '').strip()
            service_type = request.form.get('service_type', '').strip()
            provider = request.form.get('provider', '').strip()
            api_url = request.form.get('api_url', '').strip()
            api_key = request.form.get('api_key', '').strip()
            api_secret = request.form.get('api_secret', '').strip()
            priority = request.form.get('priority', '1').strip()
            rate_limit = request.form.get('rate_limit', '1000').strip()
            timeout_seconds = request.form.get('timeout_seconds', '30').strip()
            retry_count = request.form.get('retry_count', '3').strip()
            is_active = request.form.get('is_active') == 'on'
            
            # Headers and parameters (JSON format)
            headers_json = request.form.get('headers_json', '{}').strip()
            parameters_json = request.form.get('parameters_json', '{}').strip()
            success_codes_json = request.form.get('success_codes_json', '[200, 201]').strip()
            
            # Stay on page option
            stay_on_page = request.form.get('stay_on_page') == 'on'
            
            # Validation
            if not all([tenant_id, service_type, provider, api_url]):
                flash('Tenant, service type, provider, and API URL are required', 'error')
                tenants = Tenant.query.order_by(Tenant.tenant_name).all()
                return render_template('api_management/create_configuration.html',
                                     service_types=ServiceType,
                                     tenants=tenants,
                                     now=datetime.now())
            
            # Validate tenant ID and service type enum
            try:
                uuid.UUID(tenant_id)
                service_type_enum = ServiceType(service_type)
            except ValueError as e:
                flash(f'Invalid tenant ID or service type: {str(e)}', 'error')
                tenants = Tenant.query.order_by(Tenant.tenant_name).all()
                return render_template('api_management/create_configuration.html',
                                     service_types=ServiceType,
                                     tenants=tenants,
                                     now=datetime.now())
            
            # Parse JSON fields
            try:
                headers = json.loads(headers_json) if headers_json else {}
                parameters = json.loads(parameters_json) if parameters_json else {}
                success_codes = json.loads(success_codes_json) if success_codes_json else [200, 201]
            except json.JSONDecodeError as e:
                flash(f'Invalid JSON format: {str(e)}', 'error')
                tenants = Tenant.query.order_by(Tenant.tenant_name).all()
                return render_template('api_management/create_configuration.html',
                                     service_types=ServiceType,
                                     tenants=tenants,
                                     now=datetime.now())
            
            # Check for duplicate configuration
            existing_config = APIConfiguration.query.filter_by(
                tenant_id=tenant_id,
                service_type=service_type_enum,
                provider=provider
            ).first()
            
            if existing_config:
                flash('API configuration for this tenant, service type and provider already exists', 'error')
                tenants = Tenant.query.order_by(Tenant.tenant_name).all()
                return render_template('api_management/create_configuration.html',
                                     service_types=ServiceType,
                                     tenants=tenants,
                                     now=datetime.now())
            
            # Create API configuration
            config = APIConfiguration(
                tenant_id=tenant_id,
                service_type=service_type_enum,
                provider=provider,
                api_url=api_url,
                api_key=api_key,
                api_secret=api_secret,
                headers=headers,
                parameters=parameters,
                is_active=is_active,
                priority=int(priority) if priority else 1,
                rate_limit=int(rate_limit) if rate_limit else 1000,
                timeout_seconds=int(timeout_seconds) if timeout_seconds else 30,
                success_codes=success_codes,
                retry_count=int(retry_count) if retry_count else 3
            )
            
            db.session.add(config)
            db.session.commit()
            
            success_message = f'API configuration for "{provider}" created successfully!'
            
            if stay_on_page:
                flash(success_message, 'success')
                tenants = Tenant.query.order_by(Tenant.tenant_name).all()
                return render_template('api_management/create_configuration.html',
                                     service_types=ServiceType,
                                     tenants=tenants,
                                     now=datetime.now(),
                                     success_message=success_message,
                                     clear_form=True)
            else:
                flash(success_message, 'success')
                return redirect(url_for('api_management.api_configurations'))
            
        except ValueError as e:
            db.session.rollback()
            flash(f'Invalid data provided: {str(e)}', 'error')
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating API configuration: {str(e)}', 'error')
    
    # Get all tenants for dropdown
    tenants = Tenant.query.order_by(Tenant.tenant_name).all()
    return render_template('api_management/create_configuration.html',
                         service_types=ServiceType,
                         tenants=tenants,
                         now=datetime.now())


@api_management_bp.route('/configurations/<config_id>')
@login_required
@super_admin_only_required  # Changed to super admin only
def configuration_detail(config_id):
    """View API configuration details - Super Admin Only"""
    try:
        # Validate UUID format
        try:
            uuid.UUID(config_id)
        except ValueError:
            flash('Invalid configuration ID', 'error')
            return redirect(url_for('api_management.api_configurations'))
        
        # No tenant filtering for super admin
        config = APIConfiguration.query.filter_by(id=config_id).first_or_404()
        
        # Get recent request logs
        recent_logs = db.session.query(APIRequestLog).filter_by(
            api_config_id=config_id
        ).order_by(desc(APIRequestLog.created_at)).limit(10).all()
        
        return render_template('api_management/configuration_detail.html',
                             config=config,
                             recent_logs=recent_logs)
    
    except Exception as e:
        flash(f'Error loading configuration details: {str(e)}', 'error')
        return redirect(url_for('api_management.api_configurations'))


@api_management_bp.route('/configurations/<config_id>/edit', methods=['GET', 'POST'])
@login_required
@super_admin_only_required  # Changed to super admin only
def edit_configuration(config_id):
    """Edit API configuration - Super Admin Only"""
    try:
        # Validate UUID format
        try:
            uuid.UUID(config_id)
        except ValueError:
            flash('Invalid configuration ID', 'error')
            return redirect(url_for('api_management.api_configurations'))
        
        # No tenant filtering for super admin
        config = APIConfiguration.query.filter_by(id=config_id).first_or_404()
        
        if request.method == 'POST':
            try:
                # Get form data
                provider = request.form.get('provider', '').strip()
                api_url = request.form.get('api_url', '').strip()
                api_key = request.form.get('api_key', '').strip()
                api_secret = request.form.get('api_secret', '').strip()
                priority = request.form.get('priority', '1').strip()
                rate_limit = request.form.get('rate_limit', '1000').strip()
                timeout_seconds = request.form.get('timeout_seconds', '30').strip()
                retry_count = request.form.get('retry_count', '3').strip()
                is_active = request.form.get('is_active') == 'on'
                
                # Headers and parameters
                headers_json = request.form.get('headers_json', '{}').strip()
                parameters_json = request.form.get('parameters_json', '{}').strip()
                success_codes_json = request.form.get('success_codes_json', '[200, 201]').strip()
                
                # Validation
                if not all([provider, api_url]):
                    flash('Provider and API URL are required', 'error')
                    return render_template('api_management/edit_configuration.html',
                                         config=config,
                                         service_types=ServiceType,
                                         now=datetime.now())
                
                # Parse JSON fields
                try:
                    headers = json.loads(headers_json) if headers_json else {}
                    parameters = json.loads(parameters_json) if parameters_json else {}
                    success_codes = json.loads(success_codes_json) if success_codes_json else [200, 201]
                except json.JSONDecodeError as e:
                    flash(f'Invalid JSON format: {str(e)}', 'error')
                    return render_template('api_management/edit_configuration.html',
                                         config=config,
                                         service_types=ServiceType,
                                         now=datetime.now())
                
                # Update configuration
                config.provider = provider
                config.api_url = api_url
                config.api_key = api_key
                config.api_secret = api_secret
                config.headers = headers
                config.parameters = parameters
                config.is_active = is_active
                config.priority = int(priority) if priority else 1
                config.rate_limit = int(rate_limit) if rate_limit else 1000
                config.timeout_seconds = int(timeout_seconds) if timeout_seconds else 30
                config.success_codes = success_codes
                config.retry_count = int(retry_count) if retry_count else 3
                config.updated_at = datetime.utcnow()
                
                db.session.commit()
                flash(f'API configuration "{config.provider}" updated successfully', 'success')
                return redirect(url_for('api_management.configuration_detail', config_id=config_id))
                
            except ValueError as e:
                db.session.rollback()
                flash(f'Invalid data provided: {str(e)}', 'error')
            except Exception as e:
                db.session.rollback()
                flash(f'Error updating API configuration: {str(e)}', 'error')
        
        return render_template('api_management/edit_configuration.html',
                             config=config,
                             service_types=ServiceType,
                             now=datetime.now())
    
    except Exception as e:
        flash(f'Error loading configuration for editing: {str(e)}', 'error')
        return redirect(url_for('api_management.api_configurations'))


@api_management_bp.route('/configurations/<config_id>/delete', methods=['POST'])
@login_required
@super_admin_only_required  # Already correct
def delete_configuration(config_id):
    """Delete API configuration - Super Admin Only"""
    try:
        # Validate UUID format
        try:
            uuid.UUID(config_id)
        except ValueError:
            flash('Invalid configuration ID', 'error')
            return redirect(url_for('api_management.api_configurations'))
        
        # No tenant filtering for super admin
        config = APIConfiguration.query.filter_by(id=config_id).first_or_404()
        
        provider_name = config.provider
        db.session.delete(config)
        db.session.commit()
        
        flash(f'API configuration for "{provider_name}" deleted successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting API configuration: {str(e)}', 'error')
    
    return redirect(url_for('api_management.api_configurations'))


@api_management_bp.route('/configurations/<config_id>/toggle-status', methods=['POST'])
@login_required
@super_admin_only_required  # Changed to super admin only
def toggle_configuration_status(config_id):
    """Toggle API configuration active status - Super Admin Only"""
    try:
        # Validate UUID format
        try:
            uuid.UUID(config_id)
        except ValueError:
            flash('Invalid configuration ID', 'error')
            return redirect(url_for('api_management.api_configurations'))
        
        # No tenant filtering for super admin
        config = APIConfiguration.query.filter_by(id=config_id).first_or_404()
        config.is_active = not config.is_active
        config.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        status = 'activated' if config.is_active else 'deactivated'
        flash(f'API configuration "{config.provider}" {status} successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating configuration status: {str(e)}', 'error')
    
    return redirect(url_for('api_management.configuration_detail', config_id=config_id))


@api_management_bp.route('/configurations/<config_id>/test', methods=['POST'])
@login_required
@super_admin_only_required  # Changed to super admin only
def test_configuration(config_id):
    """Test API configuration - Super Admin Only"""
    try:
        # Validate UUID format
        try:
            uuid.UUID(config_id)
        except ValueError:
            return jsonify({'error': 'Invalid configuration ID'}), 400
        
        # No tenant filtering for super admin
        config = APIConfiguration.query.filter_by(id=config_id).first_or_404()
        
        # Prepare test request
        headers = config.headers.copy() if config.headers else {}
        if config.api_key:
            headers['Authorization'] = f'Bearer {config.api_key}'
        
        test_data = config.parameters.copy() if config.parameters else {}
        test_data.update({'test': True, 'timestamp': datetime.utcnow().isoformat()})
        
        # Make test request
        start_time = datetime.utcnow()
        try:
            response = requests.post(
                config.api_url,
                json=test_data,
                headers=headers,
                timeout=config.timeout_seconds
            )
            end_time = datetime.utcnow()
            response_time = (end_time - start_time).total_seconds() * 1000
            
            # Log the test request
            log_entry = APIRequestLog(
                tenant_id=config.tenant_id,
                api_config_id=config_id,
                request_url=config.api_url,
                request_method='POST',
                request_headers=headers,
                request_body=test_data,
                response_status=response.status_code,
                response_headers=dict(response.headers),
                response_body=response.text[:1000],  # Limit response body size
                response_time_ms=int(response_time)
            )
            
            db.session.add(log_entry)
            db.session.commit()
            
            return jsonify({
                'success': response.status_code in config.success_codes,
                'status_code': response.status_code,
                'response_time': f"{response_time:.2f} ms",
                'response_body': response.text[:500],
                'headers': dict(response.headers)
            })
            
        except requests.exceptions.RequestException as e:
            end_time = datetime.utcnow()
            response_time = (end_time - start_time).total_seconds() * 1000
            
            # Log the failed request
            log_entry = APIRequestLog(
                tenant_id=config.tenant_id,
                api_config_id=config_id,
                request_url=config.api_url,
                request_method='POST',
                request_headers=headers,
                request_body=test_data,
                response_status=0,
                response_time_ms=int(response_time),
                error_message=str(e)
            )
            
            db.session.add(log_entry)
            db.session.commit()
            
            return jsonify({
                'success': False,
                'error': str(e),
                'response_time': f"{response_time:.2f} ms"
            })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_management_bp.route('/logs')
@login_required
@super_admin_only_required  # Changed to super admin only
def request_logs():
    """View API request logs - Super Admin Only"""
    try:
        # Get filter parameters
        config_id = request.args.get('config_id', '').strip()
        status_filter = request.args.get('status', '').strip()
        tenant_id = request.args.get('tenant_id', '').strip()
        date_from = request.args.get('date_from', '').strip()
        date_to = request.args.get('date_to', '').strip()
        page = request.args.get('page', 1, type=int)
        per_page = 50
        
        # Base query - no tenant filtering for super admin
        query = APIRequestLog.query
        
        # Apply filters
        if config_id:
            try:
                uuid.UUID(config_id)
                query = query.filter_by(api_config_id=config_id)
            except ValueError:
                pass
        
        if tenant_id:
            try:
                uuid.UUID(tenant_id)
                query = query.filter_by(tenant_id=tenant_id)
            except ValueError:
                pass
        
        if status_filter == 'success':
            query = query.filter(APIRequestLog.response_status.between(200, 299))
        elif status_filter == 'error':
            query = query.filter(~APIRequestLog.response_status.between(200, 299))
        
        if date_from:
            try:
                from_date = datetime.strptime(date_from, '%Y-%m-%d')
                query = query.filter(APIRequestLog.created_at >= from_date)
            except ValueError:
                pass
        
        if date_to:
            try:
                to_date = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
                query = query.filter(APIRequestLog.created_at < to_date)
            except ValueError:
                pass
        
        # Execute query with pagination
        logs = query.order_by(desc(APIRequestLog.created_at)).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        # Get all configurations and tenants for filters
        available_configs = APIConfiguration.query.all()
        tenants = Tenant.query.order_by(Tenant.tenant_name).all()
        
        return render_template('api_management/logs.html',
                             logs=logs,
                             available_configs=available_configs,
                             tenants=tenants,
                             filters={
                                 'config_id': config_id,
                                 'tenant_id': tenant_id,
                                 'status': status_filter,
                                 'date_from': date_from,
                                 'date_to': date_to
                             })
    
    except Exception as e:
        flash(f'Error loading request logs: {str(e)}', 'error')
        return redirect(url_for('api_management.dashboard'))


@api_management_bp.route('/export/configurations')
@login_required
@super_admin_only_required  # Changed to super admin only
def export_configurations():
    """Export API configurations to CSV - Super Admin Only"""
    try:
        # No tenant filtering for super admin
        configs = APIConfiguration.query.order_by(APIConfiguration.service_type, APIConfiguration.provider).all()
        
        # Create CSV
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Tenant', 'Service Type', 'Provider', 'API URL', 'Status', 'Priority',
            'Rate Limit', 'Timeout (s)', 'Retry Count', 'Created At'
        ])
        
        # Write data
        for config in configs:
            tenant_name = config.tenant.tenant_name if config.tenant else 'Unknown'
            writer.writerow([
                tenant_name,
                config.service_type.value,
                config.provider,
                config.api_url,
                'Active' if config.is_active else 'Inactive',
                config.priority,
                config.rate_limit,
                config.timeout_seconds,
                config.retry_count,
                config.created_at.strftime('%Y-%m-%d %H:%M:%S')
            ])
        
        # Prepare file
        output.seek(0)
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename="api_configurations_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv"'
        
        return response
        
    except Exception as e:
        flash(f'Error exporting configurations: {str(e)}', 'error')
        return redirect(url_for('api_management.api_configurations'))
