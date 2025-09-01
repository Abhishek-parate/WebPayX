# routes/audit_logging.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import login_required, current_user
from models import (
    db, AuditLog, ErrorLog, User, UserRoleType, Tenant
)
from datetime import datetime, timedelta
from functools import wraps
import uuid
import csv
import io
from sqlalchemy import and_, or_, desc, func

audit_logging_bp = Blueprint('audit_logging', __name__, url_prefix='/audit-logging')

# Role-based access decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role not in [UserRoleType.SUPER_ADMIN, UserRoleType.ADMIN]:
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('main.dashboard'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != UserRoleType.SUPER_ADMIN:
            flash('Access denied. Super Admin privileges required.', 'error')
            return redirect(url_for('main.dashboard'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# ============================================================================
# AUDIT LOG MANAGEMENT ROUTES
# ============================================================================

@audit_logging_bp.route('/')
@login_required
@admin_required
def audit_dashboard():
    """Audit and Logging Dashboard"""
    # Get summary statistics
    today = datetime.utcnow().date()
    week_ago = today - timedelta(days=7)
    month_ago = today - timedelta(days=30)
    
    # Base query for tenant filtering
    base_query = AuditLog.query
    if current_user.role != UserRoleType.SUPER_ADMIN:
        base_query = base_query.filter_by(tenant_id=current_user.tenant_id)
    
    stats = {
        'total_logs': base_query.count(),
        'today_logs': base_query.filter(func.date(AuditLog.created_at) == today).count(),
        'week_logs': base_query.filter(func.date(AuditLog.created_at) >= week_ago).count(),
        'month_logs': base_query.filter(func.date(AuditLog.created_at) >= month_ago).count(),
    }
    
    # Error log stats
    error_base_query = ErrorLog.query
    if current_user.role != UserRoleType.SUPER_ADMIN:
        error_base_query = error_base_query.filter_by(tenant_id=current_user.tenant_id)
    
    error_stats = {
        'total_errors': error_base_query.count(),
        'unresolved_errors': error_base_query.filter_by(resolved=False).count(),
        'today_errors': error_base_query.filter(func.date(ErrorLog.created_at) == today).count(),
        'critical_errors': error_base_query.filter_by(severity='CRITICAL').count(),
    }
    
    # Recent activity
    recent_audits = base_query.order_by(desc(AuditLog.created_at)).limit(5).all()
    recent_errors = error_base_query.order_by(desc(ErrorLog.created_at)).limit(5).all()
    
    # Activity by action (top 10)
    action_stats = db.session.query(
        AuditLog.action, 
        func.count(AuditLog.id).label('count')
    ).group_by(AuditLog.action).order_by(desc('count')).limit(10).all()
    
    return render_template('audit_logging/dashboard.html',
                         stats=stats,
                         error_stats=error_stats,
                         recent_audits=recent_audits,
                         recent_errors=recent_errors,
                         action_stats=action_stats)

@audit_logging_bp.route('/audit-logs')
@login_required
@admin_required
def audit_logs():
    """View audit logs with filtering"""
    # Get filter parameters
    search = request.args.get('search', '')
    action = request.args.get('action', '')
    resource_type = request.args.get('resource_type', '')
    user_id = request.args.get('user_id', '')
    severity = request.args.get('severity', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    page = request.args.get('page', 1, type=int)
    per_page = 25
    
    # Base query
    query = AuditLog.query
    if current_user.role != UserRoleType.SUPER_ADMIN:
        query = query.filter_by(tenant_id=current_user.tenant_id)
    
    # Apply filters
    if search:
        query = query.filter(
            or_(
                AuditLog.action.ilike(f'%{search}%'),
                AuditLog.description.ilike(f'%{search}%'),
                AuditLog.resource_type.ilike(f'%{search}%')
            )
        )
    
    if action:
        query = query.filter_by(action=action)
    
    if resource_type:
        query = query.filter_by(resource_type=resource_type)
    
    if user_id:
        query = query.filter_by(user_id=user_id)
    
    if severity:
        query = query.filter_by(severity=severity)
    
    if date_from:
        try:
            from_date = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(AuditLog.created_at >= from_date)
        except ValueError:
            pass
    
    if date_to:
        try:
            to_date = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(AuditLog.created_at < to_date)
        except ValueError:
            pass
    
    # Execute query with pagination
    audit_logs = query.order_by(desc(AuditLog.created_at)).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Get filter options
    actions = db.session.query(AuditLog.action).distinct().all()
    resource_types = db.session.query(AuditLog.resource_type).distinct().all()
    severities = ['INFO', 'WARNING', 'ERROR', 'CRITICAL']
    
    # Get users for filter (limited to tenant)
    users_query = User.query
    if current_user.role != UserRoleType.SUPER_ADMIN:
        users_query = users_query.filter_by(tenant_id=current_user.tenant_id)
    users = users_query.order_by(User.full_name).all()
    
    return render_template('audit_logging/audit_logs.html',
                         audit_logs=audit_logs,
                         actions=[a[0] for a in actions if a[0]],
                         resource_types=[r[0] for r in resource_types if r[0]],
                         severities=severities,
                         users=users,
                         filters={
                             'search': search,
                             'action': action,
                             'resource_type': resource_type,
                             'user_id': user_id,
                             'severity': severity,
                             'date_from': date_from,
                             'date_to': date_to
                         })

@audit_logging_bp.route('/audit-logs/<log_id>')
@login_required
@admin_required
def audit_log_detail(log_id):
    """View detailed audit log"""
    query = AuditLog.query
    if current_user.role != UserRoleType.SUPER_ADMIN:
        query = query.filter_by(tenant_id=current_user.tenant_id)
    
    audit_log = query.filter_by(id=log_id).first_or_404()
    
    return render_template('audit_logging/audit_log_detail.html', audit_log=audit_log)

# ============================================================================
# ERROR LOG MANAGEMENT ROUTES
# ============================================================================

@audit_logging_bp.route('/error-logs')
@login_required
@admin_required
def error_logs():
    """View error logs with filtering"""
    # Get filter parameters
    search = request.args.get('search', '')
    severity = request.args.get('severity', '')
    resolved = request.args.get('resolved', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    page = request.args.get('page', 1, type=int)
    per_page = 25
    
    # Base query
    query = ErrorLog.query
    if current_user.role != UserRoleType.SUPER_ADMIN:
        query = query.filter_by(tenant_id=current_user.tenant_id)
    
    # Apply filters
    if search:
        query = query.filter(
            or_(
                ErrorLog.error_code.ilike(f'%{search}%'),
                ErrorLog.error_message.ilike(f'%{search}%')
            )
        )
    
    if severity:
        query = query.filter_by(severity=severity)
    
    if resolved:
        is_resolved = resolved.lower() == 'true'
        query = query.filter_by(resolved=is_resolved)
    
    if date_from:
        try:
            from_date = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(ErrorLog.created_at >= from_date)
        except ValueError:
            pass
    
    if date_to:
        try:
            to_date = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(ErrorLog.created_at < to_date)
        except ValueError:
            pass
    
    # Execute query with pagination
    error_logs = query.order_by(desc(ErrorLog.created_at)).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    severities = ['INFO', 'WARNING', 'ERROR', 'CRITICAL']
    
    return render_template('audit_logging/error_logs.html',
                         error_logs=error_logs,
                         severities=severities,
                         filters={
                             'search': search,
                             'severity': severity,
                             'resolved': resolved,
                             'date_from': date_from,
                             'date_to': date_to
                         })

@audit_logging_bp.route('/error-logs/<log_id>')
@login_required
@admin_required
def error_log_detail(log_id):
    """View detailed error log"""
    query = ErrorLog.query
    if current_user.role != UserRoleType.SUPER_ADMIN:
        query = query.filter_by(tenant_id=current_user.tenant_id)
    
    error_log = query.filter_by(id=log_id).first_or_404()
    
    return render_template('audit_logging/error_log_detail.html', error_log=error_log)

@audit_logging_bp.route('/error-logs/<log_id>/resolve', methods=['POST'])
@login_required
@admin_required
def resolve_error(log_id):
    """Mark error as resolved"""
    try:
        query = ErrorLog.query
        if current_user.role != UserRoleType.SUPER_ADMIN:
            query = query.filter_by(tenant_id=current_user.tenant_id)
        
        error_log = query.filter_by(id=log_id).first_or_404()
        
        error_log.resolved = True
        error_log.resolved_by = current_user.id
        error_log.resolved_at = datetime.utcnow()
        
        db.session.commit()
        flash('Error marked as resolved successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash('Error resolving error log', 'error')
    
    return redirect(url_for('audit_logging.error_logs'))

@audit_logging_bp.route('/error-logs/<log_id>/unresolve', methods=['POST'])
@login_required
@admin_required
def unresolve_error(log_id):
    """Mark error as unresolved"""
    try:
        query = ErrorLog.query
        if current_user.role != UserRoleType.SUPER_ADMIN:
            query = query.filter_by(tenant_id=current_user.tenant_id)
        
        error_log = query.filter_by(id=log_id).first_or_404()
        
        error_log.resolved = False
        error_log.resolved_by = None
        error_log.resolved_at = None
        
        db.session.commit()
        flash('Error marked as unresolved', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash('Error updating error log', 'error')
    
    return redirect(url_for('audit_logging.error_logs'))

# ============================================================================
# EXPORT AND REPORTING ROUTES
# ============================================================================

@audit_logging_bp.route('/export/audit-logs')
@login_required
@admin_required
def export_audit_logs():
    """Export audit logs to CSV"""
    # Get filter parameters (same as audit_logs route)
    search = request.args.get('search', '')
    action = request.args.get('action', '')
    resource_type = request.args.get('resource_type', '')
    user_id = request.args.get('user_id', '')
    severity = request.args.get('severity', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    # Build query (same logic as audit_logs route)
    query = AuditLog.query
    if current_user.role != UserRoleType.SUPER_ADMIN:
        query = query.filter_by(tenant_id=current_user.tenant_id)
    
    # Apply same filters...
    if search:
        query = query.filter(
            or_(
                AuditLog.action.ilike(f'%{search}%'),
                AuditLog.description.ilike(f'%{search}%'),
                AuditLog.resource_type.ilike(f'%{search}%')
            )
        )
    
    if action:
        query = query.filter_by(action=action)
    if resource_type:
        query = query.filter_by(resource_type=resource_type)
    if user_id:
        query = query.filter_by(user_id=user_id)
    if severity:
        query = query.filter_by(severity=severity)
    if date_from:
        try:
            from_date = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(AuditLog.created_at >= from_date)
        except ValueError:
            pass
    if date_to:
        try:
            to_date = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(AuditLog.created_at < to_date)
        except ValueError:
            pass
    
    # Get all matching records
    audit_logs = query.order_by(desc(AuditLog.created_at)).all()
    
    # Create CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'ID', 'Date/Time', 'User', 'Action', 'Resource Type', 'Resource ID',
        'Severity', 'Description', 'IP Address', 'User Agent'
    ])
    
    # Write data
    for log in audit_logs:
        user_name = log.user.full_name if log.user else 'System'
        writer.writerow([
            str(log.id),
            log.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            user_name,
            log.action,
            log.resource_type or '',
            str(log.resource_id) if log.resource_id else '',
            log.severity,
            log.description or '',
            str(log.ip_address) if log.ip_address else '',
            log.user_agent or ''
        ])
    
    # Prepare file
    output.seek(0)
    filename = f"audit_logs_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=filename
    )

@audit_logging_bp.route('/export/error-logs')
@login_required
@admin_required
def export_error_logs():
    """Export error logs to CSV"""
    # Similar logic to export_audit_logs but for ErrorLog
    search = request.args.get('search', '')
    severity = request.args.get('severity', '')
    resolved = request.args.get('resolved', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    query = ErrorLog.query
    if current_user.role != UserRoleType.SUPER_ADMIN:
        query = query.filter_by(tenant_id=current_user.tenant_id)
    
    # Apply filters
    if search:
        query = query.filter(
            or_(
                ErrorLog.error_code.ilike(f'%{search}%'),
                ErrorLog.error_message.ilike(f'%{search}%')
            )
        )
    if severity:
        query = query.filter_by(severity=severity)
    if resolved:
        is_resolved = resolved.lower() == 'true'
        query = query.filter_by(resolved=is_resolved)
    if date_from:
        try:
            from_date = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(ErrorLog.created_at >= from_date)
        except ValueError:
            pass
    if date_to:
        try:
            to_date = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(ErrorLog.created_at < to_date)
        except ValueError:
            pass
    
    error_logs = query.order_by(desc(ErrorLog.created_at)).all()
    
    # Create CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow([
        'ID', 'Date/Time', 'Error Code', 'Error Message', 'Severity',
        'Resolved', 'Resolved By', 'Resolved At'
    ])
    
    for log in error_logs:
        resolved_by = log.resolved_by_user.full_name if log.resolved_by_user else ''
        resolved_at = log.resolved_at.strftime('%Y-%m-%d %H:%M:%S') if log.resolved_at else ''
        
        writer.writerow([
            str(log.id),
            log.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            log.error_code or '',
            log.error_message,
            log.severity,
            'Yes' if log.resolved else 'No',
            resolved_by,
            resolved_at
        ])
    
    output.seek(0)
    filename = f"error_logs_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=filename
    )

# ============================================================================
# API ENDPOINTS
# ============================================================================

@audit_logging_bp.route('/api/stats')
@login_required
@admin_required
def get_stats():
    """Get audit and error statistics for charts"""
    days = request.args.get('days', 7, type=int)
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # Audit logs by day
    audit_stats = db.session.query(
        func.date(AuditLog.created_at).label('date'),
        func.count(AuditLog.id).label('count')
    ).filter(AuditLog.created_at >= start_date)
    
    if current_user.role != UserRoleType.SUPER_ADMIN:
        audit_stats = audit_stats.filter_by(tenant_id=current_user.tenant_id)
    
    audit_stats = audit_stats.group_by(func.date(AuditLog.created_at)).all()
    
    # Error logs by day
    error_stats = db.session.query(
        func.date(ErrorLog.created_at).label('date'),
        func.count(ErrorLog.id).label('count')
    ).filter(ErrorLog.created_at >= start_date)
    
    if current_user.role != UserRoleType.SUPER_ADMIN:
        error_stats = error_stats.filter_by(tenant_id=current_user.tenant_id)
    
    error_stats = error_stats.group_by(func.date(ErrorLog.created_at)).all()
    
    return jsonify({
        'audit_stats': [{'date': str(stat.date), 'count': stat.count} for stat in audit_stats],
        'error_stats': [{'date': str(stat.date), 'count': stat.count} for stat in error_stats]
    })

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def log_audit_event(action, resource_type=None, resource_id=None, 
                   description=None, severity='INFO', old_values=None, 
                   new_values=None, meta_data=None, user_id=None, tenant_id=None):
    """Utility function to create audit log entries"""
    try:
        from flask import request as flask_request
        
        # Get user and tenant info
        if not user_id and hasattr(current_user, 'id'):
            user_id = current_user.id
        if not tenant_id and hasattr(current_user, 'tenant_id'):
            tenant_id = current_user.tenant_id
        
        # Get request info
        ip_address = None
        user_agent = None
        if flask_request:
            ip_address = flask_request.environ.get('REMOTE_ADDR')
            user_agent = flask_request.environ.get('HTTP_USER_AGENT')
        
        audit_log = AuditLog(
            tenant_id=tenant_id,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            description=description,
            severity=severity,
            old_values=old_values or {},
            new_values=new_values or {},
            meta_data=meta_data or {},
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        db.session.add(audit_log)
        db.session.commit()
        
    except Exception as e:
        print(f"Failed to create audit log: {e}")
        db.session.rollback()

def log_error_event(error_message, error_code=None, severity='ERROR', 
                   stack_trace=None, request_data=None, response_data=None,
                   user_id=None, tenant_id=None):
    """Utility function to create error log entries"""
    try:
        # Get user and tenant info
        if not user_id and hasattr(current_user, 'id'):
            user_id = current_user.id
        if not tenant_id and hasattr(current_user, 'tenant_id'):
            tenant_id = current_user.tenant_id
        
        error_log = ErrorLog(
            tenant_id=tenant_id,
            user_id=user_id,
            error_code=error_code,
            error_message=error_message,
            severity=severity,
            stack_trace=stack_trace,
            request_data=request_data or {},
            response_data=response_data or {}
        )
        
        db.session.add(error_log)
        db.session.commit()
        
    except Exception as e:
        print(f"Failed to create error log: {e}")
        db.session.rollback()
