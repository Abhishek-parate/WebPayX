from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from models import AuditLog, db
from datetime import datetime

audit_bp = Blueprint('audit', __name__)

# ============================================
# Fetch Audit Logs
# ============================================

@audit_bp.route('/audit-logs', methods=['GET'])
@login_required
def get_audit_logs():
    """Retrieve audit logs with filters"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        user_id = request.args.get('user_id')

        query = AuditLog.query

        if start_date:
            query = query.filter(AuditLog.timestamp >= start_date)
        if end_date:
            query = query.filter(AuditLog.timestamp <= end_date)
        if user_id:
            query = query.filter(AuditLog.user_id == user_id)

        logs = query.order_by(AuditLog.timestamp.desc()).paginate(page, per_page, error_out=False)

        return jsonify({
            'logs': [log.to_dict() for log in logs.items],
            'pagination': {'page': page, 'per_page': per_page, 'total': logs.total}
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Insert methods to log actions
def log_action(user_id, action, description=''):
    """Helper to log audit actions"""
    log = AuditLog(user_id=user_id, action=action, description=description, timestamp=datetime.utcnow())
    db.session.add(log)
    db.session.commit()