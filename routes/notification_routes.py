from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from models import Notification, db

notification_bp = Blueprint('notifications', __name__)

# ============================================
# Notification CRUD
# ============================================

@notification_bp.route('/notifications', methods=['POST'])
@login_required
def create_notification():
    """Create notification"""
    data = request.get_json()
    title = data.get('title')
    message = data.get('message')
    recipient_id = data.get('recipient_id')

    notification = Notification(
        title=title,
        message=message,
        recipient_id=recipient_id,
        created_at=datetime.utcnow(),
        status='PENDING'
    )
    db.session.add(notification)
    db.session.commit()
    return jsonify({'message': 'Notification created', 'notification': notification.to_dict()})

@notification_bp.route('/notifications', methods=['GET'])
@login_required
def list_notifications():
    """List notifications for current user"""
    notifications = Notification.query.filter_by(recipient_id=current_user.id).order_by(Notification.created_at.desc()).all()
    return jsonify({'notifications': [n.to_dict() for n in notifications]})

@notification_bp.route('/notifications/<int:notification_id>', methods=['PUT'])
@login_required
def update_notification(notification_id):
    """Update notification status"""
    notification = Notification.query.get_or_404(notification_id)
    data = request.get_json()
    notification.status = data.get('status', notification.status)
    db.session.commit()
    return jsonify({'message': 'Notification updated', 'notification': notification.to_dict()})

@notification_bp.route('/notifications/<int:notification_id>', methods=['DELETE'])
@login_required
def delete_notification(notification_id):
    """Delete notification"""
    notification = Notification.query.get_or_404(notification_id)
    db.session.delete(notification)
    db.session.commit()
    return jsonify({'message': 'Notification deleted'})