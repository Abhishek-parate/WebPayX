from flask import Blueprint, request, jsonify, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy import or_
from models import User, UserSession, Tenant, db
from datetime import datetime, timedelta
import uuid

auth_bp = Blueprint('auth', __name__)

# =============================================================================
# AUTHENTICATION CRUD OPERATIONS
# =============================================================================

@auth_bp.route('/login', methods=['POST'])
def login():
    """User login with session management"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        tenant_code = data.get('tenant_code', 'DEFAULT')
        
        # Find tenant
        tenant = Tenant.query.filter_by(tenant_code=tenant_code, is_active=True).first()
        if not tenant:
            return jsonify({'error': 'Invalid tenant'}), 400
        
        # Find user
        user = User.query.filter(
            User.tenant_id == tenant.id,
            or_(User.username == username, User.email == username, User.phone == username),
            User.is_active == True
        ).first()
        
        if not user or not user.check_password(password):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check if account is locked
        if user.is_locked:
            return jsonify({'error': 'Account is locked'}), 423
        
        # Create user session
        session_token = str(uuid.uuid4())
        user_session = UserSession(
            user_id=user.id,
            session_token=session_token,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )
        
        db.session.add(user_session)
        user.last_login = datetime.utcnow()
        user.login_attempts = 0
        db.session.commit()
        
        login_user(user)
        
        return jsonify({
            'message': 'Login successful',
            'user': {
                'id': str(user.id),
                'username': user.username,
                'full_name': user.full_name,
                'role': user.role.value,
                'tenant_code': tenant.tenant_code
            },
            'session_token': session_token
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """User logout and session cleanup"""
    try:
        # Deactivate current session
        if hasattr(current_user, 'id'):
            UserSession.query.filter_by(
                user_id=current_user.id,
                is_active=True
            ).update({'is_active': False})
            db.session.commit()
        
        logout_user()
        return jsonify({'message': 'Logout successful'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/sessions', methods=['GET'])
@login_required
def get_user_sessions():
    """Get all active sessions for current user"""
    try:
        sessions = UserSession.query.filter_by(
            user_id=current_user.id,
            is_active=True
        ).order_by(UserSession.created_at.desc()).all()
        
        return jsonify({
            'sessions': [{
                'id': str(session.id),
                'ip_address': session.ip_address,
                'user_agent': session.user_agent,
                'created_at': session.created_at.isoformat(),
                'last_accessed': session.last_accessed.isoformat(),
                'expires_at': session.expires_at.isoformat()
            } for session in sessions]
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/sessions/<session_id>', methods=['DELETE'])
@login_required
def terminate_session(session_id):
    """Terminate a specific session"""
    try:
        session_obj = UserSession.query.filter_by(
            id=session_id,
            user_id=current_user.id
        ).first()
        
        if not session_obj:
            return jsonify({'error': 'Session not found'}), 404
        
        session_obj.is_active = False
        db.session.commit()
        
        return jsonify({'message': 'Session terminated successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
