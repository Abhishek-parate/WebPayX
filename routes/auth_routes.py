# routes/auth.py
"""
Authentication and Session Management Routes
===========================================
Handles login, logout, session management, password reset, and security features.
"""

from flask import Blueprint, request, jsonify, session, current_app, render_template
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy import or_, and_
from models import (
    User, UserSession, Tenant, db, UserRoleType, KYCStatus,
    AuditLog, ErrorLog
)
from datetime import datetime, timedelta
import uuid
import secrets
import hashlib
from functools import wraps
import ipaddress

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

# =============================================================================
# SECURITY HELPERS
# =============================================================================

def log_security_event(user_id, action, details, severity='INFO'):
    """Log security-related events"""
    try:
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            resource_type='AUTHENTICATION',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            description=details,
            severity=severity,
            meta_data={'endpoint': request.endpoint}
        )
        db.session.add(audit_log)
        db.session.commit()
    except:
        pass  # Don't fail if logging fails

def is_safe_ip(ip_address):
    """Check if IP address is from safe range"""
    try:
        ip = ipaddress.ip_address(ip_address)
        # Add your safe IP ranges here
        safe_ranges = [
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12')
        ]
        return any(ip in network for network in safe_ranges)
    except:
        return False

def rate_limit_check(identifier, max_attempts=5, window_minutes=15):
    """Simple rate limiting using session/cache"""
    key = f"rate_limit:{identifier}"
    now = datetime.utcnow()
    
    # In production, use Redis for this
    attempts = session.get(key, [])
    
    # Clean old attempts
    attempts = [attempt for attempt in attempts if (now - datetime.fromisoformat(attempt)).total_seconds() < window_minutes * 60]
    
    if len(attempts) >= max_attempts:
        return False
    
    attempts.append(now.isoformat())
    session[key] = attempts
    return True

# =============================================================================
# AUTHENTICATION PAGES
# =============================================================================

@auth_bp.route('/login')
def login_page():
    """Login page"""
    return render_template('auth/login.html', title='Login')

@auth_bp.route('/register')
def register_page():
    """Registration page (for tenant owners)"""
    return render_template('auth/register.html', title='Register')

@auth_bp.route('/forgot-password')
def forgot_password_page():
    """Forgot password page"""
    return render_template('auth/forgot_password.html', title='Forgot Password')

# =============================================================================
# CORE AUTHENTICATION API
# =============================================================================

@auth_bp.route('/api/login', methods=['POST'])
def login():
    """User login with enhanced security"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        tenant_code = data.get('tenant_code', 'DEFAULT').strip().upper()
        remember_me = data.get('remember_me', False)
        
        # Basic validation
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        
        # Rate limiting
        client_id = f"{request.remote_addr}:{username}"
        if not rate_limit_check(client_id):
            log_security_event(None, 'LOGIN_RATE_LIMITED', f'Rate limit exceeded for {username}', 'WARNING')
            return jsonify({'error': 'Too many login attempts. Try again later.'}), 429
        
        # Find tenant
        tenant = Tenant.query.filter_by(
            tenant_code=tenant_code, 
            is_active=True
        ).first()
        
        if not tenant:
            log_security_event(None, 'LOGIN_INVALID_TENANT', f'Invalid tenant: {tenant_code}', 'WARNING')
            return jsonify({'error': 'Invalid tenant code'}), 400
        
        # Check tenant subscription
        if not tenant.is_subscription_active:
            return jsonify({'error': 'Tenant subscription expired'}), 403
        
        # Find user
        user = User.query.filter(
            User.tenant_id == tenant.id,
            or_(
                User.username == username,
                User.email == username,
                User.phone == username
            ),
            User.is_active == True
        ).first()
        
        if not user:
            log_security_event(None, 'LOGIN_USER_NOT_FOUND', f'User not found: {username}', 'WARNING')
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check password
        if not user.check_password(password):
            user.login_attempts += 1
            
            # Lock account after 5 failed attempts
            if user.login_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=30)
                log_security_event(user.id, 'ACCOUNT_LOCKED', 'Account locked due to failed login attempts', 'WARNING')
            
            db.session.commit()
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check if account is locked
        if user.is_locked:
            remaining_time = int((user.locked_until - datetime.utcnow()).total_seconds() / 60)
            log_security_event(user.id, 'LOGIN_ACCOUNT_LOCKED', f'Login attempt on locked account', 'WARNING')
            return jsonify({
                'error': f'Account is locked. Try again in {remaining_time} minutes.'
            }), 423
        
        # Check KYC status for sensitive roles
        if user.role in [UserRoleType.ADMIN, UserRoleType.WHITE_LABEL] and user.kyc_status != KYCStatus.APPROVED:
            return jsonify({'error': 'KYC approval required for this account'}), 403
        
        # Create user session
        session_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(64)
        expires_at = datetime.utcnow() + timedelta(days=7 if remember_me else 1)
        
        user_session = UserSession(
            user_id=user.id,
            session_token=session_token,
            refresh_token=refresh_token,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            device_info={
                'platform': request.headers.get('sec-ch-ua-platform', ''),
                'mobile': request.headers.get('sec-ch-ua-mobile', ''),
                'fingerprint': hashlib.md5(f"{request.headers.get('User-Agent', '')}{request.remote_addr}".encode()).hexdigest()
            },
            expires_at=expires_at
        )
        
        db.session.add(user_session)
        
        # Update user login info
        user.last_login = datetime.utcnow()
        user.login_attempts = 0
        user.locked_until = None
        
        db.session.commit()
        
        # Flask-Login
        login_user(user, remember=remember_me)
        
        # Log successful login
        log_security_event(user.id, 'LOGIN_SUCCESS', f'Successful login from {request.remote_addr}', 'INFO')
        
        return jsonify({
            'message': 'Login successful',
            'user': {
                'id': str(user.id),
                'username': user.username,
                'full_name': user.full_name,
                'email': user.email,
                'role': user.role.value,
                'kyc_status': user.kyc_status.value,
                'tenant_code': tenant.tenant_code,
                'tenant_name': tenant.tenant_name,
                'is_verified': user.is_verified,
                'two_factor_enabled': user.two_factor_enabled
            },
            'session_token': session_token,
            'expires_at': expires_at.isoformat(),
            'permissions': get_user_permissions(user)
        })
        
    except Exception as e:
        db.session.rollback()
        log_security_event(None, 'LOGIN_ERROR', str(e), 'ERROR')
        return jsonify({'error': 'Login failed. Please try again.'}), 500

@auth_bp.route('/api/logout', methods=['POST'])
@login_required
def logout():
    """User logout with session cleanup"""
    try:
        session_token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        # Deactivate current session
        if session_token:
            UserSession.query.filter_by(
                user_id=current_user.id,
                session_token=session_token
            ).update({'is_active': False})
        else:
            # Deactivate all sessions if no specific token
            UserSession.query.filter_by(
                user_id=current_user.id,
                is_active=True
            ).update({'is_active': False})
        
        db.session.commit()
        
        # Log logout
        log_security_event(current_user.id, 'LOGOUT', 'User logged out', 'INFO')
        
        logout_user()
        session.clear()
        
        return jsonify({'message': 'Logout successful'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/api/refresh-token', methods=['POST'])
def refresh_token():
    """Refresh authentication token"""
    try:
        data = request.get_json()
        refresh_token = data.get('refresh_token')
        
        if not refresh_token:
            return jsonify({'error': 'Refresh token required'}), 400
        
        # Find session
        user_session = UserSession.query.filter_by(
            refresh_token=refresh_token,
            is_active=True
        ).first()
        
        if not user_session or user_session.is_expired:
            return jsonify({'error': 'Invalid or expired refresh token'}), 401
        
        # Generate new tokens
        new_session_token = secrets.token_urlsafe(32)
        new_refresh_token = secrets.token_urlsafe(64)
        new_expires_at = datetime.utcnow() + timedelta(days=1)
        
        # Update session
        user_session.session_token = new_session_token
        user_session.refresh_token = new_refresh_token
        user_session.expires_at = new_expires_at
        user_session.last_accessed = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'session_token': new_session_token,
            'refresh_token': new_refresh_token,
            'expires_at': new_expires_at.isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# SESSION MANAGEMENT
# =============================================================================

@auth_bp.route('/api/sessions', methods=['GET'])
@login_required
def get_user_sessions():
    """Get all active sessions for current user"""
    try:
        sessions = UserSession.query.filter_by(
            user_id=current_user.id,
            is_active=True
        ).order_by(UserSession.created_at.desc()).all()
        
        current_session_token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        sessions_data = []
        for session_obj in sessions:
            session_data = {
                'id': str(session_obj.id),
                'ip_address': session_obj.ip_address,
                'user_agent': session_obj.user_agent,
                'device_info': session_obj.device_info,
                'created_at': session_obj.created_at.isoformat(),
                'last_accessed': session_obj.last_accessed.isoformat(),
                'expires_at': session_obj.expires_at.isoformat(),
                'is_current': session_obj.session_token == current_session_token,
                'location': get_location_from_ip(session_obj.ip_address)
            }
            sessions_data.append(session_data)
        
        return jsonify({
            'sessions': sessions_data,
            'total_sessions': len(sessions_data)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/api/sessions/<session_id>', methods=['DELETE'])
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
        
        log_security_event(current_user.id, 'SESSION_TERMINATED', f'Session {session_id} terminated', 'INFO')
        
        return jsonify({'message': 'Session terminated successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/api/sessions/terminate-all', methods=['POST'])
@login_required
def terminate_all_sessions():
    """Terminate all sessions except current"""
    try:
        current_session_token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        # Terminate all sessions except current
        terminated = UserSession.query.filter(
            UserSession.user_id == current_user.id,
            UserSession.session_token != current_session_token,
            UserSession.is_active == True
        ).update({'is_active': False})
        
        db.session.commit()
        
        log_security_event(current_user.id, 'ALL_SESSIONS_TERMINATED', f'Terminated {terminated} sessions', 'INFO')
        
        return jsonify({
            'message': f'Successfully terminated {terminated} sessions',
            'terminated_count': terminated
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# =============================================================================
# PASSWORD MANAGEMENT
# =============================================================================

@auth_bp.route('/api/change-password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    try:
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')
        
        if not all([current_password, new_password, confirm_password]):
            return jsonify({'error': 'All password fields are required'}), 400
        
        if new_password != confirm_password:
            return jsonify({'error': 'New passwords do not match'}), 400
        
        if len(new_password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters long'}), 400
        
        # Verify current password
        if not current_user.check_password(current_password):
            return jsonify({'error': 'Current password is incorrect'}), 401
        
        # Set new password
        current_user.set_password(new_password)
        current_user.updated_at = datetime.utcnow()
        
        # Terminate all other sessions for security
        UserSession.query.filter(
            UserSession.user_id == current_user.id,
            UserSession.session_token != request.headers.get('Authorization', '').replace('Bearer ', ''),
            UserSession.is_active == True
        ).update({'is_active': False})
        
        db.session.commit()
        
        log_security_event(current_user.id, 'PASSWORD_CHANGED', 'Password changed successfully', 'INFO')
        
        return jsonify({'message': 'Password changed successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    """Initiate password reset process"""
    try:
        data = request.get_json()
        identifier = data.get('identifier', '').strip()  # email, phone, or username
        tenant_code = data.get('tenant_code', 'DEFAULT').strip().upper()
        
        if not identifier:
            return jsonify({'error': 'Email, phone, or username is required'}), 400
        
        # Find tenant
        tenant = Tenant.query.filter_by(tenant_code=tenant_code, is_active=True).first()
        if not tenant:
            return jsonify({'error': 'Invalid tenant code'}), 400
        
        # Find user
        user = User.query.filter(
            User.tenant_id == tenant.id,
            or_(
                User.email == identifier,
                User.phone == identifier,
                User.username == identifier
            ),
            User.is_active == True
        ).first()
        
        # Always return success for security (don't reveal if user exists)
        if user:
            # Generate reset token (implement token storage and email sending)
            reset_token = secrets.token_urlsafe(32)
            # Store token in cache/database with expiration
            # Send email/SMS with reset link
            
            log_security_event(user.id, 'PASSWORD_RESET_REQUESTED', 'Password reset requested', 'INFO')
        
        return jsonify({
            'message': 'If the account exists, a password reset link has been sent.'
        })
        
    except Exception as e:
        return jsonify({'error': 'Failed to process request'}), 500

# =============================================================================
# PROFILE MANAGEMENT
# =============================================================================

@auth_bp.route('/api/profile', methods=['GET'])
@login_required
def get_profile():
    """Get current user profile"""
    try:
        user_data = current_user.to_dict()
        
        # Add wallet information
        if current_user.wallet:
            user_data['wallet'] = {
                'balance': float(current_user.wallet.balance),
                'hold_balance': float(current_user.wallet.hold_balance),
                'available_balance': float(current_user.wallet.available_balance)
            }
        
        # Add tenant information
        if current_user.tenant:
            user_data['tenant'] = {
                'name': current_user.tenant.tenant_name,
                'code': current_user.tenant.tenant_code,
                'domain': current_user.tenant.domain
            }
        
        return jsonify({'profile': user_data})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/api/profile', methods=['PUT'])
@login_required
def update_profile():
    """Update current user profile"""
    try:
        data = request.get_json()
        
        # Allowed fields for self-update
        allowed_fields = ['full_name', 'business_name', 'address', 'settings']
        
        for field in allowed_fields:
            if field in data:
                setattr(current_user, field, data[field])
        
        current_user.updated_at = datetime.utcnow()
        db.session.commit()
        
        log_security_event(current_user.id, 'PROFILE_UPDATED', 'Profile updated', 'INFO')
        
        return jsonify({
            'message': 'Profile updated successfully',
            'profile': current_user.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_user_permissions(user):
    """Get user permissions based on role"""
    # This would integrate with your permission system
    role_permissions = {
        UserRoleType.SUPER_ADMIN: ['*'],  # All permissions
        UserRoleType.ADMIN: [
            'user.create', 'user.read', 'user.update', 'user.delete',
            'transaction.read', 'wallet.manage', 'report.view'
        ],
        UserRoleType.WHITE_LABEL: [
            'user.create', 'user.read', 'user.update',
            'transaction.read', 'wallet.manage', 'report.view'
        ],
        UserRoleType.MASTER_DISTRIBUTOR: [
            'user.create', 'user.read', 'transaction.process', 'wallet.read'
        ],
        UserRoleType.DISTRIBUTOR: [
            'user.create', 'user.read', 'transaction.process', 'wallet.read'
        ],
        UserRoleType.RETAILER: [
            'transaction.process', 'wallet.read', 'profile.update'
        ]
    }
    
    return role_permissions.get(user.role, [])

def get_location_from_ip(ip_address):
    """Get approximate location from IP address"""
    # Implement IP geolocation service integration
    return {'city': 'Unknown', 'country': 'Unknown'}

# =============================================================================
# HEALTH CHECK
# =============================================================================

@auth_bp.route('/api/health', methods=['GET'])
def health_check():
    """Authentication service health check"""
    try:
        # Test database connection
        db.session.execute('SELECT 1')
        
        return jsonify({
            'status': 'healthy',
            'service': 'authentication',
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 503