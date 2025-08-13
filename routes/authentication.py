# routes/authentication.py
from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for, session
from flask_login import login_user, logout_user, login_required, current_user
from models import User, UserSession, Tenant, UserRoleType, KYCStatus, Wallet, db
from datetime import datetime, timedelta
from functools import wraps
import uuid
import secrets

authentication_bp = Blueprint('authentication', __name__, template_folder='templates', static_folder='static')

# =============================================================================
# AUTHENTICATION PAGES
# =============================================================================

@authentication_bp.route('/login', methods=['GET', 'POST'])
def login_page():
    """Login page with both GET and POST handling"""
    if request.method == 'GET':
        # Show login form
        if current_user.is_authenticated:
            return redirect(url_for('dashboard.index'))
        
        return render_template('authentication/signin.html',
            title='Sign In',
            subtitle='Sign In to your Account'
        )
    
    elif request.method == 'POST':
        # Handle login submission - both form data and JSON
        try:
            # Handle both JSON and form data
            if request.is_json:
                # For AJAX/API requests sending JSON
                data = request.get_json()
                username = data.get('username', '').strip()
                password = data.get('password', '')
                tenant_code = data.get('tenant_code', 'DEFAULT').strip().upper()
                remember_me = data.get('remember', False)
            else:
                # For HTML form submissions
                username = request.form.get('username', '').strip()
                password = request.form.get('password', '')
                tenant_code = request.form.get('tenant_code', 'DEFAULT').strip().upper()
                remember_me = request.form.get('remember_me') == '1'
            
            # Validate required fields
            if not username or not password:
                error_msg = 'Username and password are required'
                if request.is_json:
                    return jsonify({'error': error_msg}), 400
                else:
                    flash(error_msg, 'error')
                    return render_template('authentication/signin.html')
            
            # Find tenant
            tenant = Tenant.query.filter_by(tenant_code=tenant_code, is_active=True).first()
            if not tenant:
                error_msg = 'Invalid tenant or tenant not active'
                if request.is_json:
                    return jsonify({'error': error_msg}), 400
                else:
                    flash(error_msg, 'error')
                    return render_template('authentication/signin.html')
            
            # Check tenant subscription
            if not tenant.is_subscription_active:
                error_msg = 'Tenant subscription has expired'
                if request.is_json:
                    return jsonify({'error': error_msg}), 400
                else:
                    flash(error_msg, 'error')
                    return render_template('authentication/signin.html')
            
            # Find user by username, email, or phone within the tenant
            user = User.query.filter(
                User.tenant_id == tenant.id,
                db.or_(
                    User.username == username,
                    User.email == username,
                    User.phone == username
                ),
                User.is_active == True
            ).first()
            
            if not user:
                error_msg = 'Invalid credentials'
                if request.is_json:
                    return jsonify({'error': error_msg}), 401
                else:
                    flash(error_msg, 'error')
                    return render_template('authentication/signin.html')
            
            # Check if account is locked
            if user.is_locked:
                error_msg = f'Account is locked until {user.locked_until}'
                if request.is_json:
                    return jsonify({'error': error_msg}), 401
                else:
                    flash(error_msg, 'error')
                    return render_template('authentication/signin.html')
            
            # Verify password
            if not user.check_password(password):
                # Increment login attempts
                user.login_attempts += 1
                
                # Lock account after 5 failed attempts
                if user.login_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=30)
                    db.session.commit()
                    error_msg = 'Account locked due to multiple failed attempts'
                    if request.is_json:
                        return jsonify({'error': error_msg}), 401
                    else:
                        flash(error_msg, 'error')
                        return render_template('authentication/signin.html')
                
                db.session.commit()
                error_msg = 'Invalid credentials'
                if request.is_json:
                    return jsonify({'error': error_msg}), 401
                else:
                    flash(error_msg, 'error')
                    return render_template('authentication/signin.html')
            
            # Reset login attempts on successful login
            user.login_attempts = 0
            user.locked_until = None
            user.last_login = datetime.utcnow()
            
            # Create user session
            session_token = secrets.token_urlsafe(32)
            refresh_token = secrets.token_urlsafe(64)
            
            user_session = UserSession(
                user_id=user.id,
                session_token=session_token,
                refresh_token=refresh_token,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', ''),
                device_info={
                    'accept_language': request.headers.get('Accept-Language', ''),
                    'platform': request.headers.get('Sec-Ch-Ua-Platform', '')
                },
                expires_at=datetime.utcnow() + timedelta(days=30 if remember_me else 1),
                is_active=True,
                last_accessed=datetime.utcnow()
            )
            
            db.session.add(user_session)
            db.session.commit()
            
            # Login user using Flask-Login
            login_user(user, remember=remember_me)
            
            # Store session token in session
            session['session_token'] = session_token
            session['tenant_id'] = str(tenant.id)
            
            # Success response
            if request.is_json:
                return jsonify({
                    'message': 'Login successful',
                    'success': True,
                    'redirect_url': url_for('dashboard.index'),
                    'user': {
                        'id': str(user.id),
                        'username': user.username,
                        'full_name': user.full_name,
                        'email': user.email,
                        'role': user.role.value,
                        'user_code': user.user_code,
                        'is_verified': user.is_verified,
                        'kyc_status': user.kyc_status.value
                    },
                    'tenant': {
                        'id': str(tenant.id),
                        'name': tenant.tenant_name,
                        'code': tenant.tenant_code
                    },
                    'session_token': session_token,
                    'expires_at': user_session.expires_at.isoformat()
                })
            else:
                flash('Login successful! Welcome back.', 'success')
                # Check for next parameter
                next_page = request.args.get('next')
                if next_page and next_page.startswith('/'):
                    return redirect(next_page)
                return redirect(url_for('dashboard.index'))
                
        except Exception as e:
            db.session.rollback()
            error_msg = f'Login failed: {str(e)}'
            if request.is_json:
                return jsonify({'error': error_msg}), 500
            else:
                flash(error_msg, 'error')
                return render_template('authentication/signin.html')

@authentication_bp.route('/signup')
def signup_page():
    """Signup page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    
    return render_template('authentication/signup.html',
        title='Sign Up',
        subtitle='Create New Account'
    )

@authentication_bp.route('/forgot-password')
def forgot_password_page():
    """Forgot password page"""
    return render_template('authentication/forgot_password.html',
        title='Forgot Password',
        subtitle='Reset Your Password'
    )

@authentication_bp.route('/reset-password/<token>')
def reset_password_page(token):
    """Reset password page"""
    return render_template('authentication/reset_password.html',
        title='Reset Password',
        subtitle='Set New Password',
        token=token
    )

# =============================================================================
# LOGOUT HANDLING
# =============================================================================

@authentication_bp.route('/logout', methods=['GET', 'POST'])
@login_required
def logout_page():
    """User logout with both GET and POST support"""
    try:
        # Get current session token
        session_token = session.get('session_token')
        
        if session_token:
            # Deactivate user session
            user_session = UserSession.query.filter_by(
                session_token=session_token,
                user_id=current_user.id,
                is_active=True
            ).first()
            
            if user_session:
                user_session.is_active = False
                db.session.commit()
        
        # Logout user using Flask-Login
        logout_user()
        
        # Clear session data
        session.clear()
        
        if request.is_json:
            return jsonify({'message': 'Logout successful'})
        else:
            flash('You have been logged out successfully.', 'info')
            return redirect(url_for('authentication.login_page'))
        
    except Exception as e:
        if request.is_json:
            return jsonify({'error': str(e)}), 500
        else:
            flash('Error during logout. Please try again.', 'error')
            return redirect(url_for('dashboard.index'))

# =============================================================================
# API ENDPOINTS (Legacy support)
# =============================================================================

@authentication_bp.route('/api/login', methods=['POST'])
def api_login():
    """API-only login endpoint for backwards compatibility"""
    try:
        data = request.get_json()
        
        # Extract login credentials
        username = data.get('username', '').strip()
        password = data.get('password', '')
        tenant_code = data.get('tenant_code', 'DEFAULT').strip().upper()
        remember_me = data.get('remember', False)
        
        # Validate required fields
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        
        # Find tenant
        tenant = Tenant.query.filter_by(tenant_code=tenant_code, is_active=True).first()
        if not tenant:
            return jsonify({'error': 'Invalid tenant or tenant not active'}), 400
        
        # Check tenant subscription
        if not tenant.is_subscription_active:
            return jsonify({'error': 'Tenant subscription has expired'}), 400
        
        # Find user by username, email, or phone within the tenant
        user = User.query.filter(
            User.tenant_id == tenant.id,
            db.or_(
                User.username == username,
                User.email == username,
                User.phone == username
            ),
            User.is_active == True
        ).first()
        
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check if account is locked
        if user.is_locked:
            return jsonify({'error': f'Account is locked until {user.locked_until}'}), 401
        
        # Verify password
        if not user.check_password(password):
            # Increment login attempts
            user.login_attempts += 1
            
            # Lock account after 5 failed attempts
            if user.login_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=30)
                db.session.commit()
                return jsonify({'error': 'Account locked due to multiple failed attempts'}), 401
            
            db.session.commit()
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Reset login attempts on successful login
        user.login_attempts = 0
        user.locked_until = None
        user.last_login = datetime.utcnow()
        
        # Create user session
        session_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(64)
        
        user_session = UserSession(
            user_id=user.id,
            session_token=session_token,
            refresh_token=refresh_token,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            device_info={
                'accept_language': request.headers.get('Accept-Language', ''),
                'platform': request.headers.get('Sec-Ch-Ua-Platform', '')
            },
            expires_at=datetime.utcnow() + timedelta(days=30 if remember_me else 1),
            is_active=True,
            last_accessed=datetime.utcnow()
        )
        
        db.session.add(user_session)
        db.session.commit()
        
        # Login user using Flask-Login
        login_user(user, remember=remember_me)
        
        # Store session token in session
        session['session_token'] = session_token
        session['tenant_id'] = str(tenant.id)
        
        return jsonify({
            'message': 'Login successful',
            'user': {
                'id': str(user.id),
                'username': user.username,
                'full_name': user.full_name,
                'email': user.email,
                'role': user.role.value,
                'user_code': user.user_code,
                'is_verified': user.is_verified,
                'kyc_status': user.kyc_status.value
            },
            'tenant': {
                'id': str(tenant.id),
                'name': tenant.tenant_name,
                'code': tenant.tenant_code
            },
            'session_token': session_token,
            'expires_at': user_session.expires_at.isoformat()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@authentication_bp.route('/register', methods=['POST'])
def register():
    """User registration endpoint (for retailers/end users)"""
    try:
        data = request.get_json()
        
        # Extract registration data
        required_fields = ['username', 'email', 'phone', 'password', 'full_name', 'parent_code']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        parent_code = data.get('parent_code', '').strip()
        tenant_code = data.get('tenant_code', 'DEFAULT').strip().upper()
        
        # Find tenant
        tenant = Tenant.query.filter_by(tenant_code=tenant_code, is_active=True).first()
        if not tenant:
            return jsonify({'error': 'Invalid tenant'}), 400
        
        # Find parent user
        parent_user = User.query.filter(
            User.user_code == parent_code,
            User.tenant_id == tenant.id,
            User.is_active == True
        ).first()
        
        if not parent_user:
            return jsonify({'error': 'Invalid parent code'}), 400
        
        # Check if parent can create users
        allowed_roles = []
        if parent_user.role == UserRoleType.MASTER_DISTRIBUTOR:
            allowed_roles = [UserRoleType.DISTRIBUTOR, UserRoleType.RETAILER]
        elif parent_user.role == UserRoleType.DISTRIBUTOR:
            allowed_roles = [UserRoleType.RETAILER]
        
        if not allowed_roles:
            return jsonify({'error': 'Parent user cannot create new accounts'}), 403
        
        # Default role for registration (retailer)
        user_role = UserRoleType.RETAILER
        if user_role not in allowed_roles:
            return jsonify({'error': 'Cannot register with this role under specified parent'}), 403
        
        # Check for duplicate credentials
        existing_user = User.query.filter(
            User.tenant_id == tenant.id,
            db.or_(
                User.username == data['username'],
                User.email == data['email'],
                User.phone == data['phone']
            )
        ).first()
        
        if existing_user:
            return jsonify({'error': 'User with these credentials already exists'}), 409
        
        # Generate user code
        from routes.user_management import generate_user_code
        user_code = generate_user_code(user_role)
        
        # Create user
        user = User(
            tenant_id=tenant.id,
            parent_id=parent_user.id,
            user_code=user_code,
            username=data['username'],
            email=data['email'],
            phone=data['phone'],
            role=user_role,
            full_name=data['full_name'],
            business_name=data.get('business_name'),
            address=data.get('address', {}),
            kyc_status=KYCStatus.NOT_SUBMITTED,
            is_active=True,
            tree_path=f"{parent_user.tree_path}.{user_code}" if parent_user.tree_path else user_code,
            level=parent_user.level + 1,
            settings=data.get('settings', {}),
            created_by=parent_user.id
        )
        
        user.set_password(data['password'])
        user.generate_api_key()
        
        db.session.add(user)
        db.session.flush()
        
        # Create wallet for user
        wallet = Wallet(
            user_id=user.id,
            balance=0,
            daily_limit=data.get('daily_limit', 50000),
            monthly_limit=data.get('monthly_limit', 200000)
        )
        
        db.session.add(wallet)
        db.session.commit()
        
        return jsonify({
            'message': 'Registration successful',
            'user_code': user_code,
            'user': {
                'id': str(user.id),
                'username': user.username,
                'full_name': user.full_name,
                'role': user.role.value,
                'user_code': user.user_code
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@authentication_bp.route('/refresh-token', methods=['POST'])
def refresh_token():
    """Refresh authentication token"""
    try:
        data = request.get_json()
        refresh_token = data.get('refresh_token')
        
        if not refresh_token:
            return jsonify({'error': 'Refresh token is required'}), 400
        
        # Find active session with refresh token
        user_session = UserSession.query.filter_by(
            refresh_token=refresh_token,
            is_active=True
        ).first()
        
        if not user_session or user_session.is_expired:
            return jsonify({'error': 'Invalid or expired refresh token'}), 401
        
        # Generate new session token
        new_session_token = secrets.token_urlsafe(32)
        user_session.session_token = new_session_token
        user_session.last_accessed = datetime.utcnow()
        user_session.expires_at = datetime.utcnow() + timedelta(days=1)
        
        db.session.commit()
        
        return jsonify({
            'message': 'Token refreshed successfully',
            'session_token': new_session_token,
            'expires_at': user_session.expires_at.isoformat()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@authentication_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    """Send password reset link"""
    try:
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()
            
        email_or_phone = data.get('email_or_phone', '').strip()
        tenant_code = data.get('tenant_code', 'DEFAULT').strip().upper()
        
        if not email_or_phone:
            error_msg = 'Email or phone is required'
            if request.is_json:
                return jsonify({'error': error_msg}), 400
            else:
                flash(error_msg, 'error')
                return redirect(url_for('authentication.forgot_password_page'))
        
        # Find tenant
        tenant = Tenant.query.filter_by(tenant_code=tenant_code, is_active=True).first()
        if not tenant:
            error_msg = 'Invalid tenant'
            if request.is_json:
                return jsonify({'error': error_msg}), 400
            else:
                flash(error_msg, 'error')
                return redirect(url_for('authentication.forgot_password_page'))
        
        # Find user
        user = User.query.filter(
            User.tenant_id == tenant.id,
            db.or_(
                User.email == email_or_phone,
                User.phone == email_or_phone
            ),
            User.is_active == True
        ).first()
        
        success_msg = 'If account exists, reset instructions will be sent'
        
        if user:
            # Generate reset token (in real implementation, store this in database)
            reset_token = secrets.token_urlsafe(32)
            # TODO: Send email/SMS with reset link
            # For now, just return success
        
        if request.is_json:
            return jsonify({'message': success_msg})
        else:
            flash(success_msg, 'info')
            return redirect(url_for('authentication.login_page'))
        
    except Exception as e:
        error_msg = f'Error processing request: {str(e)}'
        if request.is_json:
            return jsonify({'error': error_msg}), 500
        else:
            flash(error_msg, 'error')
            return redirect(url_for('authentication.forgot_password_page'))

@authentication_bp.route('/reset-password', methods=['POST'])
def reset_password():
    """Reset password with token"""
    try:
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()
            
        reset_token = data.get('reset_token')
        new_password = data.get('new_password')
        
        if not reset_token or not new_password:
            error_msg = 'Reset token and new password are required'
            if request.is_json:
                return jsonify({'error': error_msg}), 400
            else:
                flash(error_msg, 'error')
                return redirect(url_for('authentication.reset_password_page', token=reset_token or ''))
        
        if len(new_password) < 6:
            error_msg = 'Password must be at least 6 characters long'
            if request.is_json:
                return jsonify({'error': error_msg}), 400
            else:
                flash(error_msg, 'error')
                return redirect(url_for('authentication.reset_password_page', token=reset_token))
        
        # TODO: Verify reset token from database and update user password
        # For now, just return success
        success_msg = 'Password reset successful'
        
        if request.is_json:
            return jsonify({'message': success_msg})
        else:
            flash(success_msg, 'success')
            return redirect(url_for('authentication.login_page'))
        
    except Exception as e:
        error_msg = f'Error resetting password: {str(e)}'
        if request.is_json:
            return jsonify({'error': error_msg}), 500
        else:
            flash(error_msg, 'error')
            return redirect(url_for('authentication.reset_password_page', token=reset_token or ''))

@authentication_bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    try:
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()
            
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            error_msg = 'Current and new passwords are required'
            if request.is_json:
                return jsonify({'error': error_msg}), 400
            else:
                flash(error_msg, 'error')
                return redirect(url_for('profilesetting.profile_settings'))
        
        if len(new_password) < 6:
            error_msg = 'New password must be at least 6 characters long'
            if request.is_json:
                return jsonify({'error': error_msg}), 400
            else:
                flash(error_msg, 'error')
                return redirect(url_for('profilesetting.profile_settings'))
        
        # Verify current password
        if not current_user.check_password(current_password):
            error_msg = 'Current password is incorrect'
            if request.is_json:
                return jsonify({'error': error_msg}), 400
            else:
                flash(error_msg, 'error')
                return redirect(url_for('profilesetting.profile_settings'))
        
        # Update password
        current_user.set_password(new_password)
        current_user.updated_at = datetime.utcnow()
        
        # Invalidate all other sessions
        UserSession.query.filter(
            UserSession.user_id == current_user.id,
            UserSession.session_token != session.get('session_token')
        ).update({'is_active': False})
        
        db.session.commit()
        
        success_msg = 'Password changed successfully'
        if request.is_json:
            return jsonify({'message': success_msg})
        else:
            flash(success_msg, 'success')
            return redirect(url_for('profilesetting.profile_settings'))
        
    except Exception as e:
        db.session.rollback()
        error_msg = f'Error changing password: {str(e)}'
        if request.is_json:
            return jsonify({'error': error_msg}), 500
        else:
            flash(error_msg, 'error')
            return redirect(url_for('profilesetting.profile_settings'))

@authentication_bp.route('/verify-session', methods=['GET'])
@login_required
def verify_session():
    """Verify current session"""
    try:
        session_token = session.get('session_token')
        
        if not session_token:
            return jsonify({'error': 'No active session'}), 401
        
        # Check if session is still active
        user_session = UserSession.query.filter_by(
            session_token=session_token,
            user_id=current_user.id,
            is_active=True
        ).first()
        
        if not user_session or user_session.is_expired:
            return jsonify({'error': 'Session expired'}), 401
        
        # Update last accessed time
        user_session.last_accessed = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'message': 'Session valid',
            'user': {
                'id': str(current_user.id),
                'username': current_user.username,
                'full_name': current_user.full_name,
                'role': current_user.role.value,
                'user_code': current_user.user_code
            },
            'session_expires_at': user_session.expires_at.isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# SESSION MANAGEMENT
# =============================================================================

@authentication_bp.route('/sessions', methods=['GET'])
@login_required
def get_user_sessions():
    """Get user's active sessions"""
    try:
        sessions = UserSession.query.filter_by(
            user_id=current_user.id,
            is_active=True
        ).order_by(UserSession.last_accessed.desc()).all()
        
        sessions_data = []
        current_session_token = session.get('session_token')
        
        for user_session in sessions:
            session_data = {
                'id': str(user_session.id),
                'ip_address': user_session.ip_address,
                'user_agent': user_session.user_agent,
                'device_info': user_session.device_info,
                'created_at': user_session.created_at.isoformat(),
                'last_accessed': user_session.last_accessed.isoformat(),
                'expires_at': user_session.expires_at.isoformat(),
                'is_current': user_session.session_token == current_session_token
            }
            sessions_data.append(session_data)
        
        return jsonify({
            'sessions': sessions_data,
            'total': len(sessions_data)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@authentication_bp.route('/sessions/<session_id>', methods=['DELETE'])
@login_required
def terminate_session(session_id):
    """Terminate a specific session"""
    try:
        user_session = UserSession.query.filter_by(
            id=session_id,
            user_id=current_user.id,
            is_active=True
        ).first()
        
        if not user_session:
            return jsonify({'error': 'Session not found'}), 404
        
        # Don't allow terminating current session
        current_session_token = session.get('session_token')
        if user_session.session_token == current_session_token:
            return jsonify({'error': 'Cannot terminate current session'}), 400
        
        user_session.is_active = False
        db.session.commit()
        
        return jsonify({'message': 'Session terminated successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@authentication_bp.route('/sessions/terminate-all', methods=['POST'])
@login_required
def terminate_all_sessions():
    """Terminate all sessions except current"""
    try:
        current_session_token = session.get('session_token')
        
        # Terminate all other sessions
        terminated_count = UserSession.query.filter(
            UserSession.user_id == current_user.id,
            UserSession.session_token != current_session_token,
            UserSession.is_active == True
        ).update({'is_active': False})
        
        db.session.commit()
        
        return jsonify({
            'message': f'Terminated {terminated_count} sessions',
            'terminated_count': terminated_count
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def is_strong_password(password):
    """Check if password meets security requirements"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    
    return True, "Password is strong"

def generate_secure_token():
    """Generate a secure random token"""
    return secrets.token_urlsafe(32)

# =============================================================================
# ROLE VERIFICATION DECORATORS
# =============================================================================

def require_role(*allowed_roles):
    """Decorator to require specific user roles"""
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                if request.is_json:
                    return jsonify({'error': 'Authentication required'}), 401
                else:
                    return redirect(url_for('authentication.login_page'))
            
            if current_user.role not in allowed_roles:
                if request.is_json:
                    return jsonify({'error': 'Insufficient permissions'}), 403
                else:
                    flash('Insufficient permissions', 'error')
                    return redirect(url_for('dashboard.index'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_admin(f):
    """Decorator to require admin role"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role.value not in ['SUPER_ADMIN', 'ADMIN', 'WHITE_LABEL']:
            if request.is_json:
                return jsonify({'error': 'Admin access required'}), 403
            else:
                flash('Admin access required', 'error')
                return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    return decorated_function

# =============================================================================
# ERROR HANDLERS
# =============================================================================

@authentication_bp.errorhandler(415)
def unsupported_media_type(error):
    """Handle 415 Unsupported Media Type errors"""
    if request.is_json:
        return jsonify({
            'error': 'Unsupported Media Type',
            'message': 'Expected application/json Content-Type'
        }), 415
    else:
        flash('Unsupported request format', 'error')
        return redirect(url_for('authentication.login_page'))

@authentication_bp.errorhandler(400)
def bad_request(error):
    """Handle 400 Bad Request errors"""
    if request.is_json:
        return jsonify({
            'error': 'Bad Request',
            'message': 'Invalid request data'
        }), 400
    else:
        flash('Invalid request data', 'error')
        return redirect(url_for('authentication.login_page'))
