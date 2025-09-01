# routes/authentication.py
from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for, session
from flask_login import login_user, logout_user, login_required, current_user
from models import User, UserSession, Tenant, UserRoleType, KYCStatus, Wallet, OTPVerification, OTPType, OTPStatus, db
from utils.otp_service import otp_service
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
    """Login page with OTP verification"""
    if request.method == 'GET':
        if current_user.is_authenticated:
            return redirect(url_for('dashboard.index'))
        
        return render_template('authentication/signin.html',
            title='Sign In',
            subtitle='Sign In to your Account'
        )
    
    elif request.method == 'POST':
        try:
            # Handle both JSON and form data
            if request.is_json:
                data = request.get_json()
                username = data.get('username', '').strip()
                password = data.get('password', '')
                tenant_code = data.get('tenant_code', 'DEFAULT').strip().upper()
                remember_me = data.get('remember', False)
                otp_code = data.get('otp_code', '').strip()
                step = data.get('step', 'credentials')  # 'credentials' or 'otp'
            else:
                username = request.form.get('username', '').strip()
                password = request.form.get('password', '')
                tenant_code = request.form.get('tenant_code', 'DEFAULT').strip().upper()
                remember_me = request.form.get('remember_me') == '1'
                otp_code = request.form.get('otp_code', '').strip()
                step = request.form.get('step', 'credentials')
            
            # Step 1: Validate credentials and send OTP
            if step == 'credentials':
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
                
                # Find user
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
                    user.login_attempts += 1
                    
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
                
                # Credentials are valid, send OTP
                otp_result = otp_service.send_login_otp(
                    user_id=str(user.id),
                    phone_number=user.phone,
                    user_name=user.full_name,
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent', '')
                )
                
                if otp_result['success']:
                    # Store user info in session temporarily
                    session['login_user_id'] = str(user.id)
                    session['login_tenant_id'] = str(tenant.id)
                    session['login_remember'] = remember_me
                    
                    if request.is_json:
                        return jsonify({
                            'step': 'otp_verification',
                            'message': 'OTP sent to your registered mobile number',
                            'phone_masked': f"****{user.phone[-4:]}",
                            'expires_in_minutes': 5
                        })
                    else:
                        flash('OTP sent to your registered mobile number', 'info')
                        return render_template('authentication/otp_verification.html',
                            phone_masked=f"****{user.phone[-4:]}",
                            step='login_otp'
                        )
                else:
                    error_msg = 'Failed to send OTP. Please try again.'
                    if request.is_json:
                        return jsonify({'error': error_msg}), 500
                    else:
                        flash(error_msg, 'error')
                        return render_template('authentication/signin.html')
            
            # Step 2: Verify OTP and complete login
            elif step == 'otp':
                if not otp_code:
                    error_msg = 'OTP is required'
                    if request.is_json:
                        return jsonify({'error': error_msg}), 400
                    else:
                        flash(error_msg, 'error')
                        return render_template('authentication/otp_verification.html')
                
                # Get user info from session
                user_id = session.get('login_user_id')
                tenant_id = session.get('login_tenant_id')
                remember_me = session.get('login_remember', False)
                
                if not user_id or not tenant_id:
                    error_msg = 'Session expired. Please login again.'
                    if request.is_json:
                        return jsonify({'error': error_msg}), 400
                    else:
                        flash(error_msg, 'error')
                        return redirect(url_for('authentication.login_page'))
                
                # Get user and tenant
                user = db.session.get(User, user_id)
                tenant = db.session.get(Tenant, tenant_id)
                
                if not user or not tenant:
                    error_msg = 'Invalid session. Please login again.'
                    if request.is_json:
                        return jsonify({'error': error_msg}), 400
                    else:
                        flash(error_msg, 'error')
                        return redirect(url_for('authentication.login_page'))
                
                # Verify OTP
                otp_result = otp_service.verify_otp(
                    phone_number=user.phone,
                    otp_code=otp_code,
                    otp_type=OTPType.LOGIN,
                    user_id=str(user.id)
                )
                
                if otp_result['success']:
                    # OTP verified, complete login
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
                    
                    # Update session
                    session['session_token'] = session_token
                    session['tenant_id'] = str(tenant.id)
                    
                    # Clear temporary login session data
                    session.pop('login_user_id', None)
                    session.pop('login_tenant_id', None)
                    session.pop('login_remember', None)
                    
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
                            }
                        })
                    else:
                        flash('Login successful! Welcome back.', 'success')
                        next_page = request.args.get('next')
                        if next_page and next_page.startswith('/'):
                            return redirect(next_page)
                        return redirect(url_for('dashboard.index'))
                else:
                    # OTP verification failed
                    error_msg = otp_result['error']
                    if request.is_json:
                        return jsonify({
                            'error': error_msg,
                            'remaining_attempts': otp_result.get('remaining_attempts')
                        }), 400
                    else:
                        flash(error_msg, 'error')
                        return render_template('authentication/otp_verification.html',
                            phone_masked=f"****{user.phone[-4:]}",
                            step='login_otp'
                        )
                
        except Exception as e:
            db.session.rollback()
            error_msg = f'Login failed: {str(e)}'
            if request.is_json:
                return jsonify({'error': error_msg}), 500
            else:
                flash(error_msg, 'error')
                return render_template('authentication/signin.html')


@authentication_bp.route('/resend-login-otp', methods=['POST'])
def resend_login_otp():
    """Resend login OTP"""
    try:
        user_id = session.get('login_user_id')
        
        if not user_id:
            error_msg = 'No active login session found'
            if request.is_json:
                return jsonify({'error': error_msg}), 400
            else:
                flash(error_msg, 'error')
                return redirect(url_for('authentication.login_page'))
        
        user = User.query.get(user_id)
        if not user:
            error_msg = 'Invalid session'
            if request.is_json:
                return jsonify({'error': error_msg}), 400
            else:
                flash(error_msg, 'error')
                return redirect(url_for('authentication.login_page'))
        
        # Resend OTP
        otp_result = otp_service.resend_otp(
            phone_number=user.phone,
            otp_type=OTPType.LOGIN,
            user_id=str(user.id),
            user_name=user.full_name,
            ip_address=request.remote_addr
        )
        
        if otp_result['success']:
            message = 'OTP resent successfully'
            if request.is_json:
                return jsonify({'message': message})
            else:
                flash(message, 'success')
                return render_template('authentication/otp_verification.html',
                    phone_masked=f"****{user.phone[-4:]}",
                    step='login_otp'
                )
        else:
            error_msg = otp_result['error']
            if request.is_json:
                return jsonify({'error': error_msg}), 500
            else:
                flash(error_msg, 'error')
                return render_template('authentication/otp_verification.html',
                    phone_masked=f"****{user.phone[-4:]}",
                    step='login_otp'
                )
        
    except Exception as e:
        error_msg = f'Error resending OTP: {str(e)}'
        if request.is_json:
            return jsonify({'error': error_msg}), 500
        else:
            flash(error_msg, 'error')
            return redirect(url_for('authentication.login_page'))


@authentication_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password_page():
    """Forgot password with OTP verification"""
    if request.method == 'GET':
        return render_template('authentication/forgot_password.html',
            title='Forgot Password',
            subtitle='Reset Your Password'
        )
    
    elif request.method == 'POST':
        try:
            if request.is_json:
                data = request.get_json()
                phone_number = data.get('phone_number', '').strip()
                tenant_code = data.get('tenant_code', 'DEFAULT').strip().upper()
                otp_code = data.get('otp_code', '').strip()
                new_password = data.get('new_password', '').strip()
                step = data.get('step', 'send_otp')  # 'send_otp', 'verify_otp', 'reset_password'
            else:
                phone_number = request.form.get('phone_number', '').strip()
                tenant_code = request.form.get('tenant_code', 'DEFAULT').strip().upper()
                otp_code = request.form.get('otp_code', '').strip()
                new_password = request.form.get('new_password', '').strip()
                step = request.form.get('step', 'send_otp')
            
            # Step 1: Send OTP
            if step == 'send_otp':
                if not phone_number:
                    error_msg = 'Phone number is required'
                    if request.is_json:
                        return jsonify({'error': error_msg}), 400
                    else:
                        flash(error_msg, 'error')
                        return render_template('authentication/forgot_password.html')
                
                # Find tenant
                tenant = Tenant.query.filter_by(tenant_code=tenant_code, is_active=True).first()
                if not tenant:
                    error_msg = 'Invalid tenant'
                    if request.is_json:
                        return jsonify({'error': error_msg}), 400
                    else:
                        flash(error_msg, 'error')
                        return render_template('authentication/forgot_password.html')
                
                # Find user by phone number
                user = User.query.filter(
                    User.tenant_id == tenant.id,
                    User.phone == phone_number,
                    User.is_active == True
                ).first()
                
                if not user:
                    # Don't reveal if user exists or not for security
                    success_msg = 'If account exists, OTP will be sent to your phone'
                    if request.is_json:
                        return jsonify({'message': success_msg, 'step': 'verify_otp'})
                    else:
                        flash(success_msg, 'info')
                        return render_template('authentication/otp_verification.html',
                            phone_masked=f"****{phone_number[-4:]}",
                            step='password_reset_otp'
                        )
                
                # Send password reset OTP
                otp_result = otp_service.send_password_reset_otp(
                    phone_number=phone_number,
                    user_name=user.full_name,
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent', '')
                )
                
                if otp_result['success']:
                    # Store phone number in session
                    session['reset_phone'] = phone_number
                    session['reset_tenant_id'] = str(tenant.id)
                    
                    if request.is_json:
                        return jsonify({
                            'step': 'verify_otp',
                            'message': 'Password reset OTP sent to your phone',
                            'phone_masked': f"****{phone_number[-4:]}",
                            'expires_in_minutes': 10
                        })
                    else:
                        flash('Password reset OTP sent to your phone', 'success')
                        return render_template('authentication/otp_verification.html',
                            phone_masked=f"****{phone_number[-4:]}",
                            step='password_reset_otp'
                        )
                else:
                    error_msg = 'Failed to send OTP. Please try again.'
                    if request.is_json:
                        return jsonify({'error': error_msg}), 500
                    else:
                        flash(error_msg, 'error')
                        return render_template('authentication/forgot_password.html')
            
            # Step 2: Verify OTP
            elif step == 'verify_otp':
                if not otp_code:
                    error_msg = 'OTP is required'
                    if request.is_json:
                        return jsonify({'error': error_msg}), 400
                    else:
                        flash(error_msg, 'error')
                        return render_template('authentication/otp_verification.html')
                
                reset_phone = session.get('reset_phone')
                if not reset_phone:
                    error_msg = 'Session expired. Please start over.'
                    if request.is_json:
                        return jsonify({'error': error_msg}), 400
                    else:
                        flash(error_msg, 'error')
                        return redirect(url_for('authentication.forgot_password_page'))
                
                # Verify OTP
                otp_result = otp_service.verify_otp(
                    phone_number=reset_phone,
                    otp_code=otp_code,
                    otp_type=OTPType.PASSWORD_RESET
                )
                
                if otp_result['success']:
                    # OTP verified, proceed to password reset
                    session['otp_verified'] = True
                    
                    if request.is_json:
                        return jsonify({
                            'step': 'reset_password',
                            'message': 'OTP verified. Please set new password.'
                        })
                    else:
                        flash('OTP verified. Please set new password.', 'success')
                        return render_template('authentication/reset_password.html')
                else:
                    error_msg = otp_result['error']
                    if request.is_json:
                        return jsonify({
                            'error': error_msg,
                            'remaining_attempts': otp_result.get('remaining_attempts')
                        }), 400
                    else:
                        flash(error_msg, 'error')
                        return render_template('authentication/otp_verification.html',
                            phone_masked=f"****{reset_phone[-4:]}",
                            step='password_reset_otp'
                        )
            
            # Step 3: Reset Password
            elif step == 'reset_password':
                if not session.get('otp_verified'):
                    error_msg = 'OTP verification required'
                    if request.is_json:
                        return jsonify({'error': error_msg}), 400
                    else:
                        flash(error_msg, 'error')
                        return redirect(url_for('authentication.forgot_password_page'))
                
                if not new_password:
                    error_msg = 'New password is required'
                    if request.is_json:
                        return jsonify({'error': error_msg}), 400
                    else:
                        flash(error_msg, 'error')
                        return render_template('authentication/reset_password.html')
                
                if len(new_password) < 6:
                    error_msg = 'Password must be at least 6 characters long'
                    if request.is_json:
                        return jsonify({'error': error_msg}), 400
                    else:
                        flash(error_msg, 'error')
                        return render_template('authentication/reset_password.html')
                
                # Get user info from session
                reset_phone = session.get('reset_phone')
                reset_tenant_id = session.get('reset_tenant_id')
                
                if not reset_phone or not reset_tenant_id:
                    error_msg = 'Session expired. Please start over.'
                    if request.is_json:
                        return jsonify({'error': error_msg}), 400
                    else:
                        flash(error_msg, 'error')
                        return redirect(url_for('authentication.forgot_password_page'))
                
                # Find user
                user = User.query.filter(
                    User.tenant_id == reset_tenant_id,
                    User.phone == reset_phone,
                    User.is_active == True
                ).first()
                
                if not user:
                    error_msg = 'User not found'
                    if request.is_json:
                        return jsonify({'error': error_msg}), 400
                    else:
                        flash(error_msg, 'error')
                        return redirect(url_for('authentication.forgot_password_page'))
                
                # Update password
                user.set_password(new_password)
                user.updated_at = datetime.utcnow()
                
                # Invalidate all user sessions
                UserSession.query.filter_by(user_id=user.id, is_active=True).update({'is_active': False})
                
                db.session.commit()
                
                # Clear session data
                session.pop('reset_phone', None)
                session.pop('reset_tenant_id', None)
                session.pop('otp_verified', None)
                
                success_msg = 'Password reset successfully. Please login with new password.'
                if request.is_json:
                    return jsonify({'message': success_msg})
                else:
                    flash(success_msg, 'success')
                    return redirect(url_for('authentication.login_page'))
                
        except Exception as e:
            db.session.rollback()
            error_msg = f'Error processing request: {str(e)}'
            if request.is_json:
                return jsonify({'error': error_msg}), 500
            else:
                flash(error_msg, 'error')
                return redirect(url_for('authentication.forgot_password_page'))


@authentication_bp.route('/resend-password-reset-otp', methods=['POST'])
def resend_password_reset_otp():
    """Resend password reset OTP"""
    try:
        reset_phone = session.get('reset_phone')
        
        if not reset_phone:
            error_msg = 'No active password reset session found'
            if request.is_json:
                return jsonify({'error': error_msg}), 400
            else:
                flash(error_msg, 'error')
                return redirect(url_for('authentication.forgot_password_page'))
        
        # Find user to get name
        reset_tenant_id = session.get('reset_tenant_id')
        user = User.query.filter(
            User.tenant_id == reset_tenant_id,
            User.phone == reset_phone,
            User.is_active == True
        ).first()
        
        user_name = user.full_name if user else "User"
        
        # Resend OTP
        otp_result = otp_service.resend_otp(
            phone_number=reset_phone,
            otp_type=OTPType.PASSWORD_RESET,
            user_name=user_name,
            ip_address=request.remote_addr
        )
        
        if otp_result['success']:
            message = 'OTP resent successfully'
            if request.is_json:
                return jsonify({'message': message})
            else:
                flash(message, 'success')
                return render_template('authentication/otp_verification.html',
                    phone_masked=f"****{reset_phone[-4:]}",
                    step='password_reset_otp'
                )
        else:
            error_msg = otp_result['error']
            if request.is_json:
                return jsonify({'error': error_msg}), 500
            else:
                flash(error_msg, 'error')
                return render_template('authentication/otp_verification.html',
                    phone_masked=f"****{reset_phone[-4:]}",
                    step='password_reset_otp'
                )
        
    except Exception as e:
        error_msg = f'Error resending OTP: {str(e)}'
        if request.is_json:
            return jsonify({'error': error_msg}), 500
        else:
            flash(error_msg, 'error')
            return redirect(url_for('authentication.forgot_password_page'))


# =============================================================================
# EXISTING ROUTES (LOGOUT, API ENDPOINTS, etc.)
# =============================================================================

@authentication_bp.route('/logout', methods=['GET', 'POST'])
@login_required
def logout_page():
    """User logout"""
    try:
        session_token = session.get('session_token')
        
        if session_token:
            user_session = UserSession.query.filter_by(
                session_token=session_token,
                user_id=current_user.id,
                is_active=True
            ).first()
            
            if user_session:
                user_session.is_active = False
                db.session.commit()
        
        logout_user()
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
# API ENDPOINTS FOR MOBILE/SPA APPLICATIONS
# =============================================================================

@authentication_bp.route('/api/login', methods=['POST'])
def api_login():
    """API login endpoint"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        tenant_code = data.get('tenant_code', 'DEFAULT').strip().upper()
        otp_code = data.get('otp_code', '').strip()
        step = data.get('step', 'credentials')
        
        if step == 'credentials':
            # Validate credentials and send OTP
            if not username or not password:
                return jsonify({'error': 'Username and password are required'}), 400
            
            tenant = Tenant.query.filter_by(tenant_code=tenant_code, is_active=True).first()
            if not tenant or not tenant.is_subscription_active:
                return jsonify({'error': 'Invalid tenant or subscription expired'}), 400
            
            user = User.query.filter(
                User.tenant_id == tenant.id,
                db.or_(User.username == username, User.email == username, User.phone == username),
                User.is_active == True
            ).first()
            
            if not user or user.is_locked or not user.check_password(password):
                return jsonify({'error': 'Invalid credentials'}), 401
            
            # Send OTP
            otp_result = otp_service.send_login_otp(
                user_id=str(user.id),
                phone_number=user.phone,
                user_name=user.full_name,
                ip_address=request.remote_addr
            )
            
            if otp_result['success']:
                return jsonify({
                    'step': 'otp_verification',
                    'message': 'OTP sent successfully',
                    'phone_masked': f"****{user.phone[-4:]}",
                    'user_id': str(user.id),  # For API use
                    'expires_in_minutes': 5
                })
            else:
                return jsonify({'error': 'Failed to send OTP'}), 500
        
        elif step == 'otp':
            # Verify OTP and complete login
            user_id = data.get('user_id')
            if not user_id or not otp_code:
                return jsonify({'error': 'User ID and OTP are required'}), 400
            
            user = User.query.get(user_id)
            if not user:
                return jsonify({'error': 'Invalid user'}), 400
            
            # Verify OTP
            otp_result = otp_service.verify_otp(
                phone_number=user.phone,
                otp_code=otp_code,
                otp_type=OTPType.LOGIN,
                user_id=str(user.id)
            )
            
            if otp_result['success']:
                # Create session and login
                user.login_attempts = 0
                user.last_login = datetime.utcnow()
                
                session_token = secrets.token_urlsafe(32)
                refresh_token = secrets.token_urlsafe(64)
                
                user_session = UserSession(
                    user_id=user.id,
                    session_token=session_token,
                    refresh_token=refresh_token,
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent', ''),
                    expires_at=datetime.utcnow() + timedelta(days=1),
                    is_active=True
                )
                
                db.session.add(user_session)
                db.session.commit()
                
                return jsonify({
                    'message': 'Login successful',
                    'user': {
                        'id': str(user.id),
                        'username': user.username,
                        'full_name': user.full_name,
                        'role': user.role.value
                    },
                    'session_token': session_token,
                    'refresh_token': refresh_token,
                    'expires_at': user_session.expires_at.isoformat()
                })
            else:
                return jsonify({'error': otp_result['error']}), 400
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@authentication_bp.route('/api/forgot-password', methods=['POST'])
def api_forgot_password():
    """API forgot password endpoint"""
    try:
        data = request.get_json()
        phone_number = data.get('phone_number', '').strip()
        tenant_code = data.get('tenant_code', 'DEFAULT').strip().upper()
        otp_code = data.get('otp_code', '').strip()
        new_password = data.get('new_password', '').strip()
        step = data.get('step', 'send_otp')
        
        if step == 'send_otp':
            if not phone_number:
                return jsonify({'error': 'Phone number is required'}), 400
            
            # Send password reset OTP (even if user doesn't exist for security)
            otp_result = otp_service.send_password_reset_otp(
                phone_number=phone_number,
                ip_address=request.remote_addr
            )
            
            return jsonify({
                'step': 'verify_otp',
                'message': 'If account exists, OTP will be sent',
                'phone_masked': f"****{phone_number[-4:]}"
            })
        
        elif step == 'verify_otp':
            if not phone_number or not otp_code:
                return jsonify({'error': 'Phone number and OTP are required'}), 400
            
            otp_result = otp_service.verify_otp(
                phone_number=phone_number,
                otp_code=otp_code,
                otp_type=OTPType.PASSWORD_RESET
            )
            
            if otp_result['success']:
                return jsonify({
                    'step': 'reset_password',
                    'message': 'OTP verified. Please set new password.',
                    'reset_token': otp_result['otp_id']  # Use OTP ID as reset token
                })
            else:
                return jsonify({'error': otp_result['error']}), 400
        
        elif step == 'reset_password':
            if not phone_number or not new_password:
                return jsonify({'error': 'Phone number and new password are required'}), 400
            
            if len(new_password) < 6:
                return jsonify({'error': 'Password must be at least 6 characters long'}), 400
            
            # Find and update user
            user = User.query.filter_by(phone=phone_number, is_active=True).first()
            if user:
                user.set_password(new_password)
                UserSession.query.filter_by(user_id=user.id, is_active=True).update({'is_active': False})
                db.session.commit()
            
            return jsonify({'message': 'Password reset successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# =============================================================================
# UTILITY ROUTES
# =============================================================================

@authentication_bp.route('/api/resend-otp', methods=['POST'])
def api_resend_otp():
    """API endpoint to resend OTP"""
    try:
        data = request.get_json()
        phone_number = data.get('phone_number', '').strip()
        otp_type = data.get('otp_type', 'LOGIN')  # LOGIN or PASSWORD_RESET
        user_id = data.get('user_id')  # Required for login OTP
        
        if not phone_number:
            return jsonify({'error': 'Phone number is required'}), 400
        
        if otp_type == 'LOGIN':
            if not user_id:
                return jsonify({'error': 'User ID is required for login OTP'}), 400
            
            user = User.query.get(user_id)
            if not user:
                return jsonify({'error': 'Invalid user'}), 400
            
            otp_result = otp_service.resend_otp(
                phone_number=phone_number,
                otp_type=OTPType.LOGIN,
                user_id=str(user.id),
                user_name=user.full_name,
                ip_address=request.remote_addr
            )
        elif otp_type == 'PASSWORD_RESET':
            otp_result = otp_service.resend_otp(
                phone_number=phone_number,
                otp_type=OTPType.PASSWORD_RESET,
                ip_address=request.remote_addr
            )
        else:
            return jsonify({'error': 'Invalid OTP type'}), 400
        
        if otp_result['success']:
            return jsonify({'message': 'OTP resent successfully'})
        else:
            return jsonify({'error': otp_result['error']}), 500
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Include all other existing routes (refresh_token, change_password, etc.)
# ... (rest of your existing routes remain the same)

@authentication_bp.route('/debug/test-sms-v2', methods=['GET', 'POST'])
def test_sms_v2():
    """Enhanced SMS test with proper formatting"""
    if request.method == 'GET':
        return '''
        <html>
        <head><title>Enhanced SMS Test</title></head>
        <body>
            <h2>Enhanced SMS Test</h2>
            <form method="POST">
                <p>
                    <label>Phone Number:</label><br>
                    <input type="text" name="phone_number" placeholder="9860303985 or 919860303985" required style="padding: 10px; width: 300px;">
                </p>
                <p>
                    <label>OTP Code:</label><br>
                    <input type="text" name="otp" value="654321" style="padding: 10px; width: 200px;">
                </p>
                <p>
                    <label>User Name:</label><br>
                    <input type="text" name="user_name" value="TestUser" style="padding: 10px; width: 200px;">
                </p>
                <p>
                    <button type="submit" style="padding: 10px 20px;">Send Enhanced SMS Test</button>
                </p>
            </form>
        </body>
        </html>
        '''
    
    try:
        phone_number = request.form.get('phone_number', '').strip()
        otp_code = request.form.get('otp', '654321')
        user_name = request.form.get('user_name', 'TestUser')
        
        if not phone_number:
            return '<html><body><h2>Error:</h2><p>Phone number required</p><a href="/auth/debug/test-sms-v2">Back</a></body></html>'
        
        # Test SMS sending with enhanced service
        from utils.sms_service import sms_service
        result = sms_service.send_otp_sms(phone_number, otp_code, user_name)
        
        return f'''
        <html>
        <head><title>Enhanced SMS Test Result</title></head>
        <body>
            <h2>Enhanced SMS Test Result</h2>
            <h3>Success: {result.get('success', False)}</h3>
            <h4>Phone Formatting:</h4>
            <p><strong>Original:</strong> {phone_number}</p>
            <p><strong>Formatted:</strong> {result.get('formatted_phone', 'N/A')}</p>
            <h4>Full Details:</h4>
            <pre style="background: #f5f5f5; padding: 15px; border-radius: 5px; white-space: pre-wrap;">{result}</pre>
            <p><a href="/auth/debug/test-sms-v2">Test Again</a></p>
        </body>
        </html>
        '''
        
    except Exception as e:
        return f'''
        <html>
        <body>
            <h2>Error:</h2>
            <pre>{str(e)}</pre>
            <a href="/auth/debug/test-sms-v2">Back</a>
        </body>
        </html>
        '''
