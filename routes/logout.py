# routes/logout.py
from flask import Blueprint, redirect, url_for, flash, session, request
from flask_login import logout_user, login_required, current_user
from models import db, UserSession
from datetime import datetime

logout_bp = Blueprint('logout', __name__)

@logout_bp.route('/logout')
@login_required
def logout_user():
    """Handle user logout"""
    try:
        # Update user session end time if exists
        if hasattr(current_user, 'id'):
            user_session = UserSession.query.filter_by(
                user_id=current_user.id,
                session_id=session.get('session_id'),
                logout_time=None
            ).first()
            
            if user_session:
                user_session.logout_time = datetime.utcnow()
                user_session.ip_address = request.remote_addr
                db.session.commit()
        
        # Log the logout action
        user_info = f"{current_user.full_name} ({current_user.user_code})" if hasattr(current_user, 'full_name') else "Unknown User"
        print(f"User logged out: {user_info}")
        
        # Clear session data
        session.clear()
        
        # Logout the user
        logout_user()
        
        # Add success message
        flash('You have been successfully logged out.', 'success')
        
        # Redirect to login page
        return redirect(url_for('authentication.login_page'))
        
    except Exception as e:
        print(f"Error during logout: {e}")
        # Even if there's an error, still logout the user
        logout_user()
        session.clear()
        flash('Logged out successfully.', 'info')
        return redirect(url_for('authentication.login_page'))

@logout_bp.route('/force-logout')
def force_logout():
    """Force logout without authentication (for emergency cases)"""
    try:
        session.clear()
        logout_user()
        flash('Session cleared successfully.', 'info')
        return redirect(url_for('authentication.login_page'))
    except Exception as e:
        print(f"Error during force logout: {e}")
        return redirect(url_for('authentication.login_page'))