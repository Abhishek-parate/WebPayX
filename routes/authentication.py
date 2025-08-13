from flask import render_template
from flask import Blueprint

authentication_bp = Blueprint('authentication', __name__, template_folder='templates', static_folder='static')

@authentication_bp.route('/forgot-password')
def forgotPassword():
    return render_template('authentication/forgotPassword.html',
    )

@authentication_bp.route('/signin')
def signin():
    return render_template('authentication/signin.html',
    )

@authentication_bp.route('/signup')
def signup():
    return render_template('authentication/signup.html',
    )