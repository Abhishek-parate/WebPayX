from flask import render_template
from flask import Blueprint

logout_bp = Blueprint('logout', __name__, template_folder='templates', static_folder='static')

@logout_bp.route('/logout', endpoint='index')
def index():
    return render_template('logout/index.html',
        title='Logout',
        subtitle='Logout',
    )
