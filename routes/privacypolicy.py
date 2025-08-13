from flask import render_template
from flask import Blueprint

privacypolicy_bp = Blueprint('privacypolicy', __name__, template_folder='templates', static_folder='static')

@privacypolicy_bp.route('/privacypolicy', endpoint='index')
def index():
    return render_template('privacypolicy/index.html',
        title='Privacy Policy',
        subtitle='Privacy Policy',
    )
