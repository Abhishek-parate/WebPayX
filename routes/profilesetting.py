# WebPayX/routes/profilesetting.py
from flask import render_template
from flask import Blueprint

profilesetting_bp = Blueprint('profilesetting', __name__, template_folder='templates', static_folder='static')

@profilesetting_bp.route('/profilesetting', endpoint='index')
def index():
    return render_template('profilesetting/index.html',
        title='Profile Setting',
        subtitle='Profile Setting',
    )
