from flask import render_template
from flask import Blueprint

terms_condition_bp = Blueprint('terms_condition', __name__, template_folder='templates', static_folder='static')

@terms_condition_bp.route('/terms_condition', endpoint='index')
def index():
    return render_template('terms_condition/index.html',
        title='Terms & Condition',
        subtitle='Terms & Condition',
    )
