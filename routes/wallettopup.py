from flask import render_template
from flask import Blueprint

wallettopup_bp = Blueprint('wallettopup', __name__, template_folder='templates', static_folder='static')

@wallettopup_bp.route('/wallettopup', endpoint='index')
def index():
    return render_template('wallettopup/index.html',
        title='Wallet Top-up',
        subtitle='Wallet Top-up',
    )
