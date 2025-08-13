from flask import render_template
from flask import Blueprint

complaint_bp = Blueprint('complaint', __name__, template_folder='templates', static_folder='static')

@complaint_bp.route('/complaint', endpoint='index')
def index():
    return render_template('complaint/index.html',
        title='Complaint',
        subtitle='Complaint',
    )
