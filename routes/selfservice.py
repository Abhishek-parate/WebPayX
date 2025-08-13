from flask import render_template
from flask import Blueprint

selfservice_bp = Blueprint('selfservice', __name__, template_folder='templates', static_folder='static')

@selfservice_bp.route('/selfservice/paymentgateway', endpoint='paymentgateway')
def index():
    return render_template('selfservice/paymentgateway.html',
        title='Payment Gateway',
        subtitle='Selfservice / Payment Gateway',
    )

@selfservice_bp.route('/selfservice/ccbillpaymentservice', endpoint='ccbillpaymentservice')
def index():
    return render_template('selfservice/ccbillpaymentservice.html',
        title='CC Bill Payment Service',
        subtitle='Selfservice / CC Bill Payment Service ',
    )

@selfservice_bp.route('/selfservice/moneytransferservice', endpoint='moneytransferservice')
def index():
    return render_template('selfservice/moneytransferservice.html',
        title='Money Transfer Service',
        subtitle='Selfservice / Money Transfer Service ',
    )

@selfservice_bp.route('/selfservice/mobilerecharge', endpoint='mobilerecharge')
def index():
    return render_template('selfservice/mobilerecharge.html',
        title='Mobile Recharge',
        subtitle='Selfservice / Mobile Recharge ',
    )

@selfservice_bp.route('/selfservice/dthrecharge', endpoint='dthrecharge')
def index():
    return render_template('selfservice/dthrecharge.html',
        title='DTH Recharge',
        subtitle='Selfservice / DTH Recharge ',
    )