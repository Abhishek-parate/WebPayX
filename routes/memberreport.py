from flask import render_template
from flask import Blueprint

memberreport_bp = Blueprint('memberreport', __name__, template_folder='templates', static_folder='static')

@memberreport_bp.route('/memberreport/paymentgatewayreport', endpoint='paymentgatewayreport')
def index():
    return render_template('memberreport/paymentgatewayreport.html',
        title='Payment Gateway Report',
        subtitle='memberreport / Payment Gateway Report',
    )

@memberreport_bp.route('/memberreport/billpaymentreport', endpoint='billpaymentreport')
def index():
    return render_template('memberreport/billpaymentreport.html',
        title='Bill Payment Report',
        subtitle='memberreport / Bill Payment Report',
    )

@memberreport_bp.route('/memberreport/moneytransferreport', endpoint='moneytransferreport')
def index():
    return render_template('memberreport/moneytransferreport.html',
        title='Money Transfer Report',
        subtitle='memberreport / Money Transfer Report',
    )

@memberreport_bp.route('/memberreport/mobilerechargereport', endpoint='mobilerechargereport')
def index():
    return render_template('memberreport/mobilerechargereport.html',
        title='Mobile Recharge Report',
        subtitle='memberreport / Mobile Recharge Report',
    )

@memberreport_bp.route('/memberreport/dthrechargereport', endpoint='dthrechargereport')
def index():
    return render_template('memberreport/dthrechargereport.html',
        title='DTH Recharge Report',
        subtitle='memberreport / DTH Recharge Report',
    )

@memberreport_bp.route('/memberreport/wallettopuprecharge', endpoint='wallettopuprecharge')
def index():
    return render_template('memberreport/wallettopuprecharge.html',
        title='Wallet Top-up Report',
        subtitle='memberreport / Wallet Top-up Report',
    )
