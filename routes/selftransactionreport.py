from flask import render_template
from flask import Blueprint

selftransactionreport_bp = Blueprint('selftransactionreport', __name__, template_folder='templates', static_folder='static')

@selftransactionreport_bp.route('/selftransactionreport/paymentgatewayreport', endpoint='paymentgatewayreport')
def index():
    return render_template('selftransactionreport/paymentgatewayreport.html',
        title='Payment Gateway Report',
        subtitle='selftransactionreport / Payment Gateway Report',
    )

@selftransactionreport_bp.route('/selftransactionreport/billpaymentreport', endpoint='billpaymentreport')
def index():
    return render_template('selftransactionreport/billpaymentreport.html',
        title='Bill Payment Report',
        subtitle='selftransactionreport / Bill Payment Report',
    )

@selftransactionreport_bp.route('/selftransactionreport/moneytransferreport', endpoint='moneytransferreport')
def index():
    return render_template('selftransactionreport/moneytransferreport.html',
        title='Money Transfer Report',
        subtitle='selftransactionreport / Money Transfer Report',
    )

@selftransactionreport_bp.route('/selftransactionreport/mobilerechargereport', endpoint='mobilerechargereport')
def index():
    return render_template('selftransactionreport/mobilerechargereport.html',
        title='Mobile Recharge Report',
        subtitle='selftransactionreport / Mobile Recharge Report',
    )

@selftransactionreport_bp.route('/selftransactionreport/dthrechargereport', endpoint='dthrechargereport')
def index():
    return render_template('selftransactionreport/dthrechargereport.html',
        title='DTH Recharge Report',
        subtitle='selftransactionreport / DTH Recharge Report',
    )

@selftransactionreport_bp.route('/selftransactionreport/commissionreport', endpoint='commissionreport')
def index():
    return render_template('selftransactionreport/commissionreport.html',
        title='Commission Report',
        subtitle='selftransactionreport / Commission Report',
    )
