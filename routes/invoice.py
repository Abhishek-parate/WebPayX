from flask import render_template
from flask import Blueprint

invoice_bp = Blueprint('invoice', __name__, template_folder='templates', static_folder='static')

@invoice_bp.route('/transactions-money-transfer-report')
def invoiceAdd():
    return render_template('invoice/invoiceAdd.html',
        title='Money Transfer Report',
        subtitle='Self Transaction Report / Money Transfer Report'
    )

@invoice_bp.route('/transaction-mobile-recharge-report')
def invoiceEdit():
    return render_template('invoice/invoiceEdit.html',
        title='Mobile Recharge Report',
        subtitle='Self Transaction Report / Mobile Recharge Report'
    )

@invoice_bp.route('/transaction-payment-gateway-report')
def invoiceList():
    return render_template('invoice/invoiceList.html',
        title='Payment Gateway Report',
        subtitle='Self Transaction Report / Payment Gateway Report',
    )

@invoice_bp.route('/transactions-bill-payment-report')
def invoicePreview():
    return render_template('invoice/invoicePreview.html',
        title='Bill Payment Report',
        subtitle='Self Transaction Report / Bill Payment Report',
    )