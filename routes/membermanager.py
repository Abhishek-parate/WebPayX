from flask import render_template
from flask import Blueprint

membermanager_bp = Blueprint('membermanager', __name__, template_folder='templates', static_folder='static')

@membermanager_bp.route('/membermanager/retailer', endpoint='retailer')
def index():
    return render_template('membermanager/retailer.html',
        title='Retailer',
        subtitle='membermanager / Retailer',
    )


@membermanager_bp.route('/membermanager/distributor', endpoint='distributor')
def index():
    return render_template('membermanager/distributor.html',
        title='Distributor',
        subtitle='membermanager / Distributor',
    )


@membermanager_bp.route('/membermanager/wallettopuprequest', endpoint='wallettopuprequest')
def index():
    return render_template('membermanager/wallettopuprequest.html',
        title='Wallet Top-up Request',
        subtitle='membermanager / Wallet Top-up Request',
    )
