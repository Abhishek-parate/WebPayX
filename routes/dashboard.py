from flask import render_template, redirect, url_for
from flask import Blueprint
from flask_login import login_user, logout_user, login_required, current_user

dashboard_bp = Blueprint('dashboard', __name__, template_folder='templates', static_folder='static')

@dashboard_bp.route('/', endpoint='index')
@login_required
def index():
    # Check if user is authenticated (additional safety check)
    if not current_user.is_authenticated:
        return redirect(url_for('authentication.login_page'))
    
    return render_template('dashboard/index.html',
        title='Dashboard',
        subtitle='AI',
        script='assets/js/homeChart/homeOneChart.js'
    )

@dashboard_bp.route('/index2', endpoint='index2')
@login_required
def index2():
    return render_template('dashboard/index2.html',
        title='Dashboard',
        subtitle='CRM',
        script='assets/js/homeChart/homeTwoChart.js'
    )

@dashboard_bp.route('/index3', endpoint='index3')
@login_required
def index3():
    return render_template('dashboard/index3.html',
        title='Dashboard',
        subtitle='eCommerce',
        script='assets/js/homeChart/homeThreeChart.js'
    )

@dashboard_bp.route('/index4', endpoint='index4')
@login_required
def index4():
    return render_template('dashboard/index4.html',
        title='Dashboard',
        subtitle='Cryptocracy',
        script='assets/js/homeChart/homeFourChart.js'
    )

@dashboard_bp.route('/index5', endpoint='index5')
@login_required
def index5():
    return render_template('dashboard/index5.html',
        title='Dashboard',
        subtitle='Investment',
        script='assets/js/homeChart/homeFiveChart.js'
    )

@dashboard_bp.route('/transaction-dth-recharge-report', endpoint='index6')
@login_required
def index6():
    return render_template('dashboard/index6.html',
        title='DTH Recharge Report',
        subtitle='Self Transaction Report / DTH Recharge Report'
    )

@dashboard_bp.route('/transaction-commission-reports', endpoint='index7')
@login_required
def index7():
    return render_template('dashboard/index7.html',
        title='Commission Reports',
        subtitle='Self Transaction Report / Commission Reports'
    )

@dashboard_bp.route('/distributor', endpoint='index8')
@login_required
def index8():
    return render_template('dashboard/index8.html',
        title='Distributor',
        subtitle='Member Manager / Distributor',
    )

@dashboard_bp.route('/wallet-top-up-request', endpoint='index9')
@login_required
def index9():
    return render_template('dashboard/index9.html',
        title='Wallet Top-up Request',
        subtitle='Member Manager / Wallet Top-up Request'
    )