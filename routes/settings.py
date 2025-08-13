from flask import render_template
from flask import Blueprint

settings_bp = Blueprint('settings', __name__, template_folder='templates', static_folder='static')

@settings_bp.route('/company')
def company():
    return render_template('settings/company.html',
        title='Company',
        subtitle='Settings - Company',
    )

@settings_bp.route('/currencies')
def currencies():
    return render_template('settings/currencies.html',
        title='Currencies',
        subtitle='Settings - Currencies',
    )

@settings_bp.route('/language')
def language():
    return render_template('settings/language.html',
        title='Languages',
        subtitle='Settings - Languages',
    )

@settings_bp.route('/notification')
def notification():
    return render_template('settings/notification.html',
        title='Notification',
        subtitle='Settings - Notification',
    )

@settings_bp.route('/notification-alert')
def notificationAlert():
    return render_template('settings/notificationAlert.html',
        title='Notification Alert',
        subtitle='Settings - Notification Alert',
    )

@settings_bp.route('/payment-gateway')
def paymentGateway():
    return render_template('settings/paymentGateway.html',
        title='Languages',
        subtitle='Settings - Languages',
    )

@settings_bp.route('/theme')
def theme():
    return render_template('settings/theme.html',
        title='Theme',
        subtitle='Settings - Theme',
    )