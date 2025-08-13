import os
from flask import Flask, redirect, render_template, url_for
from routes.chart import chart_bp
from routes.aiapplication import aiapplication_bp
from routes.authentication import authentication_bp
from routes.componentspage import componentspage_bp
from routes.selfservice import selfservice_bp
from routes.selftransactionreport import selftransactionreport_bp
from routes.complaint import complaint_bp
from routes.logout import logout_bp
from routes.membermanager import membermanager_bp
from routes.memberreport import memberreport_bp
from routes.privacypolicy import privacypolicy_bp
from routes.profilesetting import profilesetting_bp
from routes.wallettopup import wallettopup_bp
from routes.terms_condition import terms_condition_bp
from routes.dashboard import dashboard_bp
from routes.forms import forms_bp
from routes.invoice import invoice_bp
from routes.settings import settings_bp
from routes.table import table_bp
from routes.user import user_bp




wowdash = Flask(__name__,
            template_folder='resource/views',
            static_folder=os.path.abspath('static'))


wowdash.register_blueprint(authentication_bp)  
wowdash.register_blueprint(selfservice_bp) 
wowdash.register_blueprint(selftransactionreport_bp)
wowdash.register_blueprint(dashboard_bp)  
wowdash.register_blueprint(complaint_bp) 
wowdash.register_blueprint(logout_bp) 
wowdash.register_blueprint(membermanager_bp) 
wowdash.register_blueprint(memberreport_bp)
wowdash.register_blueprint(privacypolicy_bp) 
wowdash.register_blueprint(wallettopup_bp)  
wowdash.register_blueprint(profilesetting_bp)
wowdash.register_blueprint(terms_condition_bp)  
wowdash.register_blueprint(user_bp)





@wowdash.route('/dashboard')
def email():
    return render_template('email.html',
        title='Admin Dashboard',
        subtitle='Admin Dashboard'
    )

@wowdash.route('/logout')
def faq():
    return render_template('faq.html',
        title='Logout',
        subtitle='Logout'
    )



@wowdash.route('/page-error')
def pageError():
    return render_template('pageError.html',
        title='404',
        subtitle='404'
    )






if __name__ == '__main__':
    wowdash.run(debug=True)