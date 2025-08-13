from flask import render_template
from flask import Blueprint

aiapplication_bp = Blueprint('aiapplication', __name__, template_folder='templates', static_folder='static')

@aiapplication_bp.route('/member-will-payment-report')
def codeGenerator():
    return render_template('aiapplication/codeGenerator.html',
        title='Bill Payment Report',
        subtitle='Member Report / Bill Payment Report',
    )

@aiapplication_bp.route('/code-generatorNew')
def codeGeneratorNew():
    return render_template('aiapplication/codeGeneratorNew.html',
        title='Code Generator',
        subtitle='Code Generator',
    )

@aiapplication_bp.route('/member-money-transfer-report')
def imageGenerator():
    return render_template('aiapplication/imageGenerator.html',
        title='Money Transfer Report',
        subtitle='Member Report / Money Transfer Report',
    )



@aiapplication_bp.route('/member-payment-gateway-report')
def textGenerator():
    return render_template('aiapplication/textGenerator.html',
        title='Payment Gateway Report',
        subtitle='Member Report / Payment Gateway Report',
    )

@aiapplication_bp.route('/text-generatorNew')
def textGeneratorNew():
    return render_template('aiapplication/textGeneratorNew.html',
        title='Text Generator',
        subtitle='Text Generator',
    )

@aiapplication_bp.route('/member-dth-recharge-report')
def videoGenerator():
    return render_template('aiapplication/videoGenerator.html',
        title='DTH Recharge Report',
        subtitle='Member Report / DTH Recharge Report',
    )

@aiapplication_bp.route('/member-mobile-recharge-report')
def voiceGenerator():
    return render_template('aiapplication/voiceGenerator.html',
        title='Mobile Recharge Report',
        subtitle='Member Report / Mobile Recharge Report',
    )
