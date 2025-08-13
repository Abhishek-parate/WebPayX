from flask import render_template
from flask import Blueprint

forms_bp = Blueprint('forms', __name__, template_folder='templates', static_folder='static')

@forms_bp.route('/form')
def form():
    return render_template('forms/form.html',
        title='Input From',
        subtitle='Input From',
    )

@forms_bp.route('/form-layout')
def formLayout():
    return render_template('forms/formLayout.html',
        title='Input Layout',
        subtitle='Input Layout',
    )

@forms_bp.route('/form-validation')
def formValidation():
    return render_template('forms/formValidation.html',
        title='Form Validation',
        subtitle='Form Validation',
    )

@forms_bp.route('/wizard')
def wizard():
    return render_template('forms/wizard.html',
        title='Wizard',
        subtitle='Wizard',
    )