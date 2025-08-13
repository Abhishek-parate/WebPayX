from flask import render_template
from flask import Blueprint

table_bp = Blueprint('table', __name__, template_folder='templates', static_folder='static')

@table_bp.route('/table-basic')
def tableBasic():
    return render_template('table/tableBasic.html',
        title='Basic Table',
        subtitle='Basic Table',
    )

@table_bp.route('/table-data')
def tableData():
    return render_template('table/tableData.html',
        title='Basic Table',
        subtitle='Basic Table',
        script='assets/js/data-table.js'
    )