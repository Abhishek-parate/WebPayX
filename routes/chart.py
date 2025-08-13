from flask import render_template
from flask import Blueprint

chart_bp = Blueprint('chart', __name__, template_folder='templates', static_folder='static')

@chart_bp.route('/column-chart')
def columnChart():
    return render_template('chart/columnChart.html',
        title='Column Chart',
        subtitle='Components / Column Chart',
        script='assets/js/columnChartPageChart.js'
    )

@chart_bp.route('/line-chart')
def lineChart():
    return render_template('chart/lineChart.html',
        title='Line Chart',
        subtitle='Components / Line Chart',
        script='assets/js/lineChartPageChart.js'
    )

@chart_bp.route('/pie-chart')
def pieChart():
    return render_template('chart/pieChart.html',
        title='Pie Chart',
        subtitle='Components / Pie Chart',
        script='assets/js/pieChartPageChart.js'
    )