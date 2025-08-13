from flask import render_template
from flask import Blueprint

user_bp = Blueprint('user', __name__, template_folder='templates', static_folder='static')

@user_bp.route('/add-user')
def addUser():
    return render_template('users/addUser.html',
        title='Add User',
        subtitle='Add User',
    )

@user_bp.route('/users-grid')
def usersGrid():
    return render_template('users/usersGrid.html',
        title='Users Grid',
        subtitle='Users Grid',
    )

@user_bp.route('/users-list')
def usersList():
    return render_template('users/usersList.html',
        title='Users List',
        subtitle='Users List',
    )

@user_bp.route('/view-profile')
def viewProfile():
    return render_template('users/viewProfile.html',
        title='View Profile',
        subtitle='View Profile',
    )