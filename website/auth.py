from flask import Blueprint, render_template, flash, redirect
from .forms import LoginForm, SignUpForm, PasswordChangeForm
from .models import User
from . import db
from flask_login import login_user, login_required, logout_user


auth = Blueprint('auth', __name__)


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    form = SignUpForm()
    if form.validate_on_submit():
        email = form.email.data
        name = form.name.data
        surname = form.surname.data
        password1 = form.password1.data
        password2 = form.password2.data

        if password1 == password2:
            new_user = User()
            new_user.email = email
            new_user.username = name
            new_user.surname = surname
            new_user.password = password2

            try:
                db.session.add(new_user)
                db.session.commit()
                flash('Account Created Successfully, You can now Login')
                return 'login.html'
            except Exception as e:
                print(e)
                flash('Account Not Created!!, Email already exists')

            form.email.data = ''
            form.name.data = ''
            form.surname.data = ''
            form.password1.data = ''
            form.password2.data = ''

    return 'signup.html'


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()

        if user:
            if user.verify_password(password=password):
                login_user(user)
                return redirect('/')
            else:
                flash('Incorrect Email or Password')

        else:
            flash('Account does not exist please Sign Up')

    return 'login.html'


@auth.route('/logout', methods=['GET', 'POST'])
@login_required
def log_out():
    logout_user()
    return redirect('/')


@auth.route('/profile/<int:customer_id>')
@login_required
def profile(user_id):
    customer = User.query.get(user_id)
    return 'Profile Page'


@auth.route('/change-password/<int:customer_id>', methods=['GET', 'POST'])
@login_required
def change_password(user_id):
    form = PasswordChangeForm()
    user = User.query.get(user_id)
    if form.validate_on_submit():
        current_password = form.current_password.data
        new_password = form.new_password.data
        confirm_new_password = form.confirm_new_password.data

        if user.verify_password(current_password):
            if new_password == confirm_new_password:
                user.password = confirm_new_password
                db.session.commit()
                flash('Password Updated Successfully')
                return 'redirect to profile/<user.id>'
            else:
                flash('New Passwords do not match!!')

        else:
            flash('Current Password is Incorrect')

    return 'return change password page'







