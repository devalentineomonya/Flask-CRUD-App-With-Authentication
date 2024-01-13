from flask import render_template, request, Blueprint, flash, redirect, url_for
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash
from .models import Users
from . import db

auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['POST', 'GET'])
@auth.route('/signin', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        data = request.form
        username = data['username']
        password = data['password']
        User = Users.query.filter((Users.username == username) | (Users.email == username)).first()
        if User:
            if check_password_hash(User.password, password):
                flash(f"You are logged in as {User.fullname}", category='success')
                login_user(User, remember=False)
                return redirect(url_for('views.home'))
            else:
                flash("You entered Wrong Password", category='error')
        else:
            flash("Wrong Username and Password", category='error')

    return render_template('login.html')


@auth.route('/register', methods=['POST', 'GET'])
@auth.route('/signup', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        data = request.form
        fullname = data['fullname']
        username = data['username']
        role = data['role']
        email = data['email']
        password = data['password']
        if len(fullname) < 3:
            flash('Fullname Should be 3 characters or above', category='error')
        elif len(username) < 3:
            flash('Username should be three characters or more', category='error')
        elif len(role) < 2:
            flash('Role Should be 2 characters or more', category='error')
        elif len(email) < 5:
            flash('Email should be 5 characters or more', category='error')
        elif '@' not in email or '.' not in email:
            flash('Email is in correct', category='error')
        elif len(password) < 4:
            flash('Password Should be 4 characters or more', category='error')

        else:
            User = Users.query.filter((Users.username == username) | (Users.email == email)).first()
            if User:
                flash("Username or Email is already taken", category='error')
                print(User)
            else:
                hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                new_user = Users(
                    fullname=fullname,
                    username=username,
                    role=role,
                    email=email,
                    password=hashed_password
                )
                db.session.add(new_user)
                db.session.commit()
                flash(f'Account for {fullname} Created successfully', category='success')
                return redirect(url_for('auth.login'))

    return render_template('register.html')


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
