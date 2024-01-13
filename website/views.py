from flask import Flask, request, render_template, Blueprint, flash, redirect, url_for
from flask_login import current_user, login_required
from werkzeug.security import generate_password_hash
from .models import Users
from . import db

views = Blueprint('views', __name__)


@views.route('/')
@views.route('/home')
@views.route('index')
@login_required
def home():
    return render_template('index.html', current_user=current_user)


@views.route('/users')
@login_required
def users():
    all_users = Users.query.all()
    return render_template('users.html', users=all_users, current_user=current_user)


@views.route('add-user', methods=['POST', 'GET'])
@login_required
def add_user():
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
                return redirect(url_for('views.users'))

    return render_template('add_user.html', current_user=current_user)


@views.route('/delete-user/<int:user_id>', methods=['POST', 'GET'])
@login_required
def delete_user(user_id):
    user = Users.query.get(user_id)
    if user:
        if user == current_user:
            flash("You can not delete the current user")
        else:
            db.session.delete(user)
            db.session.commit()
            flash(f'Account for {user.fullname} Deleted successfully', category='success')
    return redirect(url_for('views.users'))
