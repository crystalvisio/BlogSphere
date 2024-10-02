# routes/auth.py
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import hashlib
import binascii
from models import db, User
from forms import RegisterForm, LoginForm

auth_bp = Blueprint('auth_bp', __name__)

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        email = register_form.email.data
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("You've already signed up with this E-mail! Log in instead.")
            return redirect(url_for('auth_bp.login'))

        # Password hashing (you can use generate_password_hash for simplicity)
        hashed_password = generate_password_hash(register_form.password.data, method='pbkdf2:sha256', salt_length=16)

        new_user = User(
            name=register_form.name.data,
            email=email,
            password=hashed_password
            # If using salt manually, store it here
            # salt=salt
        )
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        return redirect(url_for('main_bp.home'))

    return render_template("register.html", form=register_form, current_user=current_user)

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        password = login_form.password.data

        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            flash("❗ Invalid Email or Password Entered.")
            return redirect(url_for('auth_bp.login'))

        login_user(user)
        return redirect(url_for('main_bp.home'))

    return render_template("login.html", form=login_form, current_user=current_user)

@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('main_bp.home'))
