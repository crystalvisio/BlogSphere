# routes/main.py
from flask import Blueprint, render_template
from flask_login import current_user

main_bp = Blueprint('main_bp', __name__)

@main_bp.route("/about")
def about():
    return render_template("about.html", current_user=current_user)

@main_bp.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)
