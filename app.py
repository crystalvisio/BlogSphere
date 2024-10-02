# app.py
import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
ckeditor = CKEditor()
bootstrap = Bootstrap5()
gravatar = Gravatar(
    size=100,
    rating='g',
    default='retro',
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None
)

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DB_URI", "sqlite:///instance/posts.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    ckeditor.init_app(app)
    bootstrap.init_app(app)
    gravatar.init_app(app)

    # Import models to register with SQLAlchemy
    with app.app_context():
        from models import User, BlogPost, Comment
        db.create_all()

    # Register Blueprints
    from routes.auth import auth_bp
    from routes.blog import blog_bp
    from routes.main_2 import main_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(blog_bp)
    app.register_blueprint(main_bp)

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
