import os
from datetime import date
from functools import wraps
from dotenv import load_dotenv
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_bootstrap import Bootstrap5
from sqlalchemy.orm import relationship
from flask_sqlalchemy import SQLAlchemy
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap5(app)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def user_loader(user_id):
    return db.session.get(User, user_id)

gravatar = Gravatar(
    app,
    size=100,
    rating='g',
    default='retro',
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None
)

# CONNECT TO DB
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DB_URI", "sqlite:////instance/posts.db")

db = SQLAlchemy()
db.init_app(app)


# CONFIGURE BLOGPOST TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    
    # ForeignKey to link Users(refer to primary key of the user, one user can have multiple post[One to many relationship])
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    #Create reference to the User object, the "posts" refers to the posts property in the User class.  
    author = relationship("User", back_populates = "posts")

    # Create reference to the Comment object
    comments = relationship("Comment", back_populates="parent_post")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


# CONFIGURE USER TABLE
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(100), nullable = False)
    email = db.Column(db.String(100), unique = True, nullable = False)
    password = db.Column(db.String(100), nullable = False)

    # User can have many posts and also many comments 
    posts = db.relationship("BlogPost", back_populates = "author")
    comments = relationship("Comment", back_populates = "comment_author")


# CONFIGURE COMMENT TABLE
class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key = True)
    comment = db.Column(db.Text, nullable = False)

    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    comment_author = relationship("User", back_populates = "comments")

    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


with app.app_context():
    db.create_all()


# Create Admin Decorator
def admin_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        admin = db.session.execute(db.select(User).where(User.id == 1)).scalar()
        if not admin:
            abort(403)
        return function(*args, **kwargs)
    return wrapper


@app.route("/")
def home():
    posts = db.session.execute(db.select(BlogPost)).scalars().all()
    return render_template("index.html", all_posts=posts, current_user = current_user)


@app.route("/register", methods  = ["GET", "POST"])
def register():
    register_form = RegisterForm()
    if request.method == "POST":
        email = request.form.get("email")
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()

        if user:
            flash("You've already signed up with this E-mail! Log in Instead")
            return redirect(url_for("login"))
        
        else:
            new_user = User(
                name = request.form.get("name"),
                email = email,
                password = generate_password_hash(request.form.get("password"), method = "pbkdf2", salt_length = 20)
            )
            db.session.add(new_user)
            db.session.commit()

            # This line will authenticate the user with Flask-Login
            login_user(new_user)
            return redirect(url_for("home"))

    return render_template("register.html", form = register_form, current_user = current_user)


# TODO: Retrieve a user from the database based on their email. 
@app.route("/login", methods = ["GET", "POST"])
def login():
    login_form = LoginForm()
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        valid_password = check_password_hash(user.password, password)

        if not user or not valid_password:
            flash("❗ Invalid Email or Password Entered.")
            return redirect(url_for("login"))
        
        else:
            login_user(user)
            return redirect(url_for("home"))
            
    return render_template("login.html", form = login_form, current_user = current_user)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("home"))


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods = ["GET", "POST"])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = db.get_or_404(BlogPost, post_id)

    if request.method == "POST":
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))

        new_comment = Comment(
            comment = request.form.get("comment"),
            comment_author = current_user,
            parent_post = requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id = post_id))

    return render_template("post.html", form = comment_form, post=requested_post, current_user = current_user)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@login_required
@admin_only
def add_new_post():
    create_form = CreatePostForm()
    if create_form.validate_on_submit():
        new_post = BlogPost(
            title=create_form.title.data,
            subtitle=create_form.subtitle.data,
            body=create_form.body.data,
            img_url=create_form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("home"))
    return render_template("make-post.html", form=create_form, current_user = current_user)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, current_user = current_user)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for("home"))


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)


if __name__ == "__main__":
    app.run(debug=True)
