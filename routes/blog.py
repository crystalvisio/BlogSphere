# routes/blog.py
from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from models import db, BlogPost, Comment
from forms import CreatePostForm, CommentForm
from decorators import admin_only
from datetime import date

blog_bp = Blueprint('blog_bp', __name__)

@blog_bp.route("/")
def home():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, current_user=current_user)

@blog_bp.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = BlogPost.query.get_or_404(post_id)

    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for('auth_bp.login'))

        new_comment = Comment(
            comment=comment_form.comment.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('blog_bp.show_post', post_id=post_id))

    return render_template("post.html", form=comment_form, post=requested_post, current_user=current_user)

@blog_bp.route("/new-post", methods=["GET", "POST"])
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
        return redirect(url_for('blog_bp.home'))
    return render_template("make-post.html", form=create_form, current_user=current_user)

@blog_bp.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get_or_404(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for('blog_bp.show_post', post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)

@blog_bp.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get_or_404(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('blog_bp.home'))
