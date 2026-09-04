# -*- coding: utf-8 -*-
"""
posts/routes.py
Post management with ECC-ElGamal asymmetric protection and HMAC integrity checks under the hood.
"""

from flask import render_template, url_for, flash, redirect, request, abort, Blueprint
from flask_login import current_user, login_required
from flaskblog import db
from flaskblog.models import Post
from flaskblog.posts.forms import PostForm

posts = Blueprint('posts', __name__)


@posts.route("/posts/new", methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(user_id=current_user.id)
        post.set_post_data(title=form.title.data, content=form.content.data)
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('main.home'))
    return render_template("create_post.html", title="New Post", legend="New Post", form=form)


@posts.route("/posts/<int:post_id>", methods=['GET', 'POST'])
def post(post_id):
    post = Post.query.get_or_404(post_id)
    integrity_ok = post.verify_integrity()
    return render_template('post.html', title=post.title, post=post, integrity_ok=integrity_ok)


@posts.route("/posts/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user and current_user.role != 'admin':
        abort(403)
        
    form = PostForm()
    if form.validate_on_submit():
        post.set_post_data(title=form.title.data, content=form.content.data)
        db.session.commit()
        flash('Your post has been updated!', 'success')
        return redirect(url_for('posts.post', post_id=post.id))
    elif request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content
        
    return render_template("create_post.html", title="Update Post", legend="Update Post", form=form)


@posts.route("/posts/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user and current_user.role != 'admin':
        abort(403)
        
    db.session.delete(post)
    db.session.commit()
    flash('Your post has been deleted.', 'success')
    return redirect(url_for('main.home'))
