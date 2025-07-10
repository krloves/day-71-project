from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, CreateRegisterForm, CreateLoginForm, CreateCommentForm
from typing import List
import os

'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
print(os.environ.get('SECRET_KEY'))
app.config['CKEDITOR_PKG_TYPE'] = 'full'
ckeditor = CKEditor(app)
Bootstrap5(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


def admin_only(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        # Code before the function runs
        if current_user.is_authenticated and current_user.get_id()=='1':
            return f(*args, **kwargs)
        # Code after the function runs
        else:
            return abort(403)
    return wrapper


# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_URI', 'sqlite:///posts.db')
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CONFIGURE TABLES
# TODO: Create a User table for all your registered users.
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)
    username: Mapped[str] = mapped_column(String(250), nullable=False)

    # create relationship parent (User) -> children (BlogPost & Comments)

    # populate list of posts once User and BlogPost is connected via author_id (see BlogPost comment)
    posts: Mapped[List["BlogPost"]] = relationship(back_populates="author")
    # populate list of comments once User and Comment is connected via author_id (see Comment comment)
    comments: Mapped[List["Comment"]] = relationship(back_populates="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)

    # create relationship parent (User) -> child (BlogPost)
    # on users.id = bloc_posts.author_id
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('users.id'), nullable=False)
    author: Mapped["User"] = relationship(back_populates="posts")

    # create relationship parent (BlogPost) -> child (Comments)
    # populate list of Comments once BlogPost and Comment is connected via post_id (see Comment comment)
    comments: Mapped[List["Comment"]] = relationship(back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(String(250), nullable=False)

    # create relationship parent (User) -> child (Comment)
    # on users.id = comments.author_id
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('users.id'), nullable=False)
    author: Mapped["User"] = relationship(back_populates="comments")

    # create relationship parent (BlogPost) -> child (Comment)
    # on blog_posts.id = comments.post_id
    post_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('blog_posts.id'))
    parent_post: Mapped["BlogPost"] = relationship(back_populates="comments")



with app.app_context():
    db.create_all()


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = CreateRegisterForm()


    if form.validate_on_submit():
        check_email_in_db = db.session.execute(db.select(User).where(User.email == form.email.data)).scalars().first()

        if check_email_in_db:
            flash('That email is already in use.')
            return redirect(url_for('register'))

        else:
            hashed_password_salted = generate_password_hash(
                form.password.data,
                method='pbkdf2:sha256',
                salt_length=8
            )

            new_user = User(
                email=form.email.data,
                password=hashed_password_salted,
                username=form.name.data
            )

            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=form)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = CreateLoginForm()

    if form.validate_on_submit():
        user_in_db = db.session.execute(db.select(User).where(User.email == form.email.data)).scalars().first()
        if user_in_db:
            if check_password_hash(user_in_db.password, form.password.data):
                login_user(user_in_db)
                return redirect(url_for('get_all_posts'))
            else:
                flash('Login Unsuccessful. Please check password.')
        else:
            flash('Login Unsuccessful. This email is not registered.')

        redirect(url_for('login'))

    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template(
        "index.html",
        all_posts=posts,
        logged_in=current_user.is_authenticated,
        user_id=current_user.get_id())


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    form = CreateCommentForm()
    blog_comments = db.session.execute(db.Select(Comment).where(Comment.post_id == post_id)).scalars().all()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                text=form.comment.data,
                author_id=current_user.get_id(),
                post_id=post_id,
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
        else:
            flash('You need to login first.')
            return redirect(url_for('login'))

    return render_template(
        "post.html",
        post=requested_post,
        user_id=current_user.get_id(),
        form=form,
        logged_in=current_user.is_authenticated,
        blog_comments=blog_comments)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
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
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True, port=5002)
