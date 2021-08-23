from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CreateCommentForm, RegisterForm, LoginForm
from flask_gravatar import Gravatar
from functools import wraps
import os


app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///blog.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

db = SQLAlchemy(app)


##CONFIGURE TABLES


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), unique=True, nullable=False)
    name = db.Column(db.String(250), nullable=False)
    # blog_posts = relationship("BlogPost", back_populates="author")
    blog_posts = relationship("BlogPost", backref="author")
    comments = relationship("Comment", backref="commenter")
    # comments = relationship("Comment", back_populates="user")



class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    # author = relationship("User", back_populates="blog_posts")
    comments = relationship('Comment', backref="post")
    # comments = relationship('Comment', back_populates="post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.String(250), nullable=True)
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'), nullable=False)
    # post = relationship("BlogPost", back_populates='comments')
    commenter_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    # user = relationship('User', back_populates='comments')

# one to manyについて
# ForeingnKey外部キー(親テーブルのid)を子テーブル(blog_posts)に設定する
# authorにUserインスタンスが入るとそれがもつidを取り出してauthor_idに入いり、
# 一方そのUserインスタンスのblog_postsには外部キーauthor_idの値をもつblogpostが全て入る

# manyの方にoneからの外部キーを設定して、それに対応するoneインスタンスが入るプロパティをrelationship()で設定してoneと紐づける。
# 逆にoneの方でも自身の外部キー(ここではPKのid)に応じたmanyインスタンスが入るプロパティをrelationship()で設定してmanyへの紐づけを行う。
# その際には対応するエンティティ(クラス)のどのプロパティに紐づいているを互いにback_populatesパラメータで明示する

# ①manyの方にoneからの外部キーを設定して、
# ②oneの方でrelationship()を使い、manyとの紐づけを行う。パラメーターとしてmanyのクラス名,manyに作成されるプロパティ名を入れる
# ③manyには自動的にoneのクラスが入るプロパティが作成され、①で設定したプロパティに外部キーが入り、oneには外部キーに該当するoneオブジェクトがリストで入る

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.get_id() == "1":
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function

db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(user_id)

@app.route('/')
def get_all_posts():
    # print(current_user.blog_posts)
    posts = BlogPost.query.all()

    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['POST', 'GET'])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        inputted_email = register_form.email.data
        inputted_password = register_form.password.data
        inputted_name = register_form.name.data

        user = db.session.query(User).filter_by(email=inputted_email).first()
        if user:
            flash('You have signed up with that email. Please login.')
            return redirect(url_for('login'))

        hashed_and_salted_password = generate_password_hash(inputted_password)

        new_user = User(
            email=inputted_email,
            password=hashed_and_salted_password,
            name=inputted_name
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=register_form)


@app.route('/login', methods=['POST', 'GET'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        inputted_email = login_form.email.data
        inputted_password = login_form.password.data
        user = db.session.query(User).filter_by(email=inputted_email).first()
        if not user:
            flash('The email does not exist. Please try again.')
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, inputted_password):
            flash('Password incorrect. Please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=login_form)

# logout = decorated_view

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

# @app.route("/post")
@app.route("/post/<int:post_id>", methods=['POST', 'GET'])
def show_post(post_id):
    comment_form = CreateCommentForm()
    requested_post = BlogPost.query.get(post_id)
    # print(requested_post.author.email)
    all_comments = requested_post.comments
    # print(all_comments[0].author.email)
    # all_comments = db.session.query(Comment).filter_by(post_id=post_id).all()
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash('You need to login or register to comment')
            return redirect(url_for('login'))
        # 上からコードを読んで親テーブルでリレーションされた順、その際に設定されたプロパティんに引数を入れなければならない。
        # 逆にすると何故か片方生成されない
        new_comment = Comment(
            comment=comment_form.body.data,
            commenter=current_user,
            post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id))
    return render_template("post.html", post=requested_post, form=comment_form, comments=all_comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['POST', 'GET'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            author=current_user,
            img_url=form.img_url.data,
            date=date.today().strftime("%B %d, %Y"),
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['POST', 'GET'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
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
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run()
