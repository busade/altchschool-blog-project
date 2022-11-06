from flask import Flask, render_template, url_for,flash, redirect,request
from flask_sqlalchemy  import SQLAlchemy
from flask_login import current_user, login_user, logout_user, login_required, LoginManager, UserMixin
from werkzeug.security import generate_password_hash , check_password_hash
from datetime import datetime
import os

base_dir = os.path.dirname(os.path.realpath(__file__))

app = Flask(__name__)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(base_dir, 'the_blog.db') 
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SECRET_KEY'] = 'random21787364'


db = SQLAlchemy(app)
db.init_app(app)
login_manager = LoginManager(app)


class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(80), nullable=False, unique=True)
    password = db.Column(db.Text, nullable=False)
    articles_by = db.relationship(
        "Article", back_populates="created_by", lazy="dynamic")

    def __repr__(self):
        return f"User: <{self.username}>"




class Article(db.Model):
    __tablename__ = "articles"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(40), nullable=False)
    content = db.Column(db.String, nullable=False)
    created_on = db.Column(db.DateTime, default=datetime.now())
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), unique=False, nullable=False)
    author = db.Column(db.String, nullable=False)
    created_by = db.relationship("User", back_populates="articles_by")

    def __repr__(self):
        return f"Article: <{self.title}>"

class Message(db.Model):
    __tablename__ = "messages"
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(20), nullable=False)
    title = db.Column(db.String(40), nullable=False)
    message = db.Column(db.String, nullable=False)
    def __repr__(self):
        return f"Message: <{self.title}>"



@app.before_first_request
def create_tables():
    db.create_all()


@login_manager.user_loader
def user_loader(id):
    return User.query.get(int(id))
    
@app.route('/post', methods=['GET', 'POST'])
@login_required
def post():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        user_id = current_user.id
        author = current_user.username

        title_exists = Article.query.filter_by(title=title).first()
        if title_exists:
            flash("A post with this title already exists. Please choose a new title.")
            return redirect(url_for('post'))

        new_article = Article(title=title, content=content,
                              user_id=user_id, author=author)
        db.session.add(new_article)
        db.session.commit()

        flash("Thanks!")
        return redirect(url_for('article'))

    return render_template('post.html')


@app.route('/')
def index():
    current_year = datetime.now().year
    articles = Article.query.all()
    content = { "articles": articles }
    return render_template('index.html',year= current_year, **content)




@app.route('/contact')
def contact():
    if request.method == 'POST':
        sender = request.form.get('name')
        email = request.form.get('email')
        title = request.form.get('title')
        message = request.form.get('message')

        new_message = Message(sender=sender, email=email, title=title, message=message)
        db.session.add(new_message)
        db.session.commit()

        flash("Thanks for the Message,we will be in touch.")
        return redirect(url_for('index'))
    return render_template('contact.html')


@app.route('/article/<int:id>/')
def article(id):
    article = Article.query.get_or_404(id)

    context = {
        "article": article
    }

    return render_template('article.html', **context)

@app.route('/edit/<int:id>/', methods=['GET', 'POST'])
@login_required
def edit(id):
    post_to_edit = Article.query.get_or_404(id)

    if current_user.username == post_to_edit.author:
        if request.method == 'POST':
            post_to_edit.title = request.form.get('title')
            post_to_edit.content = request.form.get('content')

            db.session.commit()
            flash("Your changes have been saved.")
            return redirect(url_for('index'))

        context = {
            'post': post_to_edit
        }

        return render_template('edit.html', **context)

    flash("You cannot edit another user's article.")
    return redirect(url_for('index'))


@app.route('/delete/<int:id>/', methods=['GET'])
@login_required
def delete(id):
    post_to_delete = Article.query.get_or_404(id)

    if current_user.username == post_to_delete.author:
        db.session.delete(post_to_delete)
        db.session.commit()
        flash("Deleted!")
        return redirect(url_for('index'))

    flash("You cannot delete another user's article.")
    return redirect(url_for('index'))


@app.route('/about')
def about():
    return render_template('about.html')

@app.errorhandler(404)
def page_not_found(e):
    return('Error page not found')




@app.route('/signup', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        user_check = User.query.filter_by(username=username).first()
        if user_check:
            flash("This username already exists.")
            return redirect(url_for('register'))

        email_check = User.query.filter_by(email=email).first()
        if email_check:
            flash("This email is already registered.")
            return redirect(url_for('register'))

        password_hash = generate_password_hash(password, method='pbkdf2:sha256',salt_length=8)
        new_user = User(first_name=first_name,last_name=last_name, username=username, email=email, password=password_hash)
        db.session.add(new_user)
        db.session.commit()

        flash("Thanks for signing up.")
        return redirect(url_for('login'))

    return render_template('signup.html')



@app.route('/login', methods=['GET', 'POST'])
def login():

    username = request.form.get('username')
    password = request.form.get('password')

    if request.method == 'POST':
        user = User.query.filter_by(username=username).first()

        if not user: 
            flash("That Username does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
                flash('Password incorrect, please try again.')
                return redirect(url_for('login'))
        else:
                login_user(user)
                return redirect(url_for('post'))
    return render_template('login.html')
    



@app.route('/logout')
def logout():
    logout_user()
    flash("Bye!.")
    return redirect(url_for('index'))




if __name__=='__main__':
    app.run(debug=True)