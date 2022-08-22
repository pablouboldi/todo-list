import os
from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from forms import *
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
Bootstrap(app)

# # CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL",  "sqlite:///todo-list.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Creo un objeto de clase LoginManager
login_manager = LoginManager()
# Le digo al objeto login_manager que trabaje con el objeto app
login_manager.init_app(app)
# Defino la función a la que se dirige por default si el login del usuario es inválido.
login_manager.login_view = "login"


# # CONFIGURE TABLES FOR THE DATABASE
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)

    # User can have many items
    lists = db.relationship('List', backref='owner')


class List(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    complete = db.Column(db.Boolean, nullable=False)
    description = db.Column(db.String(250), nullable=False)

    # Foreign Key to link users (refer to primary key of the user)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


# db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/', methods=["GET", "POST"])
def home():

    try:
        logged_user_id = current_user.id
    except AttributeError:
        logged_user_id = None

    return render_template('index.html', logged_in=current_user.is_authenticated, logged_user_id=logged_user_id)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():

        # I get the email entered in the form of the login route
        email = form.email.data

        # I search for the user with that email in the db
        user = User.query.filter_by(email=email).first()

        # I check if the user exists
        if user:
            # If it does, I get the password entered in the form of the login route
            password_entered = form.password.data

            # I check if the password matches the one stored in the db
            if check_password_hash(user.password, password_entered):
                login_user(user)  # I log in the user
                return redirect(url_for('todo_list'))

            # If the password is invalid I give the user feedback and tell them to try again
            else:
                flash("Wrong password - Try again!")
                return redirect(url_for('login'))

        # If the user does not exist I give them feedback and tell them to try again. Here I could send them to the 'register' route
        else:
            flash("That user does not exist - Try again!")
            return redirect(url_for('login'))
    else:
        return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():

        # I get the data entered in the form
        new_user_email = form.email.data
        new_name = form.name.data

        password = form.password.data
        # I hash the password for security
        new_user_password = generate_password_hash(password=password, method='pbkdf2:sha256', salt_length=8)

        # I check if the user already exists. If they do, I redirect them to the login route
        try:
            new_user = User(name=new_name, email=new_user_email, password=new_user_password)
            db.session.add(new_user)
            db.session.commit()
        except:  # It's an IntegrityError
            flash("That email already exists. Try to login instead")
            return redirect(url_for('login'))

        login_user(new_user)  # I log in the user

        return redirect(url_for('todo_list'))
    else:
        return render_template('register.html', form=form)


@app.route('/list', methods=["GET", "POST"])
def todo_list():
    incomplete = List.query.filter_by(complete=False, user_id=current_user.id).all()
    complete = List.query.filter_by(complete=True, user_id=current_user.id).all()
    return render_template('lists.html', user=current_user.name, incomplete=incomplete, complete=complete)


@app.route('/add', methods=["POST"])
def add():
    new_description = request.form['todoitem']
    new_item = List(complete=False, description=new_description, owner=current_user)
    db.session.add(new_item)
    db.session.commit()

    return redirect(url_for('todo_list'))


@app.route('/delete/<int:item_id>')
def delete(item_id):
    item_to_delete = List.query.get(item_id)
    db.session.delete(item_to_delete)
    db.session.commit()

    return redirect(url_for('todo_list'))


@app.route('/update', methods=["POST"])
def update():
    todo_checkboxes = request.form.getlist('todo-checkbox')
    done_checkboxes = request.form.getlist('done-checkbox')
    for i in todo_checkboxes:
        todo = List.query.filter_by(id=int(i)).first()
        todo.complete = True
    for i in done_checkboxes:
        done = List.query.filter_by(id=int(i)).first()
        done.complete = False
    db.session.commit()

    return redirect(url_for('todo_list'))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)
