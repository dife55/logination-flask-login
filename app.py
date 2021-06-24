from flask import Flask, flash, render_template, redirect, url_for, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import datetime


app = Flask(__name__)
app.config['SECRET_KEY'] = 'Itsnoteasywhenitshard!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    created = db.Column(db.DateTime(80))
    last_seen = db.Column(db.DateTime(80))
    count = db.Column(db.Integer)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=20)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):

    email = StringField("What's your email?",  validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    name = StringField("What should we call you?", validators=[InputRequired()])
    password = PasswordField("Create a password", validators=[InputRequired(), Length(min=8, max=20)])

class UpdateForm(FlaskForm):
    password = PasswordField("Create a new password", validators=[InputRequired(), Length(min=8, max=20)])

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)

                return redirect(url_for('dashboard'))
            
        flash('Invalid email or password. Try again!', 'error')
        return render_template('login.html', form=form)

    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(
            form.password.data, method='sha256')
        new_user = User(email=form.email.data, name=form.name.data, password=hashed_password,
                        created=datetime.datetime.now(), last_seen=datetime.datetime.now(), count=1)
        try:
            db.session.add(new_user)
            db.session.commit()

            flash('Registration form successfully submitted.', 'success')

            return redirect(url_for('login'))
        except:
            flash('The email is already taken. Try a different email.', 'error')
            return redirect('signup')

    return render_template('signup.html', form=form)


@app.route('/delete/<int:id>')
@login_required
def delete(id):
    user_to_delete = User.query.get_or_404(id)

    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        
        flash('The user account has been successfully deleted. Please create a new account if you want to use the logination services.', 'warning')
        return redirect('/signup')
    except:
        flash('There was a problem deleting that user.', 'error')
        return redirect('/signup')


@app.route('/update/<int:id>', methods=['POST', 'GET'])
@login_required
def update(id):
    user_to_update = User.query.get_or_404(id)
    form = UpdateForm()
    
    if form.validate_on_submit():
        user_to_update.password = generate_password_hash(
            form.password.data, method='sha256')
        try:
            db.session.commit()
            flash('Password successfully changed.', 'success')
            return redirect('/signedin')
        except:
            flash('There was a problem changing the password', 'error')
            return redirect('/signedin')
    else:
        return render_template('update.html', user_to_update=user_to_update, form=form, name=current_user.name, id=current_user.id )


@app.route('/signedin')
@login_required
def dashboard():
    return render_template('signedin.html', name=current_user.name, id=current_user.id)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
