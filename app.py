from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'yoursecretkey'  # Add a secret key for CSRF protection
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shops.db'  # Path to your database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Avoids SQLAlchemy warnings

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

# Loading user for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Shop model
class Shop(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(200), nullable=True)
    location = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    rating = db.Column(db.Float, nullable=True)
    products = db.relationship('Product', backref='shop', lazy=True)

    def __repr__(self):
        return f'<Shop {self.name}>'

# Product model
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(200), nullable=True)
    price = db.Column(db.Float, nullable=False)
    image_url = db.Column(db.String(255), nullable=True)
    shop_id = db.Column(db.Integer, db.ForeignKey('shop.id'), nullable=False)

    def __repr__(self):
        return f'<Product {self.name}>'

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user is None:
            hashed_password = generate_password_hash(form.password.data)
            new_user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Email already registered. Please use a different email or log in.', 'danger')

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password. Please try again.', 'danger')

    return render_template('login.html', form=form)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

@app.route('/shop_directory', methods=['GET', 'POST'])
def shop_directory():
    search = request.form.get('search', '').lower()
    category = request.form.get('category', 'All')
    categories = ['All', 'Food', 'Groceries', 'Clothing', 'Books', 'Dairy', 'Electronics', 'Furniture', 'Automotive', 'Home & Garden']

    query = Shop.query
    if search:
        query = query.filter((Shop.name.ilike(f"%{search}%")) | (Shop.location.ilike(f"%{search}%")))
    if category != 'All':
        query = query.filter_by(category=category)

    filtered_shops = query.all()
    return render_template('shop_directory.html', shops=filtered_shops, category=category, categories=categories)

@app.route('/shop/<int:shop_id>', methods=['GET'])
def shop_detail(shop_id):
    shop = Shop.query.get_or_404(shop_id)
    products = Product.query.filter_by(shop_id=shop_id).all()  # Get all products for the shop
    return render_template('shop_detail.html', shop=shop, products=products)

@app.route('/about', methods=['GET'])
def about_page():
    return render_template('about.html')

@app.route('/feedback', methods=['POST'])
def feedback():
    feedback_text = request.form.get('feedback')
    if feedback_text:
        flash("Thank you for your feedback!", "success")
    else:
        flash("Please provide valid feedback.", "danger")
    return redirect(url_for('contact'))

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        # Process the form data
        owner_name = request.form.get('owner_name')
        shop_name = request.form.get('shop_name')
        contact_email = request.form.get('contact_email')
        contact_phone = request.form.get('contact_phone')

        # Log or save the details here (e.g., save to a database)

        # Flash a success message
        flash("Thank you for your details! We will reach out to you soon.")
        return redirect(url_for('contact'))

    return render_template('contact.html')


@app.route('/')
def home():
    featured_shops = Shop.query.limit(6).all()  # Limit the number of featured shops
    return render_template('home.html', featured_shops=featured_shops)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure the database is created
    app.run(debug=True)
