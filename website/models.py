from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    username = db.Column(db.String(100))
    password_hash = db.Column(db.String(150))
    date_joined = db.Column(db.DateTime(), default=datetime.utcnow)

    cart_items = db.relationship('Cart', backref=db.backref('user', lazy=True))
    orders = db.relationship('Order', backref=db.backref('user', lazy=True))

    @property
    def password(self):
        raise AttributeError('Password is not a readable Attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password=password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password=password)

    def __str__(self):
        return '<User %r>' % User.id


class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    book_title = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    in_stock = db.Column(db.Boolean, nullable=False)
    image_url = db.Column(db.String(1000), nullable=False)
    published_year = db.Column(db.Integer, nullabe=False)
    description = db.Column(db.String(1500), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    carts = db.relationship('Cart', backref=db.backref('book', lazy=True))
    orders = db.relationship('Order', backref=db.backref('book', lazy=True))

    def __str__(self):
        return '<Book %r>' % self.book_title


class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quantity = db.Column(db.Integer, nullable=False)

    user_link = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_link = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)

    # customer product

    def __str__(self):
        return '<Cart %r>' % self.id


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(100), nullable=False)
    payment_id = db.Column(db.String(1000), nullable=False)

    user_link = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_link = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)


    def __str__(self):
        return '<Order %r>' % self.id


