from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from werkzeug.security import check_password_hash
from datetime import datetime
from app.extensions import bcrypt, db

Base = declarative_base()

class User(db.Model):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password = Column(String(128), nullable=False)
    gender = Column(String(20))
    phone_number = Column(String(20))
    role = Column(String(20), default='customer')  # e.g., customer, admin
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Define remaining relationships as needed
    # orders = relationship('Order', back_populates='user')
    # reviews = relationship('Review', back_populates='user')
    # wishlists = relationship('Wishlist', back_populates='user')
    # notifications = relationship('Notification', back_populates='user')

    def __init__(self, name, email, password, role='customer', phone_number=None, gender=None):
        self.name = name
        self.email = email
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
        self.role = role
        self.phone_number = phone_number
        self.gender = gender

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    def get_full_name(self):
        return self.name

    def __repr__(self):
        return f"<User(id={self.id}, name={self.name}, email={self.email}, role={self.role})>"

    @staticmethod
    def create_user(name, email, password, role='customer', phone_number=None, address=None):
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return {"error": "Email already exists"}, 400
        new_user = User(name, email, password, role, phone_number, address)
        db.session.add(new_user)
        db.session.commit()
        return {"message": "User created successfully"}, 201