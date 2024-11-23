from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from app.extensions import db, bcrypt

# Initialize Flask extensions
db = SQLAlchemy()  # Ensure db is initialized here if it's not in app.extensions
migrate = Migrate()  # Initialize migrate here

def create_app():
    app = Flask(__name__)

    # Load configuration
    app.config.from_object('config.Config')

    # Set up JWT
    app.config['JWT_SECRET_KEY'] = '12345'

    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    migrate.init_app(app, db)  # Properly initialize migrate
    jwt = JWTManager(app)  # Initialize JWTManager

    # Import models
    from app.models.user import User

    # Import controllers (register your blueprints here)
    # Example:
    from app.controllers.user_controller import user_bp
    # app.register_blueprint(user_bp, url_prefix='/api/v1/users')

    @app.route('/')
    def home():
        return "Welcome to Women In Tec"

    @app.route('/protected')
    @jwt_required()
    def protected():
        current_user_id = get_jwt_identity()
        return jsonify(logged_in_as=current_user_id), 200

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
