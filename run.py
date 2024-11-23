from flask import Flask
from app import create_app, db  # Ensure `db` is imported from your app
from app.models.user import User  # Import all models here for migrations

app = create_app()

# Import models for Alembic to recognize schema changes
with app.app_context():
    from app.models.user import User  # Import all models explicitly

if __name__ == "__main__":
    app.run(debug=True)
