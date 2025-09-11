from app import app, db

with app.app_context():
    db.drop_all()      # Drops the old database if exists
    db.create_all()    # Creates new database with updated tables
    print("Database reset successfully!")
