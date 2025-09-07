import os
from app import db

# Path to your database
db_path = "placement.db"

# Delete the old database if it exists
if os.path.exists(db_path):
    os.remove(db_path)
    print("✅ Old database removed")

# Recreate a new one
db.create_all()
print("✅ New database created successfully!")
