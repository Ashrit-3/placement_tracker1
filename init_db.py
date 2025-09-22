def init_db():
    with app.app_context():
        # Step 1: Create tables if they don't exist
        db.create_all()  # This ensures the 'user' table exists

        # Step 2: Check for missing columns safely
        conn = sqlite3.connect("placement.db")
        c = conn.cursor()

        # Check if 'user' table exists
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user'")
        if c.fetchone():
            # Table exists, check columns
            c.execute("PRAGMA table_info(user)")
            existing_columns = [col[1] for col in c.fetchall()]
            if "date_created" not in existing_columns:
                c.execute(
                    "ALTER TABLE user ADD COLUMN date_created DATETIME DEFAULT CURRENT_TIMESTAMP"
                )
                print("✅ Added missing column 'date_created'")
        else:
            print("⚠️ Table 'user' does not exist yet, creating via SQLAlchemy db.create_all()")

        conn.commit()
        conn.close()
        print("✅ Database initialized successfully")
