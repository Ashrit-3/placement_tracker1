def init_db():
    with app.app_context():
        db.create_all()
        # Check and create default admin inside app context
        admin_user = User.query.filter_by(username="admin").first()
        if not admin_user:
            admin_user = User(
                username="admin",
                password=generate_password_hash("admin123", method="sha256"),
                skills="",
                is_admin=True
            )
            db.session.add(admin_user)
            db.session.commit()
        print("✅ Database initialized successfully with admin user!")
