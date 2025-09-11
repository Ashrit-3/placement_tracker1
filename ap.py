from app import app

if __name__ == "__main__":
    # debug=True for local dev; remove or set False in production
    app.run(debug=True, host="0.0.0.0", port=5000)
