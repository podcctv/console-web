from app.main import app

if __name__ == "__main__":
    try:
        app.run(host="::", port=8080)
    except Exception:
        app.run(host="0.0.0.0", port=8080)

