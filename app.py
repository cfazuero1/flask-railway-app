from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "🚀 Hello from Flask on Railway + VS Code!"

@app.route("/about")
def about():
    return "This is a simple Flask app deployed with Railway."

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
