from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
# app.py (additions)
from flask_sock import Sock
import json, threading, paramiko
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from dotenv import load_dotenv
import requests
import logging
from flask import render_template



# === Load environment ===
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

# === Config ===
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SECURITY_PASSWORD_SALT'] = os.getenv("SECURITY_PASSWORD_SALT")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL", "sqlite:///site.db")

# Mail
app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER", "smtp.gmail.com")
app.config['MAIL_PORT'] = int(os.getenv("MAIL_PORT", "587"))
app.config['MAIL_USE_TLS'] = os.getenv("MAIL_USE_TLS", "True").lower() in ("true","1","yes")
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_DEFAULT_SENDER")
# --- config (after load_dotenv/app = Flask(...)) ---
app.config['CONTACT_EMAIL'] = os.getenv("CONTACT_EMAIL")


# reCAPTCHA
RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'error'
mail = Mail(app)
ts = URLSafeTimedSerializer(app.config['SECRET_KEY'])

sock = Sock(app)  # after you create `app = Flask(__name__)`

@app.route("/_health")
def health():
    return "ok", 200

@app.route("/_debug/test-mail")
def test_mail():
    try:
        # Force the recipient to be your fixed address
        to_addr = "info@hackerescaperoom.com"
        msg = Message(
            "Mail test",
            recipients=[to_addr],
            body="Mail path OK. This is a test email from your Flask app."
        )
        mail.send(msg)
        return f"Mail sent to {to_addr}", 200
    except Exception as e:
        app.logger.exception("Mail test failed")
        return f"Mail failed: {e}", 500

logging.basicConfig(level=logging.INFO)

@app.errorhandler(Exception)
def handle_all_errors(e):
    app.logger.exception("Unhandled exception")
    # You can create templates/500.html if you want something nicer
    return render_template("500.html"), 500

@sock.route('/ws/ssh')
def ws_ssh(ws):
    """
    WebSocket bridge: first message must be JSON with
    { "host": "...", "port": 22, "user": "...", "password": "..." }
    Then we shuttle bytes between the browser and the SSH channel.
    """
    client = None
    chan = None
    try:
        # 1) Receive connection params
        conf_raw = ws.receive()
        if not conf_raw:
            ws.send('*** No connection parameters received.\r\n')
            return
        conf = json.loads(conf_raw)
        host = conf.get("host", "").strip()
        port = int(conf.get("port", 22) or 22)
        user = conf.get("user", "").strip()
        password = conf.get("password", "")

        if not (host and user):
            ws.send('*** Missing host or user.\r\n')
            return

        # 2) SSH connect
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=host, port=port,
            username=user, password=password,
            look_for_keys=False, allow_agent=False, timeout=15
        )

        chan = client.invoke_shell(term='xterm')
        chan.settimeout(0.0)  # non-blocking
        ws.send(f'*** Connected to {host}:{port} as {user}\r\n')

        # 3) Reader thread: SSH -> WS
        def pump_ssh_to_ws():
            try:
                while True:
                    if chan.recv_ready():
                        data = chan.recv(4096)
                        if not data:
                            break
                        ws.send(data.decode('utf-8', 'ignore'))
                    if chan.closed or not ws.connected:
                        break
            except Exception:
                pass
            finally:
                try:
                    client.close()
                except Exception:
                    pass

        t = threading.Thread(target=pump_ssh_to_ws, daemon=True)
        t.start()

        # 4) Main loop: WS -> SSH
        while True:
            msg = ws.receive()
            if msg is None:
                break
            # xterm.js sends text; keep bytes safe
            if isinstance(msg, str):
                chan.send(msg)
            else:
                try:
                    chan.send(msg.decode('utf-8', 'ignore'))
                except Exception:
                    pass

    except Exception as e:
        try:
            ws.send(f'*** Connection error: {e}\r\n')
        except Exception:
            pass
    finally:
        try:
            if chan:
                chan.close()
        except Exception:
            pass
        try:
            if client:
                client.close()
        except Exception:
            pass
# --- About ---
@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/thanks")
def thanks():
    return render_template("thanks.html")

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip()
        body = (request.form.get("message") or "").strip()

        if not (name and email and body):
            return render_template("contact.html", error="Please fill in all fields.")

        try:
            msg = Message(
                subject=f"[Hacker Escape Room] Contact from {name}",
                recipients=[app.config["CONTACT_EMAIL"]],
                reply_to=email,
            )
            msg.body = f"From: {name} <{email}>\n\n{body}"
            mail.send(msg)
            return render_template("contact.html", message="Thank you! Your message has been sent.")
        except Exception as e:
            # Optional: log(e)
            return render_template("contact.html", error="Sorry, we couldn't send your message right now.")
    env_info = {
        "FLASK_ENV": os.getenv("FLASK_ENV"),
        "MAIL_SERVER": os.getenv("MAIL_SERVER"),
        "MAIL_PORT": os.getenv("MAIL_PORT"),
        "MAIL_DEFAULT_SENDER": os.getenv("MAIL_DEFAULT_SENDER"),
        "CONTACT_EMAIL": os.getenv("CONTACT_EMAIL"),
        "RECAPTCHA_ENABLED": os.getenv("RECAPTCHA_ENABLED"),
    }
    return render_template("contact.html")

# === Models ===
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/console1")
def console():
    return render_template("console1.html")

@app.route("/heroes")
def heroes():
    return render_template("heroes.html")
# === Routes ===
@app.route("/")
def index():
    return render_template("index.html")

# --- Register ---
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username").strip()
        email    = request.form.get("email").strip().lower()
        pw1      = request.form.get("password")
        pw2      = request.form.get("password2")

        if pw1 != pw2:
            return render_template("register.html", error="Passwords must match")

        if User.query.filter((User.username==username)|(User.email==email)).first():
            return render_template("register.html", error="Username or email already exists")

        hashed = bcrypt.generate_password_hash(pw1).decode()
        user = User(username=username, email=email, password_hash=hashed)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for("index"))

    return render_template("register.html")

# --- Login with reCAPTCHA ---
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        # Verify reCAPTCHA
        recaptcha_response = request.form.get("g-recaptcha-response")
        payload = {
            'secret': RECAPTCHA_SECRET_KEY,
            'response': recaptcha_response
        }
        r = requests.post("https://www.google.com/recaptcha/api/siteverify", data=payload)
        result = r.json()
        if not result.get("success"):
            return render_template("login.html", error="reCAPTCHA verification failed",
                                   recaptcha_site_key=RECAPTCHA_SITE_KEY)

        username = request.form.get("username").strip()
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()
        if not user or not bcrypt.check_password_hash(user.password_hash, password):
            return render_template("login.html", error="Invalid credentials",
                                   recaptcha_site_key=RECAPTCHA_SITE_KEY)

        login_user(user)
        return redirect(url_for("index"))

    return render_template("login.html", error=None, recaptcha_site_key=RECAPTCHA_SITE_KEY)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))

# --- Forgot password ---
@app.route("/forgot", methods=["GET","POST"], endpoint='forgot')
def forgot_password():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        user = User.query.filter_by(email=email).first()
        if user:
            token = ts.dumps(user.email, salt=app.config['SECURITY_PASSWORD_SALT'])
            reset_url = url_for("reset_password", token=token, _external=True)

            try:
                msg = Message("Reset your password", recipients=[user.email])
                msg.body = f"Hi {user.username},\n\nClick to reset your password:\n{reset_url}\n\nLink expires in 1 hour."
                mail.send(msg)
            except Exception:
                print(f"[DEV] Reset link for {user.email}: {reset_url}")

        return render_template("forgot_password.html", message="If that email exists, a reset link has been sent.")

    return render_template("forgot_password.html")

# --- Reset password ---
@app.route("/reset/<token>", methods=["GET","POST"])
def reset_password(token):
    try:
        email = ts.loads(token, saltforgot=app.config["SECURITY_PASSWORD_SALT"], max_age=3600)
    except SignatureExpired:
        return render_template("reset_password.html", token=token, error="Link expired")
    except BadSignature:
        return render_template("reset_password.html", token=token, error="Invalid link")

    if request.method == "POST":
        pw1 = request.form.get("password"); pw2 = request.form.get("password2")
        if pw1 != pw2 or len(pw1) < 8:
            return render_template("reset_password.html", token=token, error="Passwords must match and be ≥ 8 chars.")

        user = User.query.filter_by(email=email).first()
        if not user:
            return render_template("reset_password.html", token=token, error="Account not found")

        user.password_hash = bcrypt.generate_password_hash(pw1).decode()
        db.session.commit()
        return render_template("reset_password.html", token=token, message="Password updated. You can now log in.")

    return render_template("reset_password.html", token=token)

@app.route("/rooms")
@login_required
def rooms():
    return render_template("rooms.html")

@app.route("/room1")
@login_required
def room1():
    console_url = os.getenv("CONSOLE_URL", "https://kali-linux-docker-production-d6f3.up.railway.app/")
    return render_template("room1.html", console_url=console_url)

# === Room 2 page ===
@app.route("/room2")
def room2():
    return render_template("room2.html")

# === Flag verification endpoint for Room 2 ===
@app.route("/rooms/2/verify", methods=["POST"])
def room2_verify():
    # Room 1 correct flag (exact string you gave)
    FLAG1 = "b9c3a97ef1f633816380333d549b7412e5d173379575cd2597d41c4037795160"

    try:
        data = request.get_json(silent=True) or {}
        submitted = (data.get("flag") or "").strip()
        ok = (submitted == FLAG1)
        return jsonify({"ok": ok})
    except Exception:
        return jsonify({"ok": False}), 400

# --- Room 3 page ---
@app.route("/room3")
def room3():
    return render_template("room3.html")

# --- Room 3 flag check (currently same flag as Room 1) ---
@app.route("/room3_verify", methods=["POST"])
def room3_verify():
    FLAG1 = "thisisnotavaliable"
    data = request.get_json(silent=True) or {}
    submitted = (data.get("flag") or "").strip()
    return jsonify({"ok": submitted == FLAG1})

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
