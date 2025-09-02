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
from flask_login import login_required, current_user
from flask import request, render_template, redirect, url_for, flash, session
from flask import send_from_directory

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

QUESTIONS = [
    "What is your favorite teacher’s last name?",
    "In what city were you born?",
    "What was the name of your first pet?",
    "What is the title of your favorite movie?",
    "What street did you live on at age 10?",
    "What was your childhood nickname?",
    "Custom…"
]

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

@app.context_processor
def inject_globals():
    return {"SECURITY_QUESTIONS": QUESTIONS}

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

    # security questions
    sq1 = db.Column(db.String(255))
    sq2 = db.Column(db.String(255))
    sq3 = db.Column(db.String(255))
    sa1_hash = db.Column(db.String(255))
    sa2_hash = db.Column(db.String(255))
    sa3_hash = db.Column(db.String(255))

    def set_password(self, pw: str):
        self.password_hash = bcrypt.generate_password_hash(pw).decode("utf-8")

    def check_password(self, pw: str) -> bool:
        return bcrypt.check_password_hash(self.password_hash, pw)

    @staticmethod
    def _norm(ans: str) -> str:
        return (ans or "").strip().lower()

    @staticmethod
    def _hash_ans(ans: str) -> str:
        return bcrypt.generate_password_hash(User._norm(ans)).decode("utf-8")

    @staticmethod
    def _check_ans(hash_value: str, attempt: str) -> bool:
        return bcrypt.check_password_hash(hash_value or "", User._norm(attempt))

    @property
    def has_security_questions(self) -> bool:
        return bool(self.sq1 and self.sq2 and self.sq3 and self.sa1_hash and self.sa2_hash and self.sa3_hash)
    
    def set_security_answers(self, a1, a2, a3):
            self.sa1_hash = self._hash_ans(a1)
            self.sa2_hash = self._hash_ans(a2)
            self.sa3_hash = self._hash_ans(a3)

    def check_all_answers(self, a1: str, a2: str, a3: str) -> bool:
        return (
            self._check_ans(self.sa1_hash, a1) and
            self._check_ans(self.sa2_hash, a2) and
            self._check_ans(self.sa3_hash, a3)
        )

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
        username = (request.form.get("username") or "").strip()
        email    = (request.form.get("email") or "").strip().lower()
        pw1      = request.form.get("password") or ""
        pw2      = request.form.get("password2") or ""

        if pw1 != pw2:
            return render_template("register.html", error="Passwords must match")

        if User.query.filter((User.username == username) | (User.email == email)).first():
            return render_template("register.html", error="Username or email already exists")

        # Pick selected or custom question text
        sel1 = request.form.get("sq1_sel", "") or ""
        sel2 = request.form.get("sq2_sel", "") or ""
        sel3 = request.form.get("sq3_sel", "") or ""

        # Accept both unicode ellipsis and three dots
        def is_custom(v: str) -> bool:
            return v.strip() in ("Custom…", "Custom...")

        sq1 = (request.form.get("sq1") or "").strip() if is_custom(sel1) else sel1.strip()
        sq2 = (request.form.get("sq2") or "").strip() if is_custom(sel2) else sel2.strip()
        sq3 = (request.form.get("sq3") or "").strip() if is_custom(sel3) else sel3.strip()

        sa1 = request.form.get("sa1") or ""
        sa2 = request.form.get("sa2") or ""
        sa3 = request.form.get("sa3") or ""

        if not (sq1 and sq2 and sq3 and sa1 and sa2 and sa3):
            return render_template("register.html", error="Please complete the security questions.")

        # Create the user and persist Qs + hashed answers
        user = User(username=username, email=email)
        user.set_password(pw1)                  # your helper
        user.sq1, user.sq2, user.sq3 = sq1, sq2, sq3
        user.set_security_answers(sa1, sa2, sa3)  # hashes and stores sa*_hash

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
        identifier = (request.form.get("username_or_email") or "").strip().lower()
        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier)
        ).first()
        if not user:
            flash("No such user.", "danger")
            return redirect(url_for("forgot_password"))

        # If user has questions
        if not user.has_security_questions:
            flash("This account has no security questions set.", "warning")
            return redirect(url_for("forgot_password"))

        # Store user id temporarily in session
        session["reset_user_id"] = user.id
        return redirect(url_for("answer_questions"))

    return render_template("forgot_password.html")


@app.route("/answer-questions", methods=["GET", "POST"])
def answer_questions():
    uid = session.get("reset_user_id")
    if not uid:
        return redirect(url_for("forgot_password"))
    user = User.query.get(uid)
    if not user:
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        a1 = request.form.get("sa1") or ""
        a2 = request.form.get("sa2") or ""
        a3 = request.form.get("sa3") or ""
        if user.check_all_answers(a1, a2, a3):
            session["verified_reset"] = True
            return redirect(url_for("reset_password"))
        else:
            flash("Answers did not match. Try again.", "danger")

    return render_template("answer_questions.html", user=user)


# --- Reset password ---
@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    uid = session.get("reset_user_id")
    ok  = session.get("verified_reset")
    if not uid or not ok:
        return redirect(url_for("forgot_password"))

    user = User.query.get(uid)
    if not user:
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        pw1 = request.form.get("password") or ""
        pw2 = request.form.get("password2") or ""
        if pw1 != pw2:
            flash("Passwords must match.", "danger")
        else:
            user.set_password(pw1)
            db.session.commit()
            session.pop("reset_user_id", None)
            session.pop("verified_reset", None)
            flash("Password has been reset. You can log in now.", "success")
            return redirect(url_for("login"))

    return render_template("reset_password.html")


@app.route("/security-questions", methods=["GET", "POST"], endpoint='security-questions')
@login_required
def set_security_questions():
    # Only allow if the user hasn't set them yet OR you can relax this if you want edits
    if current_user.has_security_questions:
        flash("Your security questions are already set.", "info")
        return redirect(url_for("index"))

    if request.method == "POST":
        # Selected options
        sel1 = request.form.get("sq1_sel", "")
        sel2 = request.form.get("sq2_sel", "")
        sel3 = request.form.get("sq3_sel", "")

        # If “Custom…”, use the provided custom text
        sq1 = request.form.get("sq1_custom", "").strip() if sel1 == "Custom…" else sel1
        sq2 = request.form.get("sq2_custom", "").strip() if sel2 == "Custom…" else sel2
        sq3 = request.form.get("sq3_custom", "").strip() if sel3 == "Custom…" else sel3

        a1 = request.form.get("sa1", "")
        a2 = request.form.get("sa2", "")
        a3 = request.form.get("sa3", "")

        # Basic validation
        if not (sq1 and sq2 and sq3 and a1 and a2 and a3):
            return render_template("security_setup.html", error="Please complete all fields.")

        # Persist
        current_user.sq1, current_user.sq2, current_user.sq3 = sq1, sq2, sq3
        current_user.set_security_answers(a1, a2, a3)
        db.session.commit()

        flash("Security questions saved.", "success")
        return redirect(url_for("index"))

    return render_template("security_setup.html")

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, 'static'),
        'favicon.ico',
        mimetype='image/x-icon'
    )

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
