from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)

# ==========================================
# SECRET KEY
# ==========================================

app.secret_key = os.getenv(
    "SECRET_KEY",
    "codequest-development-key"
)

DATABASE = "codequest.db"


# ==========================================
# DATABASE CONNECTION
# ==========================================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# ==========================================
# CREATE DATABASE AND TABLE
# ==========================================

def create_database():

    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            points INTEGER DEFAULT 0,
            level INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


create_database()


# ==========================================
# HOME PAGE
# ==========================================

@app.route("/")
def home():

    return render_template("index.html")


# ==========================================
# SIGNUP
# ==========================================

@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        username = request.form["username"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        # Check empty fields
        if not username or not email or not password:
            return "Please fill all required fields!"

        # Check password
        if password != confirm_password:
            return "Passwords do not match!"

        # Hash password
        hashed_password = generate_password_hash(password)

        try:

            conn = get_db()

            # Create user
            conn.execute("""
                INSERT INTO users
                (username, email, password)
                VALUES (?, ?, ?)
            """, (
                username,
                email,
                hashed_password
            ))

            conn.commit()

            # Get newly created user
            user = conn.execute("""
                SELECT *
                FROM users
                WHERE username = ?
            """, (username,)).fetchone()

            conn.close()

            # Automatically log the player in
            session["user_id"] = user["id"]
            session["username"] = user["username"]

            # Go directly to dashboard
            return redirect("/dashboard")

        except sqlite3.IntegrityError:

            return """
            <h2>Username or email already exists!</h2>
            <a href="/signup">Try again</a>
            """

        except Exception as e:

            return f"Database error: {e}"

    return render_template("signup.html")


# ==========================================
# LOGIN
# ==========================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username_or_email = request.form["username"].strip()
        password = request.form["password"]

        conn = get_db()

        user = conn.execute("""
            SELECT *
            FROM users
            WHERE username = ? OR email = ?
        """, (
            username_or_email,
            username_or_email
        )).fetchone()

        conn.close()

        # User doesn't exist
        if user is None:

            return """
            <h2>User not found!</h2>
            <a href="/login">Try again</a>
            """

        # Check password
        if check_password_hash(
            user["password"],
            password
        ):

            # Save login session
            session["user_id"] = user["id"]
            session["username"] = user["username"]

            # Go to dashboard
            return redirect("/dashboard")

        else:

            return """
            <h2>Incorrect password!</h2>
            <a href="/login">Try again</a>
            """

    return render_template("login.html")


# ==========================================
# DASHBOARD
# ==========================================

@app.route("/dashboard")
def dashboard():

    # Check login
    if "user_id" not in session:

        return redirect("/login")

    conn = get_db()

    user = conn.execute("""
        SELECT *
        FROM users
        WHERE id = ?
    """, (
        session["user_id"],
    )).fetchone()

    conn.close()

    # If user doesn't exist
    if user is None:

        session.clear()

        return redirect("/login")

    return render_template(
        "dashboard.html",
        user=user
    )


# ==========================================
# LOGOUT
# ==========================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")


# ==========================================
# HEALTH CHECK
# ==========================================

@app.route("/health")
def health():

    return "CodeQuest is running successfully! 🎮"


# ==========================================
# RUN APPLICATION
# ==========================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
