from flask import Flask, render_template, request, redirect, session
import mysql.connector
import os
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)


# ==========================================
# SECRET KEY
# ==========================================

app.secret_key = os.getenv(
    "SECRET_KEY",
    "codequest-development-key"
)


# ==========================================
# MYSQL DATABASE CONNECTION
# ==========================================

db = mysql.connector.connect(
    host=os.getenv("DB_HOST", "localhost"),
    user=os.getenv("DB_USER", "root"),
    password=os.getenv("DB_PASSWORD"),
    database=os.getenv("DB_NAME", "codequest")
)


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

        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        # Check whether passwords match
        if password != confirm_password:
            return "Passwords do not match!"

        # Hash password before storing it
        hashed_password = generate_password_hash(password)

        try:

            cursor = db.cursor()

            query = """
            INSERT INTO users
            (username, email, password)
            VALUES (%s, %s, %s)
            """

            cursor.execute(
                query,
                (username, email, hashed_password)
            )

            db.commit()

            cursor.close()

            return redirect("/login")

        except mysql.connector.IntegrityError:

            return "Username or email already exists!"

        except Exception as e:

            return f"Database error: {e}"

    return render_template("signup.html")


# ==========================================
# LOGIN
# ==========================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username_or_email = request.form["username"]
        password = request.form["password"]

        cursor = db.cursor(dictionary=True)

        query = """
        SELECT *
        FROM users
        WHERE username = %s OR email = %s
        """

        cursor.execute(
            query,
            (username_or_email, username_or_email)
        )

        user = cursor.fetchone()

        cursor.close()

        # Check whether user exists
        if user is None:

            return "User not found!"

        # Check password
        if check_password_hash(
            user["password"],
            password
        ):

            session["user_id"] = user["id"]
            session["username"] = user["username"]

            return redirect("/dashboard")

        else:

            return "Incorrect password!"

    return render_template("login.html")


# ==========================================
# DASHBOARD
# ==========================================

@app.route("/dashboard")
def dashboard():

    # Check whether user is logged in
    if "user_id" not in session:

        return redirect("/login")

    cursor = db.cursor(dictionary=True)

    query = """
    SELECT *
    FROM users
    WHERE id = %s
    """

    cursor.execute(
        query,
        (session["user_id"],)
    )

    user = cursor.fetchone()

    cursor.close()

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
# RUN CODEQUEST
# ==========================================

if __name__ == "__main__":

    app.run(debug=True)