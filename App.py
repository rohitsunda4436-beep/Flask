import sqlite3
from functools import wraps
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, g)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "change-this-secret-key"
DB = "app.db"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    db = sqlite3.connect(DB)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS tasks(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        done INTEGER DEFAULT 0);
    """)
    db.commit()
    db.close()


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


@app.route("/")
def home():
    return redirect(url_for("tasks"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        if len(username) < 3:
            flash("Username kam se kam 3 characters ka ho.")
        elif len(password) < 6:
            flash("Password kam se kam 6 characters ka ho.")
        else:
            try:
                db = get_db()
                db.execute("INSERT INTO users(username, password) VALUES(?, ?)",
                           (username, generate_password_hash(password)))
                db.commit()
                flash("Register ho gaye! Ab login karo.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Ye username pehle se hai.")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        user = get_db().execute("SELECT * FROM users WHERE username = ?",
                                (username,)).fetchone()
        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("tasks"))
        flash("Username ya password galat hai.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/tasks", methods=["GET", "POST"])
@login_required
def tasks():
    db = get_db()
    if request.method == "POST":
        title = request.form["title"].strip()
        if title:
            db.execute("INSERT INTO tasks(user_id, title) VALUES(?, ?)",
                       (session["user_id"], title))
            db.commit()
        else:
            flash("Task khali nahi ho sakta.")
        return redirect(url_for("tasks"))
    rows = db.execute("SELECT * FROM tasks WHERE user_id = ? ORDER BY id DESC",
                      (session["user_id"],)).fetchall()
    return render_template("tasks.html", tasks=rows)


@app.route("/toggle/<int:task_id>", methods=["POST"])
@login_required
def toggle(task_id):
    db = get_db()
    db.execute("UPDATE tasks SET done = 1 - done WHERE id = ? AND user_id = ?",
               (task_id, session["user_id"]))
    db.commit()
    return redirect(url_for("tasks"))


@app.route("/delete/<int:task_id>", methods=["POST"])
@login_required
def delete(task_id):
    db = get_db()
    db.execute("DELETE FROM tasks WHERE id = ? AND user_id = ?",
               (task_id, session["user_id"]))
    db.commit()
    return redirect(url_for("tasks"))


init_db()

if __name__ == "__main__":
    app.run(debug=True)
